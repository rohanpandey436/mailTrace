"""
Persistence: SQLite store for analyses, indicators, campaigns, alerts, a
lookup cache and the hash-chained chain-of-custody ledger.

Design
------
* One connection, one re-entrant lock: every public method is atomic with
  respect to every other, which is all a single-process analyst tool needs.
  WAL mode keeps readers (the dashboard) from blocking the analysis thread.
* Analyses are stored as their canonical JSON (``model_dump_json``) next to a
  handful of indexed summary columns used for search/filter/statistics.
* The raw ``.eml`` is written once to the evidence directory and never
  modified; its SHA-256 is recorded in the ledger at ingestion.
* The custody ledger is a single global hash chain:
  ``hash = sha256(prev_hash | seq | email_id | timestamp | actor | action |
  detail_json | evidence_sha256)`` with ``detail_json`` stored verbatim so the
  chain can be re-verified byte-for-byte later (``verify_chain``).

Zero-persistence mode (Stage 5C)
--------------------------------
``Store(..., in_memory=True)`` backs the same schema with an anonymous SQLite
database (``:memory:``) and stops writing evidence files.  No directory is
created, no file is opened: every table below lives in this process and is
gone when it exits.  Every public method behaves exactly as it does on disk,
except ``get_raw`` which always returns ``None`` because the raw message was
never stored.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from .schemas import (
    Alert,
    AnalysisResult,
    Campaign,
    CaseSummary,
    CustodyChain,
    CustodyEvent,
    DashboardStats,
    Severity,
    ThreatCategory,
)

log = logging.getLogger("mailtrace.db")

GENESIS_HASH = "0" * 64
HIGH_RISK_THRESHOLD = 70

_SCHEMA = """
CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    sender_domain TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0,
    analyzed_at TEXT NOT NULL,
    campaign_id TEXT,
    originating_ip TEXT NOT NULL DEFAULT '',
    origin_country TEXT NOT NULL DEFAULT '',
    source_type TEXT NOT NULL DEFAULT 'undetermined',
    spf TEXT NOT NULL DEFAULT 'none',
    dkim TEXT NOT NULL DEFAULT 'none',
    dmarc TEXT NOT NULL DEFAULT 'none',
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_emails_analyzed ON emails(analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_emails_campaign ON emails(campaign_id);
CREATE INDEX IF NOT EXISTS idx_emails_category ON emails(category);
CREATE TABLE IF NOT EXISTS indicators (
    email_id TEXT NOT NULL,
    indicator TEXT NOT NULL,
    PRIMARY KEY (email_id, indicator)
);
CREATE INDEX IF NOT EXISTS idx_indicators_indicator ON indicators(indicator);
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaign_members (
    campaign_id TEXT NOT NULL,
    email_id TEXT PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_members_campaign ON campaign_members(campaign_id);
CREATE TABLE IF NOT EXISTS custody (
    seq INTEGER PRIMARY KEY,
    email_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_email ON custody(email_id);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    email_id TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    expires_at REAL NOT NULL
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for hashing (sorted keys, compact, UTF-8)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def chain_hash(
    prev_hash: str, seq: int, email_id: str, timestamp: str, actor: str, action: str, detail_json: str, evidence_sha256: str
) -> str:
    material = "|".join([prev_hash, str(seq), email_id, timestamp, actor, action, detail_json, evidence_sha256])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class Store:
    """Thread-safe SQLite persistence for MailTrace.

    ``in_memory=True`` (zero-persistence mode) keeps the identical schema in an
    anonymous ``:memory:`` database and writes no evidence files, so nothing at
    all reaches the filesystem.  It is keyword-only and defaults to False: every
    existing caller keeps the previous on-disk behaviour unchanged.
    """

    def __init__(self, db_path: Path, evidence_dir: Path, *, in_memory: bool = False) -> None:
        self.db_path = Path(db_path)
        self.evidence_dir = Path(evidence_dir)
        self.in_memory = bool(in_memory)
        if not self.in_memory:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        target = ":memory:" if self.in_memory else str(self.db_path)
        self._conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if not self.in_memory:
                # WAL is meaningless for :memory: (its journal mode is always "memory"),
                # and both pragmas exist only to make on-disk writes cheap and concurrent.
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
        if self.in_memory:
            log.info("store opened in memory (zero-persistence): nothing is written to %s", self.db_path.parent)
        else:
            log.info("store opened at %s", self.db_path)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                log.debug("closing store failed", exc_info=True)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """Explicit transaction (the connection runs in autocommit mode)."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    # ------------------------------------------------------------------ #
    # Analyses
    # ------------------------------------------------------------------ #
    @staticmethod
    def _summary_columns(result: AnalysisResult) -> dict[str, Any]:
        origin_geo = result.infrastructure.origin_geo
        return {
            "id": result.id,
            "filename": result.filename,
            "subject": result.email.subject or "",
            "sender": result.email.sender.address or "",
            "sender_domain": result.email.sender.domain or "",
            "category": result.verdict.category.value,
            "risk_score": int(result.verdict.risk_score),
            "severity": result.verdict.severity.value,
            "confidence": float(result.verdict.confidence),
            "analyzed_at": result.analyzed_at.isoformat(),
            "campaign_id": result.campaign_id,
            "originating_ip": result.headers.originating_ip or "",
            "origin_country": (origin_geo.country if origin_geo else "") or "",
            "source_type": result.attribution.source_type,
            "spf": result.headers.auth.spf,
            "dkim": result.headers.auth.dkim,
            "dmarc": result.headers.auth.dmarc,
        }

    def save_analysis(self, result: AnalysisResult, raw: Optional[bytes]) -> None:
        columns = self._summary_columns(result)
        columns["result_json"] = result.model_dump_json()
        names = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        with self._tx() as conn:
            conn.execute(f"INSERT OR REPLACE INTO emails ({names}) VALUES ({placeholders})", list(columns.values()))
        # Zero-persistence: the analysis lives in the in-memory database, but the
        # message itself is never copied to the evidence directory.
        if raw is not None and not self.in_memory:
            path = self.evidence_dir / f"{result.id}.eml"
            if not path.exists():
                path.write_bytes(raw)

    def get_analysis(self, email_id: str) -> Optional[AnalysisResult]:
        with self._lock:
            row = self._conn.execute("SELECT result_json FROM emails WHERE id = ?", (email_id,)).fetchone()
        if row is None:
            return None
        try:
            return AnalysisResult.model_validate_json(row["result_json"])
        except Exception:  # noqa: BLE001 - schema drift on old rows
            log.exception("stored analysis %s is unreadable", email_id)
            return None

    def get_raw(self, email_id: str) -> Optional[bytes]:
        if self.in_memory:
            # Nothing was ever written, and an evidence directory left behind by a
            # previous on-disk run must not be read back in this mode.
            return None
        path = self.evidence_dir / f"{email_id}.eml"
        try:
            return path.read_bytes()
        except OSError:
            return None

    @staticmethod
    def _row_to_summary(row: sqlite3.Row) -> CaseSummary:
        return CaseSummary(
            id=row["id"],
            filename=row["filename"],
            subject=row["subject"],
            sender=row["sender"],
            sender_domain=row["sender_domain"],
            category=ThreatCategory(row["category"]),
            risk_score=int(row["risk_score"]),
            severity=Severity(row["severity"]),
            confidence=float(row["confidence"]),
            analyzed_at=_parse_dt(row["analyzed_at"]),
            campaign_id=row["campaign_id"],
            originating_ip=row["originating_ip"],
            origin_country=row["origin_country"],
            source_type=row["source_type"],
            spf=row["spf"],
            dkim=row["dkim"],
            dmarc=row["dmarc"],
        )

    def list_cases(
        self,
        q: str = "",
        category: Optional[str] = None,
        min_risk: int = 0,
        campaign_id: Optional[str] = None,
        source_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[CaseSummary], int]:
        clauses: list[str] = ["risk_score >= ?"]
        params: list[Any] = [int(min_risk or 0)]
        if q:
            like = f"%{q.strip().lower()}%"
            clauses.append(
                "(LOWER(subject) LIKE ? OR LOWER(sender) LIKE ? OR LOWER(filename) LIKE ? "
                "OR LOWER(originating_ip) LIKE ? OR LOWER(sender_domain) LIKE ? OR LOWER(id) LIKE ?)"
            )
            params.extend([like] * 6)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if campaign_id:
            clauses.append("campaign_id = ?")
            params.append(campaign_id)
        if source_type:
            clauses.append("source_type = ?")
            params.append(source_type)
        where = " AND ".join(clauses)
        limit = max(1, min(int(limit or 50), 500))
        offset = max(0, int(offset or 0))
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM emails WHERE {where}", params).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM emails WHERE {where} ORDER BY analyzed_at DESC, id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._row_to_summary(r) for r in rows], int(total)

    def update_campaign_id(self, email_id: str, campaign_id: Optional[str]) -> None:
        """Move an email into (or out of) a campaign.

        The membership lives in two places: the indexed ``campaign_id`` column
        that drives search, and the serialised analysis that the detail view
        and the forensic report read back.  Both are rewritten here so an
        email pulled into a campaign after the fact does not report itself as
        unclustered.
        """
        with self._tx() as conn:
            conn.execute("UPDATE emails SET campaign_id = ? WHERE id = ?", (campaign_id, email_id))
            row = conn.execute("SELECT result_json FROM emails WHERE id = ?", (email_id,)).fetchone()
            if row is None:
                return
            try:
                payload = json.loads(row["result_json"])
            except (TypeError, ValueError):
                log.warning("cannot re-tag campaign on unreadable analysis %s", email_id)
                return
            payload["campaign_id"] = campaign_id
            if isinstance(payload.get("intel"), dict):
                payload["intel"]["campaign_id"] = campaign_id
            conn.execute(
                "UPDATE emails SET result_json = ? WHERE id = ?",
                (json.dumps(payload, ensure_ascii=False), email_id),
            )

    def summaries_for(self, email_ids: list[str]) -> list[CaseSummary]:
        ids = [i for i in email_ids if i]
        if not ids:
            return []
        placeholders = ", ".join("?" for _ in ids)
        with self._lock:
            rows = self._conn.execute(f"SELECT * FROM emails WHERE id IN ({placeholders})", ids).fetchall()
        by_id = {r["id"]: self._row_to_summary(r) for r in rows}
        return [by_id[i] for i in ids if i in by_id]

    # ------------------------------------------------------------------ #
    # Indicators & campaigns
    # ------------------------------------------------------------------ #
    def save_indicators(self, email_id: str, indicators: list[str]) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM indicators WHERE email_id = ?", (email_id,))
            conn.executemany(
                "INSERT OR IGNORE INTO indicators (email_id, indicator) VALUES (?, ?)",
                [(email_id, ind) for ind in dict.fromkeys(i for i in indicators if i)],
            )

    def find_emails_by_indicators(self, indicators: list[str], exclude_email_id: str = "") -> dict[str, list[str]]:
        keys = [i for i in dict.fromkeys(indicators) if i]
        if not keys:
            return {}
        placeholders = ", ".join("?" for _ in keys)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT email_id, indicator FROM indicators WHERE indicator IN ({placeholders}) AND email_id != ?",
                [*keys, exclude_email_id or ""],
            ).fetchall()
        result: dict[str, list[str]] = {}
        for row in rows:
            result.setdefault(row["email_id"], []).append(row["indicator"])
        return result

    def find_indicators_by_prefix(self, prefix: str, exclude_email_id: str = "") -> dict[str, list[str]]:
        """email_id -> that email's indicators beginning with ``prefix``.

        The fuzzy campaign matcher (Stage 5A) cannot look a SimHash or TLSH
        digest up by equality without discarding the tolerance that makes it
        useful, so it pulls every stored digest and compares distances itself.
        The half-open range keeps ``idx_indicators_indicator`` usable, which a
        ``LIKE 'prefix%'`` on a BINARY-collated column would not.
        """
        prefix = prefix or ""
        if not prefix:
            return {}
        upper_bound = prefix[:-1] + chr(ord(prefix[-1]) + 1)
        with self._lock:
            rows = self._conn.execute(
                "SELECT email_id, indicator FROM indicators "
                "WHERE indicator >= ? AND indicator < ? AND email_id != ?",
                (prefix, upper_bound, exclude_email_id or ""),
            ).fetchall()
        result: dict[str, list[str]] = {}
        for row in rows:
            result.setdefault(row["email_id"], []).append(row["indicator"])
        return result

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        with self._lock:
            row = self._conn.execute("SELECT data_json FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if row is None:
            return None
        try:
            return Campaign.model_validate_json(row["data_json"])
        except Exception:  # noqa: BLE001
            log.exception("stored campaign %s is unreadable", campaign_id)
            return None

    def list_campaigns(self) -> list[Campaign]:
        with self._lock:
            rows = self._conn.execute("SELECT data_json FROM campaigns ORDER BY updated_at DESC").fetchall()
        campaigns: list[Campaign] = []
        for row in rows:
            try:
                campaigns.append(Campaign.model_validate_json(row["data_json"]))
            except Exception:  # noqa: BLE001
                log.exception("stored campaign row is unreadable")
        return campaigns

    def upsert_campaign(self, campaign: Campaign) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO campaigns (id, name, created_at, updated_at, data_json) VALUES (?, ?, ?, ?, ?)",
                (campaign.id, campaign.name, campaign.created_at.isoformat(), campaign.updated_at.isoformat(), campaign.model_dump_json()),
            )
            conn.execute("DELETE FROM campaign_members WHERE campaign_id = ?", (campaign.id,))
            conn.executemany(
                "INSERT OR REPLACE INTO campaign_members (campaign_id, email_id) VALUES (?, ?)",
                [(campaign.id, email_id) for email_id in dict.fromkeys(campaign.email_ids)],
            )

    def campaign_for_email(self, email_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT campaign_id FROM campaign_members WHERE email_id = ?", (email_id,)).fetchone()
        return row["campaign_id"] if row else None

    def delete_campaign(self, campaign_id: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM campaign_members WHERE campaign_id = ?", (campaign_id,))
            conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))

    # ------------------------------------------------------------------ #
    # Chain of custody
    # ------------------------------------------------------------------ #
    def record_custody(self, email_id: str, actor: str, action: str, detail: dict, evidence_sha256: str) -> CustodyEvent:
        detail_json = canonical_json(detail or {})
        timestamp = _now_iso()
        with self._tx() as conn:
            last = conn.execute("SELECT seq, hash FROM custody ORDER BY seq DESC LIMIT 1").fetchone()
            seq = (int(last["seq"]) + 1) if last else 1
            prev_hash = last["hash"] if last else GENESIS_HASH
            digest = chain_hash(prev_hash, seq, email_id, timestamp, actor, action, detail_json, evidence_sha256 or "")
            conn.execute(
                "INSERT INTO custody (seq, email_id, timestamp, actor, action, detail_json, evidence_sha256, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (seq, email_id, timestamp, actor, action, detail_json, evidence_sha256 or "", prev_hash, digest),
            )
        return CustodyEvent(
            seq=seq,
            timestamp=_parse_dt(timestamp),
            actor=actor,
            action=action,
            email_id=email_id,
            detail=json.loads(detail_json),
            evidence_sha256=evidence_sha256 or "",
            prev_hash=prev_hash,
            hash=digest,
        )

    def verify_chain(self) -> tuple[bool, str]:
        """Recompute every link; returns (valid, head_hash)."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM custody ORDER BY seq ASC").fetchall()
        prev_hash = GENESIS_HASH
        expected_seq = 1
        for row in rows:
            if int(row["seq"]) != expected_seq or row["prev_hash"] != prev_hash:
                return False, prev_hash
            digest = chain_hash(
                prev_hash, int(row["seq"]), row["email_id"], row["timestamp"], row["actor"], row["action"],
                row["detail_json"], row["evidence_sha256"],
            )
            if digest != row["hash"]:
                return False, prev_hash
            prev_hash = digest
            expected_seq += 1
        return True, prev_hash

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> CustodyEvent:
        try:
            detail = json.loads(row["detail_json"])
        except (TypeError, ValueError):
            detail = {"raw": row["detail_json"]}
        return CustodyEvent(
            seq=int(row["seq"]),
            timestamp=_parse_dt(row["timestamp"]),
            actor=row["actor"],
            action=row["action"],
            email_id=row["email_id"],
            detail=detail if isinstance(detail, dict) else {"value": detail},
            evidence_sha256=row["evidence_sha256"],
            prev_hash=row["prev_hash"],
            hash=row["hash"],
        )

    def get_custody(self, email_id: str) -> CustodyChain:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM custody WHERE email_id = ? ORDER BY seq ASC", (email_id,)).fetchall()
        valid, head = self.verify_chain()
        return CustodyChain(email_id=email_id, events=[self._row_to_event(r) for r in rows], valid=valid, head_hash=head)

    # ------------------------------------------------------------------ #
    # Alerts
    # ------------------------------------------------------------------ #
    def create_alert(self, alert: Alert) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO alerts (id, created_at, email_id, subject, sender, category, risk_score, severity, message, acknowledged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alert.id, alert.created_at.isoformat(), alert.email_id, alert.subject, alert.sender,
                    alert.category.value, int(alert.risk_score), alert.severity.value, alert.message, int(alert.acknowledged),
                ),
            )

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            created_at=_parse_dt(row["created_at"]),
            email_id=row["email_id"],
            subject=row["subject"],
            sender=row["sender"],
            category=ThreatCategory(row["category"]),
            risk_score=int(row["risk_score"]),
            severity=Severity(row["severity"]),
            message=row["message"],
            acknowledged=bool(row["acknowledged"]),
        )

    def list_alerts(self, limit: int = 50, unacknowledged_only: bool = False) -> list[Alert]:
        where = "WHERE acknowledged = 0" if unacknowledged_only else ""
        limit = max(1, min(int(limit or 50), 500))
        with self._lock:
            rows = self._conn.execute(f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._tx() as conn:
            cursor = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            return cursor.rowcount > 0

    # ------------------------------------------------------------------ #
    # Lookup cache
    # ------------------------------------------------------------------ #
    def cache_get(self, key: str) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value_json, expires_at FROM cache WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) < time.time():
                self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None
        try:
            return json.loads(row["value_json"])
        except (TypeError, ValueError):
            return None

    def cache_set(self, key: str, value: Any, ttl_seconds: int) -> None:
        try:
            payload = json.dumps(value, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            return
        # The TTL is honoured as given: a non-positive lifetime stores an entry
        # that is already expired, which the next read drops.  Clamping it up
        # would keep data the caller explicitly asked to expire.
        try:
            lifetime = float(ttl_seconds)
        except (TypeError, ValueError):
            lifetime = 0.0
        expires = time.time() + lifetime
        with self._tx() as conn:
            conn.execute("INSERT OR REPLACE INTO cache (key, value_json, expires_at) VALUES (?, ?, ?)", (key, payload, expires))

    # ------------------------------------------------------------------ #
    # Statistics
    # ------------------------------------------------------------------ #
    def stats(self) -> DashboardStats:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
            high = self._conn.execute("SELECT COUNT(*) FROM emails WHERE risk_score >= ?", (HIGH_RISK_THRESHOLD,)).fetchone()[0]
            campaigns = self._conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
            alerts_open = self._conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
            avg = self._conn.execute("SELECT AVG(risk_score) FROM emails").fetchone()[0]
            categories = self._conn.execute("SELECT category, COUNT(*) AS n FROM emails GROUP BY category").fetchall()
            countries = self._conn.execute(
                "SELECT origin_country, COUNT(*) AS n FROM emails WHERE origin_country != '' "
                "GROUP BY origin_country ORDER BY n DESC LIMIT 5"
            ).fetchall()
            sources = self._conn.execute("SELECT source_type, COUNT(*) AS n FROM emails GROUP BY source_type").fetchall()
        by_category = Counter({c.value: 0 for c in ThreatCategory})
        for row in categories:
            by_category[row["category"]] = int(row["n"])
        return DashboardStats(
            total_emails=int(total),
            high_risk=int(high),
            campaigns=int(campaigns),
            alerts_open=int(alerts_open),
            by_category=dict(by_category),
            top_countries=[{"country": row["origin_country"], "count": int(row["n"])} for row in countries],
            top_source_types={row["source_type"]: int(row["n"]) for row in sources},
            avg_risk=round(float(avg or 0.0), 1),
        )
