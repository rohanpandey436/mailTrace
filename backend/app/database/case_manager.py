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

PostgreSQL (optional)
---------------------
The default and only tested backend is SQLite: every query below is written in
SQLite SQL and, on the SQLite path, reaches ``sqlite3`` untranslated.  When
``MAILTRACE_DATABASE_URL`` points at a ``postgres://`` / ``postgresql://``
server *and* the optional ``psycopg`` driver is installed (see
``requirements-pg.txt``), ``Store`` opens that server instead through
``_PostgresDialect``, a thin adapter over the four differences this module
actually depends on: the parameter marker (``?`` vs ``%s``), ``INSERT OR
REPLACE`` / ``INSERT OR IGNORE`` vs ``ON CONFLICT``, the ``PRAGMA`` statements
and rows that must be readable both by name and by position.  Everything else
- the DDL, the types, the queries - is already portable and is shared verbatim.

If the URL is set but ``psycopg`` is missing or the server cannot be reached,
the store logs the failure and falls back to SQLite rather than refusing to
start; ``Store.backend`` (surfaced by ``/api/health``) always says which engine
is actually in use.  Honest scope note: the PostgreSQL path is exercised by no
test in this repository - the suite runs entirely on SQLite - so it should be
treated as reviewed-but-unverified until someone points it at a real server.
Evidence ``.eml`` files stay on the local filesystem in both cases.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import JsonValue, ValidationError

from ..schemas import (
    CASE_STATUSES,
    Alert,
    AnalysisResult,
    Campaign,
    CaseStatus,
    CaseSummary,
    CountryCount,
    CustodyChain,
    CustodyEvent,
    DashboardStats,
    Severity,
    ThreatCategory,
)

if TYPE_CHECKING:  # pragma: no cover - annotations only; psycopg is an optional runtime dependency
    import psycopg

log = logging.getLogger("mailtrace.db")

GENESIS_HASH = "0" * 64
HIGH_RISK_THRESHOLD = 70
DEFAULT_CASE_STATUS: CaseStatus = "open"
# Column text -> the typed status; anything else normalises to the default.
_STATUS_BY_NAME: dict[str, CaseStatus] = {str(name): name for name in CASE_STATUSES}

# Stage 6 quick-bar.  The decision lives in its own table rather than in a new
# ``emails`` column so that an existing deployment picks it up from
# ``CREATE TABLE IF NOT EXISTS`` with no migration and no ALTER TABLE, and so a
# re-analysis of the same id (INSERT OR REPLACE on ``emails``) cannot silently
# discard an analyst's decision.  The authoritative record of *who* decided
# *when* is the custody ledger; this table is the indexed projection the case
# list reads.

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
CREATE TABLE IF NOT EXISTS case_status (
    email_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'open',
    decided_at TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT ''
);
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_dt(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for hashing (sorted keys, compact, UTF-8)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def chain_hash(
    prev_hash: str, seq: int, email_id: str, timestamp: str, actor: str, action: str, detail_json: str, evidence_sha256: str
) -> str:
    material = "|".join([prev_hash, str(seq), email_id, timestamp, actor, action, detail_json, evidence_sha256])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# SQL dialects
#
# Everything in ``Store`` below is written once, in SQLite SQL with ``?``
# markers.  A dialect supplies only what genuinely differs between engines:
#   * how to open a connection and apply the schema (PRAGMA vs nothing),
#   * the upsert spelling (INSERT OR REPLACE/IGNORE vs ON CONFLICT).
# ``_SqliteDialect`` is the identity: it hands the sqlite3 connection straight
# back and emits exactly the SQL this module used before the split existed, so
# the tested path is byte-for-byte unchanged.
POSTGRES_SCHEMES = ("postgres://", "postgresql://")

# A connection-like object: ``execute(sql, params) -> cursor``, ``executemany``
# and ``close``.  On SQLite it *is* a ``sqlite3.Connection``.
Connection = Any
# A result row: readable by column name and by position (sqlite3.Row / _PgRow).
Row = Any


def _insert_columns(columns: list[str]) -> tuple[str, str]:
    return ", ".join(columns), ", ".join("?" for _ in columns)


class _SqliteDialect:
    """The historical behaviour of this module, unchanged."""

    name = "sqlite"

    def __init__(self, target: str, *, on_disk: bool) -> None:
        self.target = target
        self.on_disk = on_disk

    def connect(self) -> Connection:
        conn = sqlite3.connect(self.target, check_same_thread=False, isolation_level=None, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self, conn: Connection) -> None:
        if self.on_disk:
            # WAL is meaningless for :memory: (its journal mode is always "memory"),
            # and both pragmas exist only to make on-disk writes cheap and concurrent.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)

    @staticmethod
    def upsert(table: str, columns: list[str], conflict: tuple[str, ...]) -> str:
        names, placeholders = _insert_columns(columns)
        return f"INSERT OR REPLACE INTO {table} ({names}) VALUES ({placeholders})"

    @staticmethod
    def insert_ignore(table: str, columns: list[str]) -> str:
        names, placeholders = _insert_columns(columns)
        return f"INSERT OR IGNORE INTO {table} ({names}) VALUES ({placeholders})"


class _PgRow:
    """A row readable both as ``row["column"]`` and ``row[0]``, like sqlite3.Row.

    psycopg ships ``tuple_row`` (positional only) and ``dict_row`` (name only);
    this module uses both styles, so it needs the sqlite3 hybrid.
    """

    __slots__ = ("_index", "_values")

    def __init__(self, names: tuple[str, ...], values: Sequence[object]) -> None:
        self._values = tuple(values)
        self._index = {name: position for position, name in enumerate(names)}

    def __getitem__(self, key: str | int) -> object:
        return self._values[self._index[key] if isinstance(key, str) else key]

    def __iter__(self) -> Iterator[object]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def keys(self) -> list[str]:
        return list(self._index)


def _pg_row_factory(cursor: psycopg.Cursor[object]) -> Callable[[Sequence[object]], _PgRow]:
    names = tuple(column.name for column in (cursor.description or ()))

    def make_row(values: Sequence[object]) -> _PgRow:
        return _PgRow(names, values)

    return make_row


class _PgConnection:
    """Makes a psycopg connection answer to the small sqlite3 API used here.

    Two translations, both narrow:
      * ``?`` -> ``%s``.  Safe because no SQL string in this module contains a
        literal ``?`` or ``%`` - the ``%`` wildcards of the search LIKE live in
        the *parameter*, never in the statement.
      * parameterless statements are sent with ``params=None`` so psycopg does
        not scan them for placeholders at all.
    """

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    @staticmethod
    def _translate(sql: str) -> str:
        return sql.replace("?", "%s")

    def execute(self, sql: str, params: Any = ()) -> Any:
        cursor = self._conn.cursor()
        cursor.execute(self._translate(sql), tuple(params) or None)
        return cursor

    def executemany(self, sql: str, seq_of_params: Any) -> Any:
        rows = [tuple(params) for params in seq_of_params]
        cursor = self._conn.cursor()
        if rows:
            cursor.executemany(self._translate(sql), rows)
        return cursor

    def close(self) -> None:
        self._conn.close()


class _PostgresDialect:
    """PostgreSQL / Supabase backend (optional: needs ``psycopg``)."""

    name = "postgresql"

    def __init__(self, url: str) -> None:
        self.url = url

    def connect(self) -> Connection:
        import psycopg  # optional dependency, imported only when configured

        # autocommit mirrors sqlite3's isolation_level=None: the explicit
        # BEGIN/COMMIT in Store._tx is then the only transaction control, in
        # both engines.
        conn = psycopg.connect(self.url, autocommit=True, row_factory=_pg_row_factory)
        return _PgConnection(conn)

    def init_schema(self, conn: Connection) -> None:
        for statement in self._schema_statements():
            conn.execute(statement)

    @staticmethod
    def _schema_statements() -> list[str]:
        """``_SCHEMA`` is already valid PostgreSQL (TEXT/INTEGER/REAL, IF NOT
        EXISTS, no AUTOINCREMENT - ``custody.seq`` is computed by this module).
        The single adjustment: ``indicators.indicator`` is given the binary "C"
        collation, because ``find_indicators_by_prefix`` walks a half-open
        string range that only means what it says under byte ordering, and
        because the index must then match that ordering to be usable."""
        schema = _SCHEMA.replace("    indicator TEXT NOT NULL,", '    indicator TEXT COLLATE "C" NOT NULL,')
        return [statement.strip() for statement in schema.split(";") if statement.strip()]

    @staticmethod
    def upsert(table: str, columns: list[str], conflict: tuple[str, ...]) -> str:
        names, placeholders = _insert_columns(columns)
        updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in columns if c not in conflict)
        target = ", ".join(conflict)
        action = f"DO UPDATE SET {updates}" if updates else "DO NOTHING"
        return f"INSERT INTO {table} ({names}) VALUES ({placeholders}) ON CONFLICT ({target}) {action}"

    @staticmethod
    def insert_ignore(table: str, columns: list[str]) -> str:
        names, placeholders = _insert_columns(columns)
        return f"INSERT INTO {table} ({names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"


def _make_dialect(target: str, database_url: str, *, on_disk: bool) -> Any:
    """PostgreSQL when it is configured, reachable and importable; SQLite otherwise.

    A configured-but-unusable server degrades to SQLite with a loud error rather
    than taking the service down: the free-tier deployment has no database
    attached and must still start.  ``Store.backend`` reports what was chosen.
    """
    url = (database_url or "").strip()
    if not url or not url.startswith(POSTGRES_SCHEMES):
        return _SqliteDialect(target, on_disk=on_disk)
    if not on_disk:
        # Zero-persistence promises that nothing leaves the process; shipping
        # rows to a database server would break exactly that promise.
        log.warning("zero-persistence mode ignores MAILTRACE_DATABASE_URL and stays in memory")
        return _SqliteDialect(target, on_disk=on_disk)
    return _PostgresDialect(url)


class Store:
    """Thread-safe SQLite persistence for MailTrace.

    ``in_memory=True`` (zero-persistence mode) keeps the identical schema in an
    anonymous ``:memory:`` database and writes no evidence files: no
    ``mailtrace.db``, no ``evidence/`` directory and no copy of any analysed
    message reaches the filesystem, and neither directory is even created.

    It is not literally true that the process writes nothing at all: the
    classifier caches ``model.joblib`` and ``url_model.joblib`` under the data
    directory on first use. Those are trained solely from the bundled seed
    corpus and contain no analysed-email data, which is why they are permitted
    here; delete them and they are simply retrained.

    Keyword-only and defaults to False, so every existing caller keeps the
    previous on-disk behaviour unchanged.
    """

    def __init__(
        self, db_path: Path, evidence_dir: Path, *, in_memory: bool = False, database_url: str = ""
    ) -> None:
        self.db_path = Path(db_path)
        self.evidence_dir = Path(evidence_dir)
        self.in_memory = bool(in_memory)
        if not self.in_memory:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        target = ":memory:" if self.in_memory else str(self.db_path)
        self._dialect = _make_dialect(target, database_url, on_disk=not self.in_memory)
        try:
            self._conn = self._dialect.connect()
        except Exception as exc:  # noqa: BLE001 - an unreachable server must not stop the service
            log.error(
                "PostgreSQL backend unavailable (%s: %s); falling back to SQLite at %s. "
                "Install backend/requirements-pg.txt and check MAILTRACE_DATABASE_URL.",
                type(exc).__name__, exc, self.db_path,
            )
            self._dialect = _SqliteDialect(target, on_disk=not self.in_memory)
            self._conn = self._dialect.connect()
        with self._lock:
            self._dialect.init_schema(self._conn)
        if self.in_memory:
            log.info("store opened in memory (zero-persistence): nothing is written to %s", self.db_path.parent)
        elif self.backend == "sqlite":
            log.info("store opened at %s", self.db_path)
        else:
            log.info("store opened on %s (evidence .eml files stay at %s)", self.backend, self.evidence_dir)

    @property
    def backend(self) -> str:
        """``"sqlite"`` or ``"postgresql"``: the engine actually in use."""
        return str(self._dialect.name)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:  # sqlite3.Error or a psycopg error
                log.debug("closing store failed", exc_info=True)

    @contextmanager
    def _tx(self) -> Iterator[Connection]:
        """Explicit transaction (the connection runs in autocommit mode)."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
            except Exception:  # sqlite3.Error or a psycopg error; closing is best effort
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

    def save_analysis(self, result: AnalysisResult, raw: bytes | None) -> None:
        columns = self._summary_columns(result)
        columns["result_json"] = result.model_dump_json()
        sql = self._dialect.upsert("emails", list(columns), ("id",))
        with self._tx() as conn:
            conn.execute(sql, list(columns.values()))
        # Zero-persistence: the analysis lives in the in-memory database, but the
        # message itself is never copied to the evidence directory.
        if raw is not None and not self.in_memory:
            path = self.evidence_dir / f"{result.id}.eml"
            if not path.exists():
                path.write_bytes(raw)

    def get_analysis(self, email_id: str) -> AnalysisResult | None:
        with self._lock:
            row = self._conn.execute("SELECT result_json FROM emails WHERE id = ?", (email_id,)).fetchone()
        if row is None:
            return None
        try:
            return AnalysisResult.model_validate_json(row["result_json"])
        except ValidationError:  # schema drift on old rows
            log.exception("stored analysis %s is unreadable", email_id)
            return None

    def get_raw(self, email_id: str) -> bytes | None:
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
    def _row_status(row: Row) -> CaseStatus:
        """Analyst decision on a joined case row; 'open' when the query did not join.

        Only the two quick-bar endpoints ever write this column, but an unknown
        value is still normalised rather than trusted, so a hand-edited database
        cannot make ``CaseSummary`` fail validation for the whole listing.
        """
        try:
            value = row["status"]
        except (IndexError, KeyError, TypeError):
            return DEFAULT_CASE_STATUS
        return _STATUS_BY_NAME.get(str(value or DEFAULT_CASE_STATUS).strip().lower(), DEFAULT_CASE_STATUS)

    @staticmethod
    def _row_to_summary(row: Row) -> CaseSummary:
        return CaseSummary(
            status=Store._row_status(row),
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
        category: str | None = None,
        min_risk: int = 0,
        campaign_id: str | None = None,
        source_type: str | None = None,
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
                f"SELECT emails.*, COALESCE(case_status.status, '{DEFAULT_CASE_STATUS}') AS status "
                "FROM emails LEFT JOIN case_status ON case_status.email_id = emails.id "
                f"WHERE {where} ORDER BY analyzed_at DESC, id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._row_to_summary(r) for r in rows], int(total)

    def update_campaign_id(self, email_id: str, campaign_id: str | None) -> None:
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
            rows = self._conn.execute(
                f"SELECT emails.*, COALESCE(case_status.status, '{DEFAULT_CASE_STATUS}') AS status "
                "FROM emails LEFT JOIN case_status ON case_status.email_id = emails.id "
                f"WHERE emails.id IN ({placeholders})",
                ids,
            ).fetchall()
        by_id = {r["id"]: self._row_to_summary(r) for r in rows}
        return [by_id[i] for i in ids if i in by_id]

    # ------------------------------------------------------------------ #
    # Stage 6 quick-bar: analyst decisions
    # ------------------------------------------------------------------ #
    def get_case_status(self, email_id: str) -> CaseStatus:
        """Current analyst decision on a case ('open' when none was recorded)."""
        with self._lock:
            row = self._conn.execute("SELECT status FROM case_status WHERE email_id = ?", (email_id,)).fetchone()
        return self._row_status(row) if row is not None else DEFAULT_CASE_STATUS

    def set_case_status(self, email_id: str, status: str, actor: str = "") -> bool:
        """Record the analyst decision on a case; False when the case does not exist.

        This is MailTrace bookkeeping only.  Nothing here contacts a mail
        gateway, moves a message or blocks a sender - the decision and its
        author are written to the custody ledger by the caller, and this row is
        the indexed copy the case list reads.
        """
        status = (status or DEFAULT_CASE_STATUS).strip().lower()
        if status not in CASE_STATUSES:
            raise ValueError(f"unknown case status {status!r}; expected one of {', '.join(CASE_STATUSES)}")
        with self._tx() as conn:
            if conn.execute("SELECT 1 FROM emails WHERE id = ?", (email_id,)).fetchone() is None:
                return False
            conn.execute(
                self._dialect.upsert("case_status", ["email_id", "status", "decided_at", "actor"], ("email_id",)),
                (email_id, status, _now_iso(), actor or ""),
            )
        return True

    # ------------------------------------------------------------------ #
    # Indicators & campaigns
    # ------------------------------------------------------------------ #
    def save_indicators(self, email_id: str, indicators: list[str]) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM indicators WHERE email_id = ?", (email_id,))
            conn.executemany(
                self._dialect.insert_ignore("indicators", ["email_id", "indicator"]),
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

        The range is a *byte* range, so on PostgreSQL the ``indicator`` column
        is declared ``COLLATE "C"`` (see ``_PostgresDialect._schema_statements``):
        under a locale collation ``'simhash:...' < 'simhash;'`` is not the
        guarantee it is here, and the index would not match the comparison.
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

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        with self._lock:
            row = self._conn.execute("SELECT data_json FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if row is None:
            return None
        try:
            return Campaign.model_validate_json(row["data_json"])
        except ValidationError:
            log.exception("stored campaign %s is unreadable", campaign_id)
            return None

    def list_campaigns(self) -> list[Campaign]:
        with self._lock:
            rows = self._conn.execute("SELECT data_json FROM campaigns ORDER BY updated_at DESC").fetchall()
        campaigns: list[Campaign] = []
        for row in rows:
            try:
                campaigns.append(Campaign.model_validate_json(row["data_json"]))
            except ValidationError:
                log.exception("stored campaign row is unreadable")
        return campaigns

    def upsert_campaign(self, campaign: Campaign) -> None:
        with self._tx() as conn:
            conn.execute(
                self._dialect.upsert("campaigns", ["id", "name", "created_at", "updated_at", "data_json"], ("id",)),
                (campaign.id, campaign.name, campaign.created_at.isoformat(), campaign.updated_at.isoformat(), campaign.model_dump_json()),
            )
            conn.execute("DELETE FROM campaign_members WHERE campaign_id = ?", (campaign.id,))
            conn.executemany(
                # email_id is the primary key: an email joining this campaign is
                # moved out of whichever campaign previously claimed it.
                self._dialect.upsert("campaign_members", ["campaign_id", "email_id"], ("email_id",)),
                [(campaign.id, email_id) for email_id in dict.fromkeys(campaign.email_ids)],
            )

    def campaign_for_email(self, email_id: str) -> str | None:
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
    def record_custody(
        self, email_id: str, actor: str, action: str, detail: dict[str, object], evidence_sha256: str
    ) -> CustodyEvent:
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
    def _row_to_event(row: Row) -> CustodyEvent:
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
                self._dialect.upsert(
                    "alerts",
                    ["id", "created_at", "email_id", "subject", "sender", "category", "risk_score", "severity", "message", "acknowledged"],
                    ("id",),
                ),
                (
                    alert.id, alert.created_at.isoformat(), alert.email_id, alert.subject, alert.sender,
                    alert.category.value, int(alert.risk_score), alert.severity.value, alert.message, int(alert.acknowledged),
                ),
            )

    @staticmethod
    def _row_to_alert(row: Row) -> Alert:
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
            return bool(cursor.rowcount > 0)

    # ------------------------------------------------------------------ #
    # Lookup cache
    # ------------------------------------------------------------------ #
    def cache_get(self, key: str) -> JsonValue | None:
        with self._lock:
            row = self._conn.execute("SELECT value_json, expires_at FROM cache WHERE key = ?", (key,)).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) < time.time():
                self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None
        try:
            value: JsonValue = json.loads(row["value_json"])
        except (TypeError, ValueError):
            return None
        return value

    def cache_set(self, key: str, value: object, ttl_seconds: int) -> None:
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
            conn.execute(self._dialect.upsert("cache", ["key", "value_json", "expires_at"], ("key",)), (key, payload, expires))

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
            top_countries=[CountryCount(country=str(row["origin_country"]), count=int(row["n"])) for row in countries],
            top_source_types={row["source_type"]: int(row["n"]) for row in sources},
            avg_risk=round(float(avg or 0.0), 1),
        )
