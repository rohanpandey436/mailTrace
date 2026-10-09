from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..config import Settings
from ..database.case_manager import Store
from ..schemas import AnalysisResult, CaseOrigin, Retention, RetentionState
from .errors import NotFound

log = logging.getLogger("mailtrace.retention")

RETAIN_ACTION = "retention_set"
FREEZE_ACTION = "evidence_frozen"
PURGE_ACTION = "purged"

_ORIGINS: dict[str, CaseOrigin] = {"dashboard": "dashboard", "gmail": "gmail"}
_REMOVED = ["analysis", "original message", "indicators", "alerts", "analyst decision"]


class RetentionLimit(ValueError):
    pass


@dataclass(frozen=True)
class Plan:

    origin: CaseOrigin = "dashboard"
    listed: bool = True
    hours: int | None = None

    @property
    def tracked(self) -> bool:
        return self.origin != "dashboard" or not self.listed or self.hours is not None


def plan(origin: CaseOrigin, listed: bool | None, hours: int | None, cfg: Settings) -> Plan:
    from_gmail = origin == "gmail"
    if hours is not None and hours > cfg.retention_max_hours:
        raise RetentionLimit(
            f"retention_hours is {hours}; the longest period this server accepts is {cfg.retention_max_hours}"
        )
    if hours is None and from_gmail:
        hours = cfg.retention_default_hours
    return Plan(origin=origin, listed=(not from_gmail) if listed is None else bool(listed), hours=hours)


def _moment(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _describe(row: dict[str, Any], now: datetime) -> Retention:
    expires_at = _moment(row.get("expires_at"))
    frozen_at = _moment(row.get("frozen_at"))
    purged_at = _moment(row.get("purged_at"))
    state: RetentionState = "permanent"
    seconds_left: int | None = None
    if purged_at is not None:
        state = "purged"
    elif frozen_at is not None:
        state = "frozen"
    elif expires_at is not None:
        state = "expiring"
        seconds_left = max(0, int((expires_at - now).total_seconds()))
    return Retention(
        email_id=str(row.get("email_id") or ""),
        origin=_ORIGINS.get(str(row.get("origin") or ""), "dashboard"),
        listed=bool(row.get("listed")),
        state=state,
        created_at=_moment(row.get("created_at")),
        expires_at=None if frozen_at is not None else expires_at,
        seconds_left=seconds_left,
        frozen_at=frozen_at,
        frozen_by=str(row.get("frozen_by") or ""),
        purged_at=purged_at,
    )


def apply(store: Store, result: AnalysisResult, chosen: Plan, actor: str, now: datetime | None = None) -> Retention | None:
    if not chosen.tracked:
        return None
    now = now or datetime.now(UTC)
    expires_at = now + timedelta(hours=chosen.hours) if chosen.hours is not None else None
    store.set_retention(
        result.id,
        chosen.origin,
        chosen.listed,
        expires_at.isoformat() if expires_at is not None else None,
        result.email.raw_sha256,
    )
    store.record_custody(
        result.id,
        actor,
        RETAIN_ACTION,
        {
            "origin": chosen.origin,
            "listed": chosen.listed,
            "retention_hours": chosen.hours,
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
            "note": "deleted automatically when the period ends unless it is frozen as evidence"
            if expires_at is not None
            else "kept until it is removed by an administrator",
        },
        result.email.raw_sha256,
    )
    return current(store, result.id, now)


def _gone(email_id: str, row: dict[str, Any]) -> NotFound:
    purged_at = _moment(row.get("purged_at"))
    when = purged_at.strftime("%d %b %Y at %H:%M UTC") if purged_at is not None else "an earlier date"
    return NotFound(
        f"email {email_id} was deleted on {when} when its retention period ended; "
        "only its custody record remains"
    )


def _expired(row: dict[str, Any], now: datetime) -> bool:
    if row.get("frozen_at") or row.get("purged_at"):
        return False
    expires_at = _moment(row.get("expires_at"))
    return expires_at is not None and expires_at <= now


def _purge(store: Store, row: dict[str, Any], now: datetime) -> bool:
    email_id = str(row.get("email_id") or "")
    if not email_id:
        return False
    existed = store.purge_case(email_id)
    expires_at = _moment(row.get("expires_at"))
    created_at = _moment(row.get("created_at"))
    hours: int | None = None
    if expires_at is not None and created_at is not None:
        hours = round((expires_at - created_at).total_seconds() / 3600)
    store.record_custody(
        email_id,
        "system",
        PURGE_ACTION,
        {
            "reason": "retention period ended",
            "origin": str(row.get("origin") or ""),
            "retention_hours": hours,
            "expired_at": expires_at.isoformat() if expires_at is not None else None,
            "purged_at": now.isoformat(),
            "removed": list(_REMOVED) if existed else [],
        },
        str(row.get("evidence_sha256") or ""),
    )
    log.info("email %s deleted at the end of its retention period", email_id)
    return True


def purge_expired(store: Store, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(UTC)
    purged: list[str] = []
    for row in store.retention_pending():
        if not _expired(row, now):
            continue
        try:
            if _purge(store, row, now):
                purged.append(str(row["email_id"]))
        except Exception:
            log.exception("could not delete expired email %s", row.get("email_id"))
    return purged


def ensure_available(store: Store, email_id: str, now: datetime | None = None) -> None:
    row = store.get_retention(email_id)
    if row is None:
        return
    now = now or datetime.now(UTC)
    if row.get("purged_at"):
        raise _gone(email_id, row)
    if _expired(row, now):
        _purge(store, row, now)
        raise _gone(email_id, store.get_retention(email_id) or row)


def current(store: Store, email_id: str, now: datetime | None = None) -> Retention:
    now = now or datetime.now(UTC)
    row = store.get_retention(email_id)
    if row is not None:
        if _expired(row, now):
            _purge(store, row, now)
            row = store.get_retention(email_id) or row
        return _describe(row, now)
    if not store.case_exists(email_id):
        raise NotFound(f"email {email_id} not found")
    return Retention(email_id=email_id)


def freeze(store: Store, email_id: str, actor: str, now: datetime | None = None) -> Retention:
    now = now or datetime.now(UTC)
    ensure_available(store, email_id, now)
    before = current(store, email_id, now)
    if before.state != "expiring":
        return before
    if not store.freeze_retention(email_id, actor):
        return current(store, email_id, now)
    row = store.get_retention(email_id) or {}
    store.record_custody(
        email_id,
        actor,
        FREEZE_ACTION,
        {
            "origin": before.origin,
            "would_have_expired_at": before.expires_at.isoformat() if before.expires_at is not None else None,
            "note": "automatic deletion cancelled; the case is preserved as evidence",
        },
        str(row.get("evidence_sha256") or ""),
    )
    log.info("email %s frozen as evidence by %s", email_id, actor)
    return current(store, email_id, now)


def summary(store: Store, cfg: Settings) -> str:
    waiting = len(store.retention_pending())
    return f"sweep every {cfg.retention_sweep_seconds} s; {waiting} case(s) awaiting deletion"
