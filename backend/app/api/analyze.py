"""
Ingestion and case-retrieval endpoints.

Uploaded files (multipart ``files``) and pasted raw messages share one
``_process`` helper: the request handler validates the payload size, then a
worker thread runs ``pipeline.analyze_bytes`` (analysis and SQLite access are
synchronous), raises an alert when the verdict crosses the threshold and
masks PII on the way out when requested.  Files are processed sequentially so
the store never interleaves writes from a single request.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Optional, get_args

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from ..config import Settings
from ..db import Store
from ..engine import pipeline
from ..engine.csvexport import UTF8_BOM, render_case_list_csv
from ..engine.privacy import mask_result
from ..schemas import (
    AnalysisResult,
    CaseDecision,
    CaseSummary,
    DashboardStats,
    RawSubmission,
    SourceType,
    ThreatCategory,
)
from .alerts import maybe_alert
from .deps import DEFAULT_ACTOR, get_settings, get_store, mask_alert, mask_param, mask_summary

router = APIRouter(prefix="/api", tags=["analysis"])

_PATH_SEPARATORS = re.compile(r"[\\/]+")
_MAX_FILENAME = 200
_CATEGORIES = {c.value for c in ThreatCategory}
_SOURCE_TYPES = set(get_args(SourceType))

# Bulk CSV export: a ceiling on rows so one request cannot pin the process, and
# the page size the store already allows per query.
MAX_EXPORT_ROWS = 5000
_EXPORT_PAGE = 500

# Stage 6 quick-bar.  decision -> (case status, custody action).
_DECISIONS: dict[str, tuple[str, str]] = {
    "quarantine": ("quarantined", "quarantine_decision"),
    "block": ("blocked", "block_decision"),
}
_DECISION_ACTIONS = {action for _, action in _DECISIONS.values()}


def _choice(value: Optional[str], allowed: set[str], name: str) -> Optional[str]:
    """Normalise an optional enum-like filter: blank means 'no filter', anything else must be a known value."""
    value = (value or "").strip()
    if not value:
        return None
    if value not in allowed:
        raise HTTPException(status_code=422, detail=f"unknown {name} '{value}'; expected one of: {', '.join(sorted(allowed))}")
    return value


def _clean_filename(name: Optional[str], fallback: str) -> str:
    """Last path segment only, trimmed, never empty."""
    tail = _PATH_SEPARATORS.split((name or "").strip())[-1].strip()
    return (tail or fallback)[:_MAX_FILENAME]


def _check_size(size: int, filename: str, settings: Settings) -> None:
    if size == 0:
        raise HTTPException(status_code=400, detail=f"'{filename}' is empty")
    if size > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"'{filename}' is {size} bytes; the upload limit is {settings.max_upload_bytes} bytes",
        )


def _process(
    raw: bytes, filename: str, actor: str, mask: bool, store: Store, settings: Settings
) -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
    """Worker-thread body: pipeline, alerting, optional masking, JSON-ready dumps."""
    result = pipeline.analyze_bytes(raw, filename, store, settings, actor)
    alert = maybe_alert(result, store, settings)
    if mask:
        result = mask_result(result)
        alert = mask_alert(alert) if alert is not None else None
    return result.model_dump(mode="json"), (alert.model_dump(mode="json") if alert is not None else None)


def _load(store: Store, email_id: str) -> AnalysisResult:
    result = store.get_analysis(email_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"email {email_id} not found")
    return result


@router.post("/analyze")
async def analyze_upload(
    files: list[UploadFile] = File(..., description="One or more RFC 822 messages (.eml / .txt)"),
    actor: str = Query(DEFAULT_ACTOR, min_length=1, max_length=64, description="Recorded in the chain of custody"),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    payloads: list[tuple[str, bytes]] = []
    for index, upload in enumerate(files, start=1):
        filename = _clean_filename(upload.filename, f"upload-{index}.eml")
        raw = await upload.read()
        _check_size(len(raw), filename, settings)
        payloads.append((filename, raw))

    results: list[dict[str, Any]] = []
    alerts: list[dict[str, Any]] = []
    for filename, raw in payloads:
        result, alert = await run_in_threadpool(_process, raw, filename, actor, mask, store, settings)
        results.append(result)
        if alert is not None:
            alerts.append(alert)
    return {"results": results, "alerts": alerts}


@router.post("/analyze/raw")
async def analyze_raw(
    submission: RawSubmission,
    actor: str = Query(DEFAULT_ACTOR, min_length=1, max_length=64, description="Recorded in the chain of custody"),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    filename = _clean_filename(submission.filename, "pasted.eml")
    raw = submission.raw.encode("utf-8", errors="surrogateescape")
    _check_size(len(raw), filename, settings)
    result, alert = await run_in_threadpool(_process, raw, filename, actor, mask, store, settings)
    return {"results": [result], "alerts": [alert] if alert is not None else []}


@router.get("/emails")
def list_emails(
    q: str = Query("", max_length=200, description="Matches subject, sender, filename, origin IP, sender domain"),
    category: Optional[str] = Query(None, max_length=32, description="Legitimate|Suspicious|Impersonated|Phishing|Fraud-Related; blank = all"),
    min_risk: int = Query(0, ge=0, le=100),
    campaign_id: Optional[str] = Query(None, max_length=64),
    source_type: Optional[str] = Query(None, max_length=64, description="Attribution source type; blank = all"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
) -> dict[str, Any]:
    # Plain strings (not enums) so that the blank values HTML forms and curl users
    # send ("category=") mean "no filter" instead of failing validation.
    rows, total = store.list_cases(
        q=q.strip(),
        category=_choice(category, _CATEGORIES, "category"),
        min_risk=min_risk,
        campaign_id=(campaign_id or "").strip() or None,
        source_type=_choice(source_type, _SOURCE_TYPES, "source_type"),
        limit=limit,
        offset=offset,
    )
    if mask:
        rows = [mask_summary(row) for row in rows]
    return {"items": [row.model_dump(mode="json") for row in rows], "total": total}


# Registered before ``/emails/{email_id}``: FastAPI matches routes in order, and
# the path parameter would otherwise swallow the literal "export.csv".
@router.get("/emails/export.csv")
def export_emails_csv(
    q: str = Query("", max_length=200, description="Matches subject, sender, filename, origin IP, sender domain"),
    category: Optional[str] = Query(None, max_length=32, description="Legitimate|Suspicious|Impersonated|Phishing|Fraud-Related; blank = all"),
    min_risk: int = Query(0, ge=0, le=100),
    campaign_id: Optional[str] = Query(None, max_length=64),
    source_type: Optional[str] = Query(None, max_length=64, description="Attribution source type; blank = all"),
    limit: int = Query(MAX_EXPORT_ROWS, ge=1, le=MAX_EXPORT_ROWS, description="Hard cap on exported rows"),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
) -> Response:
    """The case list as a CSV, with the same filters ``GET /api/emails`` accepts.

    Intended for bulk analysis in a spreadsheet or a notebook, so it pages past
    the 500-row ceiling ``list_cases`` puts on a single query, up to
    ``MAX_EXPORT_ROWS``.  Every cell is passed through the formula-injection
    guard in ``engine/csvexport.py``.

    Honest scope note: this exports *case metadata*, not evidence, so unlike a
    per-case report it writes no custody event - there is no single email the
    event would belong to.  Exporting one case's evidence (``format=csv`` on
    the report endpoint, or the raw ``.eml``) is recorded as it always was.
    """
    filters = dict(
        q=q.strip(),
        category=_choice(category, _CATEGORIES, "category"),
        min_risk=min_risk,
        campaign_id=(campaign_id or "").strip() or None,
        source_type=_choice(source_type, _SOURCE_TYPES, "source_type"),
    )
    rows: list[CaseSummary] = []
    while len(rows) < limit:
        page, total = store.list_cases(**filters, limit=min(_EXPORT_PAGE, limit - len(rows)), offset=len(rows))
        if not page:
            break
        rows.extend(page)
        if len(rows) >= total:
            break
    if mask:
        rows = [mask_summary(row) for row in rows]
    return Response(
        content=UTF8_BOM + render_case_list_csv(rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="MailTrace-cases.csv"'},
    )


@router.get("/emails/{email_id}")
def get_email(
    email_id: str,
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> AnalysisResult:
    result = _load(store, email_id)
    if mask:
        return mask_result(result)
    if settings.pii_mask_default:
        store.record_custody(
            email_id, DEFAULT_ACTOR, "viewed_unmasked", {"view": "analysis", "masked": False}, result.email.raw_sha256
        )
    return result


@router.get("/emails/{email_id}/raw")
def get_raw(
    email_id: str,
    store: Store = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> Response:
    raw = store.get_raw(email_id)
    if raw is None:
        if settings.zero_persistence:
            # Say why, rather than implying the case never existed or handing back
            # an empty download: in this mode the message was analysed and dropped.
            raise HTTPException(
                status_code=404,
                detail=(
                    f"the raw message for email {email_id} is not available: MailTrace is running in "
                    "zero-persistence mode, so no copy of it was ever written to disk"
                ),
            )
        raise HTTPException(status_code=404, detail=f"email {email_id} not found")
    store.record_custody(
        email_id, DEFAULT_ACTOR, "exported", {"format": "eml", "size": len(raw)}, hashlib.sha256(raw).hexdigest()
    )
    return Response(
        content=raw,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{email_id}.eml"'},
    )


# --------------------------------------------------------------------------- #
# Stage 6 quick-bar: quarantine / block
#
# What these endpoints do and, more importantly, what they do not do.
#
# They record an analyst's decision about a case: the decision and its author
# go into the hash-linked chain of custody, the case gets a status the case
# list can filter and display, and the response hands back the IOCs to feed to
# whatever actually enforces - a mail gateway, a firewall, a SIEM or the
# outbound webhooks in ``api/alerts.py``.
#
# They do NOT contact Microsoft 365, Google Workspace or any mail transfer
# agent.  Nothing is moved to a quarantine folder, no sender is added to a
# block list, no message is recalled or deleted.  MailTrace is a forensic
# analysis tool with no mailbox credentials and no write access to mail flow,
# and a button that silently did nothing while claiming otherwise would be
# worse than no button at all.  ``CaseDecision.enforced`` is therefore always
# False, and the dashboard wording says "record decision", not "quarantine".
# --------------------------------------------------------------------------- #
# The correlation engine and the attribution engine label the same fact
# differently ("ip:" vs "origin_ip:", "domain:" vs "sender_domain:"), so a plain
# string dedupe across the two leaves every shared fact in the list twice and
# inflates the count an analyst is shown. Normalise the prefix before comparing.
_INDICATOR_ALIASES: dict[str, str] = {
    "origin_ip": "ip",
    "sender_domain": "domain",
    "reply_to": "replyto",
    "url_host": "urlhost",
    "attachment_sha256": "file",
    "sender": "sender",
}


def _indicator_key(indicator: str) -> str:
    prefix, sep, value = indicator.partition(":")
    if not sep:
        return indicator.strip().lower()
    return f"{_INDICATOR_ALIASES.get(prefix.strip().lower(), prefix.strip().lower())}:{value.strip().lower()}"


def _decision_indicators(result: AnalysisResult) -> list[str]:
    """IOCs worth handing to the system that does enforce, newest evidence first.

    Deduplicated by the fact each one states rather than by its exact spelling,
    so the same IP appearing as both ``ip:`` and ``origin_ip:`` is listed once.
    """
    seen: set[str] = set()
    out: list[str] = []
    for indicator in [*result.intel.indicators, *result.attribution.indicators]:
        key = _indicator_key(indicator)
        if key in seen:
            continue
        seen.add(key)
        out.append(indicator)
    return out


def _decision_state(store: Store, result: AnalysisResult) -> CaseDecision:
    chain = store.get_custody(result.id)
    return CaseDecision(
        email_id=result.id,
        status=store.get_case_status(result.id),
        enforced=False,
        indicators=_decision_indicators(result),
        history=[event for event in chain.events if event.action in _DECISION_ACTIONS],
    )


def _record_decision(email_id: str, decision: str, actor: str, store: Store) -> CaseDecision:
    status, action = _DECISIONS[decision]
    result = _load(store, email_id)
    previous = store.get_case_status(email_id)
    if not store.set_case_status(email_id, status, actor):
        raise HTTPException(status_code=404, detail=f"email {email_id} not found")
    store.record_custody(
        email_id,
        actor,
        action,
        {
            "decision": decision,
            "status": status,
            "previous_status": previous,
            "category": result.verdict.category.value,
            "risk_score": result.verdict.risk_score,
            "indicator_count": len(_decision_indicators(result)),
            # Recorded in the ledger itself so a reader of the chain, years
            # later, cannot mistake this for gateway enforcement.
            "enforced": False,
            "note": "analyst decision recorded in MailTrace; no mail system was contacted",
        },
        result.email.raw_sha256,
    )
    return _decision_state(store, result)


@router.post("/emails/{email_id}/quarantine")
def quarantine_email(
    email_id: str,
    actor: str = Query(DEFAULT_ACTOR, min_length=1, max_length=64, description="Recorded in the chain of custody"),
    store: Store = Depends(get_store),
) -> CaseDecision:
    """Record a decision to quarantine this message and return its IOCs.

    Writes a ``quarantine_decision`` event to the chain of custody and sets the
    case status to ``quarantined``.  It does not quarantine anything in a mail
    system: see the note above this endpoint.
    """
    return _record_decision(email_id, "quarantine", actor, store)


@router.post("/emails/{email_id}/block")
def block_email(
    email_id: str,
    actor: str = Query(DEFAULT_ACTOR, min_length=1, max_length=64, description="Recorded in the chain of custody"),
    store: Store = Depends(get_store),
) -> CaseDecision:
    """Record a decision to block this sender/infrastructure and return its IOCs.

    Writes a ``block_decision`` event to the chain of custody and sets the case
    status to ``blocked``.  It does not add anything to a real block list: see
    the note above this endpoint.
    """
    return _record_decision(email_id, "block", actor, store)


@router.get("/emails/{email_id}/decision")
def get_decision(email_id: str, store: Store = Depends(get_store)) -> CaseDecision:
    """The decision currently recorded against a case, with its ledger history."""
    return _decision_state(store, _load(store, email_id))


@router.get("/stats")
def get_stats(store: Store = Depends(get_store)) -> DashboardStats:
    return store.stats()
