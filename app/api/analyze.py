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
from ..engine.privacy import mask_result
from ..schemas import AnalysisResult, DashboardStats, RawSubmission, SourceType, ThreatCategory
from .alerts import maybe_alert
from .deps import DEFAULT_ACTOR, get_settings, get_store, mask_alert, mask_param, mask_summary

router = APIRouter(prefix="/api", tags=["analysis"])

_PATH_SEPARATORS = re.compile(r"[\\/]+")
_MAX_FILENAME = 200
_CATEGORIES = {c.value for c in ThreatCategory}
_SOURCE_TYPES = set(get_args(SourceType))


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
def get_raw(email_id: str, store: Store = Depends(get_store)) -> Response:
    raw = store.get_raw(email_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"email {email_id} not found")
    store.record_custody(
        email_id, DEFAULT_ACTOR, "exported", {"format": "eml", "size": len(raw)}, hashlib.sha256(raw).hexdigest()
    )
    return Response(
        content=raw,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{email_id}.eml"'},
    )


@router.get("/stats")
def get_stats(store: Store = Depends(get_store)) -> DashboardStats:
    return store.stats()
