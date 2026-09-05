"""
Ingestion and case endpoints.

Uploaded files (multipart ``files``) and pasted raw messages share one
``_process`` helper: the handler validates the payload size, then a worker
thread runs ``pipeline.analyze_bytes`` (analysis and database access are
synchronous), raises an alert when the verdict crosses the threshold and
masks PII on the way out when requested.  Files are processed sequentially so
the store never interleaves writes from a single request.

``POST /api/analyze/async`` is the same ingestion through the Celery queue in
``app/tasks.py``: it answers with job ids instead of results, which is what a
mailbox export of several hundred messages needs.  The jobs endpoints below
poll them.

Handlers here only translate HTTP into calls on the domain layer; the analyst
decision logic lives in ``app/core/decisions.py``.
"""
from __future__ import annotations

import hashlib
import re
from typing import Annotated, get_args

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from .. import tasks
from ..config import Settings
from ..core import decisions, explanations, pipeline
from ..core.errors import NotFound
from ..database.case_manager import Store
from ..schemas import (
    Alert,
    AnalysisResult,
    AnalyzeResponse,
    AsyncAnalyzeResponse,
    CaseDecision,
    CaseListResponse,
    CaseSummary,
    DashboardStats,
    JobStatus,
    LimeReport,
    RawSubmission,
    SourceType,
    ThreatCategory,
)
from ..utils.csv_exporter import UTF8_BOM, render_case_list_csv
from ..utils.pii_masker import mask_result
from .alerts import maybe_alert
from .deps import DEFAULT_ACTOR, ActorParam, MaskDep, SettingsDep, StoreDep, mask_alert, mask_summary

router = APIRouter(prefix="/api", tags=["analysis"])

_PATH_SEPARATORS = re.compile(r"[\\/]+")
_MAX_FILENAME = 200
_CATEGORIES = {category.value for category in ThreatCategory}
_SOURCE_TYPES = set(get_args(SourceType))

# Bulk CSV export: a ceiling on rows so one request cannot pin the process, and
# the page size the store already allows per query.
MAX_EXPORT_ROWS = 5000
_EXPORT_PAGE = 500

# Async ingestion. The cap is on how many messages one request may enqueue, not
# on how many the queue holds: it stops a single upload from filling the broker,
# and the client simply submits the next batch.
MAX_ASYNC_FILES = 500
# Job ids are UUIDs the broker issued. Polling is a public endpoint, so an id is
# checked for shape before it is used as a key in the result backend.
_MAX_POLL_IDS = 100
_JOB_ID = re.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _choice(value: str | None, allowed: set[str], name: str) -> str | None:
    """Normalise an optional enum-like filter: blank means 'no filter', anything else must be a known value."""
    value = (value or "").strip()
    if not value:
        return None
    if value not in allowed:
        raise HTTPException(
            status_code=422, detail=f"unknown {name} '{value}'; expected one of: {', '.join(sorted(allowed))}"
        )
    return value


def _clean_filename(name: str | None, fallback: str) -> str:
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


def _check_job_id(job_id: str) -> None:
    """Reject anything that is not a broker-issued id before it is used as a key."""
    if not _JOB_ID.fullmatch(job_id):
        raise HTTPException(status_code=422, detail=f"'{job_id[:64]}' is not a job id")


def _process(
    raw: bytes, filename: str, actor: str, mask: bool, store: Store, settings: Settings
) -> tuple[AnalysisResult, Alert | None]:
    """Worker-thread body: pipeline, alerting, optional masking."""
    result = pipeline.analyze_bytes(raw, filename, store, settings, actor)
    alert = maybe_alert(result, store, settings)
    if mask:
        result = mask_result(result)
        alert = mask_alert(alert) if alert is not None else None
    return result, alert


class CaseFilters:
    """The filters ``GET /api/emails`` and its CSV export share.

    Plain strings rather than enums, so the blank values HTML forms and curl
    users send (``category=``) mean "no filter" instead of failing validation.
    """

    def __init__(
        self,
        q: Annotated[str, Query(max_length=200, description="Matches subject, sender, filename, origin IP, sender domain")] = "",
        category: Annotated[
            str | None, Query(max_length=32, description="Legitimate|Suspicious|Impersonated|Phishing|Fraud-Related; blank = all")
        ] = None,
        min_risk: Annotated[int, Query(ge=0, le=100)] = 0,
        campaign_id: Annotated[str | None, Query(max_length=64)] = None,
        source_type: Annotated[str | None, Query(max_length=64, description="Attribution source type; blank = all")] = None,
    ) -> None:
        self.q = q.strip()
        self.category = _choice(category, _CATEGORIES, "category")
        self.min_risk = min_risk
        self.campaign_id = (campaign_id or "").strip() or None
        self.source_type = _choice(source_type, _SOURCE_TYPES, "source_type")

    def page(self, store: Store, limit: int, offset: int) -> tuple[list[CaseSummary], int]:
        return store.list_cases(
            q=self.q,
            category=self.category,
            min_risk=self.min_risk,
            campaign_id=self.campaign_id,
            source_type=self.source_type,
            limit=limit,
            offset=offset,
        )


FiltersDep = Annotated[CaseFilters, Depends()]


@router.post("/analyze")
async def analyze_upload(
    store: StoreDep,
    settings: SettingsDep,
    mask: MaskDep,
    files: Annotated[list[UploadFile], File(description="One or more RFC 822 messages (.eml / .txt)")],
    actor: ActorParam = DEFAULT_ACTOR,
) -> AnalyzeResponse:
    payloads: list[tuple[str, bytes]] = []
    for index, upload in enumerate(files, start=1):
        filename = _clean_filename(upload.filename, f"upload-{index}.eml")
        raw = await upload.read()
        _check_size(len(raw), filename, settings)
        payloads.append((filename, raw))

    response = AnalyzeResponse(results=[])
    for filename, raw in payloads:
        result, alert = await run_in_threadpool(_process, raw, filename, actor, mask, store, settings)
        response.results.append(result)
        if alert is not None:
            response.alerts.append(alert)
    return response


@router.post("/analyze/raw")
async def analyze_raw(
    submission: RawSubmission,
    store: StoreDep,
    settings: SettingsDep,
    mask: MaskDep,
    actor: ActorParam = DEFAULT_ACTOR,
) -> AnalyzeResponse:
    filename = _clean_filename(submission.filename, "pasted.eml")
    raw = submission.raw.encode("utf-8", errors="surrogateescape")
    _check_size(len(raw), filename, settings)
    result, alert = await run_in_threadpool(_process, raw, filename, actor, mask, store, settings)
    return AnalyzeResponse(results=[result], alerts=[alert] if alert is not None else [])


@router.post("/analyze/async", status_code=202)
async def analyze_upload_async(
    settings: SettingsDep,
    files: Annotated[list[UploadFile], File(description="One or more RFC 822 messages (.eml / .txt)")],
    actor: ActorParam = DEFAULT_ACTOR,
) -> AsyncAnalyzeResponse:
    """Queue messages for analysis and answer immediately with job ids.

    Every message is validated here rather than in the worker, so a payload
    that is empty or too large is refused with the same status the synchronous
    endpoint would use, before anything is enqueued.

    No ``mask`` parameter: nothing analysable is returned, and the case is read
    back through ``/api/emails/{id}``, which applies the masking policy.
    """
    if len(files) > MAX_ASYNC_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"{len(files)} messages in one request; the limit is {MAX_ASYNC_FILES}. Submit them in batches.",
        )

    payloads: list[tuple[str, bytes]] = []
    for index, upload in enumerate(files, start=1):
        filename = _clean_filename(upload.filename, f"upload-{index}.eml")
        raw = await upload.read()
        _check_size(len(raw), filename, settings)
        payloads.append((filename, raw))

    jobs: list[JobStatus] = []
    for filename, raw in payloads:
        # apply_async talks to the broker over a socket, and in eager mode it
        # runs the whole analysis, so neither belongs on the event loop.
        job_id = await run_in_threadpool(tasks.enqueue, raw, filename, actor)
        jobs.append(JobStatus(**tasks.job_state(job_id), filename=filename))
    return AsyncAnalyzeResponse(jobs=jobs, queue=tasks.queue_status(settings))


@router.get("/jobs/{job_id}")
async def get_job(job_id: str) -> JobStatus:
    """Poll one queued message."""
    _check_job_id(job_id)
    return JobStatus(**await run_in_threadpool(tasks.job_state, job_id))


@router.get("/jobs")
async def get_jobs(
    ids: Annotated[str, Query(max_length=_MAX_POLL_IDS * 40, description="Comma-separated job ids")],
) -> list[JobStatus]:
    """Poll a whole batch in one request.

    A browser watching 300 uploads would otherwise open 300 connections per
    tick; this keeps a progress bar to one request.
    """
    job_ids = [part.strip() for part in ids.split(",") if part.strip()]
    if not job_ids:
        raise HTTPException(status_code=422, detail="ids must name at least one job")
    if len(job_ids) > _MAX_POLL_IDS:
        raise HTTPException(status_code=422, detail=f"{len(job_ids)} ids; the limit per request is {_MAX_POLL_IDS}")
    for job_id in job_ids:
        _check_job_id(job_id)
    states = await run_in_threadpool(lambda: [tasks.job_state(job_id) for job_id in job_ids])
    return [JobStatus(**state) for state in states]


@router.get("/emails")
def list_emails(
    filters: FiltersDep,
    store: StoreDep,
    mask: MaskDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CaseListResponse:
    rows, total = filters.page(store, limit=limit, offset=offset)
    if mask:
        rows = [mask_summary(row) for row in rows]
    return CaseListResponse(items=rows, total=total)


# Registered before ``/emails/{email_id}``: FastAPI matches routes in order, and
# the path parameter would otherwise swallow the literal "export.csv".
@router.get("/emails/export.csv")
def export_emails_csv(
    filters: FiltersDep,
    store: StoreDep,
    mask: MaskDep,
    limit: Annotated[int, Query(ge=1, le=MAX_EXPORT_ROWS, description="Hard cap on exported rows")] = MAX_EXPORT_ROWS,
) -> Response:
    """The case list as a CSV, with the same filters ``GET /api/emails`` accepts.

    Intended for bulk analysis in a spreadsheet or a notebook, so it pages past
    the 500-row ceiling ``list_cases`` puts on a single query, up to
    ``MAX_EXPORT_ROWS``.  Every cell is passed through the formula-injection
    guard in ``app/utils/csv_exporter.py``.

    Honest scope note: this exports *case metadata*, not evidence, so unlike a
    per-case report it writes no custody event - there is no single email the
    event would belong to.  Exporting one case's evidence (``format=csv`` on
    the report endpoint, or the raw ``.eml``) is recorded as it always was.
    """
    rows: list[CaseSummary] = []
    while len(rows) < limit:
        page, total = filters.page(store, limit=min(_EXPORT_PAGE, limit - len(rows)), offset=len(rows))
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
def get_email(email_id: str, store: StoreDep, settings: SettingsDep, mask: MaskDep) -> AnalysisResult:
    result = decisions.load_case(store, email_id)
    if mask:
        return mask_result(result)
    if settings.pii_mask_default:
        store.record_custody(
            email_id, DEFAULT_ACTOR, "viewed_unmasked", {"view": "analysis", "masked": False}, result.email.raw_sha256
        )
    return result


@router.get("/emails/{email_id}/raw")
def get_raw(email_id: str, store: StoreDep, settings: SettingsDep) -> Response:
    raw = store.get_raw(email_id)
    if raw is None:
        if settings.zero_persistence:
            # Say why, rather than implying the case never existed or handing back
            # an empty download: in this mode the message was analysed and dropped.
            raise NotFound(
                f"the raw message for email {email_id} is not available: MailTrace is running in "
                "zero-persistence mode, so no copy of it was ever written to disk"
            )
        raise NotFound(f"email {email_id} not found")
    store.record_custody(
        email_id, DEFAULT_ACTOR, "exported", {"format": "eml", "size": len(raw)}, hashlib.sha256(raw).hexdigest()
    )
    return Response(
        content=raw,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{email_id}.eml"'},
    )


# Stage 6 quick-bar.  What these record, and what they deliberately do not do,
# is documented once in app/core/decisions.py.
@router.post("/emails/{email_id}/quarantine")
def quarantine_email(email_id: str, store: StoreDep, actor: ActorParam = DEFAULT_ACTOR) -> CaseDecision:
    """Record a decision to quarantine this message and return its IOCs.

    Writes a ``quarantine_decision`` event to the chain of custody and sets the
    case status to ``quarantined``.  It does not quarantine anything in a mail
    system.
    """
    return decisions.record(store, email_id, "quarantine", actor)


@router.post("/emails/{email_id}/block")
def block_email(email_id: str, store: StoreDep, actor: ActorParam = DEFAULT_ACTOR) -> CaseDecision:
    """Record a decision to block this sender/infrastructure and return its IOCs.

    Writes a ``block_decision`` event to the chain of custody and sets the case
    status to ``blocked``.  It does not add anything to a real block list.
    """
    return decisions.record(store, email_id, "block", actor)


@router.get("/emails/{email_id}/decision")
def get_decision(email_id: str, store: StoreDep) -> CaseDecision:
    """The decision currently recorded against a case, with its ledger history."""
    return decisions.current(store, decisions.load_case(store, email_id))


@router.get("/emails/{email_id}/explanation")
async def get_explanation(email_id: str, store: StoreDep, settings: SettingsDep) -> LimeReport:
    """The LIME explanation for a case, fitted on the first request and cached.

    Kept off the ingest path deliberately: the surrogate costs several times the
    rest of the analysis and changes no verdict, so it is built when a person
    actually opens the case.  See ``app/core/explanations.py``.
    """
    result = decisions.load_case(store, email_id)
    return await run_in_threadpool(explanations.lime_report, result, settings, store)


@router.get("/stats")
def get_stats(store: StoreDep) -> DashboardStats:
    return store.stats()
