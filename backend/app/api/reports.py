"""
Forensic report and chain-of-custody endpoints.

Generating a report is itself a custody event: it is recorded *before* the
custody chain is read, so the report documents its own creation and its
``custody_head_hash`` covers that event.  The event records the requested
format, so the ledger distinguishes a JSON pull from a PDF hand-over.  A masked
report is built from an already-masked analysis and then passed through
``mask_report_fields`` so the narrative sections cannot leak what the
structured data hides.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..core import decisions
from ..core.errors import NotFound
from ..schemas import CustodyChain, CustodyVerification
from ..utils.csv_exporter import UTF8_BOM, render_report_csv
from ..utils.pdf_generator import PdfUnavailable, build_report, render_html, render_pdf
from ..utils.pii_masker import mask_report_fields, mask_result
from .deps import DEFAULT_ACTOR, MaskDep, StoreDep

router = APIRouter(prefix="/api", tags=["reports"])

ReportFormat = Literal["json", "html", "pdf", "csv"]

# Content-Disposition is a header: keep the filename to characters that need no
# quoting or encoding, whatever the report id happens to contain.
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _report_filename(report_id: str, extension: str) -> str:
    return "MailTrace-" + (_UNSAFE_FILENAME.sub("-", report_id).strip("-") or "report") + "." + extension


@router.get("/reports/{email_id}")
def get_report(
    email_id: str,
    store: StoreDep,
    mask: MaskDep,
    fmt: Annotated[ReportFormat, Query(alias="format")] = "json",
) -> Response:
    result = decisions.load_case(store, email_id)
    if mask:
        result = mask_result(result)
    store.record_custody(
        email_id, DEFAULT_ACTOR, "report_generated", {"format": fmt, "masked": mask}, result.email.raw_sha256
    )
    report = build_report(result, store.get_custody(email_id), mask, generated_by=DEFAULT_ACTOR)
    if mask:
        report = mask_report_fields(report)
    if fmt == "html":
        return HTMLResponse(render_html(report))
    if fmt == "csv":
        # Rendered from the same (already masked, if asked) report object as
        # every other format, so the CSV can never show more than the HTML.
        # The BOM makes Excel read it as UTF-8 instead of the host code page.
        return Response(
            content=UTF8_BOM + render_report_csv(report),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{_report_filename(report.report_id, "csv")}"'},
        )
    if fmt == "pdf":
        try:
            pdf = render_pdf(report)
        except PdfUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{_report_filename(report.report_id, "pdf")}"'},
        )
    return JSONResponse(content=report.model_dump(mode="json"))


@router.get("/custody/verify")
def verify_custody(store: StoreDep) -> CustodyVerification:
    valid, head_hash = store.verify_chain()
    return CustodyVerification(valid=valid, head_hash=head_hash)


@router.get("/custody/{email_id}")
def get_custody(email_id: str, store: StoreDep) -> CustodyChain:
    chain = store.get_custody(email_id)
    if not chain.events:
        raise NotFound(f"no custody records for email {email_id}")
    return chain
