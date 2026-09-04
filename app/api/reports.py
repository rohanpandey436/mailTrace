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
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..db import Store
from ..engine.privacy import mask_report_fields, mask_result
from ..engine.reporting import PdfUnavailable, build_report, render_html, render_pdf
from ..schemas import CustodyChain
from .deps import DEFAULT_ACTOR, get_store, mask_param

router = APIRouter(prefix="/api", tags=["reports"])

# Content-Disposition is a header: keep the filename to characters that need no
# quoting or encoding, whatever the report id happens to contain.
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _pdf_filename(report_id: str) -> str:
    return "MailTrace-" + (_UNSAFE_FILENAME.sub("-", report_id).strip("-") or "report") + ".pdf"


@router.get("/reports/{email_id}")
def get_report(
    email_id: str,
    fmt: Literal["json", "html", "pdf"] = Query("json", alias="format"),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
) -> Response:
    result = store.get_analysis(email_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"email {email_id} not found")
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
    if fmt == "pdf":
        try:
            pdf = render_pdf(report)
        except PdfUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{_pdf_filename(report.report_id)}"'},
        )
    return JSONResponse(content=report.model_dump(mode="json"))


@router.get("/custody/verify")
def verify_custody(store: Store = Depends(get_store)) -> dict[str, Any]:
    valid, head_hash = store.verify_chain()
    return {"valid": valid, "head_hash": head_hash}


@router.get("/custody/{email_id}")
def get_custody(email_id: str, store: Store = Depends(get_store)) -> CustodyChain:
    chain = store.get_custody(email_id)
    if not chain.events:
        raise HTTPException(status_code=404, detail=f"no custody records for email {email_id}")
    return chain
