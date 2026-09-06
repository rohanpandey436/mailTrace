"""Forensic report and chain-of-custody endpoints."""
from __future__ import annotations

import re
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..core import decisions, explanations
from ..core.errors import NotFound
from ..schemas import CustodyChain, CustodyVerification
from ..utils.csv_exporter import UTF8_BOM, render_report_csv
from ..utils.pdf_generator import PdfUnavailable, build_report, render_html, render_pdf
from ..utils.pii_masker import mask_report_fields, mask_result
from .deps import DEFAULT_ACTOR, MaskDep, SettingsDep, StoreDep

router = APIRouter(prefix="/api", tags=["reports"])

ReportFormat = Literal["json", "html", "pdf", "csv"]

_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _report_filename(report_id: str, extension: str) -> str:
    return "MailTrace-" + (_UNSAFE_FILENAME.sub("-", report_id).strip("-") or "report") + "." + extension


@router.get("/reports/{email_id}")
def get_report(
    email_id: str,
    store: StoreDep,
    settings: SettingsDep,
    mask: MaskDep,
    fmt: Annotated[ReportFormat, Query(alias="format")] = "json",
) -> Response:
    result = decisions.load_case(store, email_id)
    result = explanations.attach(result, settings, store)
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
