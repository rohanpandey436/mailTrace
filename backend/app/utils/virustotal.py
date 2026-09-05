"""
Optional VirusTotal file-hash reputation for attachments (TRACE + INTEL).

Only the SHA-256 digest of an attachment is ever sent, never the file
-------------------------------------------------------------------
This module calls ``GET /api/v3/files/{sha256}``, which asks "has anyone
already analysed a file with this digest?".  It deliberately does not call the
upload endpoint, and there is no code path here that can.  That is a privacy
decision, not an oversight:

* A file uploaded to VirusTotal is retained and shared with VirusTotal's
  partners and paying subscribers.  The attachments MailTrace inspects belong
  to the *victim*: invoices, salary slips, contracts, KYC documents, scans of
  identity papers.  Uploading them would disclose the protected organisation's
  confidential material to third parties as a side effect of investigating an
  attack on it - and, for Indian deployments, would export personal data the
  DPDP Act 2023 expects a fiduciary to keep.
* A hash is a one-way digest.  Sending it reveals nothing about the content:
  a result comes back only when somebody else, somewhere, already submitted a
  byte-identical file.  A miss is silence, not a disclosure.
* The trade-off is honest and worth stating: targeted malware built for one
  victim has never been submitted by anyone, so a hash lookup will not find
  it.  This is intelligence about *known* files, and it supplements the
  offline analysis in ``attachments.py`` rather than replacing it.

Everything here is inert without a key
--------------------------------------
``enrich`` returns immediately when ``Settings.virustotal_key`` is empty, when
``Settings.enable_network`` is false, or when the message has no non-inline
attachment.  In those cases no digest is computed for the check, no socket is
opened, no finding is produced and the analysis is byte-for-byte what it was
before this module existed - which is the state the public demo runs in.

Verdicts are cached through the ``Store`` under ``vt:file:<sha256>``, so a
campaign that sends the same payload to fifty mailboxes costs one request.
Misses are cached too: an unknown file stays unknown for the cache TTL.
"""
from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any

from ..config import Settings
from ..schemas import AttachmentAnalysis, AttachmentMeta, Finding, Severity
from .cache import cache_get, cache_set

if TYPE_CHECKING:  # pragma: no cover
    from ..database.case_manager import Store
    from .parser import RawAttachment

log = logging.getLogger("mailtrace.virustotal")

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"
# The public API allows 4 requests/minute; one message is not allowed to spend
# the whole budget, and a mail bomb with 60 attachments must not stall analysis.
MAX_LOOKUPS_PER_MESSAGE = 4
# Detections at or above this many engines are treated as confirmed malware
# rather than as a single scanner's opinion.
CONFIRMED_DETECTIONS = 3


def _timeout(cfg: Settings) -> float:
    return max(1.0, float(cfg.lookup_timeout or 3.0))


def _parse(payload: dict[str, Any]) -> dict[str, Any]:
    """The few fields worth keeping out of a VT v3 file report."""
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}

    def count(name: str) -> int:
        try:
            return max(0, int(stats.get(name) or 0))
        except (TypeError, ValueError):
            return 0

    malicious, suspicious = count("malicious"), count("suspicious")
    total = malicious + suspicious + count("harmless") + count("undetected")
    label = ((attributes.get("popular_threat_classification") or {}).get("suggested_threat_label") or "").strip()
    return {
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "engines": total,
        "threat_label": label,
        "type_description": (attributes.get("type_description") or "").strip(),
        "reputation": attributes.get("reputation"),
    }


def lookup_hash(sha256: str, cfg: Settings, store: Store | None) -> dict[str, Any] | None:
    """VirusTotal's verdict for one SHA-256, or None when the lookup is disabled or fails.

    ``{"found": False}`` means VirusTotal answered and has never seen the file,
    which is a real (and cacheable) answer.  ``None`` means no answer at all:
    no key, network disabled, a timeout, a rate limit or an unexpected body.
    """
    digest = (sha256 or "").strip().lower()
    if not digest or not cfg.virustotal_key or not cfg.enable_network:
        return None
    key = f"vt:file:{digest}"
    cached = cache_get(store, key)
    if isinstance(cached, dict):
        return cached
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency of the API
        log.debug("httpx is not installed; VirusTotal lookup skipped")
        return None
    try:
        with httpx.Client(timeout=_timeout(cfg)) as client:
            response = client.get(
                VT_FILE_URL.format(sha256=digest),
                headers={"x-apikey": cfg.virustotal_key, "Accept": "application/json"},
            )
    except (httpx.HTTPError, httpx.InvalidURL):  # timeout, DNS, TLS: intel is optional
        log.debug("VirusTotal lookup failed for %s", digest, exc_info=True)
        return None
    if response.status_code == 404:
        verdict: dict[str, Any] = {"found": False}
    elif response.status_code == 200:
        try:
            verdict = _parse(response.json())
        except (ValueError, TypeError, AttributeError, KeyError):  # unexpected body shape
            log.debug("VirusTotal returned an unreadable body for %s", digest, exc_info=True)
            return None
    else:
        # 401 (bad key), 429 (quota) and 5xx are transient or configuration
        # problems: log once at debug and leave the analysis untouched.
        log.debug("VirusTotal returned HTTP %d for %s", response.status_code, digest)
        return None
    cache_set(store, key, verdict, cfg.cache_ttl_seconds)
    return verdict


def _severity(malicious: int, suspicious: int) -> Severity | None:
    if malicious >= CONFIRMED_DETECTIONS:
        return Severity.CRITICAL
    if malicious >= 1:
        return Severity.HIGH
    if suspicious >= 1:
        return Severity.MEDIUM
    return None


def _finding(meta: AttachmentMeta, verdict: dict[str, Any]) -> Finding | None:
    """A finding for one flagged attachment; None when no engine flagged it."""
    malicious = int(verdict.get("malicious") or 0)
    suspicious = int(verdict.get("suspicious") or 0)
    severity = _severity(malicious, suspicious)
    if severity is None:
        return None
    engines = int(verdict.get("engines") or 0)
    label = verdict.get("threat_label") or ""
    detail = (
        f"{meta.filename} matches a file already known to VirusTotal: "
        f"{malicious} of {engines} anti-virus engines call it malicious"
        + (f" and {suspicious} call it suspicious" if suspicious else "")
        + (f". VirusTotal's threat label is {label}" if label else "")
        + ". Only the SHA-256 was sent; the file itself was not uploaded."
    )
    return Finding(
        id="virustotal_detection",
        module="attachments",
        severity=severity,
        title="Attachment flagged by VirusTotal",
        detail=detail,
        evidence={
            "filename": meta.filename,
            "sha256": meta.sha256,
            "malicious": malicious,
            "suspicious": suspicious,
            "engines": engines,
            "threat_label": label,
            "url": VT_GUI_URL.format(sha256=meta.sha256),
            "source": "virustotal-v3",
        },
    )


def enrich(
    analysis: AttachmentAnalysis,
    raw_attachments: list[RawAttachment],
    cfg: Settings,
    store: Store | None = None,
) -> list[Finding]:
    """Look every non-inline attachment up by hash and append any detections.

    Returns the findings that were added to ``analysis.findings`` (empty when
    the lookup is disabled, which is the default).  Inline images are skipped:
    they are excluded from the attachment score for the same reason - a logo in
    a signature block is not the payload, and spending the rate-limit budget on
    it would push the real attachment out of the request allowance.
    """
    if not cfg.virustotal_key or not cfg.enable_network:
        return []  # no key, no request, no latency, no finding
    inline_hashes = {
        att.sha256 for att, raw in _pair(analysis.attachments, raw_attachments) if raw is not None and raw.is_inline
    }
    findings: list[Finding] = []
    looked_up = 0
    for meta in analysis.attachments:
        if looked_up >= MAX_LOOKUPS_PER_MESSAGE:
            log.debug("VirusTotal lookup budget of %d reached; remaining attachments skipped", MAX_LOOKUPS_PER_MESSAGE)
            break
        if not meta.sha256 or meta.sha256 in inline_hashes or not meta.size:
            continue
        looked_up += 1
        verdict = lookup_hash(meta.sha256, cfg, store)
        if not verdict or not verdict.get("found"):
            continue
        finding = _finding(meta, verdict)
        if finding is not None:
            findings.append(finding)
    if findings:
        # Prepended so the VirusTotal verdict leads the attachment section: a
        # third-party detection outranks any local heuristic about the file.
        analysis.findings[:0] = findings
        analysis.score = max(analysis.score, 1.0 if any(f.severity == Severity.CRITICAL for f in findings) else 0.75)
    return findings


def _pair(metas: list[AttachmentMeta], raws: list[RawAttachment]) -> list[tuple[AttachmentMeta, Any]]:
    """Match metadata back to the raw parts it came from, by digest.

    ``analyze_attachments`` drops any part whose analysis raised, so the two
    lists can differ in length and must not be zipped positionally.  Matching
    on the SHA-256 that the analyzer already computed is exact and cheap.
    """
    by_digest: dict[str, Any] = {}
    for raw in raws or []:
        by_digest.setdefault(hashlib.sha256(raw.data or b"").hexdigest(), raw)
    return [(meta, by_digest.get(meta.sha256)) for meta in metas]
