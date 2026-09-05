"""
Stage 6 OUTPUT + ACT: CSV reports, the WebSocket alert feed beside the
unchanged SSE one, the optional VirusTotal hash lookup and the quick-bar
decision endpoints.
"""
from __future__ import annotations

import asyncio
import csv
import io
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api import alerts as alerts_api
from app.utils import csv_exporter as csvexport, virustotal
from app.main import create_app
from app.schemas import Alert, AttachmentAnalysis, AttachmentMeta, Severity, ThreatCategory

# A subject that is a live formula in Excel, LibreOffice and Google Sheets.
EVIL_SUBJECT = '=HYPERLINK("http://evil.test","Click me")'
EVIL_MESSAGE = (
    b"From: \"=cmd|'/c calc'!A0\" <evil@attacker.test>\r\n"
    b"To: victim@acme-corp.in\r\n"
    b"Subject: " + EVIL_SUBJECT.encode() + b"\r\n"
    b"Date: Mon, 1 Sep 2025 10:00:00 +0530\r\n"
    b"\r\nPay the attached invoice today.\r\n"
)


@pytest.fixture
def client(cfg):
    app = create_app(cfg)
    with TestClient(app) as test_client:
        yield test_client


def _upload(client, raw: bytes, name: str) -> dict:
    response = client.post("/api/analyze", files=[("files", (name, raw, "message/rfc822"))])
    assert response.status_code == 200, response.text
    return response.json()["results"][0]


def _rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text.lstrip(csvexport.UTF8_BOM))))


def _alert(alert_id: str = "alr-test01") -> Alert:
    return Alert(
        id=alert_id,
        created_at=datetime.now(timezone.utc),
        email_id="e1",
        subject="Probe subject",
        sender="attacker@evil.example",
        category=ThreatCategory.PHISHING,
        risk_score=90,
        severity=Severity.HIGH,
        message="probe",
    )


# --------------------------------------------------------------------------- #
# Formula-injection guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("=1+1", "'=1+1"),
        ("+41 12345", "'+41 12345"),
        ("-5", "'-5"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tsneaky", "'\tsneaky"),
        ("\rsneaky", "'\rsneaky"),
        ("ordinary subject", "ordinary subject"),
        ("", ""),
        (None, ""),
        (True, "yes"),
        (False, "no"),
        (83, "83"),
        (0.5, "0.5"),
        (["a", "b"], "a; b"),
    ],
)
def test_sanitize_cell(raw, expected):
    assert csvexport.sanitize_cell(raw) == expected


def test_sanitize_cell_guards_every_dangerous_prefix():
    for prefix in csvexport.FORMULA_PREFIXES:
        assert csvexport.sanitize_cell(prefix + "payload").startswith(csvexport.FORMULA_GUARD)


# --------------------------------------------------------------------------- #
# Per-case report CSV
# --------------------------------------------------------------------------- #
def test_report_csv_has_header_block_and_findings_table(client, sample):
    result = _upload(client, sample("phishing"), "phishing.eml")
    response = client.get(f"/api/reports/{result['id']}?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"].endswith('.csv"')
    body = response.text
    assert body.startswith(csvexport.UTF8_BOM)       # Excel reads it as UTF-8
    assert "\r\n" in body                            # RFC 4180 line endings

    rows = _rows(body)
    fields = {(row[0], row[1]): row[2] for row in rows if len(row) == 3}
    assert fields[("Case", "Email ID")] == result["id"]
    assert fields[("Verdict", "Category")] == "Phishing"
    assert int(fields[("Verdict", "Risk score (0-100)")]) == result["verdict"]["risk_score"]
    assert fields[("Evidence", "Raw SHA-256")] == result["email"]["raw_sha256"]
    assert fields[("Evidence", "Custody chain valid")] == "yes"
    # All five threat-score pillars, each carrying the weight that was applied.
    pillars = [key[1] for key in fields if key[0] == "Threat score"]
    for name in ("Authentication", "Text / intent", "URLs", "Network", "Entropy"):
        assert any(p.startswith(name + " (weight ") for p in pillars), name
    # Origin block and the IOC list.
    assert ("Origin", "IP") in fields
    assert [row[2] for row in rows if row and row[0] == "IOC"]

    # The findings table follows the header block, one row per finding.
    header_index = rows.index(list(csvexport.FINDING_COLUMNS))
    finding_rows = [row for row in rows[header_index + 1:] if row]
    assert len(finding_rows) == len(result["findings"])
    assert finding_rows[0][2] == result["findings"][0]["id"]


def test_report_csv_respects_mask(client, sample):
    result = _upload(client, sample("phishing"), "phishing.eml")
    unmasked = client.get(f"/api/reports/{result['id']}?format=csv").text
    masked = client.get(f"/api/reports/{result['id']}?format=csv&mask=true").text
    assert "alerts@sbi-kyc-update.xyz" in unmasked
    assert "alerts@sbi-kyc-update.xyz" not in masked
    assert "a***s@sbi-kyc-update.xyz" in masked
    assert "sbi-kyc-update.xyz" in masked          # the domain is an indicator, so it stays
    fields = {(r[0], r[1]): r[2] for r in _rows(masked) if len(r) == 3}
    assert fields[("Report", "PII masked")] == "yes"


def test_report_csv_is_recorded_in_the_custody_ledger(client, sample):
    result = _upload(client, sample("bec"), "bec.eml")
    client.get(f"/api/reports/{result['id']}?format=csv")
    chain = client.get(f"/api/custody/{result['id']}").json()
    formats = [e["detail"].get("format") for e in chain["events"] if e["action"] == "report_generated"]
    assert "csv" in formats
    assert chain["valid"] is True


def test_report_csv_neutralises_formula_cells(client):
    result = _upload(client, EVIL_MESSAGE, "+evil.eml")
    rows = _rows(client.get(f"/api/reports/{result['id']}?format=csv").text)
    fields = {(row[0], row[1]): row[2] for row in rows if len(row) == 3}
    assert fields[("Case", "Subject")] == "'" + EVIL_SUBJECT
    assert fields[("Case", "From display name")].startswith("'=cmd|")
    assert fields[("Case", "File name")] == "'+evil.eml"
    # Nothing anywhere in the file can still be read as a formula.
    for row in rows:
        for cell in row:
            assert not cell.startswith(("=", "+", "@", "\t", "\r"))


def test_report_csv_404_for_unknown_case(client):
    assert client.get("/api/reports/does-not-exist?format=csv").status_code == 404


# --------------------------------------------------------------------------- #
# Case-list CSV
# --------------------------------------------------------------------------- #
def test_case_list_csv_exports_every_case(client, sample):
    phishing = _upload(client, sample("phishing"), "phishing.eml")
    legit = _upload(client, sample("legit"), "legit.eml")
    response = client.get("/api/emails/export.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert 'filename="MailTrace-cases.csv"' in response.headers["content-disposition"]
    rows = _rows(response.text)
    assert rows[0] == list(csvexport.CASE_COLUMNS)
    ids = {row[0] for row in rows[1:] if row}
    assert ids == {phishing["id"], legit["id"]}


def test_case_list_csv_takes_the_same_filters_as_the_listing(client, sample):
    phishing = _upload(client, sample("phishing"), "phishing.eml")
    _upload(client, sample("legit"), "legit.eml")

    def ids(query: str) -> set[str]:
        return {row[0] for row in _rows(client.get("/api/emails/export.csv?" + query).text)[1:] if row}

    assert ids("category=Phishing") == {phishing["id"]}
    assert ids("min_risk=80") == {phishing["id"]}
    assert ids("q=sbi") == {phishing["id"]}
    assert ids("source_type=legitimate_sender") != {phishing["id"]}
    assert ids("campaign_id=nope") == set()
    assert client.get("/api/emails/export.csv?category=Nope").status_code == 422


def test_case_list_csv_masks_and_guards_cells(client):
    _upload(client, EVIL_MESSAGE, "+evil.eml")
    plain = _rows(client.get("/api/emails/export.csv").text)[1]
    columns = dict(zip(csvexport.CASE_COLUMNS, plain))
    assert columns["Subject"] == "'" + EVIL_SUBJECT
    assert columns["File name"] == "'+evil.eml"
    assert columns["Sender"] == "evil@attacker.test"
    assert columns["Status"] == "open"
    masked = dict(zip(csvexport.CASE_COLUMNS, _rows(client.get("/api/emails/export.csv?mask=true").text)[1]))
    assert masked["Sender"] == "e***l@attacker.test"


def test_case_list_csv_route_is_not_shadowed_by_the_case_detail_route(client):
    # "/api/emails/{email_id}" would happily match the literal "export.csv".
    assert client.get("/api/emails/export.csv").headers["content-type"].startswith("text/csv")
    assert client.get("/api/emails/export.csv").status_code == 200


# --------------------------------------------------------------------------- #
# Quick-bar decisions
# --------------------------------------------------------------------------- #
def test_quarantine_and_block_record_a_decision(client, sample):
    result = _upload(client, sample("phishing"), "phishing.eml")
    email_id = result["id"]

    before = client.get(f"/api/emails/{email_id}/decision").json()
    assert before["status"] == "open" and before["history"] == []
    assert before["enforced"] is False and before["indicators"]

    quarantined = client.post(f"/api/emails/{email_id}/quarantine?actor=rohan").json()
    assert quarantined["status"] == "quarantined"
    assert quarantined["enforced"] is False
    assert [e["action"] for e in quarantined["history"]] == ["quarantine_decision"]
    event = quarantined["history"][0]
    assert event["actor"] == "rohan"
    assert event["detail"]["enforced"] is False
    assert "no mail system was contacted" in event["detail"]["note"]
    assert event["detail"]["previous_status"] == "open"

    blocked = client.post(f"/api/emails/{email_id}/block").json()
    assert blocked["status"] == "blocked"
    assert [e["action"] for e in blocked["history"]] == ["quarantine_decision", "block_decision"]
    assert blocked["history"][1]["detail"]["previous_status"] == "quarantined"

    # The decision survives a re-read and the ledger is still verifiable.
    assert client.get(f"/api/emails/{email_id}/decision").json()["status"] == "blocked"
    assert client.get("/api/custody/verify").json()["valid"] is True


def test_case_list_and_csv_show_the_decision(client, sample):
    result = _upload(client, sample("phishing"), "phishing.eml")
    other = _upload(client, sample("legit"), "legit.eml")
    client.post(f"/api/emails/{result['id']}/quarantine")

    statuses = {row["id"]: row["status"] for row in client.get("/api/emails").json()["items"]}
    assert statuses == {result["id"]: "quarantined", other["id"]: "open"}

    rows = _rows(client.get("/api/emails/export.csv").text)
    exported = {row[0]: dict(zip(csvexport.CASE_COLUMNS, row))["Status"] for row in rows[1:] if row}
    assert exported == {result["id"]: "quarantined", other["id"]: "open"}


def test_decision_endpoints_404_on_an_unknown_case(client):
    assert client.post("/api/emails/nope/quarantine").status_code == 404
    assert client.post("/api/emails/nope/block").status_code == 404
    assert client.get("/api/emails/nope/decision").status_code == 404


def test_store_rejects_an_unknown_status(store):
    with pytest.raises(ValueError):
        store.set_case_status("whatever", "deleted")


# --------------------------------------------------------------------------- #
# Live alert feed: WebSocket, and the unchanged SSE stream
# --------------------------------------------------------------------------- #
def test_alert_websocket_streams_the_same_alert_json(client, sample):
    with client.websocket_connect("/api/alerts/ws") as websocket:
        assert alerts_api.broadcaster.subscriber_count() == 1
        result = _upload(client, sample("phishing"), "phishing.eml")
        payload = websocket.receive_json()
    assert payload["email_id"] == result["id"]
    assert payload["category"] == "Phishing"
    assert payload["sender"] == "alerts@sbi-kyc-update.xyz"
    # The stored alert and the streamed one are the same record.
    assert payload["id"] == client.get("/api/alerts").json()[0]["id"]


def test_alert_websocket_honours_mask_and_releases_its_queue(client):
    before = alerts_api.broadcaster.subscriber_count()
    with client.websocket_connect("/api/alerts/ws?mask=true") as websocket:
        alerts_api.broadcaster.publish(_alert())
        payload = websocket.receive_json()
    assert payload["sender"] == "a***r@evil.example"
    assert alerts_api.broadcaster.subscriber_count() == before  # no leaked queue


def test_several_websocket_clients_all_receive_the_alert(client):
    with client.websocket_connect("/api/alerts/ws") as first:
        with client.websocket_connect("/api/alerts/ws") as second:
            assert alerts_api.broadcaster.subscriber_count() == 2
            alerts_api.broadcaster.publish(_alert("alr-fanout1"))
            assert first.receive_json()["id"] == "alr-fanout1"
            assert second.receive_json()["id"] == "alr-fanout1"
    assert alerts_api.broadcaster.subscriber_count() == 0


def test_both_live_transports_are_registered(client):
    """Adding the WebSocket did not displace the SSE route.

    WebSocket routes are not part of an OpenAPI document, so the socket is
    proved to exist by the connection tests above and the HTTP stream by the
    published schema.
    """
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/alerts/stream" in paths
    assert "/api/emails/export.csv" in paths
    assert "/api/emails/{email_id}/quarantine" in paths
    assert "/api/emails/{email_id}/block" in paths
    with client.websocket_connect("/api/alerts/ws"):
        pass


@pytest.mark.parametrize("mask", [False, True])
def test_sse_stream_still_emits_alerts(mask):
    """Drive the SSE endpoint's generator directly.

    Reading an open SSE stream over ``TestClient`` and then closing it
    deadlocks: the generator only stops when ``is_disconnected()`` turns true,
    and the test transport only reports the disconnect once the response has
    been fully consumed, which never happens for an endless stream.  That is a
    property of the test client, not of the endpoint, so the endpoint's own
    async generator is exercised here instead - preamble, event framing,
    masking and the ``finally`` that releases the subscriber queue.
    """

    class _Request:
        def __init__(self) -> None:
            self.checks = 0

        async def is_disconnected(self) -> bool:
            self.checks += 1
            return self.checks > 3   # let it produce the preamble and one alert

    async def run() -> tuple[object, list[str]]:
        alerts_api.broadcaster.bind(asyncio.get_running_loop())
        response = await alerts_api.stream_alerts(_Request(), mask=mask)
        alerts_api.broadcaster.publish(_alert("alr-sse0001"))
        return response, [chunk async for chunk in response.body_iterator]

    response, chunks = asyncio.run(run())
    assert response.media_type == "text/event-stream"
    assert response.headers["cache-control"] == "no-cache"
    assert chunks[0] == ": connected\n\n"
    event = next(c for c in chunks if c.startswith("event: alert\ndata: "))
    assert '"alr-sse0001"' in event
    assert ('"a***r@evil.example"' in event) is mask
    assert alerts_api.broadcaster.subscriber_count() == 0


# --------------------------------------------------------------------------- #
# Optional VirusTotal hash lookup
# --------------------------------------------------------------------------- #
def _meta(name: str, digest: str, size: int = 1024) -> AttachmentMeta:
    return AttachmentMeta(filename=name, sha256=digest, size=size, extension=name.rsplit(".", 1)[-1])


def test_virustotal_is_inert_without_a_key(cfg, monkeypatch):
    """No key means no request, no latency and no change to the findings."""

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("VirusTotal must not be contacted without a key")

    monkeypatch.setattr(virustotal, "lookup_hash", explode)
    analysis = AttachmentAnalysis(attachments=[_meta("invoice.pdf", "a" * 64)], score=0.2)
    assert cfg.virustotal_key == ""
    assert virustotal.enrich(analysis, [], cfg, None) == []
    assert analysis.findings == [] and analysis.score == 0.2


def test_virustotal_lookup_makes_no_call_without_a_key(cfg):
    assert virustotal.lookup_hash("b" * 64, cfg, None) is None


def test_virustotal_lookup_is_skipped_when_the_network_is_off(cfg):
    cfg.virustotal_key = "key"
    assert cfg.enable_network is False
    assert virustotal.lookup_hash("b" * 64, cfg, None) is None


def test_virustotal_adds_a_finding_when_engines_flag_the_file(cfg, monkeypatch):
    cfg.virustotal_key = "key"
    cfg.enable_network = True
    verdicts = {
        "a" * 64: {"found": True, "malicious": 42, "suspicious": 3, "engines": 70, "threat_label": "trojan.emotet"},
        "b" * 64: {"found": True, "malicious": 0, "suspicious": 0, "engines": 70, "threat_label": ""},
        "c" * 64: {"found": False},
    }
    monkeypatch.setattr(virustotal, "lookup_hash", lambda digest, config, store: verdicts.get(digest))
    analysis = AttachmentAnalysis(
        attachments=[_meta("bad.docm", "a" * 64), _meta("clean.pdf", "b" * 64), _meta("unknown.zip", "c" * 64)],
        score=0.1,
    )
    findings = virustotal.enrich(analysis, [], cfg, None)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "virustotal_detection" and finding.severity == Severity.CRITICAL
    assert "42 of 70" in finding.detail and "trojan.emotet" in finding.detail
    assert "the file itself was not uploaded" in finding.detail
    assert finding.evidence["sha256"] == "a" * 64
    assert analysis.findings[0] is finding      # leads the attachment section
    assert analysis.score == 1.0


def test_virustotal_skips_inline_parts_and_caps_the_request_budget(cfg, monkeypatch):
    from app.core.parser import RawAttachment

    cfg.virustotal_key = "key"
    cfg.enable_network = True
    logo = b"\x89PNG logo bytes"
    import hashlib

    logo_digest = hashlib.sha256(logo).hexdigest()
    asked: list[str] = []

    def record(digest, config, store):
        asked.append(digest)
        return {"found": False}

    monkeypatch.setattr(virustotal, "lookup_hash", record)
    attachments = [_meta("logo.png", logo_digest)] + [
        _meta(f"file{i}.pdf", f"{i:064d}") for i in range(virustotal.MAX_LOOKUPS_PER_MESSAGE + 2)
    ]
    analysis = AttachmentAnalysis(attachments=attachments)
    virustotal.enrich(analysis, [RawAttachment("logo.png", "image/png", logo, is_inline=True)], cfg, None)
    assert logo_digest not in asked                               # inline part skipped
    assert len(asked) == virustotal.MAX_LOOKUPS_PER_MESSAGE       # rate-limit budget respected


def test_virustotal_severity_ladder():
    assert virustotal._severity(10, 0) == Severity.CRITICAL
    assert virustotal._severity(1, 0) == Severity.HIGH
    assert virustotal._severity(0, 2) == Severity.MEDIUM
    assert virustotal._severity(0, 0) is None


def test_virustotal_parses_a_v3_file_report():
    parsed = virustotal._parse({
        "data": {"attributes": {
            "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 2, "undetected": 60},
            "popular_threat_classification": {"suggested_threat_label": "trojan.agent/generic"},
            "type_description": "Win32 EXE",
        }}
    })
    assert parsed == {
        "found": True, "malicious": 5, "suspicious": 1, "engines": 68,
        "threat_label": "trojan.agent/generic", "type_description": "Win32 EXE", "reputation": None,
    }
    # A body with nothing recognisable must degrade, not raise.
    assert virustotal._parse({})["engines"] == 0
