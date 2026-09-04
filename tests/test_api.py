from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(cfg):
    app = create_app(cfg)
    with TestClient(app) as test_client:
        yield test_client


def _upload(client, sample, key, name):
    response = client.post("/api/analyze", files=[("files", (name, sample(key), "message/rfc822"))])
    assert response.status_code == 200, response.text
    return response.json()


def test_health_and_index(client):
    health = client.get("/api/health").json()
    assert health["status"] == "ok" and health["network"] is False and "engine_version" in health
    index = client.get("/")
    assert index.status_code == 200 and "MailTrace" in index.text


def test_upload_list_get_and_mask(client, sample):
    data = _upload(client, sample, "phishing", "phishing.eml")
    assert len(data["results"]) == 1
    result = data["results"][0]
    assert result["verdict"]["category"] == "Phishing"
    assert result["masked"] is False
    assert data["alerts"] and data["alerts"][0]["email_id"] == result["id"]

    listing = client.get("/api/emails").json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == result["id"]

    unmasked = client.get(f"/api/emails/{result['id']}").json()
    assert unmasked["email"]["sender"]["address"] == "alerts@sbi-kyc-update.xyz"
    masked = client.get(f"/api/emails/{result['id']}?mask=true").json()
    assert masked["masked"] is True and masked["email"]["sender"]["address"] == "a***s@sbi-kyc-update.xyz"
    assert masked["headers"]["originating_ip"] == "45.148.10.72"

    assert client.get("/api/emails/does-not-exist").status_code == 404
    raw = client.get(f"/api/emails/{result['id']}/raw")
    assert raw.status_code == 200 and raw.content == sample("phishing")


def test_raw_submission_and_stats(client, sample):
    response = client.post("/api/analyze/raw", json={"raw": sample("legit").decode("utf-8"), "filename": "legit.eml"})
    assert response.status_code == 200, response.text
    assert response.json()["results"][0]["verdict"]["category"] == "Legitimate"
    assert response.json()["alerts"] == []
    stats = client.get("/api/stats").json()
    assert stats["total_emails"] == 1 and stats["by_category"]["Legitimate"] == 1


def test_reports_custody_and_alerts(client, sample):
    result = _upload(client, sample, "bec", "bec.eml")["results"][0]
    report = client.get(f"/api/reports/{result['id']}?format=json").json()
    assert report["report_id"].startswith("RPT-") and report["analysis"]["id"] == result["id"]
    assert report["evidence_integrity"]["custody_valid"] is True
    assert report["custody"]["valid"] is True
    html = client.get(f"/api/reports/{result['id']}?format=html&mask=true")
    assert html.status_code == 200 and "text/html" in html.headers["content-type"]
    assert "rajesh.mehta@" not in html.text and "acme-corp-in.com" in html.text
    verify = client.get("/api/custody/verify").json()
    assert verify["valid"] is True and len(verify["head_hash"]) == 64
    chain = client.get(f"/api/custody/{result['id']}").json()
    actions = [e["action"] for e in chain["events"]]
    assert actions[:2] == ["ingested", "analyzed"] and "report_generated" in actions
    # The BEC sample scores at the Fraud floor (60), below the alert threshold; the
    # phishing sample scores well above it and must raise an alert.
    assert client.get("/api/alerts").json() == []
    phishing = _upload(client, sample, "phishing", "phishing.eml")["results"][0]
    alerts = client.get("/api/alerts").json()
    assert alerts and alerts[0]["email_id"] == phishing["id"]
    ack = client.post(f"/api/alerts/{alerts[0]['id']}/ack")
    assert ack.status_code == 200
    assert client.get("/api/alerts?unacknowledged_only=true").json() == []
    assert client.post("/api/alerts/nope/ack").status_code == 404


def test_campaigns_and_graph(client, sample):
    first = _upload(client, sample, "phishing", "one.eml")["results"][0]
    second = _upload(client, sample, "phishing", "two.eml")["results"][0]
    assert second["campaign_id"]
    campaigns = client.get("/api/campaigns").json()
    assert len(campaigns) == 1 and set(campaigns[0]["email_ids"]) == {first["id"], second["id"]}
    detail = client.get(f"/api/campaigns/{campaigns[0]['id']}").json()
    assert {e["id"] for e in detail["emails"]} == {first["id"], second["id"]}
    assert any(n["type"] == "campaign" for n in detail["graph"]["nodes"])
    assert any(n.get("attrs", {}).get("shared_by", 0) >= 2 for n in detail["graph"]["nodes"])
    graph = client.get(f"/api/graph?email_id={first['id']}").json()
    assert graph["nodes"] and graph["edges"]
    assert client.get("/api/graph").status_code in (400, 422)
    assert client.get("/api/campaigns/missing").status_code == 404


def test_rejects_empty_and_oversized_upload(client, cfg):
    empty = client.post("/api/analyze", files=[("files", ("empty.eml", b"", "message/rfc822"))])
    assert empty.status_code == 400
    big = b"x" * (cfg.max_upload_bytes + 1)
    huge = client.post("/api/analyze", files=[("files", ("big.eml", big, "message/rfc822"))])
    assert huge.status_code == 413
