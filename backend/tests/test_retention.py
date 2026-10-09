from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.core import retention
from app.main import create_app


@pytest.fixture
def client(cfg):
    app = create_app(cfg)
    with TestClient(app) as test_client:
        yield test_client


def _store(client):
    return client.app.state.store


def _from_gmail(client, sample, key="phishing", **extra):
    body = {"raw": sample(key).decode("utf-8"), "filename": f"{key}.eml", "origin": "gmail", **extra}
    response = client.post("/api/analyze/raw", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _upload(client, sample, key):
    response = client.post("/api/analyze", files=[("files", (f"{key}.eml", sample(key), "message/rfc822"))])
    assert response.status_code == 200, response.text
    return response.json()["results"][0]


def _actions(client, email_id):
    return [event["action"] for event in client.get(f"/api/custody/{email_id}").json()["events"]]


def test_gmail_case_is_private_and_expires_in_a_day(client, sample):
    data = _from_gmail(client, sample)
    result = data["results"][0]
    assert result["verdict"]["category"] == "Phishing" and result["verdict"]["risk_score"] >= 70
    assert data["alerts"] == []
    kept = data["retention"][0]
    assert kept["email_id"] == result["id"]
    assert kept["origin"] == "gmail" and kept["listed"] is False and kept["state"] == "expiring"
    assert 24 * 3600 - 60 <= kept["seconds_left"] <= 24 * 3600

    assert client.get("/api/emails").json() == {"items": [], "total": 0}
    assert client.get("/api/stats").json()["total_emails"] == 0
    assert client.get("/api/alerts").json() == []
    assert client.get("/api/campaigns").json() == []
    assert result["campaign_id"] is None

    assert client.get(f"/api/emails/{result['id']}").json()["id"] == result["id"]
    assert client.get(f"/api/emails/{result['id']}/raw").content == sample("phishing")
    assert client.get(f"/api/emails/{result['id']}/retention").json()["state"] == "expiring"
    assert _actions(client, result["id"])[:3] == ["ingested", "analyzed", "retention_set"]


def test_dashboard_case_stays_listed_and_permanent(client, sample):
    response = client.post("/api/analyze/raw", json={"raw": sample("legit").decode("utf-8"), "filename": "legit.eml"})
    data = response.json()
    assert data["retention"] == []
    email_id = data["results"][0]["id"]
    kept = client.get(f"/api/emails/{email_id}/retention").json()
    assert kept["state"] == "permanent" and kept["listed"] is True and kept["expires_at"] is None
    assert client.get("/api/emails").json()["total"] == 1
    assert "retention_set" not in _actions(client, email_id)
    assert client.get("/api/emails/unknown/retention").status_code == 404


def test_sweep_deletes_the_case_and_keeps_the_ledger(client, sample, cfg):
    email_id = _from_gmail(client, sample)["results"][0]["id"]
    store = _store(client)
    mirror = cfg.evidence_dir / f"{email_id}.eml"
    assert mirror.is_file()

    assert retention.purge_expired(store, datetime.now(UTC) + timedelta(hours=23)) == []
    assert client.get(f"/api/emails/{email_id}").status_code == 200

    assert retention.purge_expired(store, datetime.now(UTC) + timedelta(hours=25)) == [email_id]
    assert not mirror.exists()
    gone = client.get(f"/api/emails/{email_id}")
    assert gone.status_code == 404 and "was deleted" in gone.json()["error"]
    assert client.get(f"/api/emails/{email_id}/raw").status_code == 404
    assert client.get(f"/api/reports/{email_id}?format=json").status_code == 404
    assert client.post(f"/api/emails/{email_id}/freeze").status_code == 404

    kept = client.get(f"/api/emails/{email_id}/retention").json()
    assert kept["state"] == "purged" and kept["purged_at"] is not None
    chain = client.get(f"/api/custody/{email_id}").json()
    purge = chain["events"][-1]
    assert purge["action"] == "purged" and purge["detail"]["retention_hours"] == 24
    assert purge["detail"]["removed"] and purge["evidence_sha256"] == chain["events"][0]["evidence_sha256"]
    assert client.get("/api/custody/verify").json()["valid"] is True
    assert retention.purge_expired(store, datetime.now(UTC) + timedelta(hours=30)) == []


def test_an_expired_case_is_never_served(client, sample):
    email_id = _from_gmail(client, sample, retention_hours=1)["results"][0]["id"]
    store = _store(client)
    row = store.get_retention(email_id)
    store.set_retention(
        email_id, "gmail", False, (datetime.now(UTC) - timedelta(minutes=1)).isoformat(), row["evidence_sha256"]
    )
    assert client.get(f"/api/emails/{email_id}").status_code == 404
    assert _actions(client, email_id)[-1] == "purged"
    assert store.case_exists(email_id) is False


def test_freeze_cancels_the_deletion(client, sample):
    email_id = _from_gmail(client, sample)["results"][0]["id"]
    frozen = client.post(f"/api/emails/{email_id}/freeze?actor=inspector")
    assert frozen.status_code == 200, frozen.text
    body = frozen.json()
    assert body["state"] == "frozen" and body["frozen_by"] == "inspector"
    assert body["expires_at"] is None and body["seconds_left"] is None and body["listed"] is False

    again = client.post(f"/api/emails/{email_id}/freeze?actor=someone-else").json()
    assert again["frozen_by"] == "inspector" and again["frozen_at"] == body["frozen_at"]
    assert _actions(client, email_id).count("evidence_frozen") == 1

    assert retention.purge_expired(_store(client), datetime.now(UTC) + timedelta(days=30)) == []
    assert client.get(f"/api/emails/{email_id}").status_code == 200
    assert client.get("/api/emails").json()["total"] == 0
    assert client.get("/api/custody/verify").json()["valid"] is True


def test_freezing_a_permanent_case_changes_nothing(client, sample):
    email_id = _upload(client, sample, "legit")["id"]
    body = client.post(f"/api/emails/{email_id}/freeze").json()
    assert body["state"] == "permanent"
    assert "evidence_frozen" not in _actions(client, email_id)


def test_retention_period_is_bounded(client, sample, cfg):
    raw = sample("legit").decode("utf-8")
    too_long = client.post(
        "/api/analyze/raw", json={"raw": raw, "origin": "gmail", "retention_hours": cfg.retention_max_hours + 1}
    )
    assert too_long.status_code == 422 and str(cfg.retention_max_hours) in too_long.json()["error"]
    assert client.post("/api/analyze/raw", json={"raw": raw, "retention_hours": 0}).status_code == 422
    assert client.post("/api/analyze/raw", json={"raw": raw, "origin": "telegram"}).status_code == 422
    short = client.post("/api/analyze/raw", json={"raw": raw, "origin": "gmail", "retention_hours": 2}).json()
    assert 2 * 3600 - 60 <= short["retention"][0]["seconds_left"] <= 2 * 3600


def test_a_private_case_reads_correlations_but_writes_none(client, sample):
    first = _upload(client, sample, "phishing")
    private = _from_gmail(client, sample)["results"][0]
    related = private["intel"]["related_incidents"]
    assert [item["email_id"] for item in related] == [first["id"]]
    assert private["campaign_id"] is None
    assert client.get("/api/campaigns").json() == []

    second = _upload(client, sample, "phishing")
    campaigns = client.get("/api/campaigns").json()
    assert len(campaigns) == 1
    assert sorted(campaigns[0]["email_ids"]) == sorted([first["id"], second["id"]])
    assert [item["email_id"] for item in second["intel"]["related_incidents"]] == [first["id"]]


def test_purging_a_listed_member_repairs_the_campaign(client, sample):
    first = _upload(client, sample, "phishing")
    body = {"raw": sample("phishing").decode("utf-8"), "filename": "again.eml", "retention_hours": 1}
    data = client.post("/api/analyze/raw", json=body).json()
    second = data["results"][0]
    assert data["retention"][0]["listed"] is True and data["retention"][0]["origin"] == "dashboard"
    assert len(client.get("/api/campaigns").json()) == 1
    assert client.get("/api/emails").json()["total"] == 2

    purged = retention.purge_expired(_store(client), datetime.now(UTC) + timedelta(hours=2))
    assert purged == [second["id"]]
    assert client.get("/api/campaigns").json() == []
    assert client.get("/api/emails").json()["total"] == 1
    assert client.get(f"/api/emails/{first['id']}").json()["campaign_id"] is None
    assert client.get("/api/alerts").json()[0]["email_id"] == first["id"]
    assert len(client.get("/api/alerts").json()) == 1


def test_health_reports_the_sweep(client, sample):
    assert client.get("/api/health").json()["retention"].endswith("0 case(s) awaiting deletion")
    _from_gmail(client, sample, key="legit")
    assert client.get("/api/health").json()["retention"].endswith("1 case(s) awaiting deletion")
