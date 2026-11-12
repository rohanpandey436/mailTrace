from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

BUNDLED = {
    "bec_payment_diversion",
    "fraud_lottery_advance_fee",
    "impersonation_ceo_gift_cards",
    "legit_transactional",
    "phishing_sbi_kyc",
}


@pytest.fixture
def client(cfg):
    app = create_app(cfg)
    with TestClient(app) as test_client:
        yield test_client


def test_every_bundled_sample_is_offered(client):
    names = client.get("/api/samples").json()

    assert names == sorted(names)
    assert set(names) >= BUNDLED


def test_a_sample_is_checked_as_a_private_case_that_expires(client, sample):
    response = client.post("/api/samples/phishing_sbi_kyc")
    assert response.status_code == 200, response.text
    data = response.json()
    result = data["results"][0]

    assert result["verdict"]["category"] == "Phishing" and result["filename"] == "phishing_sbi_kyc.eml"
    assert data["alerts"] == []
    kept = data["retention"][0]
    assert kept["origin"] == "sample" and kept["listed"] is False and kept["state"] == "expiring"
    assert 24 * 3600 - 60 <= kept["seconds_left"] <= 24 * 3600

    assert client.get("/api/emails").json() == {"items": [], "total": 0}
    assert client.get("/api/stats").json()["total_emails"] == 0
    assert client.get("/api/alerts").json() == []
    assert client.get(f"/api/emails/{result['id']}").json()["id"] == result["id"]
    assert client.get(f"/api/emails/{result['id']}/raw").content == sample("phishing")
    assert client.get(f"/api/emails/{result['id']}/retention").json()["origin"] == "sample"


def test_every_sample_gets_a_verdict(client):
    for name in sorted(BUNDLED):
        response = client.post(f"/api/samples/{name}")
        assert response.status_code == 200, name
        assert response.json()["results"][0]["verdict"]["risk_score"] >= 0, name


def test_an_unknown_sample_is_not_found(client):
    for name in ("nope", "phishing_sbi_kyc.eml", "PHISHING_SBI_KYC"):
        assert client.post(f"/api/samples/{name}").status_code == 404, name
