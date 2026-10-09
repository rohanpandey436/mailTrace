from __future__ import annotations

import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from app.api import intel
from app.main import create_app
from app.utils.cache import MemoryCache


@pytest.fixture
def client(cfg):
    intel.reset_cache()
    app = create_app(cfg)
    with TestClient(app) as test_client:
        yield test_client
    intel.reset_cache()


def _digest(indicator: str) -> str:
    return hashlib.sha256(indicator.encode("utf-8")).hexdigest()


def _upload(client, sample, key):
    response = client.post("/api/analyze", files=[("files", (f"{key}.eml", sample(key), "message/rfc822"))])
    assert response.status_code == 200, response.text
    return response.json()["results"][0]


def _cache_rows(client) -> int:
    store = client.app.state.store
    return int(store._conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0])


def test_lookup_answers_without_touching_the_store(client):
    body = {
        "domains": [
            {"domain": "login.sbi-kyc-update.xyz", "role": "sender"},
            {"domain": "gmail.com", "role": "reply_to"},
            {"domain": "SBI-KYC-UPDATE.xyz.", "role": "url"},
        ],
        "ips": ["45.148.10.72", "10.0.0.5", "45.148.10.72"],
        "origin_ip": "45.148.10.72",
    }
    response = client.post("/api/intel/lookup", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["stored"] is False and data["network"] is False

    assert [item["domain"] for item in data["domains"]] == ["sbi-kyc-update.xyz", "gmail.com"]
    lookalike, freemail = data["domains"]
    assert lookalike["role"] == "sender" and lookalike["lookalike_of"] == "sbi" and lookalike["source"] == "offline"
    assert "lookalike_domain" in [finding["id"] for finding in lookalike["findings"]]
    assert freemail["is_free_mail"] is True

    assert [item["ip"] for item in data["ips"]] == ["45.148.10.72"]
    assert data["ips"][0]["source"] == "offline"

    assert _cache_rows(client) == 0
    assert client.get("/api/emails").json()["total"] == 0
    assert client.get("/api/custody/verify").json()["head_hash"] == "0" * 64


def test_lookup_rejects_what_is_not_a_domain_or_an_address(client, cfg):
    assert client.post("/api/intel/lookup", json={"domains": [{"domain": "not a domain"}]}).status_code == 422
    assert client.post("/api/intel/lookup", json={"domains": [{"domain": "user@example.com"}]}).status_code == 422
    assert client.post("/api/intel/lookup", json={"domains": [{"domain": "a.example", "role": "owner"}]}).status_code == 422
    assert client.post("/api/intel/lookup", json={"ips": ["999.1.1.1"]}).status_code == 422
    assert client.post("/api/intel/lookup", json={"origin_ip": "example.com"}).status_code == 422
    many = [{"domain": f"host{index}.example"} for index in range(cfg.intel_max_domains + 1)]
    assert client.post("/api/intel/lookup", json={"domains": many}).status_code == 413
    addresses = [f"8.8.8.{index}" for index in range(cfg.intel_max_ips + 1)]
    assert client.post("/api/intel/lookup", json={"ips": addresses}).status_code == 413
    empty = client.post("/api/intel/lookup", json={})
    assert empty.status_code == 200 and empty.json()["domains"] == [] and empty.json()["ips"] == []


def test_match_finds_an_earlier_case_from_digests_alone(client, sample):
    earlier = _upload(client, sample, "phishing")
    indicators = [item for item in earlier["intel"]["indicators"] if not item.startswith(("simhash:", "tlsh:"))]
    assert any(item.startswith("sender:") for item in indicators)

    response = client.post("/api/intel/match", json={"fingerprints": [_digest(item) for item in indicators]})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["stored"] is False and data["worst_risk"] == earlier["verdict"]["risk_score"]
    assert len(data["incidents"]) == 1
    incident = data["incidents"][0]
    assert incident["category"] == "Phishing" and incident["in_campaign"] is False
    assert sorted(incident["shared"]) == sorted(_digest(item) for item in indicators)
    assert set(incident) == {"risk_score", "category", "analyzed_at", "in_campaign", "shared", "fuzzy"}

    text = response.text
    assert earlier["id"] not in text and earlier["email"]["subject"] not in text
    assert earlier["email"]["sender"]["address"] not in text
    assert client.get("/api/emails").json()["total"] == 1


def test_match_needs_a_strong_indicator_or_two_weak_ones(client, sample):
    earlier = _upload(client, sample, "phishing")
    subject = next(item for item in earlier["intel"]["indicators"] if item.startswith("subject:"))
    sender = next(item for item in earlier["intel"]["indicators"] if item.startswith("sender:"))
    weak_only = client.post("/api/intel/match", json={"fingerprints": [_digest(subject)]}).json()
    assert weak_only["incidents"] == [] and weak_only["worst_risk"] == 0
    strong = client.post("/api/intel/match", json={"fingerprints": [_digest(sender), _digest("sender:nobody@example.org")]}).json()
    assert [incident["shared"] for incident in strong["incidents"]] == [[_digest(sender)]]
    unknown = client.post("/api/intel/match", json={"fingerprints": [_digest("sender:nobody@example.org")]}).json()
    assert unknown["incidents"] == []


def test_match_links_a_reworded_copy_by_its_simhash(client, sample):
    earlier = _upload(client, sample, "fraud")
    fuzzy = earlier["email"]["fuzzy"]
    assert fuzzy["body_length"] >= 200 and len(fuzzy["simhash"]) == 16
    same = client.post("/api/intel/match", json={"simhash": fuzzy["simhash"], "body_length": fuzzy["body_length"]}).json()
    assert [incident["fuzzy"] for incident in same["incidents"]] == [["simhash~0"]]
    assert same["incidents"][0]["shared"] == []

    flipped = format(int(fuzzy["simhash"], 16) ^ 0b111, "016x")
    near = client.post("/api/intel/match", json={"simhash": flipped, "body_length": fuzzy["body_length"]}).json()
    assert [incident["fuzzy"] for incident in near["incidents"]] == [["simhash~3"]]

    far = format(int(fuzzy["simhash"], 16) ^ ((1 << 40) - 1), "016x")
    assert client.post("/api/intel/match", json={"simhash": far, "body_length": fuzzy["body_length"]}).json()["incidents"] == []
    short = client.post("/api/intel/match", json={"simhash": fuzzy["simhash"], "body_length": 50}).json()
    assert short["incidents"] == []


def test_private_cases_cannot_be_matched(client, sample):
    body = {"raw": sample("phishing").decode("utf-8"), "filename": "p.eml", "origin": "gmail"}
    private = client.post("/api/analyze/raw", json=body).json()["results"][0]
    indicators = [item for item in private["intel"]["indicators"] if not item.startswith(("simhash:", "tlsh:"))]
    data = client.post(
        "/api/intel/match",
        json={
            "fingerprints": [_digest(item) for item in indicators],
            "simhash": private["email"]["fuzzy"]["simhash"],
            "body_length": private["email"]["fuzzy"]["body_length"],
        },
    ).json()
    assert data["incidents"] == [] and data["campaigns"] == 0


def test_match_counts_campaigns(client, sample):
    first = _upload(client, sample, "phishing")
    _upload(client, sample, "phishing")
    sender = next(item for item in first["intel"]["indicators"] if item.startswith("sender:"))
    data = client.post("/api/intel/match", json={"fingerprints": [_digest(sender)]}).json()
    assert len(data["incidents"]) == 2 and data["campaigns"] == 1
    assert all(incident["in_campaign"] for incident in data["incidents"])


def test_match_validates_its_input(client, cfg):
    assert client.post("/api/intel/match", json={"fingerprints": ["sender:a@b.com"]}).status_code == 422
    assert client.post("/api/intel/match", json={"fingerprints": ["ab" * 31]}).status_code == 422
    assert client.post("/api/intel/match", json={"simhash": "xyz"}).status_code == 422
    assert client.post("/api/intel/match", json={"body_length": -1}).status_code == 422
    many = [_digest(str(index)) for index in range(cfg.intel_max_fingerprints + 1)]
    assert client.post("/api/intel/match", json={"fingerprints": many}).status_code == 413
    assert client.post("/api/intel/match", json={}).json() == {
        "incidents": [], "campaigns": 0, "worst_risk": 0, "stored": False,
    }


def test_older_indicators_are_indexed_when_the_store_opens(cfg):
    from app.database.case_manager import Store

    store = Store(cfg.db_path, cfg.evidence_dir)
    store.save_indicators("old-case", ["sender:a@example.org", "simhash:0011223344556677"])
    store._conn.execute("DELETE FROM indicator_digests")
    assert store.find_emails_by_digests([_digest("sender:a@example.org")]) == {}
    store.close()

    reopened = Store(cfg.db_path, cfg.evidence_dir)
    try:
        assert reopened.find_emails_by_digests([_digest("sender:a@example.org")]) == {"old-case": ["sender:a@example.org"]}
        assert reopened.find_emails_by_digests([_digest("simhash:0011223344556677")]) == {}
    finally:
        reopened.close()


def test_memory_cache_expires_and_evicts():
    cache = MemoryCache(max_entries=2)
    cache.cache_set("a", {"value": 1}, 60)
    cache.cache_set("b", [1, 2], 60)
    assert cache.cache_get("a") == {"value": 1}
    cache.cache_set("c", "three", 60)
    assert cache.cache_get("b") is None and cache.cache_get("a") == {"value": 1} and cache.cache_get("c") == "three"
    assert len(cache) == 2

    cache.cache_set("gone", 1, -1)
    assert cache.cache_get("gone") is None
    cache.cache_set("soon", 1, 0)
    time.sleep(0.01)
    assert cache.cache_get("soon") is None
    cache.cache_set("bad", object(), 60)
    assert cache.cache_get("bad") is None
    cache.clear()
    assert len(cache) == 0
