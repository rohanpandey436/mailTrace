from __future__ import annotations

from datetime import UTC, datetime

from app.core import pipeline
from app.database.case_manager import GENESIS_HASH, Store
from app.schemas import Alert, Severity, ThreatCategory


def test_custody_chain_links_and_verifies(store: Store):
    e1 = store.record_custody("m1", "system", "ingested", {"filename": "a.eml"}, "ab" * 32)
    e2 = store.record_custody("m1", "analyst", "analyzed", {"risk_score": 80}, "ab" * 32)
    e3 = store.record_custody("m2", "system", "ingested", {}, "cd" * 32)
    assert e1.seq == 1 and e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.hash and e3.prev_hash == e2.hash
    valid, head = store.verify_chain()
    assert valid and head == e3.hash
    chain = store.get_custody("m1")
    assert [e.action for e in chain.events] == ["ingested", "analyzed"]
    assert chain.valid and chain.head_hash == e3.hash
    assert chain.events[1].detail == {"risk_score": 80}


def test_tampering_breaks_the_chain(store: Store):
    store.record_custody("m1", "system", "ingested", {"filename": "a.eml"}, "ab" * 32)
    store.record_custody("m1", "system", "analyzed", {"risk_score": 12}, "ab" * 32)
    with store._lock:  # simulate an attacker editing the ledger directly
        store._conn.execute("UPDATE custody SET detail_json = ? WHERE seq = 2", ('{"risk_score":99}',))
    valid, _ = store.verify_chain()
    assert valid is False
    assert store.get_custody("m1").valid is False


def test_analysis_roundtrip_and_listing(store: Store, cfg, sample):
    result = pipeline.analyze_bytes(sample("phishing"), "phish.eml", store, cfg)
    loaded = store.get_analysis(result.id)
    assert loaded is not None and loaded.verdict.category == result.verdict.category
    assert loaded.email.sender.address == "alerts@sbi-kyc-update.xyz"
    assert store.get_raw(result.id) == sample("phishing")
    rows, total = store.list_cases()
    assert total == 1 and rows[0].id == result.id and rows[0].category == ThreatCategory.PHISHING
    assert rows[0].originating_ip == "45.148.10.72" and rows[0].spf == "fail"
    assert store.list_cases(q="sbi")[1] == 1
    assert store.list_cases(q="nomatch")[1] == 0
    assert store.list_cases(category="Legitimate")[1] == 0
    assert store.list_cases(min_risk=100)[1] == 0
    assert store.summaries_for([result.id, "missing"])[0].id == result.id
    assert store.get_analysis("missing") is None
    chain = store.get_custody(result.id)
    assert [e.action for e in chain.events] == ["ingested", "analyzed"]
    assert chain.events[0].evidence_sha256 == result.email.raw_sha256
    stats = store.stats()
    assert stats.total_emails == 1 and stats.high_risk == 1 and stats.by_category["Phishing"] == 1


def test_alerts_and_cache(store: Store):
    alert = Alert(id="alr-1", created_at=datetime.now(UTC), email_id="m1", subject="s", sender="a@b.c",
                  category=ThreatCategory.PHISHING, risk_score=90, severity=Severity.CRITICAL, message="m")
    store.create_alert(alert)
    assert [a.id for a in store.list_alerts()] == ["alr-1"]
    assert store.list_alerts(unacknowledged_only=True)[0].acknowledged is False
    assert store.acknowledge_alert("alr-1") is True
    assert store.list_alerts(unacknowledged_only=True) == []
    assert store.acknowledge_alert("nope") is False
    store.cache_set("k", {"a": 1}, 60)
    assert store.cache_get("k") == {"a": 1}
    store.cache_set("expired", [1], -100)
    assert store.cache_get("expired") is None
    assert store.cache_get("missing") is None
    assert store.stats().alerts_open == 0
