from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import Settings

TEST_DATABASE_URL = os.environ.get("MAILTRACE_TEST_DATABASE_URL", "").strip()
TABLES = (
    "emails", "indicators", "indicator_digests", "campaigns", "campaign_members", "custody", "alerts",
    "cache", "case_status", "evidence", "retention",
)

SAMPLES = ROOT.parent / "samples"
SAMPLE_FILES = {
    "phishing": "phishing_sbi_kyc.eml",
    "bec": "bec_payment_diversion.eml",
    "legit": "legit_transactional.eml",
    "fraud": "fraud_lottery_advance_fee.eml",
    "ceo": "impersonation_ceo_gift_cards.eml",
}


def make_settings(data_dir: Path) -> Settings:
    return Settings(
        data_dir=data_dir,
        org_name="Acme Corp",
        org_domains=["acme-corp.in"],
        executives=["ceo", "cfo", "managing director", "sarthak srivastava"],
        enable_network=False,
        alert_threshold=70,
        database_url=TEST_DATABASE_URL,
    )


@pytest.fixture(autouse=True)
def fresh_database():
    if TEST_DATABASE_URL:
        import psycopg

        with psycopg.connect(TEST_DATABASE_URL, autocommit=True, prepare_threshold=None) as conn:
            for table in TABLES:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
    yield


@pytest.fixture
def cfg(tmp_path: Path) -> Settings:
    settings = make_settings(tmp_path / "data")
    settings.ensure_dirs()
    return settings


@pytest.fixture
def store(cfg: Settings):
    from app.database.case_manager import Store

    handle = Store(cfg.db_path, cfg.evidence_dir, database_url=cfg.database_url)
    yield handle
    handle.close()


@pytest.fixture
def sample():
    def _load(key: str) -> bytes:
        name = SAMPLE_FILES.get(key, key)
        return (SAMPLES / name).read_bytes()

    return _load


@pytest.fixture(scope="session")
def session_cfg(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    settings = make_settings(tmp_path_factory.mktemp("mailtrace") / "data")
    settings.ensure_dirs()
    return settings


@pytest.fixture(scope="session")
def analyses(session_cfg: Settings) -> dict:
    from app.core import pipeline

    results = {}
    for key, name in SAMPLE_FILES.items():
        results[key] = pipeline.analyze_bytes((SAMPLES / name).read_bytes(), name, None, session_cfg)
    return results
