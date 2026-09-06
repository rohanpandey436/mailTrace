"""Runtime configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent   # .../mailtrace/backend
PROJECT_DIR = BASE_DIR.parent                        # .../mailtrace
ENV_PREFIX = "MAILTRACE_"

DEFAULT_WEIGHTS: dict[str, float] = {
    "auth": 0.20,     # SPF / DKIM / DMARC / alignment / forged sender fields
    "text": 0.35,     # NLP intent, BEC patterns, social-engineering language
    "url": 0.25,      # link risk, lookalike and deceptive domains
    "network": 0.10,  # origin infrastructure, VPN / TOR, routing anomalies, blocklists
    "entropy": 0.10,  # attachment Shannon entropy and file-level payload risk
}
PILLARS: tuple[str, ...] = tuple(DEFAULT_WEIGHTS)


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, no interpolation."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _env(name: str, default: str) -> str:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(ENV_PREFIX + name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(ENV_PREFIX + name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(ENV_PREFIX + name, default))
    except (TypeError, ValueError):
        return default


def _downloaded_geolite() -> str:
    """The GeoLite2 database ``scripts/fetch_geolite2.py`` writes, when it is there."""
    path = BASE_DIR / "data" / "GeoLite2-City.mmdb"
    return str(path) if path.is_file() else ""


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(ENV_PREFIX + name)
    if raw is None:
        return list(default)
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


@dataclass
class Settings:
    # Storage
    data_dir: Path = field(default_factory=lambda: BASE_DIR / "data")
    database_url: str = ""
    redis_url: str = ""
    queue_workers: int = 1
    # How long a finished job stays pollable. The case itself is in the database.
    queue_result_ttl: int = 3600
    # Organisation context (the party being protected)
    org_name: str = "Protected Organisation"
    org_domains: list[str] = field(default_factory=lambda: ["example.org"])
    executives: list[str] = field(default_factory=lambda: ["ceo", "cfo", "managing director"])
    protected_brands: list[str] = field(default_factory=list)
    trusted_relays: list[str] = field(default_factory=list)
    # Network enrichment
    enable_network: bool = True
    lookup_timeout: float = 3.0
    max_domain_lookups: int = 6
    max_geo_lookups: int = 8
    abuseipdb_key: str = ""
    urlhaus_key: str = ""
    virustotal_key: str = ""
    maxmind_db: str = ""
    transformer_enabled: bool = False
    transformer_model: str = ""
    url_model_enabled: bool = True
    lime_enabled: bool = True
    lime_samples: int = 160
    entropy_threshold: float = 7.0
    simhash_max_distance: int = 12
    tlsh_max_distance: int = 60
    # Stage 5B: outbound alert webhooks (comma separated), e.g. a SIEM or Slack URL.
    webhook_urls: list[str] = field(default_factory=list)
    # Stage 5C: analyse and return, storing nothing on disk.
    zero_persistence: bool = False
    cache_ttl_seconds: int = 6 * 3600
    # Privacy / alerting
    pii_mask_default: bool = False
    alert_threshold: int = 70
    # Scoring
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    # Web
    host: str = "127.0.0.1"
    port: int = 8000
    max_upload_bytes: int = 15 * 1024 * 1024
    log_level: str = "info"

    # Derived paths -------------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "mailtrace.db"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def model_path(self) -> Path:
        return self.data_dir / "model.joblib"

    @property
    def url_model_path(self) -> Path:
        """Cache for the XGBoost URL/domain model, beside the text model."""
        return self.data_dir / "url_model.joblib"

    @property
    def corpus_path(self) -> Path:
        return BASE_DIR / "app" / "ai" / "seed_corpus.json"

    @property
    def static_dir(self) -> Path:
        """The single-page dashboard, which lives outside the backend package."""
        return PROJECT_DIR / "frontend"

    @property
    def samples_dir(self) -> Path:
        return PROJECT_DIR / "samples"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> Settings:
        _load_dotenv(BASE_DIR / ".env")
        _load_dotenv(PROJECT_DIR / ".env")
        weights = dict(DEFAULT_WEIGHTS)
        for key in weights:
            weights[key] = _env_float("WEIGHT_" + key.upper(), weights[key])
        total = sum(weights.values()) or 1.0
        weights = {k: v / total for k, v in weights.items()}
        return cls(
            data_dir=Path(_env("DATA_DIR", "").strip() or str(BASE_DIR / "data")),
            database_url=_env("DATABASE_URL", os.environ.get("DATABASE_URL", "")).strip(),
            # Render, Heroku and docker-compose publish a bare REDIS_URL; the prefixed name wins.
            redis_url=_env("REDIS_URL", os.environ.get("REDIS_URL", "")).strip(),
            queue_workers=_env_int("QUEUE_WORKERS", 1),
            queue_result_ttl=_env_int("QUEUE_RESULT_TTL", 3600),
            org_name=_env("ORG_NAME", "Protected Organisation"),
            org_domains=_env_list("ORG_DOMAINS", ["example.org"]),
            executives=_env_list("EXECUTIVES", ["ceo", "cfo", "managing director"]),
            protected_brands=_env_list("PROTECTED_BRANDS", []),
            trusted_relays=_env_list("TRUSTED_RELAYS", []),
            enable_network=_env_bool("ENABLE_NETWORK", True),
            lookup_timeout=_env_float("LOOKUP_TIMEOUT", 3.0),
            max_domain_lookups=_env_int("MAX_DOMAIN_LOOKUPS", 6),
            max_geo_lookups=_env_int("MAX_GEO_LOOKUPS", 8),
            abuseipdb_key=_env("ABUSEIPDB_KEY", ""),
            urlhaus_key=_env("URLHAUS_KEY", ""),
            virustotal_key=_env("VIRUSTOTAL_KEY", ""),
            maxmind_db=_env("MAXMIND_DB", "").strip() or _downloaded_geolite(),
            transformer_enabled=_env_bool("TRANSFORMER", False),
            transformer_model=_env("TRANSFORMER_MODEL", ""),
            url_model_enabled=_env_bool("URL_MODEL", True),
            lime_enabled=_env_bool("LIME", True),
            lime_samples=_env_int("LIME_SAMPLES", 160),
            entropy_threshold=_env_float("ENTROPY_THRESHOLD", 7.0),
            simhash_max_distance=_env_int("SIMHASH_MAX_DISTANCE", 12),
            tlsh_max_distance=_env_int("TLSH_MAX_DISTANCE", 60),
            # URLs keep their case, so _env_list (which lowercases) is not used here.
            webhook_urls=[u.strip() for u in _env("WEBHOOK_URLS", "").split(",") if u.strip()],
            zero_persistence=_env_bool("ZERO_PERSISTENCE", False),
            cache_ttl_seconds=_env_int("CACHE_TTL_SECONDS", 6 * 3600),
            pii_mask_default=_env_bool("PII_MASK_DEFAULT", False),
            alert_threshold=_env_int("ALERT_THRESHOLD", 70),
            weights=weights,
            host=_env("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"),
            port=_env_int("PORT", int(os.environ.get("PORT", "8000") or 8000)),
            max_upload_bytes=_env_int("MAX_UPLOAD_BYTES", 15 * 1024 * 1024),
            log_level=_env("LOG_LEVEL", "info"),
        )


settings: Settings = Settings.from_env()
