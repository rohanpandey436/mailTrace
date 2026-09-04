"""
Runtime configuration.

Everything is read from environment variables (optionally seeded from a `.env`
file in the project root).  No third-party settings library is used so the
engine can be imported in isolation (tests, CLI) without side effects.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # .../mailtrace
ENV_PREFIX = "MAILTRACE_"

DEFAULT_WEIGHTS: dict[str, float] = {
    "authentication": 0.20,
    "content": 0.35,
    "links": 0.25,
    "infrastructure": 0.10,
    "anomaly": 0.10,
}


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, no interpolation.
    Existing environment variables always win."""
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


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(ENV_PREFIX + name)
    if raw is None:
        return list(default)
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


@dataclass
class Settings:
    # Storage
    data_dir: Path = field(default_factory=lambda: BASE_DIR / "data")
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
    def corpus_path(self) -> Path:
        return BASE_DIR / "app" / "ml" / "seed_corpus.json"

    @property
    def static_dir(self) -> Path:
        return BASE_DIR / "app" / "static"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> "Settings":
        _load_dotenv(BASE_DIR / ".env")
        weights = dict(DEFAULT_WEIGHTS)
        for key in weights:
            weights[key] = _env_float("WEIGHT_" + key.upper(), weights[key])
        total = sum(weights.values()) or 1.0
        weights = {k: v / total for k, v in weights.items()}
        return cls(
            data_dir=Path(_env("DATA_DIR", str(BASE_DIR / "data"))),
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
            cache_ttl_seconds=_env_int("CACHE_TTL_SECONDS", 6 * 3600),
            pii_mask_default=_env_bool("PII_MASK_DEFAULT", False),
            alert_threshold=_env_int("ALERT_THRESHOLD", 70),
            weights=weights,
            # Cloud hosts (Render, Railway, Fly, Koyeb) inject PORT and expect the
            # app to listen on every interface. Honour those without a prefix so
            # the same code runs locally and when deployed.
            host=_env("HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"),
            port=_env_int("PORT", int(os.environ.get("PORT", "8000") or 8000)),
            max_upload_bytes=_env_int("MAX_UPLOAD_BYTES", 15 * 1024 * 1024),
            log_level=_env("LOG_LEVEL", "info"),
        )


settings: Settings = Settings.from_env()
