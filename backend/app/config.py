"""Environment-driven configuration with secure defaults."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://sentinel:sentinel@localhost:5432/sentinel"
    redis_url: str = "redis://localhost:6379/0"

    secret_key: str = "insecure-development-key-change-me"
    access_token_expire_minutes: int = 480

    # OPT-IN ONLY for isolated lab environments: permits loopback/private targets.
    allow_private_targets: bool = False

    object_storage_dir: str = "/data/reports"
    cors_origins: str = "http://localhost:4173,http://localhost:5173"

    # Conservative scan defaults (overridable per scan, bounded above by these caps).
    default_rate_limit_rps: float = 1.0
    max_rate_limit_rps: float = 10.0
    default_max_requests: int = 500
    max_max_requests: int = 5000
    default_max_depth: int = 3
    max_max_depth: int = 8
    default_max_urls: int = 200
    max_max_urls: int = 2000
    max_scan_duration_seconds: int = 3600


settings = Settings()