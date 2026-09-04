"""Environment-backed API settings."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("CIPHERFAULT_DATABASE_URL", "sqlite:///./cipherfault-api.db")
    redis_url: str = os.getenv("CIPHERFAULT_REDIS_URL", "redis://localhost:6379/0")
    storage_backend: str = os.getenv("CIPHERFAULT_STORAGE_BACKEND", "local")
    storage_dir: Path = Path(os.getenv("CIPHERFAULT_STORAGE_DIR", "./.cipherfault_uploads"))
    max_upload_bytes: int = int(os.getenv("CIPHERFAULT_MAX_UPLOAD_BYTES", str(100 * 1024 * 1024)))
    free_tier_monthly_scans: int = int(os.getenv("CIPHERFAULT_FREE_TIER_MONTHLY_SCANS", "25"))
    require_recognizer: bool = os.getenv("CIPHERFAULT_REQUIRE_RECOGNIZER", "1") == "1"
    rate_limit_requests: int = int(os.getenv("CIPHERFAULT_RATE_LIMIT_REQUESTS", "60"))
    rate_limit_window_seconds: int = int(os.getenv("CIPHERFAULT_RATE_LIMIT_WINDOW_SECONDS", "60"))
    keepalive_enabled: bool = os.getenv("CIPHERFAULT_KEEPALIVE_ENABLED", "0") == "1"
    keepalive_interval_seconds: int = int(os.getenv("CIPHERFAULT_KEEPALIVE_INTERVAL_SECONDS", "120"))
    supabase_url: str | None = os.getenv("CIPHERFAULT_SUPABASE_URL")
    supabase_key: str | None = os.getenv("CIPHERFAULT_SUPABASE_KEY")
    supabase_bucket: str | None = os.getenv("CIPHERFAULT_SUPABASE_BUCKET")
    run_jobs_inline: bool = os.getenv("CIPHERFAULT_RUN_JOBS_INLINE", "0") == "1"
    dev_api_key: str | None = os.getenv("CIPHERFAULT_DEV_API_KEY")
    port: int = int(os.getenv("PORT", "8000"))


settings = Settings()
