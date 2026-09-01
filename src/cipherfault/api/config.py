"""Environment-backed API settings."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("CIPHERFAULT_DATABASE_URL", "sqlite:///./cipherfault-api.db")
    redis_url: str = os.getenv("CIPHERFAULT_REDIS_URL", "redis://localhost:6379/0")
    storage_dir: Path = Path(os.getenv("CIPHERFAULT_STORAGE_DIR", "./.cipherfault_uploads"))
    run_jobs_inline: bool = os.getenv("CIPHERFAULT_RUN_JOBS_INLINE", "0") == "1"
    dev_api_key: str | None = os.getenv("CIPHERFAULT_DEV_API_KEY")


settings = Settings()
