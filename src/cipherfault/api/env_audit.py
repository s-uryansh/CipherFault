"""Log deployment env presence without leaking values."""

from __future__ import annotations

import logging
import os


REQUIRED_ENV = (
    "CIPHERFAULT_DATABASE_URL",
    "CIPHERFAULT_REDIS_URL",
    "CIPHERFAULT_STORAGE_BACKEND",
    "CIPHERFAULT_SUPABASE_URL",
    "CIPHERFAULT_SUPABASE_BUCKET",
    "CIPHERFAULT_SUPABASE_KEY",
    "CIPHERFAULT_RUN_JOBS_INLINE",
    "CIPHERFAULT_REQUIRE_RECOGNIZER",
    "CIPHERFAULT_MAX_UPLOAD_BYTES",
    "CIPHERFAULT_FREE_TIER_MONTHLY_SCANS",
    "CIPHERFAULT_RATE_LIMIT_REQUESTS",
    "CIPHERFAULT_RATE_LIMIT_WINDOW_SECONDS",
    "CIPHERFAULT_KEEPALIVE_ENABLED",
    "CIPHERFAULT_KEEPALIVE_INTERVAL_SECONDS",
)


def log_env_status() -> None:
    log = logging.getLogger("cipherfault.env")
    for name in REQUIRED_ENV:
        log.info("env %s=%s", name, "set" if os.getenv(name) else "unset")
