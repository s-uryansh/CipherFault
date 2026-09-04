"""Scan queue wiring."""

from __future__ import annotations

from redis import Redis
from rq import Queue

from .config import settings


def redis_connection() -> Redis:
    return Redis.from_url(settings.redis_url)


def scan_queue() -> Queue:
    return Queue("scans", connection=redis_connection())


def check_redis() -> None:
    redis_connection().ping()
