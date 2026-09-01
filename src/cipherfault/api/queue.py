"""Scan queue wiring."""

from __future__ import annotations

from redis import Redis
from rq import Queue

from .config import settings


def scan_queue() -> Queue:
    return Queue("scans", connection=Redis.from_url(settings.redis_url))
