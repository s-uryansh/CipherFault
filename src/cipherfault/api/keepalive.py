"""Background keepalive checks for hosted dependencies."""

from __future__ import annotations

import asyncio
import logging
from uuid import uuid4

from sqlalchemy import text

from .config import settings
from .db.session import engine
from .queue import check_redis
from .storage import _bucket, _storage_url, _supabase_request


log = logging.getLogger("cipherfault.keepalive")


async def keepalive_loop() -> None:
    while True:
        await asyncio.sleep(settings.keepalive_interval_seconds)
        await asyncio.to_thread(run_keepalive_once)


def run_keepalive_once() -> dict[str, str]:
    return {
        "database": _check_database(),
        "redis": _check_redis(),
        "supabase": _check_supabase(),
    }


def _check_database() -> str:
    check_id = str(uuid4())
    try:
        with engine.begin() as connection:
            connection.execute(text(
                "create table if not exists service_keepalives "
                "(id varchar(36) primary key, created_at timestamptz default now())"
            ))
            connection.execute(text("insert into service_keepalives (id) values (:id)"), {"id": check_id})
            found = connection.execute(text("select id from service_keepalives where id = :id"), {"id": check_id}).scalar_one()
            connection.execute(text("delete from service_keepalives where id = :id"), {"id": check_id})
        return "ok" if found == check_id else "mismatch"
    except Exception:
        log.exception("database keepalive failed")
        return "failed"


def _check_redis() -> str:
    try:
        check_redis()
        return "ok"
    except Exception:
        log.exception("redis keepalive failed")
        return "failed"


def _check_supabase() -> str:
    if settings.storage_backend != "supabase":
        return "skipped"
    try:
        _supabase_request("GET", f"{_storage_url()}/bucket/{_bucket()}")
        return "ok"
    except Exception:
        log.exception("supabase keepalive failed")
        return "failed"
