"""Hosted API middleware."""

from __future__ import annotations

import logging
from time import monotonic
from uuid import uuid4

from fastapi import Request
from redis import Redis
from starlette.responses import JSONResponse

from .config import settings


log = logging.getLogger("cipherfault.api")


async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    start = monotonic()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("request failed", extra={"request_id": request_id, "path": request.url.path})
        raise
    response.headers["X-Request-ID"] = request_id
    log.info(
        "request complete",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": int((monotonic() - start) * 1000),
        },
    )
    return response


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in {"/healthz", "/readyz"}:
        return await call_next(request)
    client = request.headers.get("X-API-Key") or (request.client.host if request.client else "unknown")
    key = f"rate:{client}:{int(monotonic() // settings.rate_limit_window_seconds)}"
    try:
        redis = Redis.from_url(settings.redis_url)
        count = redis.incr(key)
        if count == 1:
            redis.expire(key, settings.rate_limit_window_seconds)
    except Exception as exc:
        log.exception("rate limiter failed")
        return JSONResponse(
            {"detail": "rate limiter unavailable", "component": "redis", "error": str(exc)},
            status_code=503,
        )
    if count > settings.rate_limit_requests:
        return JSONResponse(
            {"detail": "rate limit exceeded", "limit": settings.rate_limit_requests},
            status_code=429,
            headers={"Retry-After": str(settings.rate_limit_window_seconds)},
        )
    return await call_next(request)
