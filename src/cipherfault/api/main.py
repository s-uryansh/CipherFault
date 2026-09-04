"""FastAPI entry point for CipherFault SaaS."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import asyncio
from datetime import datetime, timezone
import logging
from secrets import token_urlsafe

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from rq import Retry
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from .auth import current_org, hash_api_key
from .bootstrap import _seed_dev_api_key
from .config import settings
from .db.models import ApiKey, Org, Scan, UsageEvent
from .db.session import check_db, get_db, init_db
from .env_audit import log_env_status
from .keepalive import check_supabase_storage, run_keepalive_once, keepalive_loop
from .middleware import rate_limit_middleware, request_context_middleware
from .queue import check_redis, scan_queue
from .runtime import require_inference_ready
from .storage import delete_upload, save_upload, storage_path_belongs_to_org
from .worker import execute_scan_job


logging.basicConfig(level=logging.INFO)


class ScanCreate(BaseModel):
    storage_path: str
    filename: str | None = None


class ApiKeyCreate(BaseModel):
    name: str
    expires_at: datetime | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_env_status()
    init_db()
    if settings.dev_api_key:
        _seed_dev_api_key(settings.dev_api_key)
    task = asyncio.create_task(keepalive_loop()) if settings.keepalive_enabled else None
    try:
        yield
    finally:
        if task:
            task.cancel()


app = FastAPI(title="CipherFault API", version="0.1.0", lifespan=lifespan)
app.middleware("http")(request_context_middleware)
app.middleware("http")(rate_limit_middleware)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logging.getLogger("cipherfault.api").exception("unhandled API error")
    return JSONResponse({"detail": "internal server error", "error": str(exc)}, status_code=500)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        check_db()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"database unavailable: {exc}") from exc
    try:
        if not settings.run_jobs_inline:
            check_redis()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"redis unavailable: {exc}") from exc
    try:
        if settings.require_recognizer:
            require_inference_ready()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"inference unavailable: {exc}") from exc
    try:
        if settings.storage_backend == "supabase":
            check_supabase_storage()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"storage unavailable: {exc}") from exc
    return {"status": "ready"}


@app.get("/health/dependencies")
def dependency_health() -> dict[str, str]:
    return run_keepalive_once()


@app.post("/v1/scans/upload", status_code=status.HTTP_202_ACCEPTED)
def upload_scan(
    file: UploadFile = File(...),
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _enforce_quota(org, db)
    try:
        filename, path = save_upload(file, org.id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    scan = Scan(org_id=org.id, filename=filename, storage_path=str(path), status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(UsageEvent(org_id=org.id, scan_id=scan.id, event_type="scan_created"))
    db.commit()
    job_id = _enqueue(scan, db)
    return {"scan_id": scan.id, "job_id": job_id, "status": scan.status}


@app.post("/v1/scans", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    body: ScanCreate,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _enforce_quota(org, db)
    if not storage_path_belongs_to_org(body.storage_path, org.id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "storage path does not belong to org")
    scan = Scan(
        org_id=org.id,
        filename=body.filename or body.storage_path.rsplit("/", 1)[-1],
        storage_path=body.storage_path,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(UsageEvent(org_id=org.id, scan_id=scan.id, event_type="scan_created"))
    db.commit()
    job_id = _enqueue(scan, db)
    return {"scan_id": scan.id, "job_id": job_id, "status": scan.status}


@app.get("/v1/scans/{scan_id}")
def get_scan(
    scan_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = _scan_for_org(db, scan_id, org.id)
    return {
        "id": scan.id,
        "filename": scan.filename,
        "status": scan.status,
        "stage": scan.stage,
        "error": scan.error,
        "runtime": scan.runtime_json,
        "created_at": scan.created_at.isoformat(),
        "updated_at": scan.updated_at.isoformat(),
    }


@app.get("/v1/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict:
    scan = _scan_for_org(db, scan_id, org.id)
    if scan.status != "complete" or scan.report_json is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is not complete")
    return scan.report_json


@app.get("/v1/scans/{scan_id}/cbom")
def get_cbom(
    scan_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict:
    scan = _scan_for_org(db, scan_id, org.id)
    if scan.status != "complete" or scan.cbom_json is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "scan is not complete")
    return scan.cbom_json


@app.delete("/v1/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> None:
    scan = _scan_for_org(db, scan_id, org.id)
    delete_upload(scan.storage_path)
    db.delete(scan)
    db.commit()


@app.get("/v1/orgs/{org_id}/scans")
def list_scans(
    org_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    if org_id != org.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "wrong org")
    scans = db.scalars(select(Scan).where(Scan.org_id == org.id).order_by(desc(Scan.created_at)).limit(100)).all()
    return [
        {
            "id": scan.id,
            "filename": scan.filename,
            "status": scan.status,
            "tier1": len((scan.report_json or {}).get("verified_facts", [])),
            "tier2": len((scan.report_json or {}).get("indicators", [])),
            "target_sha256": (scan.report_json or {}).get("target_sha256"),
            "created_at": scan.created_at.isoformat(),
        }
        for scan in scans
    ]


@app.get("/v1/orgs/{org_id}/usage")
def get_usage(
    org_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if org_id != org.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "wrong org")
    completed = db.scalar(select(func.count()).select_from(Scan).where(Scan.org_id == org.id, Scan.status == "complete"))
    return {
        "org_id": org.id,
        "tier": org.tier,
        "scans_completed": completed or 0,
        "monthly_limit": _monthly_limit(org),
        "monthly_used": _monthly_usage(org, db),
    }


@app.get("/v1/orgs/{org_id}/api-keys")
def list_api_keys(
    org_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    if org_id != org.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "wrong org")
    keys = db.scalars(select(ApiKey).where(ApiKey.org_id == org.id).order_by(desc(ApiKey.created_at))).all()
    return [
        {
            "id": key.id,
            "name": key.name,
            "key_prefix": key.key_prefix,
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "created_at": key.created_at.isoformat(),
        }
        for key in keys
    ]


@app.post("/v1/orgs/{org_id}/api-keys", status_code=status.HTTP_201_CREATED)
def create_api_key(
    org_id: str,
    body: ApiKeyCreate,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if org_id != org.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "wrong org")
    raw_key = "cf_" + token_urlsafe(32)
    key = ApiKey(
        org_id=org.id,
        name=body.name,
        key_hash=hash_api_key(raw_key),
        key_prefix=raw_key[:8],
        expires_at=body.expires_at,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return {"id": key.id, "name": key.name, "key_prefix": key.key_prefix, "api_key": raw_key}


@app.delete("/v1/orgs/{org_id}/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    org_id: str,
    key_id: str,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> None:
    if org_id != org.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "wrong org")
    key = db.get(ApiKey, key_id)
    if key is None or key.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "api key not found")
    key.revoked_at = datetime.now(timezone.utc)
    db.commit()


def _scan_for_org(db: Session, scan_id: str, org_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


def _enqueue(scan: Scan, db: Session) -> str:
    if settings.run_jobs_inline:
        execute_scan_job(scan.id)
        return scan.id
    try:
        job = scan_queue().enqueue(
            execute_scan_job,
            scan.id,
            retry=Retry(max=2, interval=[30, 120]),
            job_timeout=900,
        )
    except Exception as exc:
        scan.status = "failed"
        scan.stage = None
        scan.error = f"queue unavailable: {exc}"
        db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"queue unavailable: {exc}") from exc
    return job.id


def _enforce_quota(org: Org, db: Session) -> None:
    limit = _monthly_limit(org)
    if limit is not None and _monthly_usage(org, db) >= limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "monthly scan quota exceeded")


def _monthly_limit(org: Org) -> int | None:
    return settings.free_tier_monthly_scans if org.tier == "free" else None


def _monthly_usage(org: Org, db: Session) -> int:
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return db.scalar(
        select(func.count()).select_from(UsageEvent).where(
            UsageEvent.org_id == org.id,
            UsageEvent.event_type == "scan_created",
            UsageEvent.created_at >= start,
        )
    ) or 0
