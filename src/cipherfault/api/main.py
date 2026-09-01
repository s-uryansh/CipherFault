"""FastAPI entry point for CipherFault SaaS."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from rq import Retry
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from .auth import current_org, hash_api_key
from .config import settings
from .db.models import ApiKey, Org, Scan
from .db.session import SessionLocal, get_db, init_db
from .queue import scan_queue
from .storage import save_upload
from .worker import execute_scan_job


class ScanCreate(BaseModel):
    storage_path: str
    filename: str | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if settings.dev_api_key:
        _seed_dev_api_key(settings.dev_api_key)
    yield


app = FastAPI(title="CipherFault API", version="0.1.0", lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scans/upload", status_code=status.HTTP_202_ACCEPTED)
def upload_scan(
    file: UploadFile = File(...),
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    filename, path = save_upload(file)
    scan = Scan(org_id=org.id, filename=filename, storage_path=str(path), status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    job_id = _enqueue(scan.id)
    return {"scan_id": scan.id, "job_id": job_id, "status": scan.status}


@app.post("/v1/scans", status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    body: ScanCreate,
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = Scan(
        org_id=org.id,
        filename=body.filename or body.storage_path.rsplit("/", 1)[-1],
        storage_path=body.storage_path,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    job_id = _enqueue(scan.id)
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


def _scan_for_org(db: Session, scan_id: str, org_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


def _enqueue(scan_id: str) -> str:
    if settings.run_jobs_inline:
        execute_scan_job(scan_id)
        return scan_id
    job = scan_queue().enqueue(
        execute_scan_job,
        scan_id,
        retry=Retry(max=2, interval=[30, 120]),
        job_timeout=900,
    )
    return job.id


def _seed_dev_api_key(raw_key: str) -> None:
    db = SessionLocal()
    try:
        if db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(raw_key))):
            return
        org = db.scalar(select(Org).where(Org.name == "Dev Org")) or Org(name="Dev Org")
        db.add(org)
        db.flush()
        db.add(ApiKey(org_id=org.id, name="dev", key_hash=hash_api_key(raw_key)))
        db.commit()
    finally:
        db.close()
