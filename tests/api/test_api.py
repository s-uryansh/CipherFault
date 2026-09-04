import os
import sys
import asyncio
from io import BytesIO
from types import SimpleNamespace

os.environ["CIPHERFAULT_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["CIPHERFAULT_RUN_JOBS_INLINE"] = "1"
os.environ["CIPHERFAULT_REQUIRE_RECOGNIZER"] = "0"
os.environ["CIPHERFAULT_STORAGE_DIR"] = "/tmp/cipherfault-api-test-uploads"

sys.path.insert(0, "src")

import pytest
from fastapi import HTTPException, UploadFile

from cipherfault.api.auth import hash_api_key
from cipherfault.api.db.models import ApiKey, Org
from cipherfault.api.db.session import SessionLocal, init_db
from cipherfault.api.main import (
    ApiKeyCreate,
    ScanCreate,
    create_api_key,
    create_scan,
    delete_scan,
    get_cbom,
    get_findings,
    get_me,
    get_scan,
    get_usage,
    healthz,
    readyz,
    list_api_keys,
    revoke_api_key,
    upload_scan,
)
from cipherfault.report import AnalysisReport
from cipherfault.api import middleware


API_KEY = "test-key"
ORG_ID = None


def setup_module():
    global ORG_ID
    init_db()
    db = SessionLocal()
    try:
        org = Org(name="Test Org")
        db.add(org)
        db.flush()
        ORG_ID = org.id
        db.add(ApiKey(org_id=org.id, name="test", key_hash=hash_api_key(API_KEY)))
        db.commit()
    finally:
        db.close()


def test_healthz_does_not_require_auth():
    assert healthz() == {"status": "ok"}


def test_readyz_reports_database_failure(monkeypatch):
    monkeypatch.setattr("cipherfault.api.main.check_db", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    with pytest.raises(HTTPException) as exc:
        readyz()
    assert exc.value.status_code == 503
    assert "database unavailable" in exc.value.detail


def test_readyz_reports_supabase_failure(monkeypatch):
    monkeypatch.setattr(
        "cipherfault.api.main.settings",
        SimpleNamespace(run_jobs_inline=True, require_recognizer=False, storage_backend="supabase"),
    )
    monkeypatch.setattr("cipherfault.api.main.check_supabase_storage", lambda: (_ for _ in ()).throw(RuntimeError("bucket missing")))
    with pytest.raises(HTTPException) as exc:
        readyz()
    assert exc.value.status_code == 503
    assert "storage unavailable" in exc.value.detail


def test_upload_scan_completes_inline(monkeypatch, tmp_path):
    report = AnalysisReport(target="demo.out", target_sha256="0" * 64)
    report.verified_facts = [{"id": "fact-1"}]

    def fake_run_scan_report(path, *, fingerprint_reference=None):
        return report

    monkeypatch.setattr("cipherfault.api.worker.run_scan_report", fake_run_scan_report)
    monkeypatch.setattr("cipherfault.api.worker.report_to_cbom", lambda report: {"bomFormat": "CycloneDX"})
    db = SessionLocal()
    org = db.get(Org, ORG_ID)
    upload = UploadFile(file=BytesIO(b"\x7fELF\x02\x01" + b"0" * 32), filename="demo.out")
    response = upload_scan(file=upload, org=org, db=db)

    scan_id = response["scan_id"]
    status = get_scan(scan_id, org=org, db=db)
    assert status["status"] == "complete"
    findings = get_findings(scan_id, org=org, db=db)
    assert findings["verified_facts"] == [{"id": "fact-1"}]
    cbom = get_cbom(scan_id, org=org, db=db)
    assert cbom == {"bomFormat": "CycloneDX"}
    usage = get_usage(ORG_ID, org=org, db=db)
    assert usage["scans_completed"] >= 1
    assert usage["monthly_used"] >= 1
    delete_scan(scan_id, org=org, db=db)
    with pytest.raises(HTTPException) as exc:
        get_scan(scan_id, org=org, db=db)
    assert exc.value.status_code == 404
    db.close()


def test_auth_is_required():
    from cipherfault.api.auth import current_org

    with pytest.raises(HTTPException) as exc:
        current_org(x_api_key=None, db=SessionLocal())
    assert exc.value.status_code == 401


def test_get_me_returns_current_org():
    db = SessionLocal()
    org = db.get(Org, ORG_ID)
    assert get_me(org=org) == {"org_id": ORG_ID, "org_name": "Test Org", "tier": "free"}
    db.close()


def test_create_scan_rejects_cross_org_storage_path():
    db = SessionLocal()
    org = db.get(Org, ORG_ID)
    with pytest.raises(HTTPException) as exc:
        create_scan(ScanCreate(storage_path="/tmp/other-org/demo.out"), org=org, db=db)
    assert exc.value.status_code == 403
    db.close()


def test_api_key_create_list_and_revoke():
    db = SessionLocal()
    org = db.get(Org, ORG_ID)

    created = create_api_key(ORG_ID, ApiKeyCreate(name="ci"), org=org, db=db)
    assert created["api_key"].startswith("cf_")
    assert created["key_prefix"] == created["api_key"][:8]

    keys = list_api_keys(ORG_ID, org=org, db=db)
    assert any(key["id"] == created["id"] and key["revoked_at"] is None for key in keys)

    revoke_api_key(ORG_ID, created["id"], org=org, db=db)
    keys = list_api_keys(ORG_ID, org=org, db=db)
    assert any(key["id"] == created["id"] and key["revoked_at"] is not None for key in keys)
    db.close()


def test_rate_limit_middleware_blocks_after_limit(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.count = 0

        def incr(self, key):
            self.count += 1
            return self.count

        def expire(self, key, seconds):
            return True

    fake = FakeRedis()
    monkeypatch.setattr(middleware, "settings", SimpleNamespace(redis_url="redis://test", rate_limit_requests=1, rate_limit_window_seconds=60))
    monkeypatch.setattr(middleware.Redis, "from_url", lambda url: fake)
    request = SimpleNamespace(
        url=SimpleNamespace(path="/v1/scans/upload"),
        headers={"X-API-Key": "test-key"},
        client=SimpleNamespace(host="127.0.0.1"),
    )

    async def ok_response(request):
        return SimpleNamespace(status_code=200, headers={})

    first = asyncio.run(middleware.rate_limit_middleware(request, ok_response))
    second = asyncio.run(middleware.rate_limit_middleware(request, ok_response))

    assert first.status_code == 200
    assert second.status_code == 429
