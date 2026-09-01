import os
import sys
from io import BytesIO

os.environ["CIPHERFAULT_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["CIPHERFAULT_RUN_JOBS_INLINE"] = "1"
os.environ["CIPHERFAULT_STORAGE_DIR"] = "/tmp/cipherfault-api-test-uploads"

sys.path.insert(0, "src")

import pytest
from fastapi import HTTPException, UploadFile

from cipherfault.api.auth import hash_api_key
from cipherfault.api.db.models import ApiKey, Org
from cipherfault.api.db.session import SessionLocal, init_db
from cipherfault.api.main import delete_scan, get_cbom, get_findings, get_scan, get_usage, healthz, upload_scan
from cipherfault.report import AnalysisReport


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
