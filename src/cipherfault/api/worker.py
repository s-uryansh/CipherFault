"""RQ worker entry points."""

from __future__ import annotations

from .db.models import Scan, UsageEvent
from .db.session import SessionLocal
from .config import settings
from .runtime import inference_metadata, require_inference_ready
from .storage import scan_input
from cipherfault.cbom import report_to_cbom
from cipherfault.service import run_scan_report


def execute_scan_job(scan_id: str) -> None:
    if settings.require_recognizer:
        require_inference_ready()
    session = SessionLocal()
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        scan.stage = "scanning"
        session.commit()

        with scan_input(scan.storage_path) as binary_path:
            report = run_scan_report(binary_path)
        scan.report_json = report.to_dict()
        scan.cbom_json = report_to_cbom(report)
        scan.runtime_json = inference_metadata() if settings.require_recognizer else {}
        scan.status = "complete"
        scan.stage = None
        session.add(UsageEvent(org_id=scan.org_id, scan_id=scan.id))
        session.commit()
    except Exception as exc:
        if "scan" in locals() and scan is not None:
            scan.status = "failed"
            scan.stage = None
            scan.error = str(exc)
            session.commit()
        raise
    finally:
        session.close()
