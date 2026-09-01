"""RQ worker entry points."""

from __future__ import annotations

from .db.models import Scan, UsageEvent
from .db.session import SessionLocal
from cipherfault.cbom import report_to_cbom
from cipherfault.service import run_scan_report


def execute_scan_job(scan_id: str) -> None:
    session = SessionLocal()
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        scan.stage = "scanning"
        session.commit()

        report = run_scan_report(scan.storage_path)
        scan.report_json = report.to_dict()
        scan.cbom_json = report_to_cbom(report)
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
