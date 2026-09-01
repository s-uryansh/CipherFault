"""Small deployable service boundary around the scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from .cbom import report_to_cbom
from .report import AnalysisReport
from .scanner import scan_binary


OutputFormat = Literal["json", "cbom"]


def run_scan_report(
    binary_path: str | Path,
    *,
    fingerprint_reference: str | Path | None = None,
) -> AnalysisReport:
    """Run one inference-only scan and return the in-memory report."""
    return scan_binary(binary_path, fingerprint_reference=fingerprint_reference)


def run_scan(
    binary_path: str | Path,
    *,
    fingerprint_reference: str | Path | None = None,
    output_format: OutputFormat = "json",
) -> dict:
    """Run one inference-only scan and return a JSON-serializable document."""
    report = run_scan_report(binary_path, fingerprint_reference=fingerprint_reference)
    if output_format == "json":
        return report.to_dict()
    if output_format == "cbom":
        return report_to_cbom(report)
    raise ValueError(f"unsupported output_format: {output_format}")
