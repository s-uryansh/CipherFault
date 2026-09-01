import sys

sys.path.insert(0, "src")

from cipherfault.report import AnalysisReport
from cipherfault.service import run_scan


def test_run_scan_returns_report_dict(monkeypatch):
    def fake_scan(binary, fingerprint_reference=None):
        assert str(binary) == "target"
        assert str(fingerprint_reference) == "reference"
        return AnalysisReport(target="target", target_sha256="0" * 64)

    monkeypatch.setattr("cipherfault.service.scan_binary", fake_scan)

    assert run_scan("target", fingerprint_reference="reference")["target"] == "target"


def test_run_scan_rejects_unknown_output_format(monkeypatch):
    monkeypatch.setattr(
        "cipherfault.service.scan_binary",
        lambda binary, fingerprint_reference=None: AnalysisReport(
            target=str(binary), target_sha256="0" * 64
        ),
    )

    try:
        run_scan("target", output_format="xml")
    except ValueError as exc:
        assert "unsupported output_format" in str(exc)
    else:
        raise AssertionError("unsupported output format accepted")
