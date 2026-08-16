import json
import sys

sys.path.insert(0, "src")

from cipherfault.cli import main
from cipherfault.report import AnalysisReport

def test_cli_help_exits_zero(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "scan" in capsys.readouterr().out


def test_cli_version_exits_zero(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert capsys.readouterr().out.strip() == "cipherfault 0.1.0"

def test_json_and_cbom_flags_are_mutually_exclusive():
    try:
        main(["scan", "demo", "--format", "xml"])
    except SystemExit as exc:
        assert exc.code == 2


def test_scanner_rejects_non_elf_before_lifting(tmp_path):
    from cipherfault.scanner import scan_binary

    target = tmp_path / "text"
    target.write_text("not a binary")
    try:
        scan_binary(target)
    except ValueError as exc:
        assert "64-bit little-endian ELF" in str(exc)
    else:
        raise AssertionError("non-ELF input accepted")


def test_cli_passes_fingerprint_reference(monkeypatch):
    observed = {}

    def fake_scan(binary, fingerprint_reference=None):
        observed.update(binary=binary, reference=fingerprint_reference)
        return AnalysisReport(target=str(binary), target_sha256="0" * 64)

    monkeypatch.setattr("cipherfault.cli.scan_binary", fake_scan)

    assert main(["scan", "target", "--fingerprint-reference", "reference"]) == 0
    assert str(observed["binary"]) == "target"
    assert str(observed["reference"]) == "reference"
