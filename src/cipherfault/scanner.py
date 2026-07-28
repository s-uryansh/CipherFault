"""Binary scanner orchestration."""

from pathlib import Path

from .rules import Finding, hardcoded_key_finding, ecb_mode_finding, static_iv_finding
from .taint.anchors import find_anchors, callee_name
from .taint.tracer import trace_operand


def scan_binary(binary_path: str | Path) -> list[Finding]:
    import pyghidra

    binary_path = Path(binary_path)
    if not binary_path.exists():
        raise FileNotFoundError(binary_path)

    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    findings: list[Finding] = []

    with pyghidra.open_program(str(binary_path)) as flat_api:
        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        decomp.openProgram(program)

        for anchor in find_anchors(program, decomp, monitor):
            cipher = anchor.operands.get("cipher")
            if cipher is not None:
                finding = ecb_mode_finding(anchor, cipher_selector_name(program, cipher))
                if finding is not None:
                    findings.append(finding)

            iv = anchor.operands.get("iv")
            if iv is not None:
                path = trace_operand(iv, anchor.high, program, decomp, monitor)
                finding = static_iv_finding(anchor, path)
                if finding is not None:
                    findings.append(finding)

            key = anchor.operands.get("key")
            if key is None:
                continue
            path = trace_operand(key, anchor.high, program, decomp, monitor)
            finding = hardcoded_key_finding(anchor, path)
            if finding is not None:
                findings.append(finding)

    return findings


def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [finding.to_dict() for finding in findings]

def cipher_selector_name(program, vn) -> str | None:
    direct = callee_name(program, vn)
    if direct is not None:
        return direct
    d = vn.getDef()
    if d is None or d.getMnemonic() != "CALL" or d.getNumInputs() == 0:
        return None
    return callee_name(program, d.getInput(0))
