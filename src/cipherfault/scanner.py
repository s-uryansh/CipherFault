""""Binary Scanner orchestration"""

from pathlib import Path

from .rules import Finding, hardcoded_key_finding
from .taint.anchors import find_anchors
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
            key = anchor.operands.get("key")
            if key is None:
                continue
            path = trace_operand(key, anchor.high, program, decomp, monitor)
            finding = hardcoded_key_finding(anchor, path)
            if finding is not None:
                findings.append(finding)

    return findings

def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [finding.to_dict()for finding in findings]