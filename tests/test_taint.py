"""Regression: key operand must resolve to .rodata 0x102010 on both fixtures."""
import sys, os
sys.path.insert(0, "src")
import pyghidra
pyghidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from cipherfault.taint.anchors import find_anchors
from cipherfault.taint.tracer import trace_operand

EXPECT_ORIGIN = "0x102010"
FIXTURES = ["corpus/build/aes_ecb_demo_strip", "corpus/build/aes_ecb_ip_strip"]


def check(binary):
    with pyghidra.open_program(binary) as flat_api:
        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        decomp.openProgram(program)
        anchors = find_anchors(program, decomp, monitor)
        assert len(anchors) == 1, f"{binary}: expected 1 anchor, got {len(anchors)}"
        a = anchors[0]
        assert "key" in a.operands, f"{binary}: no key operand"
        path = trace_operand(a.operands["key"], a.high, program, decomp, monitor)
        assert path.terminal == "CONST", f"{binary}: terminal={path.terminal}"
        assert path.origin == EXPECT_ORIGIN, f"{binary}: origin={path.origin}"
    print(f"[PASS] {binary}: key -> CONST {EXPECT_ORIGIN}")


if __name__ == "__main__":
    for f in FIXTURES:
        if not os.path.exists(f):
            print(f"[SKIP] {f} not built"); continue
        check(f)
    print("[+] all taint regressions passed")