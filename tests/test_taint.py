"""Regression: key operand must resolve to .rodata 0x102010 on both fixtures."""
import sys, os
sys.path.insert(0, "src")
from cipherfault.taint.anchors import find_anchors
from cipherfault.taint.tracer import trace_operand
from cipherfault.taint.tracer import _weak_source
from cipherfault.ghidra import analyzed_program

EXPECT_ORIGIN = "0x102010"
FIXTURES = ["corpus/build/aes_ecb_demo_strip", "corpus/build/aes_ecb_ip_strip"]


def test_weak_source_uses_recovered_static_name():
    import pyghidra

    pyghidra.start()
    from ghidra.program.model.pcode import PcodeOp

    class Function:
        def getName(self): return "FUN_401000"
        def getEntryPoint(self): return "401000"

    class Manager:
        def getFunctionAt(self, address): return Function()

    class Program:
        def getFunctionManager(self): return Manager()

    class Target:
        def isAddress(self): return True
        def getAddress(self): return "401000"

    class Definition:
        def getOpcode(self): return PcodeOp.CALL
        def getNumInputs(self): return 1
        def getInput(self, index): return Target()

    class Value:
        def getDef(self): return Definition()
        def __str__(self): return "value"

    assert _weak_source(Value(), Program(), set(), {"401000": "rand"}) == "rand"


def check(binary):
    with analyzed_program(binary) as (program, monitor):
        from ghidra.app.decompiler import DecompInterface

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
