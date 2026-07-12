import sys
sys.path.insert(0, "src")
import pyghidra
pyghidra.start()

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from cipherfault.taint.anchors import find_anchors
from cipherfault.taint.tracer import trace_operand

with pyghidra.open_program(sys.argv[1]) as flat_api:
    program = flat_api.getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    decomp.openProgram(program)

    for a in find_anchors(program, decomp, monitor):
        print(f"[+] {a.callee} in {a.func_name} @ {a.call_addr}")
        if "key" not in a.operands:
            print("    (no key operand)"); continue
        path = trace_operand(a.operands["key"], a.high, program, decomp, monitor)
        print(f"    key trace: terminal={path.terminal} origin={path.origin}")
        for s in path.steps:
            print(f"        {s.kind:10} {s.detail}")