#!/usr/bin/env python3
"""
Can Ghidra high P-code (SSA) trace the AES key operand of EVP_EncryptInit_ex back to a .rodata constant on a stripped binary
"""

import sys
import pyghidra

pyghidra.start()

TARGET_CALL = "EVP_EncryptInit_ex"
KEY_INPUT_IDX = 4

def probe(binary_path):
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.util.task import ConsoleTaskMonitor

    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        decomp = DecompInterface()
        decomp.openProgram(program)

        fm = program.getFunctionManager()
        for f in fm.getFunctions(True):
            if f.isThunk() or f.isExternal():
                continue
            res = decomp.decompileFunction(f, 60, monitor)
            if not res.decompileCompleted():
                continue
            high = res.getHighFunction()
            if high is None:
                continue

            for op in high.getPcodeOps():
                if op.getOpcode() != PcodeOp.CALL:
                    continue
                if _callee_name(program, op.getInput(0)) != TARGET_CALL:
                    continue

                print(
                    f"[+] {TARGET_CALL} in {f.getName()}"
                    f"@ {op.getSeqnum().getTarget()} ({op.getNumInputs()} inputes)"
                )
                if op.getNumInputs() <= KEY_INPUT_IDX:
                    print(f"    !! only {op.getNumInputs()} inputs : protoype not"
                        f"recovered, key operand missing")
                    continue
                print(f"    key varnode: {op.getInput(KEY_INPUT_IDX)}")
                trace(op.getInput(KEY_INPUT_IDX), 0 , set(), high, program, decomp, monitor)

def _callee_name(program, target_vn):
    if not target_vn.isAddress():
        return None
    fn = program.getFunctionManager().getFunctionAt(target_vn.getAddress())
    return str(fn.getName()) if fn else None

def trace(vn, depth, seen, high, program, decomp, monitor, max_ip=3):
    from ghidra.program.model.pcode import PcodeOp
    pad = " " + " " * depth
    key = str(vn)
    if key in seen:
        print(f"{pad}<cycle>"); return
    seen.add(key)

    if vn.isConstant():
        print(f"{pad}CONST {hex(vn.getOffset())} <- terminal")
        return
    if vn.isAddress():
        print(f"{pad}ADDR {vn.getAddress()} <- terminal (check .rodata)")
        return

    d = vn.getDef()
    if d is None:
        slot = _param_slot(vn, high)

        if slot is not None and max_ip > 0:
            print(f"{pad}INPUT {vn} == param slot {slot}, hoping to callers")
            _hop_to_callers(high, slot, depth, seen, program, decomp, monitor, max_ip)
        else:
            print(f"{pad}INPUT {vn} <- no def (fn arg / uninit): chain ends here")
        return

    print(f"{pad}{d.getMnemonic()} -> {vn}")

    if d.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.INDIRECT):
        print(f"{pad} (value from {d.getMnemonic()}: not following)")
        return
    for i in range(d.getNumInputs()):
        trace(d.getInput(i), depth +  1, seen, high, program, decomp, monitor, max_ip)


def _param_slot(vn, high):
    """
    if vn is a func parameter of high. return its slot index else None
    """
    lsm = high.getLocalSymbolMap()
    for sym in lsm.getSymbols():
        if not sym.isParameter():
            continue
        hv = sym.getHighVariable()
        if hv is None:
            continue
        for rep in hv.getInstances():
            if rep == vn:
                return sym.getCategoryIndex()
    return None

def _hop_to_callers(callee_high, slot, depth, seen, program, decomp, monitor, max_ip):
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.util.task import ConsoleTaskMonitor
    callee_fn = callee_high.getFunction()
    entry = callee_fn.getEntryPoint()
    ref_mgr = program.getReferenceManager()

    for ref in ref_mgr.getReferencesTo(entry):
        if not ref.getReferenceType().isCall():
            continue
        caller_fn = program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
        if caller_fn is None:
            continue
        res = decomp.decompileFunction(caller_fn, 60, monitor)
        if not res.decompileCompleted():
            continue
        caller_high = res.getHighFunction()
        call_addr = ref.getFromAddress()
        for op in caller_high.getPcodeOps(call_addr):
            if op.getOpcode() != PcodeOp.CALL:
                continue
            arg_idx = slot + 1
            if op.getNumInputs() <= arg_idx:
                print("     " + "       "  * (depth+1) + f"caller {caller_fn.getName(): }"
                                            f"only {op.getNumInputs()} args, slot {slot} missing")
                continue
            arg_vn = op.getInput(arg_idx)
            print("     " + "       "  * (depth+1) +
                f">> hop into {caller_fn.getName()} @ {call_addr}, arg {slot} = {arg_vn}")
            trace(arg_vn, depth + 2, seen, caller_high, program, decomp, monitor, max_ip - 1)

def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: probe.py <stripped_binary>")
    probe(sys.argv[1])

if __name__ == "__main__":
    main()