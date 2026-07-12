"""
Trace an operand varnode backward through SSA def-use chains to its origin.
Intra-procedural + bounded inter-procedural hop along resolved call edges..
"""

from dataclasses import dataclass, field

@dataclass
class Step:
    kind: str
    detail: str
    varnode: str

@dataclass
class ProvenancePath:
    steps: list = field(default_factory=list)
    terminal: str = None
    origin: str = None

    def add(self, step):
        self.steps.append(step)

def trace_operand(vn, high, program, decomp, monitor, max_ip=3):
    """
    Entry Point: reutrns a provenance path for a single operand varnode.
    """
    path = ProvenancePath()
    _walk(vn, high, program, decomp, monitor, max_ip, set(), path)
    return path

def _param_slot(vn, high):
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

def _walk(vn, high, program, decomp, monitor, max_ip, seen, path):
    from ghidra.program.model.pcode import PcodeOp

    key = str(vn)
    if key in seen:
        path.add(Step("CYCLE", "cycle", key)); return
    seen.add(key)

    if vn.isConstant():
        path.add(Step("CONST", hex(vn.getOffset()), key))
        path.terminal = "CONST"; path.origin = hex(vn.getOffset())
        return
    if vn.isAddress():
        addr = str(vn.getAddress())
        path.add(Step("ADDR", addr, key))
        path.terminal = "ADDR"; path.origin = addr
        return

    d = vn.getDef()
    if d is None:
        slot = _param_slot(vn, high)
        if slot is not None and max_ip > 0:
            path.add(Step("PARAM_HOP", f"param slot {slot}", key))
            _hop_to_callers(high, slot, program, decomp, monitor, max_ip, seen, path)
        else:
            path.add(Step("INPUT", "no def (arg/uninit or depth exhausted)", key))
            path.terminal = "INPUT"
        return

    path.add(Step("OP", d.getMnemonic(), key))
    if d.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.INDIRECT):
        path.add(Step("CUT", f"value from {d.getMnemonic()}", key))
        return
    for i in range(d.getNumInputs()):
        _walk(d.getInput(i), high, program, decomp, monitor, max_ip, seen, path)


def _hop_to_callers(callee_high, slot, program, decomp, monitor, max_ip, seen, path):
    from ghidra.program.model.pcode import PcodeOp

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
                continue
            arg_vn = op.getInput(arg_idx)
            path.add(Step("PARAM_HOP",
                        f"hop into {caller_fn.getName()} @ {call_addr}, arg {slot}",
                        str(arg_vn)))
            _walk(arg_vn, caller_high, program, decomp, monitor, max_ip - 1, seen, path)