"""
This is to find the crytographic init call sites in a decompiled lib
will return structured anchors for the tracer to walk backward from
"""

from dataclasses import dataclass

CRYPTO_INITS = {
    "EVP_EncryptInit_ex": {"key": 4, "iv": 5},
    "EVP_DecryptInit_ex": {"key": 4, "iv": 5},
}

@dataclass
class Anchor:
    func_name: str
    callee: str
    call_addr: str
    operands: dict
    high: object

def _callee_name(program, target_vm):
    if not target_vm.isAddress():
        return None
    fn = program.getFunctionManager().getFunctionAt(target_vm.getAddress())
    return str(fn.getName()) if fn else None

def find_anchors(program, decomp, monitor, timeout=60):
    """
    Decompile everey functionm return list[Anchor]
    """
    from ghidra.program.model.pcode import PcodeOp

    anchors = []
    fm = program.getFunctionManager()
    for f in fm.getFunctions(True):
        if f.isThunk() or f.isExternal():
            continue
        res = decomp.decompileFunction(f, timeout, monitor)
        if not res.decompileCompleted():
            continue
        high = res.getHighFunction()
        if high is None:
            continue

        for op in high.getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL:
                continue
            callee = _callee_name(program, op.getInput(0))
            if callee not in CRYPTO_INITS:
                continue

            operand_map = CRYPTO_INITS[callee]
            operands = {}
            for name, idx in operand_map.items():
                if op.getNumInputs() > idx:
                    operands[name] = op.getInput(idx)

            anchors.append(Anchor(
                func_name=str(f.getName()),
                callee=callee,
                call_addr=str(op.getSeqnum().getTarget()),
                operands=operands,
                high=high
            ))
    return anchors