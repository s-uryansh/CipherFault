"""Find cryptographic init call sites in a decompiled program."""

from dataclasses import dataclass


CRYPTO_INITS = {
    "EVP_EncryptInit_ex": {"cipher": 2, "key": 4, "iv": 5},
    "EVP_DecryptInit_ex": {"cipher": 2, "key": 4, "iv": 5},
}

WEAK_RANDOM_SOURCES = {
    "time": "TIME",
    "clock": "TIME",
    "gettimeofday": "TIME",
    "rand": "WEAK_RNG",
    "srand": "WEAK_RNG_SEED"
}


@dataclass
class Anchor:
    func_name: str
    callee: str
    call_addr: str
    operands: dict
    high: object


def callee_name(program, target_vn):
    if not target_vn.isAddress():
        return None
    fn = program.getFunctionManager().getFunctionAt(target_vn.getAddress())
    return str(fn.getName()) if fn else None


def find_anchors(program, decomp, monitor, timeout=60):
    """Decompile each internal function and return crypto init anchors."""
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
            callee = callee_name(program, op.getInput(0))
            if callee not in CRYPTO_INITS:
                continue

            operands = {}
            for name, idx in CRYPTO_INITS[callee].items():
                if op.getNumInputs() > idx:
                    operands[name] = op.getInput(idx)

            anchors.append(
                Anchor(
                    func_name=str(f.getName()),
                    callee=callee,
                    call_addr=str(op.getSeqnum().getTarget()),
                    operands=operands,
                    high=high,
                )
            )
    return anchors