"""Runtime-dependent patterns emitted only as analyst questions."""

from __future__ import annotations

from collections import defaultdict

from .report import Indicator


def repeated_operand_indicators(anchors) -> list[Indicator]:
    groups = defaultdict(list)
    for anchor in anchors:
        operand = _repeated_operand(anchor)
        value = anchor.operands.get(operand) if operand else None
        if value is None or (value.isConstant() and value.getOffset() == 0):
            continue
        groups[(anchor.primitive or "AES", anchor.func_name, operand, str(value))].append(anchor.call_addr)
    return [
        Indicator(
            tier="INDICATOR",
            primitive=primitive,
            pattern=f"same {operand} operand across multiple crypto-init calls in function scope",
            analyst_question=(
                "does this function handle multiple independent sessions?"
                if operand == "iv"
                else "is reuse of this key operand across encapsulations intended?"
            ),
            function=function,
            addresses=tuple(addresses),
            operand=operand,
        )
        for (primitive, function, operand, _), addresses in groups.items()
        if len(addresses) > 1
    ]


def _repeated_operand(anchor) -> str | None:
    if anchor.primitive == "ML-KEM" and "key" in anchor.operands:
        return "key"
    if anchor.primitive in {None, "AES"} and "iv" in anchor.operands:
        return "iv"
    return None


def rng_quality_indicator(anchor, path, operand: str) -> Indicator:
    return Indicator(
        tier="INDICATOR",
        primitive=anchor.primitive or "AES",
        pattern=f"{operand} operand is fed by RNG source {path.origin}",
        analyst_question="is this RNG correctly configured and sufficiently seeded at runtime?",
        function=anchor.func_name,
        addresses=(anchor.call_addr,),
        operand=operand,
    )


def verification_outcome_indicators(program, decomp, monitor, resolved_names=None) -> list[Indicator]:
    """Flag verification results that do not reach a branch or function return."""
    from ghidra.program.model.pcode import PcodeOp
    from .taint.anchors import VERIFY_FUNCTIONS, callee_name

    indicators = []
    for function in program.getFunctionManager().getFunctions(True):
        if function.isThunk() or function.isExternal():
            continue
        result = decomp.decompileFunction(function, 60, monitor)
        if not result.decompileCompleted() or result.getHighFunction() is None:
            continue
        for op in result.getHighFunction().getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL or not op.getNumInputs():
                continue
            callee = callee_name(program, op.getInput(0), resolved_names)
            if callee not in VERIFY_FUNCTIONS or _reaches_enforcement(op.getOutput()):
                continue
            address = str(op.getSeqnum().getTarget())
            indicators.append(Indicator(
                tier="INDICATOR",
                primitive=_verification_primitive(callee),
                pattern=f"{callee} result has no observed enforcement in function scope",
                analyst_question="is the signature-verification result enforced by the caller or elsewhere?",
                function=str(function.getName()),
                addresses=(address,),
                operand="return_value",
            ))
    return indicators


def _reaches_enforcement(value, seen=None) -> bool:
    from ghidra.program.model.pcode import PcodeOp

    if value is None:
        return False
    seen = seen or set()
    key = str(value)
    if key in seen:
        return False
    seen.add(key)
    for op in value.getDescendants():
        if op.getOpcode() in {PcodeOp.CBRANCH, PcodeOp.RETURN}:
            return True
        output = op.getOutput()
        if output is not None and _reaches_enforcement(output, seen):
            return True
    return False


def _verification_primitive(callee: str) -> str:
    if callee.startswith("RSA_"):
        return "RSA"
    if callee.startswith("ECDSA_"):
        return "ECC"
    return "SIGNATURE"
