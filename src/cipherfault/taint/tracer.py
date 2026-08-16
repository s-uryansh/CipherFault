"""
Trace an operand varnode backward through SSA def-use chains to its origin.
Intra-procedural + bounded inter-procedural hop along resolved call edges..
"""

from dataclasses import dataclass, field

MAX_INTERPROCEDURAL_HOPS = 3

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


def weak_source_reaching_pointer(
    pointer,
    high,
    program,
    resolved_names=None,
    decomp=None,
    monitor=None,
    max_ip=MAX_INTERPROCEDURAL_HOPS,
    seen=None,
    before_address=None,
):
    """Return provenance when a weak-source value is stored into pointer's buffer."""
    from ghidra.program.model.pcode import PcodeOp
    from .anchors import WEAK_RANDOM_SOURCES, callee_name

    target_bases = _pointer_bases(pointer, set())
    if not target_bases:
        return None

    matches = []
    for op in high.getPcodeOps():
        if op.getOpcode() != PcodeOp.STORE or op.getNumInputs() < 3:
            continue
        if not _before(op, before_address):
            continue
        store_pointer = op.getInput(1)
        if not target_bases.intersection(_pointer_bases(store_pointer, set())):
            continue
        matches.append(op)
    if matches:
        op = max(matches, key=_op_offset)
        store_pointer = op.getInput(1)
        source = _weak_source(op.getInput(2), program, set(), resolved_names)
        if source is not None:
            if _has_later_buffer_write(
                pointer, high, program, resolved_names, _op_offset(op), before_address
            ):
                return None
            path = ProvenancePath(terminal=WEAK_RANDOM_SOURCES[source], origin=source)
            path.add(Step("WEAK_RANDOM_SOURCE", source, str(op.getInput(2))))
            path.add(Step("STORE", str(op.getSeqnum().getTarget()), str(store_pointer)))
            path.add(Step("OPERAND", "stored value reaches operand buffer", str(pointer)))
            return path
    if decomp is None or max_ip <= 0:
        return None
    return _buffer_source_from_callers(
        pointer,
        high,
        program,
        decomp,
        monitor,
        resolved_names,
        max_ip,
        seen or set(),
        weak_source_reaching_pointer,
        before_address,
    )


def rng_source_reaching_pointer(
    pointer,
    high,
    program,
    resolved_names=None,
    decomp=None,
    monitor=None,
    max_ip=MAX_INTERPROCEDURAL_HOPS,
    seen=None,
    before_address=None,
):
    """Return provenance when a named RNG writes directly to an operand buffer."""
    from ghidra.program.model.pcode import PcodeOp
    from .anchors import RNG_SOURCES, callee_name

    target_bases = _pointer_bases(pointer, set())
    matches = []
    for op in high.getPcodeOps():
        if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 2:
            continue
        if not _before(op, before_address):
            continue
        source = callee_name(program, op.getInput(0), resolved_names)
        if source not in RNG_SOURCES or not target_bases.intersection(_pointer_bases(op.getInput(1), set())):
            continue
        matches.append((op, source))
    if matches:
        op, source = max(matches, key=lambda match: _op_offset(match[0]))
        if _has_later_buffer_write(
            pointer, high, program, resolved_names, _op_offset(op), before_address
        ):
            return None
        path = ProvenancePath(terminal="RNG", origin=source)
        path.add(Step("RNG_SOURCE", source, str(op.getInput(0))))
        path.add(Step("OPERAND", "RNG output reaches operand buffer", str(pointer)))
        return path
    if decomp is None or max_ip <= 0:
        return None
    return _buffer_source_from_callers(
        pointer,
        high,
        program,
        decomp,
        monitor,
        resolved_names,
        max_ip,
        seen or set(),
        rng_source_reaching_pointer,
        before_address,
    )


def _buffer_source_from_callers(
    pointer,
    high,
    program,
    decomp,
    monitor,
    resolved_names,
    max_ip,
    seen,
    finder,
    before_address,
):
    from ghidra.program.model.pcode import PcodeOp

    slots = _parameter_slots_reaching(pointer, high, set())
    if len(slots) != 1:
        return None
    slot = next(iter(slots))
    entry = high.getFunction().getEntryPoint()
    cycle_key = (str(entry), slot)
    if cycle_key in seen:
        return None
    seen.add(cycle_key)

    paths = []
    call_count = 0
    for ref in program.getReferenceManager().getReferencesTo(entry):
        if not ref.getReferenceType().isCall():
            continue
        caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
        if caller is None:
            return None
        call_count += 1
        result = decomp.decompileFunction(caller, 60, monitor)
        if not result.decompileCompleted() or result.getHighFunction() is None:
            return None
        caller_high = result.getHighFunction()
        matched = False
        for op in caller_high.getPcodeOps(ref.getFromAddress()):
            if op.getOpcode() != PcodeOp.CALL:
                continue
            matched = True
            arg_index = slot + 1
            if op.getNumInputs() <= arg_index:
                return None
            path = finder(
                op.getInput(arg_index),
                caller_high,
                program,
                resolved_names,
                decomp,
                monitor,
                max_ip - 1,
                set(seen),
                str(ref.getFromAddress()),
            )
            if path is None:
                return None
            path.steps.insert(0, Step(
                "PARAM_HOP",
                f"buffer source in {caller.getName()} @ {ref.getFromAddress()}, arg {slot}",
                str(op.getInput(arg_index)),
            ))
            paths.append(path)
        if not matched:
            return None
    origins = {(path.terminal, path.origin) for path in paths}
    return paths[0] if call_count and len(paths) == call_count and len(origins) == 1 else None


def _parameter_slots_reaching(vn, high, seen):
    from ghidra.program.model.pcode import PcodeOp

    key = str(vn)
    if key in seen:
        return set()
    seen.add(key)
    slot = _param_slot(vn, high)
    if slot is not None:
        return {slot}
    definition = vn.getDef()
    if definition is None or definition.getOpcode() not in {
        PcodeOp.COPY,
        PcodeOp.CAST,
        PcodeOp.INDIRECT,
        PcodeOp.MULTIEQUAL,
        PcodeOp.PTRADD,
        PcodeOp.PTRSUB,
    }:
        return set()
    slots = set()
    for index in range(definition.getNumInputs()):
        if definition.getOpcode() in {PcodeOp.PTRADD, PcodeOp.PTRSUB} and index > 0:
            continue
        slots.update(_parameter_slots_reaching(definition.getInput(index), high, seen))
    return slots


def copied_source_reaching_pointer(
    pointer, high, program, decomp, monitor, resolved_names=None, before_address=None
):
    """Trace the source of a resolved memcpy/memmove into an operand buffer."""
    from ghidra.program.model.pcode import PcodeOp
    from .anchors import callee_name

    target_bases = _pointer_bases(pointer, set())
    if not target_bases:
        return None
    matches = []
    for op in high.getPcodeOps():
        if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 3:
            continue
        if not _before(op, before_address):
            continue
        callee = callee_name(program, op.getInput(0), resolved_names)
        if callee not in {"memcpy", "memmove"}:
            continue
        if not target_bases.intersection(_pointer_bases(op.getInput(1), set())):
            continue
        matches.append(op)
    for op in sorted(matches, key=_op_offset, reverse=True):
        callee = callee_name(program, op.getInput(0), resolved_names)
        if _has_later_buffer_write(
            pointer, high, program, resolved_names, _op_offset(op), before_address
        ):
            return None
        path = trace_operand(op.getInput(2), high, program, decomp, monitor)
        if path.terminal not in {"CONST", "ADDR"}:
            continue
        path.steps.insert(0, Step("BUFFER_COPY", f"{callee} source reaches operand buffer", str(op.getInput(2))))
        return path
    return None


def constant_buffer_reaching_pointer(
    pointer, high, program, resolved_names=None, before_address=None, required_size=16
):
    """Prove a constant byte fill reaches the operand buffer."""
    from ghidra.program.model.pcode import PcodeOp
    from .anchors import callee_name

    target_bases = _pointer_bases(pointer, set())
    matches = []
    for op in high.getPcodeOps():
        if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 4:
            continue
        if not _before(op, before_address) or callee_name(
            program, op.getInput(0), resolved_names
        ) != "memset":
            continue
        if not target_bases.intersection(_pointer_bases(op.getInput(1), set())):
            continue
        value, size = op.getInput(2), op.getInput(3)
        if value.isConstant() and size.isConstant() and size.getOffset() >= required_size:
            matches.append(op)
    if not matches:
        return _constant_stack_writes_reaching_pointer(
            pointer, high, before_address, required_size
        )
    op = max(matches, key=_op_offset)
    if _has_later_buffer_write(
        pointer, high, program, resolved_names, _op_offset(op), before_address
    ):
        return None
    value, size = op.getInput(2), op.getInput(3)
    origin = f"memset({hex(value.getOffset() & 0xff)}, {size.getOffset()} bytes)"
    path = ProvenancePath(terminal="CONST", origin=origin)
    path.add(Step("CONST_BUFFER", origin, str(op.getInput(1))))
    path.add(Step("OPERAND", "constant-filled buffer reaches operand", str(pointer)))
    return path


def _constant_stack_writes_reaching_pointer(pointer, high, before_address, required_size):
    """Recognize memcpy/memset lowered by the compiler to stack assignments."""
    from ghidra.program.model.pcode import PcodeOp

    start = _stack_pointer_offset(pointer, set())
    if start is None:
        return None
    covered = set()
    evidence = []
    for op in high.getPcodeOps():
        if op.getOpcode() != PcodeOp.COPY or not _before(op, before_address):
            continue
        output = op.getOutput()
        span = _stack_span(output)
        if span is None:
            continue
        write_start, write_size = span
        overlap = range(max(start, write_start), min(start + required_size, write_start + write_size))
        overlap = set(overlap)
        if not overlap:
            continue
        value = op.getInput(0)
        if value.isConstant():
            covered.update(overlap)
            evidence.append(str(op.getSeqnum().getTarget()))
        else:
            covered.difference_update(overlap)
    if len(covered) != required_size:
        return None
    origin = f"constant stack writes ({required_size} bytes)"
    path = ProvenancePath(terminal="CONST", origin=origin)
    path.add(Step("CONST_BUFFER", origin, ", ".join(evidence)))
    path.add(Step("OPERAND", "constant-filled stack buffer reaches operand", str(pointer)))
    return path


def _has_later_buffer_write(
    pointer, high, program, resolved_names, after_offset, before_address
):
    from ghidra.program.model.pcode import PcodeOp
    from .anchors import RNG_SOURCES, callee_name

    target_bases = _pointer_bases(pointer, set())
    for op in high.getPcodeOps():
        offset = _op_offset(op)
        if offset <= after_offset or not _before(op, before_address):
            continue
        if op.getOpcode() == PcodeOp.COPY and _stack_write_overlaps(pointer, op.getOutput()):
            return True
        if op.getOpcode() == PcodeOp.STORE and op.getNumInputs() > 1:
            if target_bases.intersection(_pointer_bases(op.getInput(1), set())):
                return True
        if op.getOpcode() != PcodeOp.CALL:
            continue
        callee = callee_name(program, op.getInput(0), resolved_names)
        for index in range(1, op.getNumInputs()):
            if not target_bases.intersection(_pointer_bases(op.getInput(index), set())):
                continue
            if index == 1 or callee in RNG_SOURCES | {"memcpy", "memmove", "memset"}:
                return True
    return False


def _stack_write_overlaps(pointer, output, size=16):
    start = _stack_pointer_offset(pointer, set())
    span = _stack_span(output)
    if start is None or span is None:
        return False
    write_start, write_size = span
    return write_start < start + size and start < write_start + write_size


def _stack_span(vn):
    if vn is None:
        return None
    address = vn.getAddress()
    if not address.getAddressSpace().isStackSpace():
        return None
    return int(address.getOffset()), int(vn.getSize())


def _stack_pointer_offset(vn, seen):
    from ghidra.program.model.pcode import PcodeOp

    key = str(vn)
    if key in seen:
        return None
    seen.add(key)
    span = _stack_span(vn)
    if span is not None:
        return span[0]
    definition = vn.getDef()
    if definition is None:
        return None
    if definition.getOpcode() == PcodeOp.PTRSUB and definition.getNumInputs() > 1:
        offset = definition.getInput(1)
        return int(offset.getOffset()) if offset.isConstant() else None
    if definition.getOpcode() not in {PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT}:
        return None
    return _stack_pointer_offset(definition.getInput(0), seen)


def _op_offset(op):
    return int(op.getSeqnum().getTarget().getOffset())


def _before(op, address):
    if address is None:
        return True
    try:
        limit = int(address.getOffset())
    except AttributeError:
        limit = int(str(address), 16)
    return _op_offset(op) < limit


def _pointer_bases(vn, seen):
    from ghidra.program.model.pcode import PcodeOp

    key = str(vn)
    if key in seen:
        return set()
    seen.add(key)
    if vn.isAddress():
        return {("address", str(vn.getAddress()))}

    definition = vn.getDef()
    if definition is None:
        return {("input", key)}
    if definition.getOpcode() == PcodeOp.PTRSUB and definition.getNumInputs() > 1:
        base = definition.getInput(0)
        offset = definition.getInput(1)
        if offset.isConstant():
            return {(str(base), int(offset.getOffset()))}
    if definition.getOpcode() not in {
        PcodeOp.COPY,
        PcodeOp.CAST,
        PcodeOp.INDIRECT,
        PcodeOp.MULTIEQUAL,
        PcodeOp.PTRADD,
        PcodeOp.PTRSUB,
    }:
        return set()

    bases = set()
    for index in range(definition.getNumInputs()):
        value = definition.getInput(index)
        if definition.getOpcode() == PcodeOp.PTRADD and index > 0:
            continue
        if definition.getOpcode() == PcodeOp.PTRSUB and index > 0:
            continue
        bases.update(_pointer_bases(value, seen))
    return bases


def _weak_source(vn, program, seen, resolved_names=None):
    from ghidra.program.model.pcode import PcodeOp
    from .anchors import WEAK_RANDOM_SOURCES, callee_name

    key = str(vn)
    if key in seen:
        return None
    seen.add(key)
    definition = vn.getDef()
    if definition is None:
        return None
    if definition.getOpcode() == PcodeOp.CALL and definition.getNumInputs():
        name = callee_name(program, definition.getInput(0), resolved_names)
        return name if name in WEAK_RANDOM_SOURCES else None
    if definition.getOpcode() in (PcodeOp.CALLIND, PcodeOp.INDIRECT):
        return None
    for index in range(definition.getNumInputs()):
        source = _weak_source(definition.getInput(index), program, seen, resolved_names)
        if source is not None:
            return source
    return None

def trace_operand(vn, high, program, decomp, monitor, max_ip=MAX_INTERPROCEDURAL_HOPS):
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

    # Register and unique-space varnode names repeat in every function.  Scope
    # cycle detection to the high function so an inter-procedural hop cannot
    # mistake the callee's return register for the caller's register.
    key = f"{high.getFunction().getEntryPoint()}:{vn}"
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
            if _hop_to_callers(high, slot, program, decomp, monitor, max_ip, seen, path):
                return
        path.add(Step("INPUT", "no def (arg/uninit, ambiguous callers, or depth exhausted)", key))
        path.terminal = "INPUT"
        return

    path.add(Step("OP", d.getMnemonic(), key))
    if d.getOpcode() == PcodeOp.CALL:
        if max_ip > 0 and _hop_to_return(d, program, decomp, monitor, max_ip, seen, path):
            return
        path.add(Step("CUT", "value from unresolved CALL", key))
        path.terminal = "CALL"
        return
    if d.getOpcode() in (PcodeOp.CALLIND, PcodeOp.INDIRECT):
        path.add(Step("CUT", f"value from {d.getMnemonic()}", key))
        path.terminal = "INDIRECT"
        return
    if d.getOpcode() in {PcodeOp.COPY, PcodeOp.CAST} and d.getNumInputs():
        _walk(d.getInput(0), high, program, decomp, monitor, max_ip, seen, path)
        return
    if d.getOpcode() == PcodeOp.PTRSUB and d.getNumInputs() > 1:
        base, offset = d.getInput(0), d.getInput(1)
        if base.isConstant() and base.getOffset() == 0 and offset.isConstant():
            _walk(offset, high, program, decomp, monitor, max_ip, seen, path)
            return
        path.add(Step("CUT", "non-static PTRSUB base", key))
        path.terminal = "POINTER"
        return
    if d.getOpcode() == PcodeOp.MULTIEQUAL:
        if _walk_unanimous(d, high, program, decomp, monitor, max_ip, seen, path):
            return
        path.add(Step("CUT", "ambiguous MULTIEQUAL origins", key))
        path.terminal = "INPUT"
        return
    path.add(Step("CUT", f"unsupported value transform {d.getMnemonic()}", key))
    path.terminal = "MEMORY" if d.getOpcode() == PcodeOp.LOAD else "TRANSFORM"


def _walk_unanimous(op, high, program, decomp, monitor, max_ip, seen, path):
    candidates = []
    for index in range(op.getNumInputs()):
        candidate = ProvenancePath()
        _walk(
            op.getInput(index),
            high,
            program,
            decomp,
            monitor,
            max_ip,
            set(seen),
            candidate,
        )
        candidates.append(candidate)
    origins = {(candidate.terminal, candidate.origin) for candidate in candidates}
    if len(origins) != 1 or next(iter(origins))[0] in {
        None,
        "INPUT",
        "CALL",
        "INDIRECT",
        "MEMORY",
        "POINTER",
        "TRANSFORM",
    }:
        return False
    candidate = candidates[0]
    path.steps.extend(candidate.steps)
    path.terminal, path.origin = candidate.terminal, candidate.origin
    return True


def _hop_to_return(call, program, decomp, monitor, max_ip, seen, path):
    from ghidra.program.model.pcode import PcodeOp

    if not call.getNumInputs() or not call.getInput(0).isAddress():
        return False
    callee = program.getFunctionManager().getFunctionAt(call.getInput(0).getAddress())
    if callee is None or callee.isExternal():
        return False
    result = decomp.decompileFunction(callee, 60, monitor)
    if not result.decompileCompleted() or result.getHighFunction() is None:
        return False
    callee_high = result.getHighFunction()
    traced = []
    for op in callee_high.getPcodeOps():
        if op.getOpcode() != PcodeOp.RETURN or op.getNumInputs() < 2:
            continue
        candidate = ProvenancePath()
        _walk(op.getInput(1), callee_high, program, decomp, monitor, max_ip - 1, set(seen), candidate)
        traced.append(candidate)
    origins = {(candidate.terminal, candidate.origin) for candidate in traced}
    if len(origins) != 1 or next(iter(origins))[0] in {None, "INPUT", "CALL", "INDIRECT"}:
        return False
    candidate = traced[0]
    path.add(Step("RETURN_HOP", f"return from {callee.getName()}", str(call.getOutput())))
    path.steps.extend(candidate.steps)
    path.terminal, path.origin = candidate.terminal, candidate.origin
    return True


def _hop_to_callers(callee_high, slot, program, decomp, monitor, max_ip, seen, path):
    from ghidra.program.model.pcode import PcodeOp

    callee_fn = callee_high.getFunction()
    entry = callee_fn.getEntryPoint()
    ref_mgr = program.getReferenceManager()

    candidates = []
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
                unresolved = ProvenancePath(terminal="INPUT")
                unresolved.add(Step(
                    "CUT",
                    f"caller operand {slot} not recovered in {caller_fn.getName()} @ {call_addr}",
                    "",
                ))
                candidates.append(unresolved)
                continue
            arg_vn = op.getInput(arg_idx)
            candidate = ProvenancePath()
            candidate.add(Step(
                "PARAM_HOP",
                f"hop into {caller_fn.getName()} @ {call_addr}, arg {slot}",
                str(arg_vn),
            ))
            _walk(
                arg_vn,
                caller_high,
                program,
                decomp,
                monitor,
                max_ip - 1,
                set(seen),
                candidate,
            )
            candidates.append(candidate)

    origins = {(candidate.terminal, candidate.origin) for candidate in candidates}
    if len(origins) != 1 or next(iter(origins))[0] in {None, "INPUT", "CALL", "INDIRECT"}:
        return False
    candidate = candidates[0]
    path.steps.extend(candidate.steps)
    path.terminal, path.origin = candidate.terminal, candidate.origin
    return True
