"""
Lift every function in a binary into LiftedFunction objects.
No symbol dependency: iterates all functions, named or FUN_xxx.
"""

from .types import BasicBlock, LiftedFunction
from ..ghidra import analyzed_program

def lift_binary(binary_path: str) -> list[LiftedFunction]:
    results: list[LiftedFunction] = []

    with analyzed_program(binary_path) as (program, monitor):
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.block import BasicBlockModel

        fm = program.getFunctionManager()
        listing = program.getListing()
        bbm = BasicBlockModel(program)
        decomp = DecompInterface()
        decomp.openProgram(program)

        for f in fm.getFunctions(True):
            if f.isThunk() or f.isExternal():
                continue
            lf = LiftedFunction(
                name=str(f.getName()),
                entry=str(f.getEntryPoint()),
                image_base=int(program.getImageBase().getOffset()),
            )

            body = f.getBody()
            block_iter = bbm.getCodeBlocksContaining(body, monitor)
            while block_iter.hasNext():
                block = block_iter.next()
                block_addr = str(block.getFirstStartAddress())

                # extract instructions in this block
                instrs: list[str] = []
                instr_addrs: list[str] = []
                pcode_ops: list[str] = []
                instr_iter = listing.getInstructions(block, True)
                while instr_iter.hasNext():
                    instr = instr_iter.next()
                    instrs.append(str(instr.toString()))
                    instr_addrs.append(str(instr.getAddress()))
                    pcode_ops.extend(str(op.getMnemonic()) for op in instr.getPcode())

                lf.blocks[block_addr] = BasicBlock(
                    address=block_addr,
                    instructions=instrs,
                    instruction_addresses=instr_addrs,
                    pcode_ops=pcode_ops,
                )
                lf.cfg.add_node(block_addr)
                lf.dfg.add_node(block_addr)

                # CFG
                dests = block.getDestinations(monitor)
                while dests.hasNext():
                    d = dests.next()
                    dest_start = d.getDestinationBlock().getFirstStartAddress()
                    if body.contains(dest_start):
                        lf.cfg.add_edge(block_addr, str(dest_start))
            _add_data_dependencies(lf, f, body, bbm, decomp, monitor)
            results.append(lf)
        return results


def _add_data_dependencies(lf, function, body, bbm, decomp, monitor):
    result = decomp.decompileFunction(function, 60, monitor)
    if not result.decompileCompleted() or result.getHighFunction() is None:
        return

    for op in result.getHighFunction().getPcodeOps():
        destination = _block_at(bbm, op.getSeqnum().getTarget(), body, monitor)
        if destination is None:
            continue
        for index in range(op.getNumInputs()):
            definition = op.getInput(index).getDef()
            if definition is None:
                continue
            source = _block_at(bbm, definition.getSeqnum().getTarget(), body, monitor)
            if source is not None and source != destination:
                lf.dfg.add_edge(source, destination)


def _block_at(bbm, address, body, monitor):
    block = bbm.getFirstCodeBlockContaining(address, monitor)
    if block is None or not body.contains(block.getFirstStartAddress()):
        return None
    return str(block.getFirstStartAddress())
