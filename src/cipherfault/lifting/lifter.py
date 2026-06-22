"""
Lift every function in a binary into LiftedFunction objects.
No symbol dependency: iterates all functions, named or FUN_xxx.
"""

import pyghidra
from .types import BasicBlock, LiftedFunction

pyghidra.start()

def lift_binary(binary_path: str) -> list[LiftedFunction]:
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    results: list[LiftedFunction] = []

    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        listing = program.getListing()
        bbm = BasicBlockModel(program)
        monitor = ConsoleTaskMonitor()

        for f in fm.getFunctions(True):
            if f.isThunk() or f.isExternal():
                continue
            lf = LiftedFunction(
                name=str(f.getName()),
                entry=str(f.getEntryPoint()),
            )

            body = f.getBody()
            block_iter = bbm.getCodeBlocksContaining(body, monitor)
            while block_iter.hasNext():
                block = block_iter.next()
                block_addr = str(block.getFirstStartAddress())

                # extract instructions in this block
                instrs: list[str] = []
                instr_iter = listing.getInstructions(block, True)
                while instr_iter.hasNext():
                    instr = instr_iter.next()
                    instrs.append(str(instr.toString()))

                lf.blocks[block_addr] = BasicBlock(address=block_addr, instructions=instrs)
                lf.cfg.add_node(block_addr)

                # CFG
                dests = block.getDestinations(monitor)
                while dests.hasNext():
                    d = dests.next()
                    dest_start = d.getDestinationBlock().getFirstStartAddress()
                    if body.contains(dest_start):
                        lf.cfg.add_edge(block_addr, str(dest_start))
            results.append(lf)
        return results