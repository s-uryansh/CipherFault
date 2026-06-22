#!/usr/bin/env python3
"""CFG spike: lift one function via Ghidra (pyghidra), build CFG in NetworkX."""
import sys
import pyghidra

pyghidra.start()


def build_cfg(binary_path: str, func_name: str):
    import networkx as nx
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor
    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()
        target = None
        for f in fm.getFunctions(True):
            if str(f.getName()) == func_name:
                target = f
                break
        if target is None:
            names = sorted(str(f.getName()) for f in fm.getFunctions(True))
            raise SystemExit(
                f"function {func_name!r} not found. "
                f"available (first 40): {names[:40]}"
            )
        print(f"[+] found {func_name} @ {target.getEntryPoint()}")
        bbm = BasicBlockModel(program)
        monitor = ConsoleTaskMonitor()
        body = target.getBody()
        g = nx.DiGraph()
        block_iter = bbm.getCodeBlocksContaining(body, monitor)
        while block_iter.hasNext():
            block = block_iter.next()
            node_id = str(block.getFirstStartAddress())
            g.add_node(node_id, name=str(block.getName()))
            dests = block.getDestinations(monitor)
            while dests.hasNext():
                d = dests.next()
                dest_start = d.getDestinationBlock().getFirstStartAddress()
                if body.contains(dest_start):
                    g.add_edge(node_id, str(dest_start))
        return g


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract_cfg.py <binary> <function_name>")
    g = build_cfg(sys.argv[1], sys.argv[2])
    print(f"[+] CFG: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    for n in g.nodes(data=True):
        print("    node:", n)
    for e in g.edges():
        print("    edge:", e)


if __name__ == "__main__":
    main()
