import sys
sys.path.insert(0, "src")
from cipherfault.lifting.lifter import lift_binary

funcs = lift_binary(sys.argv[1])
print(f"[+] lifted {len(funcs)} functions")

for lf in funcs:
    total_instrs = sum(len(b.instructions) for b in lf.blocks.values())
    print(f"    {lf.name:24} {lf.cfg.number_of_nodes():3} blocks    "
        f"{lf.cfg.number_of_edges():3} edges {total_instrs:4} instrs")