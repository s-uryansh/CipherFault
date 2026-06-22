"""
Turn a region (set of block addresses) into a PyTorch Geometric graph.
V1 dumb featurization: per-block mnemonic counts over a fixed vocabulary.
"""

import torch
from torch_geometric.data import Data
from ..lifting.types import LiftedFunction

VOCAB = ["MOV", "XOR", "AND", "OR", "SHL", "SHR", "ROL", "ROR",
        "ADD", "SUB", "LEA", "CMP", "TEST", "JMP", "CALL", "PUSH", "POP"
        ]
VOCAB_INDEX = {m: i for i, m in enumerate(VOCAB)}

# instruction string looks like "MOV RBP, RSP"
# mnemonic is the first token
def _mnemonic(instr_str: str) -> str:
    return instr_str.strip().split()[0].upper() if instr_str.strip() else ""

def block_features(instructions: list[str]) -> list[float]:
    vec = [0.0] * len(VOCAB)
    for ins in instructions:
        m = _mnemonic(ins)
        if m in VOCAB_INDEX:
            vec[VOCAB_INDEX[m]] += 1.0
    return vec

def region_to_data(lf: LiftedFunction, region: set[str], label: int) -> Data:
    # stabel ordering -> node indices are deterministic
    nodes = sorted(region)
    idx = {addr: i for i, addr in enumerate(nodes)}

    x = torch.tensor([block_features(lf.blocks[a].instructions) for a in nodes],
                    dtype=torch.float)
    src, dst = [], []
    for a in nodes:
        for b in lf.cfg.successors(a):
            if b in idx:
                src.append(idx[a])
                dst.append(idx[b])
    edge_index = torch.tensor([src, dst], dtype=torch.long)

    return Data(x=x, edge_index=edge_index, y=torch.tensor([label], dtype=torch.long))