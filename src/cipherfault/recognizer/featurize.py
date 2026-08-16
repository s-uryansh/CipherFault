"""Turn normalized P-code regions into PyTorch Geometric graphs."""

from hashlib import blake2b
from pathlib import Path
import re
from typing import Callable

import numpy as np
import torch
from elftools.elf.elffile import ELFFile
from torch_geometric.data import Data
from ..lifting.types import LiftedFunction

VOCAB = [
    "COPY", "LOAD", "STORE", "BRANCH", "CBRANCH", "BRANCHIND", "CALL",
    "CALLIND", "RETURN", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS",
    "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "INT_ZEXT", "INT_SEXT",
    "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "INT_2COMP", "INT_NEGATE", "INT_XOR", "INT_AND", "INT_OR", "INT_LEFT",
    "INT_RIGHT", "INT_SRIGHT", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM",
    "INT_SREM", "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "FLOAT_ADD",
    "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "PIECE", "SUBPIECE", "CAST",
    "PTRADD", "PTRSUB", "MULTIEQUAL", "INDIRECT", "CALLOTHER",
    "AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC",
    "AESKEYGENASSIST", "VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST",
]
VOCAB_INDEX = {m: i for i, m in enumerate(VOCAB)}
SEMANTIC_BINS = 128
_NUMBER = re.compile(r"(?<![A-Za-z_])(?:0x[0-9a-f]+|\d+)", re.IGNORECASE)
_REGISTER = re.compile(
    r"\b(?:R(?:AX|BX|CX|DX|SI|DI|SP|BP|IP|[0-9]+)|E(?:AX|BX|CX|DX|SI|DI|SP|BP|IP)|"
    r"(?:[ABCD][HL])|(?:[XYZ]MM\d+)|(?:ST\d+))\b",
    re.IGNORECASE,
)

# instruction string looks like "MOV RBP, RSP"
# mnemonic is the first token
def _mnemonic(instr_str: str) -> str:
    return instr_str.strip().split()[0].upper() if instr_str.strip() else ""

class ReadOnlyMemory:
    def __init__(self, binary: str | Path):
        with Path(binary).open("rb") as stream:
            elf = ELFFile(stream)
            self.minimum_load_address = min(
                segment["p_vaddr"] for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            )
            self.sections = [
                (section["sh_addr"], section.data())
                for section in elf.iter_sections()
                if section["sh_flags"] & 2 and not section["sh_flags"] & (1 | 4)
            ]

    def read(self, address: int, size: int = 32) -> bytes | None:
        for start, data in self.sections:
            offset = address - start
            if 0 <= offset < len(data):
                return data[offset:offset + size]
        return None

    def image_bias(self, program_image_base: int) -> int:
        return program_image_base - self.minimum_load_address


def block_features(
    pcode_ops: list[str],
    instructions: list[str],
    read_constant: Callable[[int], bytes | None] | None = None,
    image_bias: int = 0,
) -> list[float]:
    vec = [0.0] * (len(VOCAB) + SEMANTIC_BINS)
    for ins in [*pcode_ops, *instructions]:
        m = _mnemonic(ins)
        if m in VOCAB_INDEX:
            vec[VOCAB_INDEX[m]] += 1.0
    semantic = [_mnemonic(instruction) for instruction in instructions if _mnemonic(instruction)]
    for mnemonic in semantic:
        _add_hashed(vec, f"ins:{mnemonic}")
    for left, right in zip(semantic, semantic[1:]):
        _add_hashed(vec, f"pair:{left}>{right}")
    for instruction in instructions:
        shape = _NUMBER.sub("<IMM>", _REGISTER.sub("<REG>", instruction.upper()))
        _add_hashed(vec, f"shape:{shape}")
        for number in _NUMBER.findall(instruction):
            value = int(number, 0)
            if value <= 0xFFFF:
                _add_hashed(vec, f"imm:{value}")
            elif read_constant and (content := read_constant(value - image_bias)):
                for offset in range(0, len(content), 4):
                    _add_hashed(vec, f"ro:{content[offset:offset + 4].hex()}")
    for left, right in zip(pcode_ops, pcode_ops[1:]):
        _add_hashed(vec, f"pcode:{left}>{right}")
    return vec


def _add_hashed(vec: list[float], token: str) -> None:
    bucket = int.from_bytes(blake2b(token.encode(), digest_size=8).digest(), "big") % SEMANTIC_BINS
    vec[len(VOCAB) + bucket] += 1.0

def region_to_data(
    lf: LiftedFunction,
    region: set[str],
    label: int,
    read_constant: Callable[[int], bytes | None] | None = None,
    image_bias: int = 0,
) -> Data:
    # stabel ordering -> node indices are deterministic
    nodes = sorted(region)
    idx = {addr: i for i, addr in enumerate(nodes)}

    x = torch.tensor([block_features(
        lf.blocks[a].pcode_ops, lf.blocks[a].instructions, read_constant, image_bias
    ) for a in nodes],
                    dtype=torch.float)
    src, dst, edge_types = [], [], []
    for edge_type, graph in enumerate((lf.cfg, lf.dfg)):
        for a in nodes:
            if a not in graph:
                continue
            for b in graph.successors(a):
                if b in idx:
                    src.append(idx[a])
                    dst.append(idx[b])
                    edge_types.append(edge_type)
    edge_index = torch.tensor([src, dst], dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        edge_type=torch.tensor(edge_types, dtype=torch.long),
        y=torch.tensor([label], dtype=torch.long),
    )


def graph_summary(graph) -> np.ndarray:
    present = (graph.x > 0).float()
    structure = torch.tensor([
        graph.num_nodes, graph.edge_index.shape[1],
        int((graph.edge_type == 0).sum()), int((graph.edge_type == 1).sum()),
    ])
    return torch.cat((
        present.mean(dim=0), present.max(dim=0).values,
        torch.log1p(present.sum(dim=0)), structure,
    )).numpy()
