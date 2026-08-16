"""
Data structures for lifted functions. Plain dataclasses, no Ghidra imports.
So the rest of package can consume these without booting a JVM
"""

from dataclasses import dataclass, field
import networkx as nx

@dataclass
class BasicBlock:
    address: str
    instructions: list[str]
    pcode_ops: list[str] = field(default_factory=list)
    taint: str | None = None
    instruction_addresses: list[str] = field(default_factory=list)

@dataclass
class LiftedFunction:
    name: str
    entry: str
    image_base: int = 0
    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    cfg: nx.DiGraph = field(default_factory=nx.DiGraph)
    dfg: nx.DiGraph = field(default_factory=nx.DiGraph)
