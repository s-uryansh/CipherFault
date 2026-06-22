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
    taint: str | None = None

@dataclass
class LiftedFunction:
    name: str
    entry: str
    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    cfg: nx.DiGraph = field(default_factory=nx.DiGraph)