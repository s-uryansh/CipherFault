"""
Partition a function's CFG into candidate regions (one ~= one primitive)
Structure-based: each non trivial loop (SCC) becomes a region
"""

import networkx as nx
from ..lifting.types import LiftedFunction

def extract_regions(lf: LiftedFunction) -> list[set[str]]:
    """
    Returns a list of regions; each region is a set of block addresses.
    """
    regions: list[set[str]] = []

    for scc in nx.strongly_connected_components(lf.cfg):
        if len(scc) > 1:
            regions.append(set(scc))
        else:
            (node,) = tuple(scc)
            if node in lf.cfg.successors(node):
                regions.append({node})
    return regions