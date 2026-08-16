"""Extract loop-centered sub-function recognition regions."""

import networkx as nx
from ..lifting.types import LiftedFunction

def extract_regions(lf: LiftedFunction) -> list[set[str]]:
    """Return each loop SCC with its immediate CFG setup/exit context."""
    regions: set[frozenset[str]] = set()

    for scc in nx.strongly_connected_components(lf.cfg):
        if len(scc) == 1:
            (node,) = tuple(scc)
            if not lf.cfg.has_edge(node, node):
                continue
        region = set(scc)
        for node in scc:
            region.update(lf.cfg.predecessors(node))
            region.update(lf.cfg.successors(node))
        regions.add(frozenset(region))
    return [set(region) for region in sorted(regions, key=lambda item: tuple(sorted(item)))]
