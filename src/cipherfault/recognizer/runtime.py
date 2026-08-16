"""Load the gated recognizer and classify deployment-shaped binary regions."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import torch
from torch_geometric.loader import DataLoader

from ..lifting.lifter import lift_binary
from ..regions.extractor import extract_regions
from ..report import PrimitiveEvidence
from .featurize import ReadOnlyMemory, graph_summary, region_to_data
from .model import PrimitiveGraphSAGE


SEMANTIC_VETO_THRESHOLD = 0.95


def default_model_path() -> Path:
    candidates = (
        Path(__file__).resolve().parents[3] / "models" / "recognizer.pt",
        Path.cwd() / "models" / "recognizer.pt",
    )
    return next((path for path in candidates if path.exists()), candidates[0])


def recognize_binary(binary: str | Path) -> tuple[list[PrimitiveEvidence], list[PrimitiveEvidence]]:
    model_path = default_model_path()
    semantic_path = model_path.with_suffix(".semantic.joblib")
    if not model_path.exists() or not semantic_path.exists():
        return [], []

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    labels = checkpoint.get("labels", {0: "AES", 1: "ML-KEM", 2: "none"})
    none_id = next(label for label, name in labels.items() if name == "none")
    model = PrimitiveGraphSAGE(checkpoint["input_dim"], classes=checkpoint.get("classes", len(labels)))
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()
    semantic_head = joblib.load(semantic_path)
    memory = ReadOnlyMemory(binary)
    graphs = []
    for function in lift_binary(str(binary)):
        bias = memory.image_bias(function.image_base)
        for region in extract_regions(function):
            if sum(len(function.blocks[address].instructions) for address in region) < 5:
                continue
            graph = region_to_data(function, region, none_id, memory.read, bias)
            graph.address = min(region)
            graphs.append(graph)
    if not graphs:
        return [], []

    logits = []
    with torch.no_grad():
        for batch in DataLoader(graphs, batch_size=64):
            logits.append(model(batch.x, batch.edge_index, batch.edge_type, batch.batch))
    probabilities = (torch.cat(logits) / checkpoint["temperature"]).softmax(dim=1)
    semantic = semantic_head.predict_proba(np.stack([graph_summary(graph) for graph in graphs]))
    thresholds = checkpoint["thresholds"]
    asserted, candidates = [], []
    for graph, scores, corroboration in zip(graphs, probabilities, semantic):
        score, primitive_id = scores[:none_id].max(dim=0)
        primitive_id = int(primitive_id)
        evidence = PrimitiveEvidence(
            primitive=labels[primitive_id],
            address=graph.address,
            method="gnn-semantic-ensemble",
            confidence=float(min(score, corroboration[primitive_id])),
        )
        if float(score) >= thresholds[primitive_id] and corroboration[primitive_id] >= SEMANTIC_VETO_THRESHOLD:
            asserted.append(evidence)
        elif float(score) >= 0.5:
            candidates.append(evidence)
    return asserted, candidates
