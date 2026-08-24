"""Load the gated recognizer and classify deployment-shaped binary regions."""

from __future__ import annotations

import os
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
    if configured := os.environ.get("CIPHERFAULT_RECOGNIZER_MODEL"):
        return Path(configured)
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
    semantic_thresholds = checkpoint.get("semantic_thresholds", {})
    deployable = _deployable_label_ids(checkpoint, none_id)
    asserted, candidates = [], []
    for graph, scores, corroboration in zip(graphs, probabilities, semantic):
        primitive_id, score, method = _recognized_label(
            scores, corroboration, thresholds, semantic_thresholds, deployable, none_id
        )
        if primitive_id is None:
            continue
        evidence = PrimitiveEvidence(
            primitive=labels[primitive_id],
            address=graph.address,
            method=method,
            confidence=float(score),
        )
        if method != "candidate":
            asserted.append(evidence)
        else:
            candidates.append(evidence)
    return asserted, candidates


def _deployable_label_ids(checkpoint: dict, none_id: int) -> set[int]:
    return set(checkpoint.get("deployable_label_ids", range(none_id)))


def _recognized_label(scores, corroboration, thresholds, semantic_thresholds, deployable, none_id):
    best = None
    for primitive_id in sorted(deployable):
        if primitive_id >= none_id:
            continue
        gnn_score = float(scores[primitive_id])
        semantic_score = float(corroboration[primitive_id])
        if gnn_score >= thresholds[primitive_id] and semantic_score >= SEMANTIC_VETO_THRESHOLD:
            confidence = min(gnn_score, semantic_score)
            if best is None or confidence > best[1]:
                best = (primitive_id, confidence, "gnn-semantic-ensemble")
        elif semantic_score >= semantic_thresholds.get(primitive_id, 1.1):
            if best is None or semantic_score > best[1]:
                best = (primitive_id, semantic_score, "semantic-head")
        elif gnn_score >= 0.5 or semantic_score >= 0.5:
            confidence = max(gnn_score, semantic_score)
            if best is None or confidence > best[1]:
                best = (primitive_id, confidence, "candidate")
    return best or (None, 0.0, "candidate")
