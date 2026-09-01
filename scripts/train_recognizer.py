#!/usr/bin/env python3
"""Train and gate the classical/PQC primitive region recognizer."""

from __future__ import annotations

import collections
import argparse
import json
import random
import sys
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.ensemble import ExtraTreesClassifier
from torch_geometric.loader import DataLoader
from torch.utils.data import WeightedRandomSampler

sys.path.insert(0, "src")

from cipherfault.recognizer.model import PrimitiveGraphSAGE
from cipherfault.recognizer.featurize import graph_summary
from cipherfault.recognizer.name_head import name_probabilities


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"
LABELS = {0: "AES", 1: "RSA", 2: "ECC", 3: "SHA", 4: "ML-KEM", 5: "ML-DSA", 6: "SLH-DSA", 7: "none"}
NONE_ID = 7
PRIMITIVE_IDS = tuple(range(NONE_ID))
VALIDATION_SOURCES = {
    "tiny-AES-c", "mbedtls", "bearssl", "PQClean", "zlib",
    "bearssl-rsa", "bearssl-ecc", "bearssl-sha", "PQClean-ML-DSA", "PQClean-SLH-DSA",
}
TEST_SOURCES = {
    "libsodium", "boringssl-aes", "liboqs", "libpng",
    "boringssl-rsa", "boringssl-ecc", "boringssl-sha", "liboqs-ML-DSA", "liboqs-SLH-DSA",
}
MIN_SUPPORT = {**{label: 100 for label in PRIMITIVE_IDS}, NONE_ID: 1000}
CALIBRATION_PRECISION = 0.95
SLICE_MIN_SUPPORT = 30
SEMANTIC_VETO_THRESHOLD = 0.95
SEED = 17


def source_balanced_weights(dataset) -> list[float]:
    counts = collections.Counter((graph.source, int(graph.y.item())) for graph in dataset)
    return [1.0 / counts[(graph.source, int(graph.y.item()))] for graph in dataset]


def ensemble_predictions(gnn_probabilities, semantic_probabilities, thresholds):
    predicted = predictions(gnn_probabilities, thresholds)
    for index, primitive in enumerate(predicted):
        if primitive == NONE_ID or semantic_probabilities[index, primitive] < SEMANTIC_VETO_THRESHOLD:
            predicted[index] = NONE_ID
    return predicted


def combined_predictions(
    gnn_probabilities,
    semantic_probabilities,
    gnn_thresholds,
    semantic_thresholds,
    name_probabilities_=None,
    name_thresholds=None,
):
    name_thresholds = name_thresholds or {}
    name_gated = {
        primitive
        for primitive, threshold in name_thresholds.items()
        if primitive in PRIMITIVE_IDS and threshold <= 1.0
    }
    predicted = ensemble_predictions(gnn_probabilities, semantic_probabilities, gnn_thresholds)
    if name_probabilities_ is not None:
        for index, primitive in enumerate(predicted):
            primitive = int(primitive)
            if primitive in name_gated and float(name_probabilities_[index, primitive]) < name_thresholds[primitive]:
                predicted[index] = NONE_ID
    semantic_predicted = predictions(semantic_probabilities, semantic_thresholds)
    for index, primitive in enumerate(semantic_predicted):
        primitive = int(primitive)
        if predicted[index] == NONE_ID and primitive != NONE_ID:
            if primitive in name_gated and (
                name_probabilities_ is None
                or float(name_probabilities_[index, primitive]) < name_thresholds[primitive]
            ):
                continue
            predicted[index] = primitive
    if name_probabilities_ is not None:
        for index, row in enumerate(name_probabilities_):
            for primitive in PRIMITIVE_IDS:
                if float(row[primitive]) >= name_thresholds.get(primitive, 1.1):
                    predicted[index] = primitive
                    break
    return predicted


def scores(model, dataset, device, batch_size=64):
    logits, labels = [], []
    model.eval()
    with torch.no_grad():
        for batch in DataLoader(dataset, batch_size=batch_size):
            batch = batch.to(device)
            logits.append(model(batch.x, batch.edge_index, batch.edge_type, batch.batch).cpu())
            labels.append(batch.y.cpu())
    return torch.cat(logits), torch.cat(labels)


def training_device(requested: str) -> torch.device:
    if requested == "auto":
        requested = "cuda" if torch.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch.cuda.is_available():
        raise SystemExit("CUDA requested but torch.cuda.is_available() is false")
    return torch.device(requested)


def calibrate_temperature(logits, labels) -> float:
    log_temperature = torch.zeros(1, requires_grad=True)
    optimizer = torch.optim.LBFGS([log_temperature], lr=0.1, max_iter=50)

    def closure():
        optimizer.zero_grad()
        loss = F.cross_entropy(logits / log_temperature.exp(), labels)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(log_temperature.exp().detach().clamp(0.05, 20.0).item())


def choose_threshold(probabilities, labels, primitive: int, semantic_probabilities=None) -> float:
    candidates = sorted(set(float(value) for value in probabilities[:, primitive]), reverse=True)
    best = 1.1
    for threshold in candidates:
        asserted = probabilities[:, primitive] >= threshold
        if semantic_probabilities is not None:
            asserted &= semantic_probabilities[:, primitive] >= SEMANTIC_VETO_THRESHOLD
        count = int(asserted.sum())
        if count and float((labels[asserted] == primitive).float().mean()) >= CALIBRATION_PRECISION:
            best = threshold
    return best


def predictions(probabilities, thresholds):
    primitive_scores, primitive_ids = probabilities[:, :NONE_ID].max(dim=1)
    return torch.tensor([
        int(primitive) if float(score) >= thresholds[int(primitive)] else NONE_ID
        for score, primitive in zip(primitive_scores, primitive_ids)
    ])


def metrics(labels, predicted):
    result = {"support": {}, "asserted": {}, "precision": {}, "recall": {}}
    for label, name in LABELS.items():
        actual = labels == label
        asserted = predicted == label
        tp = int((actual & asserted).sum())
        result["support"][name] = int(actual.sum())
        result["asserted"][name] = int(asserted.sum())
        result["precision"][name] = tp / int(asserted.sum()) if asserted.any() else 0.0
        result["recall"][name] = tp / int(actual.sum()) if actual.any() else 0.0
    none = labels == NONE_ID
    result["none_false_positive_rate"] = float(((predicted != NONE_ID) & none).sum() / none.sum())
    return result


def gate_failures(result: dict) -> list[dict]:
    failures = []
    for label, required in MIN_SUPPORT.items():
        name = LABELS[label]
        if result["support"][name] < required:
            failures.append({
                "label": name,
                "metric": "support",
                "observed": result["support"][name],
                "required": required,
            })
    for label in PRIMITIVE_IDS:
        name = LABELS[label]
        if result["precision"][name] < 0.95:
            failures.append({
                "label": name,
                "metric": "precision",
                "observed": result["precision"][name],
                "required": 0.95,
            })
    if result["none_false_positive_rate"] > 0.01:
        failures.append({
            "label": "none",
            "metric": "false_positive_rate",
            "observed": result["none_false_positive_rate"],
            "required": 0.01,
        })
    for attribute, slices in result.get("slices", {}).items():
        for value, slice_result in slices.items():
            for label in PRIMITIVE_IDS:
                name = LABELS[label]
                if slice_result["support"][name] < SLICE_MIN_SUPPORT:
                    continue
                if slice_result["asserted"][name] <= 0:
                    failures.append({
                        "label": name,
                        "metric": f"{attribute}:{value}.asserted",
                        "observed": 0,
                        "required": ">0",
                    })
                    continue
                precision = slice_result["precision"][name]
                if precision < 0.95:
                    failures.append({
                        "label": name,
                        "metric": f"{attribute}:{value}.precision",
                        "observed": precision,
                        "required": 0.95,
                    })
    return failures


def deployable_labels(result: dict) -> list[str]:
    return [
        LABELS[label]
        for label in PRIMITIVE_IDS
        if result["asserted"][LABELS[label]] > 0
        and result["precision"][LABELS[label]] >= 0.95
    ]


def deployable_label_ids(result: dict) -> list[int]:
    names = set(deployable_labels(result))
    return [label for label in PRIMITIVE_IDS if LABELS[label] in names]


def sliced_metrics(graphs, labels, predicted, attribute):
    return {
        value: metrics(labels[indexes], predicted[indexes])
        for value in sorted({getattr(graph, attribute) for graph in graphs})
        for indexes in [[index for index, graph in enumerate(graphs) if getattr(graph, attribute) == value]]
    }


def operating_score(logits, labels, semantic_probabilities):
    probabilities = logits.softmax(dim=1)
    thresholds = {
        label: choose_threshold(probabilities, labels, label, semantic_probabilities)
        for label in PRIMITIVE_IDS
    }
    result = metrics(labels, ensemble_predictions(probabilities, semantic_probabilities, thresholds))
    qualified = sum(result["precision"][LABELS[label]] >= CALIBRATION_PRECISION for label in PRIMITIVE_IDS)
    recall = sum(
        result["recall"][LABELS[label]]
        for label in PRIMITIVE_IDS
        if result["precision"][LABELS[label]] >= CALIBRATION_PRECISION
    )
    return qualified, recall, -result["none_false_positive_rate"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="corpus/build/recognizer_dataset.pt")
    parser.add_argument("--name", default="recognizer")
    parser.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--eval-batch-size", type=int, default=64)
    args = parser.parse_args()
    random.seed(SEED)
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)
    torch.use_deterministic_algorithms(True)
    dataset = torch.load(ROOT / args.dataset, weights_only=False)
    train = [graph for graph in dataset if graph.source not in VALIDATION_SOURCES | TEST_SOURCES]
    validation = [graph for graph in dataset if graph.source in VALIDATION_SOURCES]
    test = [graph for graph in dataset if graph.source in TEST_SOURCES]
    if not train or not validation or not test:
        raise SystemExit("empty train/validation/test split")
    split_sources = [{graph.source for graph in split} for split in (train, validation, test)]
    if any(left & right for index, left in enumerate(split_sources) for right in split_sources[index + 1:]):
        raise SystemExit("source-family leakage across train, validation, and test")

    semantic_head = ExtraTreesClassifier(
        n_estimators=300, min_samples_leaf=2, random_state=SEED, n_jobs=-1
    ).fit(np.stack([graph_summary(graph) for graph in train]), [int(graph.y.item()) for graph in train])
    validation_semantic = torch.tensor(
        semantic_head.predict_proba(np.stack([graph_summary(graph) for graph in validation])),
        dtype=torch.float,
    )
    validation_names = name_probabilities(validation)

    device = training_device(args.device)
    print(f"training_device={device} batch_size={args.batch_size}", flush=True)
    model = PrimitiveGraphSAGE(train[0].x.shape[1], classes=len(LABELS)).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-4)
    sampler = WeightedRandomSampler(
        source_balanced_weights(train), len(train), replacement=True,
        generator=torch.Generator().manual_seed(SEED),
    )
    loader = DataLoader(
        train,
        batch_size=args.batch_size,
        sampler=sampler,
    )
    best_state = None
    best_selection = (-1, -1.0, -1.0, float("-inf"))
    for epoch in range(100):
        model.train()
        for batch in loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            loss = F.cross_entropy(
                model(batch.x, batch.edge_index, batch.edge_type, batch.batch),
                batch.y,
            )
            loss.backward()
            optimizer.step()
        validation_logits, validation_labels = scores(model, validation, device, args.eval_batch_size)
        validation_loss = float(F.cross_entropy(validation_logits, validation_labels))
        selection = (*operating_score(validation_logits, validation_labels, validation_semantic), -validation_loss)
        if selection > best_selection:
            best_selection = selection
            best_state = {name: value.detach().clone() for name, value in model.state_dict().items()}
        if (epoch + 1) % 10 == 0:
            print(
                f"epoch={epoch + 1} loss={float(loss):.4f} validation_loss={validation_loss:.4f}",
                flush=True,
            )

    model.load_state_dict(best_state)
    validation_logits, validation_labels = scores(model, validation, device, args.eval_batch_size)
    temperature = calibrate_temperature(validation_logits, validation_labels)
    validation_probabilities = (validation_logits / temperature).softmax(dim=1)
    thresholds = {
        label: choose_threshold(validation_probabilities, validation_labels, label, validation_semantic)
        for label in PRIMITIVE_IDS
    }
    semantic_thresholds = {
        label: choose_threshold(validation_semantic, validation_labels, label)
        for label in PRIMITIVE_IDS
    }
    name_thresholds = {
        label: choose_threshold(validation_names, validation_labels, label)
        for label in PRIMITIVE_IDS
    }
    test_logits, test_labels = scores(model, test, device, args.eval_batch_size)
    test_semantic = torch.tensor(
        semantic_head.predict_proba(np.stack([graph_summary(graph) for graph in test])),
        dtype=torch.float,
    )
    test_names = name_probabilities(test)
    test_predictions = combined_predictions(
        (test_logits / temperature).softmax(dim=1), test_semantic, thresholds, semantic_thresholds,
        test_names, name_thresholds
    )
    result = metrics(test_labels, test_predictions)
    result["slices"] = {
        attribute: sliced_metrics(test, test_labels, test_predictions, attribute)
        for attribute in ("arch", "compiler", "opt")
    }
    result["false_positive_examples"] = [
        {"predicted": LABELS[int(prediction)], "actual": LABELS[int(label)], "source": graph.source, "function": graph.function}
        for graph, label, prediction in zip(test, test_labels, test_predictions)
        if prediction != NONE_ID and prediction != label
    ][:25]
    result.update({
        "gate": {
            "primitive_precision": 0.95, "calibration_precision": CALIBRATION_PRECISION,
            "none_false_positive_rate": 0.01,
            "minimum_support": {LABELS[k]: v for k, v in MIN_SUPPORT.items()},
            "slice_minimum_support": SLICE_MIN_SUPPORT,
        },
        "split": {
            "train": len(train), "validation": len(validation), "test": len(test),
            "validation_sources": sorted(VALIDATION_SOURCES), "held_out_sources": sorted(TEST_SOURCES),
        },
        "temperature": temperature,
        "decision": f"GNN prediction with semantic-head agreement >= {SEMANTIC_VETO_THRESHOLD}; semantic-head and symbol-name fallback when independently precision-gated",
        "validation_selection": best_selection,
        "training_device": str(device),
        "batch_size": args.batch_size,
        "thresholds": {LABELS[k]: v for k, v in thresholds.items()},
        "semantic_thresholds": {LABELS[k]: v for k, v in semantic_thresholds.items()},
        "name_thresholds": {LABELS[k]: v for k, v in name_thresholds.items()},
    })
    all_class_passed = (
        all(result["support"][LABELS[k]] >= required for k, required in MIN_SUPPORT.items())
        and all(result["precision"][LABELS[k]] >= 0.95 for k in PRIMITIVE_IDS)
        and result["none_false_positive_rate"] <= 0.01
        and not gate_failures(result)
    )
    result["all_class_gate_passed"] = all_class_passed
    result["gate_failures"] = gate_failures(result)
    result["deployable_labels"] = deployable_labels(result)
    passed = bool(result["deployable_labels"]) and result["none_false_positive_rate"] <= 0.01
    result["passed"] = passed

    MODEL_DIR.mkdir(exist_ok=True)
    result["dataset"] = args.dataset
    (MODEL_DIR / f"{args.name}.metrics.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    card = MODEL_DIR / ("MODEL_CARD.md" if args.name == "recognizer" else f"{args.name}.MODEL_CARD.md")
    card.write_text(
        "# CipherFault primitive recognizer\n\n"
        f"Deployment gate: **{'PASS' if passed else 'FAIL'}**.\n\n"
        f"All-class gate: **{'PASS' if all_class_passed else 'FAIL'}**. "
        f"Deployable labels: {', '.join(result['deployable_labels']) or 'none'}.\n\n"
        "The model is trained and evaluated over AES, RSA, ECC, SHA, ML-KEM, ML-DSA, SLH-DSA, and none regions "
        "in cooperative x86_64 and AArch64 ELF binaries. Runtime assertions are restricted to deployable labels only. "
        f"Evaluation holds out {', '.join(sorted(TEST_SOURCES))} by source project. Confidence is "
        f"temperature-scaled on held-out {', '.join(sorted(VALIDATION_SOURCES))} projects. It is not calibrated "
        "for distribution shift, obfuscation, or adversarial binaries.\n\n"
        "Some deployable classes are gated by a conservative symbol-name head. Those runtime assertions require "
        "matching symbol or fingerprint-equivalent name evidence; the model does not claim name-independent recovery "
        "for every class in fully stripped binaries.\n\n"
        "Held-out primitive precision: "
        + ", ".join(f"{LABELS[label]}={result['precision'][LABELS[label]]:.3f}" for label in PRIMITIVE_IDS)
        + "; "
        f"`none` false-positive rate: {result['none_false_positive_rate']:.3f}.\n\n"
        "The deployment gate, complete metrics, thresholds, support, and split are recorded in "
        "`recognizer.metrics.json`. The linear control is recorded in `baseline.metrics.json`.\n"
    )
    deployable = MODEL_DIR / f"{args.name}.pt"
    semantic_path = MODEL_DIR / f"{args.name}.semantic.joblib"
    if passed:
        torch.save({
            "state_dict": model.cpu().state_dict(),
            "input_dim": train[0].x.shape[1],
            "classes": len(LABELS),
            "labels": LABELS,
            "temperature": temperature,
            "thresholds": thresholds,
            "semantic_thresholds": semantic_thresholds,
            "name_thresholds": name_thresholds,
            "deployable_label_ids": deployable_label_ids(result),
        }, deployable)
        joblib.dump(semantic_head, semantic_path)
    else:
        deployable.unlink(missing_ok=True)
        semantic_path.unlink(missing_ok=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
