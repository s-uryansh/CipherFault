#!/usr/bin/env python3
"""Check recognizer metrics and deployable artifacts agree."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-artifacts", action="store_true")
    parser.add_argument("--require-all-class", action="store_true")
    args = parser.parse_args(argv)

    metrics_path = ROOT / "models" / "recognizer.metrics.json"
    model_path = ROOT / "models" / "recognizer.pt"
    semantic_path = ROOT / "models" / "recognizer.semantic.joblib"

    metrics = json.loads(metrics_path.read_text())
    if args.require_all_class and not metrics.get("all_class_gate_passed"):
        raise SystemExit("all-class recognizer gate failed: " + _failure_summary(metrics))
    deployable = metrics.get("deployable_labels", [])
    if metrics.get("passed") != bool(deployable):
        raise SystemExit("recognizer metrics `passed` does not match deployable labels")
    if not metrics.get("passed"):
        print("recognizer gate has no deployable labels")
        return 0
    for label in deployable:
        if metrics.get("asserted", {}).get(label, 0) <= 0:
            raise SystemExit(f"deployable label has no assertions: {label}")
        precision = metrics.get("precision", {}).get(label, 0.0)
        required = metrics.get("gate", {}).get("primitive_precision", 0.95)
        if precision < required:
            raise SystemExit(f"deployable label below precision gate: {label}={precision} < {required}")
    missing = [str(path.relative_to(ROOT)) for path in (model_path, semantic_path) if not path.exists()]
    if missing and not args.require_artifacts:
        print("recognizer artifacts not present: " + ", ".join(missing))
        return 0
    if missing:
        raise SystemExit("recognizer metrics passed but model or semantic artifact is missing")

    import torch

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    labels = checkpoint["labels"]
    expected_ids = {label_id for label_id, name in labels.items() if name in deployable}
    observed_ids = set(checkpoint.get("deployable_label_ids", []))
    if observed_ids != expected_ids:
        raise SystemExit(
            f"deployable label mismatch: metrics={sorted(expected_ids)} checkpoint={sorted(observed_ids)}"
        )
    print("recognizer artifacts ok: " + ", ".join(deployable))
    return 0


def _failure_summary(metrics: dict) -> str:
    failures = metrics.get("gate_failures", [])
    if not failures:
        return "no gate_failures recorded"
    return "; ".join(
        f"{failure['label']} {failure['metric']}={failure['observed']} required={failure['required']}"
        for failure in failures
    )


if __name__ == "__main__":
    raise SystemExit(main())
