#!/usr/bin/env python3
"""Fail fast when a deploy image cannot run inference like local dev."""

from __future__ import annotations

from pathlib import Path

import torch

from cipherfault.recognizer.runtime import default_model_path
from cipherfault.service import run_scan


def main() -> int:
    model_path = default_model_path()
    semantic_path = model_path.with_suffix(".semantic.joblib")
    missing = [str(path) for path in (model_path, semantic_path) if not path.exists()]
    if missing:
        raise SystemExit("missing deploy model artifact(s): " + ", ".join(missing))

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=True)
    if "state_dict" not in checkpoint or "labels" not in checkpoint:
        raise SystemExit(f"invalid recognizer checkpoint: {model_path}")

    if not callable(run_scan):
        raise SystemExit("cipherfault.service.run_scan is not importable")

    labels = ", ".join(checkpoint["labels"].values())
    print(f"deploy runtime ok: {model_path} ({labels})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
