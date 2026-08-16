#!/usr/bin/env python3
"""Inspect ML-KEM regions already present in the recognizer dataset."""

from __future__ import annotations

import collections
import sys

import torch

sys.path.insert(0, "src")

from cipherfault.pqc.mlkem import parameter_set_by_name


DATASET = "corpus/build/recognizer_dataset.pt"
ML_KEM_LABEL = 1


def main() -> int:
    ds = torch.load(DATASET, weights_only=False)
    mlkem = [d for d in ds if int(d.y.item()) == ML_KEM_LABEL]
    params = parameter_set_by_name("ML-KEM-768")

    print(f"regions_total={len(ds)}")
    print(f"mlkem_regions={len(mlkem)}")
    print("mlkem_by_source", collections.Counter(getattr(d, "source", "?") for d in mlkem))
    print("mlkem_by_compiler", collections.Counter(getattr(d, "compiler", "?") for d in mlkem))
    print("mlkem_by_opt", collections.Counter(getattr(d, "opt", "?") for d in mlkem))
    print(f"fips203_default_candidate={params.name if params else None}")
    print("note=dataset label says ML-KEM; this script does not prove exact parameter set from binary evidence yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
