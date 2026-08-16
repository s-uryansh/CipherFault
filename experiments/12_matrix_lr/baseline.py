#!/usr/bin/env python3
"""Logistic-regression baseline for the matrix-backed recognizer dataset."""

from __future__ import annotations

import collections
import json
import random
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, "src")


DATASET = "corpus/build/recognizer_dataset.pt"
HELD_OUT_SOURCES = {"libsodium", "mbedtls", "liboqs", "libpng"}
METRICS = Path("models/baseline.metrics.json")


def vec(d):
    return d.x.sum(0).numpy()


def labels(ds):
    return [int(d.y.item()) for d in ds]


def function_disjoint_split(ds, seed=0):
    keys = sorted({d.fn_key for d in ds})
    rng = random.Random(seed)
    rng.shuffle(keys)
    split = int(0.8 * len(keys))
    train_keys = set(keys[:split])
    train = [d for d in ds if d.fn_key in train_keys]
    test = [d for d in ds if d.fn_key not in train_keys]
    return train, test


def compiler_holdout_split(ds):
    train = [d for d in ds if getattr(d, "compiler", None) == "gcc"]
    test = [d for d in ds if getattr(d, "compiler", None) == "clang"]
    return train, test


def source_holdout_split(ds):
    return (
        [d for d in ds if d.source not in HELD_OUT_SOURCES],
        [d for d in ds if d.source in HELD_OUT_SOURCES],
    )


def report(name, train, test):
    print(f"\n[{name}] train={len(train)} test={len(test)}")
    if not train or not test:
        print("skipped: empty split")
        return None

    y_train = labels(train)
    y_test = labels(test)
    if len(set(y_train)) < 2:
        print(f"skipped: train has one class {collections.Counter(y_train)}")
        return None

    x_train = np.stack([vec(d) for d in train])
    x_test = np.stack([vec(d) for d in test])
    clf = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=2000),
    ).fit(x_train, y_train)
    pred = clf.predict(x_test)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        pred,
        average="macro",
        zero_division=0,
    )
    print(f"accuracy={accuracy_score(y_test, pred):.3f}")
    print(f"precision_macro={precision:.3f}")
    print(f"recall_macro={recall:.3f}")
    print(f"f1_macro={f1:.3f}")
    print("confusion_matrix=")
    matrix = confusion_matrix(y_test, pred)
    print(matrix)
    return {
        "train": len(train),
        "test": len(test),
        "accuracy": accuracy_score(y_test, pred),
        "precision_macro": precision,
        "recall_macro": recall,
        "f1_macro": f1,
        "confusion_matrix": matrix.tolist(),
    }


def main() -> int:
    ds = torch.load(DATASET, weights_only=False)
    print(f"regions={len(ds)}")
    print("by_label", collections.Counter(labels(ds)))
    print("by_source", collections.Counter(getattr(d, "source", "?") for d in ds))

    results = {
        "model": "standard-scaled logistic regression over P-code histograms",
        "dataset_regions": len(ds),
        "function_disjoint": report("function_disjoint", *function_disjoint_split(ds)),
        "compiler_holdout_gcc_to_clang": report("compiler_holdout_gcc_to_clang", *compiler_holdout_split(ds)),
        "source_holdout": report("source_holdout", *source_holdout_split(ds)),
    }
    METRICS.parent.mkdir(exist_ok=True)
    METRICS.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(f"[+] wrote {METRICS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
