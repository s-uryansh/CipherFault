#!/usr/bin/env python3
"""Build recognizer training graphs from the matrix metadata."""

from __future__ import annotations

import argparse
import collections
from hashlib import sha256
import json
import re
import sys
from pathlib import Path

import torch

sys.path.insert(0, "src")

from cipherfault.lifting.lifter import lift_binary
from cipherfault.recognizer.dwarf import _image_bias, candidate_labeled_regions, source_ranges
from cipherfault.recognizer.featurize import ReadOnlyMemory, region_to_data


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "corpus" / "build" / "matrix" / "metadata.jsonl"
OUT = ROOT / "corpus" / "build" / "recognizer_dataset.pt"
SUMMARY = ROOT / "corpus" / "build" / "recognizer_dataset.summary.json"
CACHE = ROOT / "corpus" / "build" / "recognizer_cache"
LIFT_CACHE = ROOT / "corpus" / "build" / "lift_cache"

LABELS = {
    "AES": 0,
    "RSA": 1,
    "ECC": 2,
    "SHA": 3,
    "ML-KEM": 4,
    "ML-DSA": 5,
    "SLH-DSA": 6,
    "none": 7,
}


def load_rows() -> list[dict]:
    with MATRIX.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def label_id(row: dict) -> int:
    labels = row.get("labels") or []
    if not labels:
        raise ValueError(f"missing labels for {row.get('artifact')}")
    label = labels[0]
    if label not in LABELS:
        raise ValueError(f"unknown label {label!r} for {row.get('artifact')}")
    return LABELS[label]


def function_label(row: dict, function_name: str) -> int:
    label = label_id(row)
    if label == LABELS["none"]:
        return label
    if any(re.search(pattern, function_name) for pattern in row.get("exclude_symbol_patterns", [])):
        return LABELS["none"]
    includes = row.get("include_symbol_patterns", [])
    if includes and not any(re.search(pattern, function_name) for pattern in includes):
        return LABELS["none"]
    return label


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    args = parser.parse_args()
    rows = load_rows()[args.start:args.stop]
    if args.reverse:
        rows.reverse()
    ok_rows = [row for row in rows if row.get("status") == "ok"]
    dataset = []
    per_artifact = []

    CACHE.mkdir(parents=True, exist_ok=True)
    LIFT_CACHE.mkdir(parents=True, exist_ok=True)
    errors = []
    for index, row in enumerate(ok_rows, 1):
        artifact = row["artifact"]
        path = ROOT / artifact
        region_count = 0
        function_count = 0
        label_config = json.dumps(
            {key: row.get(key, []) for key in ("labels", "include_symbol_patterns", "exclude_symbol_patterns")},
            sort_keys=True,
        ).encode()
        cache_key = sha256(b"v13-eight-classes\0" + artifact.encode() + b"\0" + label_config + b"\0" + path.read_bytes()).hexdigest()
        cache_path = CACHE / f"{cache_key}.pt"
        if cache_path.exists():
            graphs = torch.load(cache_path, weights_only=False)
        if not cache_path.exists() or not graphs:
            graphs = []
            try:
                lift_key = sha256(b"lift-v1\0" + path.read_bytes()).hexdigest()
                lift_path = LIFT_CACHE / f"{lift_key}.pt"
                if lift_path.exists():
                    functions = torch.load(lift_path, weights_only=False)
                else:
                    functions = lift_binary(str(path))
                    torch.save(functions, lift_path)
                dwarf_ranges = source_ranges(path)
                read_only = ReadOnlyMemory(path)
            except Exception as exc:
                errors.append({"artifact": artifact, "error": str(exc)})
                print(f"[{index}/{len(ok_rows)}] failed {artifact}: {exc}", flush=True)
                continue
            for lf in functions:
                function_count += 1
                for region_index, (region, from_target_source) in enumerate(
                    candidate_labeled_regions(lf, dwarf_ranges, row["source_file"])
                ):
                    if not region or sum(len(lf.blocks[address].instructions) for address in region) < 5:
                        continue
                    label = function_label(row, lf.name) if from_target_source else LABELS["none"]
                    data = region_to_data(
                        lf, region, label, read_only.read, _image_bias(lf, dwarf_ranges)
                    )
                    data.source = row["source"]
                    data.compiler = row["compiler"]
                    data.arch = row["arch"]
                    data.opt = row["opt"]
                    data.artifact = artifact
                    data.source_file = row["source_file"]
                    data.labels = [next(name for name, value in LABELS.items() if value == label)]
                    data.function = lf.name
                    data.fn_key = f"{row['source']}:{row['source_file']}:{lf.name}:{region_index}"
                    data._instructions = [lf.blocks[address].instructions for address in sorted(region)]
                    graphs.append(data)
            torch.save(graphs, cache_path)
        for data in graphs:
            if not hasattr(data, "y"):
                raise ValueError(f"cached graph has no DWARF label: {artifact}")
        dataset.extend(graphs)
        region_count = len(graphs)
        if not function_count:
            function_count = len(graphs)
        print(f"[{index}/{len(ok_rows)}] {artifact}: {region_count} regions", flush=True)

        per_artifact.append(
            {
                "artifact": artifact,
                "source": row["source"],
                "compiler": row["compiler"],
                "opt": row["opt"],
                "functions": function_count,
                "regions": region_count,
            }
        )

    if args.cache_only:
        print(f"[+] warmed {len(ok_rows) - len(errors)} artifacts; errors={len(errors)}")
        return 1 if errors else 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    torch.save(dataset, OUT)

    summary = {
        "labeling": "DWARF subprogram and inline source ranges",
        "artifact_type": "debug-enabled ELF shared object",
        "input_rows": len(rows),
        "ok_rows": len(ok_rows),
        "dataset_regions": len(dataset),
        "label_map": LABELS,
        "by_label": dict(collections.Counter(int(d.y.item()) for d in dataset)),
        "by_source": dict(collections.Counter(getattr(d, "source", "?") for d in dataset)),
        "by_arch": dict(collections.Counter(getattr(d, "arch", "?") for d in dataset)),
        "artifacts": per_artifact,
        "zero_region_artifacts": [row for row in per_artifact if row["regions"] == 0],
        "errors": errors,
    }
    SUMMARY.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    print(f"[+] wrote {OUT.relative_to(ROOT)}")
    print(f"[+] wrote {SUMMARY.relative_to(ROOT)}")
    print(f"[+] regions={len(dataset)}")
    print(f"[+] by_source={summary['by_source']}")
    print(f"[+] by_label={summary['by_label']}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
