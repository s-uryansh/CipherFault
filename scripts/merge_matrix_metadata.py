#!/usr/bin/env python3
"""Validate and merge independently built compiler-matrix shards."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


COMPILERS = {f"{family}-{version}" for family, versions in {"gcc": (11, 12, 13), "clang": (15, 16, 17)}.items() for version in versions}
ARCHES = {"x86_64", "aarch64"}
COMMON_OPTS = {"-O0", "-O1", "-O2", "-O3", "-Os"}
ROOT = Path(__file__).resolve().parents[1]


def artifact_matches_arch(path: Path, arch: str) -> bool:
    if not path.exists():
        return False
    with path.open("rb") as stream:
        header = stream.read(20)
    return len(header) == 20 and header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == {"x86_64": 62, "aarch64": 183}[arch]


def merge(paths: list[Path]) -> list[dict]:
    rows = [json.loads(line) for path in paths for line in path.read_text(encoding="utf-8").splitlines()]
    failed = [row for row in rows if row["status"] != "ok"]
    if failed:
        raise ValueError(f"matrix contains {len(failed)} failed builds")
    invalid = [row["artifact"] for row in rows if not artifact_matches_arch(ROOT / row["artifact"], row["arch"])]
    if invalid:
        raise ValueError(f"matrix contains {len(invalid)} missing or wrong-architecture artifacts")
    keys = [(row["arch"], row["compiler"], row["opt"], row["source_file"]) for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError("matrix contains duplicate build coordinates")
    actual = {(row["compiler"], row["arch"], row["opt"]) for row in rows}
    expected = {
        (compiler, arch, opt)
        for compiler in COMPILERS
        for arch in ARCHES
        for opt in COMMON_OPTS | ({"-Oz"} if compiler.startswith("clang-") else set())
    }
    if actual != expected:
        raise ValueError(f"matrix coverage mismatch: missing={sorted(expected - actual)} extra={sorted(actual - expected)}")
    counts = {len({row["source_file"] for row in rows if row["compiler"] == compiler and row["arch"] == arch and row["opt"] == opt}) for compiler, arch, opt in expected}
    if len(counts) != 1:
        raise ValueError(f"matrix shards disagree on source count: {sorted(counts)}")
    return sorted(rows, key=lambda row: (row["arch"], row["compiler"], row["opt"], row["source_file"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("shards", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=Path("corpus/build/matrix/metadata.jsonl"))
    args = parser.parse_args()
    rows = merge(args.shards)
    args.output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    print(f"[+] wrote {args.output} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
