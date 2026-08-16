#!/usr/bin/env python3
"""Evaluate scanner recall against a manifest of expected facts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, "src")

from cipherfault.scanner import findings_as_dicts, scan_binary

def load_manifest(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def fact_key(fact: dict) -> tuple[str, str]:
    return str(fact["fact_type"]), str(fact["cwe"])

def fact_matches(expected: dict, observed: dict) -> bool:
    return (
        fact_key(expected) == fact_key(observed)
        and ("origin" not in expected or str(expected["origin"]) == str(observed.get("origin")))
    )

def evaluate_entry(entry: dict, findings: list[dict]) -> dict:
    expected = entry["expected_facts"]
    forbidden = entry.get("forbidden_facts", [])
    hits = [fact for fact in expected if any(fact_matches(fact, seen) for seen in findings)]
    misses = [fact for fact in expected if not any(fact_matches(fact, seen) for seen in findings)]
    false_positives = [fact for fact in forbidden if any(fact_matches(fact, seen) for seen in findings)]
    return {
        "id": entry["id"],
        "binary": entry["binary"],
        "expected": len(expected),
        "hits": len(hits),
        "misses": [
            {
                **fact,
                "reason": "not emitted",
            }
            for fact in misses
        ],
        "false_positives": false_positives,
        "observed": [
            {"fact_type": fact_type, "cwe": cwe}
            for fact_type, cwe in sorted({fact_key(finding) for finding in findings})
        ],
    }

def summarize(results: list[dict]) -> dict:
    expected = sum(result["expected"] for result in results)
    hits = sum(result["hits"] for result in results)
    false_positives = sum(len(result.get("false_positives", [])) for result in results)
    misses = expected - hits
    return {
        "cases": len(results),
        "expected": expected,
        "hits": hits,
        "misses": misses,
        "false_positives": false_positives,
        "recall": hits / expected if expected else 0.0,
        "success": misses == 0 and false_positives == 0,
        "results": results,
    }

def evaluate_manifest(path: str | Path) -> dict:
    results = []
    for entry in load_manifest(path):
        findings = findings_as_dicts(scan_binary(
            entry["binary"],
            fingerprint_reference=entry.get("fingerprint_reference"),
        ).verified_facts)
        results.append(evaluate_entry(entry, findings))
    return summarize(results)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    args = parser.parse_args(argv)
    summary = evaluate_manifest(args.manifest)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["success"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
