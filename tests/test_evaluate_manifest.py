import json
import sys

sys.path.insert(0, "scripts")

import evaluate_manifest as evaluator
from evaluate_manifest import evaluate_entry, summarize
from cipherfault.report import AnalysisReport

def test_evaluate_entry_counts_hits_and_misses():
    entry = {
        "id": "case",
        "binary": "demo",
        "expected_facts": [
            {"fact_type": "ecb_mode", "cwe": "CWE-327"},
            {"fact_type": "hardcoded_key", "cwe": "CWE-321"},
        ],
    }
    findings = [
        {"fact_type": "ecb_mode", "cwe": "CWE-327"},
    ]

    result = evaluate_entry(entry, findings)

    assert result["expected"] == 2
    assert result["hits"] == 1
    assert result["misses"] == [
        {
            "fact_type": "hardcoded_key",
            "cwe": "CWE-321",
            "reason": "not emitted",
        }
    ]
    assert result["false_positives"] == []

def test_summarize_reports_recall():
    summary = summarize(
        [
            {"expected": 2, "hits": 1},
            {"expected": 1, "hits": 1},
        ]
    )

    assert summary["cases"] == 2
    assert summary["expected"] == 3
    assert summary["hits"] == 2
    assert summary["misses"] == 1
    assert summary["recall"] == 2 / 3


def test_evaluate_entry_reports_forbidden_observations():
    entry = {
        "id": "negative",
        "binary": "demo",
        "expected_facts": [],
        "forbidden_facts": [{"fact_type": "hardcoded_key", "cwe": "CWE-321"}],
    }

    result = evaluate_entry(entry, [{"fact_type": "hardcoded_key", "cwe": "CWE-321"}])

    assert result["false_positives"] == [
        {"fact_type": "hardcoded_key", "cwe": "CWE-321"}
    ]


def test_summarize_is_unsuccessful_for_misses_or_false_positives():
    summary = summarize([
        {"expected": 1, "hits": 0, "false_positives": []},
        {"expected": 0, "hits": 0, "false_positives": [{"fact_type": "x"}]},
    ])

    assert summary["success"] is False
    assert summary["false_positives"] == 1


def test_manifest_passes_optional_fingerprint_reference(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps([{
        "id": "static",
        "binary": "target",
        "fingerprint_reference": "reference",
        "expected_facts": [],
    }]))
    observed = {}

    def fake_scan(binary, fingerprint_reference=None):
        observed.update(binary=binary, reference=fingerprint_reference)
        return AnalysisReport(target=binary, target_sha256="0" * 64)

    monkeypatch.setattr(evaluator, "scan_binary", fake_scan)

    assert evaluator.evaluate_manifest(path)["success"] is True
    assert observed == {"binary": "target", "reference": "reference"}


def test_parameter_expectations_are_distinguished_by_origin():
    entry = {
        "id": "pqc",
        "binary": "demo",
        "expected_facts": [
            {"fact_type": "parameter_set", "cwe": "None", "origin": "ML-DSA-65"},
            {"fact_type": "parameter_set", "cwe": "None", "origin": "SLH-DSA-SHA2-128s"},
        ],
    }
    findings = [
        {"fact_type": "parameter_set", "cwe": None, "origin": "ML-DSA-65"},
    ]

    result = evaluate_entry(entry, findings)

    assert result["hits"] == 1
    assert result["misses"][0]["origin"] == "SLH-DSA-SHA2-128s"
