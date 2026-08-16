import os
import subprocess
import sys

import pytest

sys.path.insert(0, "src")

from cipherfault.taint import anchors
from cipherfault.scanner import scan_binary


class Function:
    def __init__(self, name, tokens):
        self.name = name
        self.tokens = tokens


def test_matches_same_shape_after_addresses_change():
    assert callable(getattr(anchors, "match_fingerprints", None))
    catalog = {"EVP_EncryptInit_ex": ("CALL address", "MOV register,address", "RET")}
    functions = [Function("FUN_00401230", ("CALL address", "MOV register,address", "RET"))]

    assert anchors.match_fingerprints(functions, catalog) == {"FUN_00401230": "EVP_EncryptInit_ex"}


def test_ambiguous_fingerprint_is_not_resolved():
    assert callable(getattr(anchors, "match_fingerprints", None))
    shape = ("MOV register,register", "RET")
    catalog = {"time": shape, "clock": shape}

    assert anchors.match_fingerprints([Function("FUN_1", shape)], catalog) == {}


def test_shape_matching_multiple_target_functions_is_not_resolved():
    shape = ("MOV register,address", "RET")
    catalog = {"EVP_aes_128_ecb": shape}
    functions = [Function("FUN_1", shape), Function("FUN_2", shape)]

    assert anchors.match_fingerprints(functions, catalog) == {}


def test_high_similarity_fingerprint_tolerates_one_compiler_inserted_instruction():
    reference = tuple(f"OP{i}" for i in range(10))
    target = (*reference[:5], "STACK_CANARY", *reference[5:])

    assert anchors.match_fingerprints(
        [Function("FUN_1", target)], {"getrandom": reference}
    ) == {"FUN_1": "getrandom"}


def test_fuzzy_fingerprint_requires_margin_from_second_anchor():
    target = tuple(f"OP{i}" for i in range(10))
    catalog = {"time": target, "clock": (*target[:5], "OTHER", *target[5:])}

    assert anchors.match_fingerprints([Function("FUN_1", target)], catalog) == {}


def test_reference_catalog_requests_crypto_and_provenance_anchors():
    assert {
        "EVP_EncryptInit_ex",
        "EVP_DecryptInit_ex",
        "EVP_aes_128_ecb",
        "EVP_aes_256_cbc",
        "rand",
        "srand",
        "time",
        "gettimeofday",
        "memcpy",
    } <= anchors.FINGERPRINT_NAMES


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_reference_recovers_anchor_in_independently_linked_stripped_binary():
    subprocess.run(["make", "-C", "corpus/fixtures/static_anchor"], check=True)

    report = scan_binary(
        "corpus/build/static_anchor_target",
        fingerprint_reference="corpus/build/static_anchor_reference",
    )

    assert {primitive.primitive for primitive in report.primitives} == {"AES"}
    assert {primitive.method for primitive in report.primitives} == {"normalized_fingerprint_anchor"}
    assert {finding.fact_type for finding in report.verified_facts} == {
        "ecb_mode",
        "hardcoded_key",
    }


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_fingerprint_recovers_anchors_across_gcc_and_clang_optimization():
    subprocess.run(["make", "-C", "corpus/fixtures/static_anchor"], check=True)

    report = scan_binary(
        "corpus/build/static_anchor_cross_target",
        fingerprint_reference="corpus/build/static_anchor_cross_reference",
    )

    assert {primitive.primitive for primitive in report.primitives} == {"AES"}
    assert {finding.fact_type for finding in report.verified_facts} == {"ecb_mode", "hardcoded_key"}


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_stripped_reference_is_rejected():
    subprocess.run(["make", "-C", "corpus/fixtures/static_anchor"], check=True)

    with pytest.raises(ValueError, match="no supported anchor symbols"):
        scan_binary(
            "corpus/build/static_anchor_target",
            fingerprint_reference="corpus/build/static_anchor_target",
        )
