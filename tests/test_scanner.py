import os
import subprocess
import sys

import pytest

sys.path.insert(0, "src")

pytest.importorskip("pyghidra")

from cipherfault.scanner import _validate_target, primitive_from_cipher_selector, scan_binary
from cipherfault.taint.anchors import anchor_spec


FIXTURE = "corpus/build/aes_ecb_demo_strip"
CBC_FIXTURE = "corpus/build/aes_cbc_static_iv_strip"
WEAK_RNG_FIXTURE = "corpus/build/aes_weak_rng_key_strip"
UNRELATED_RAND_FIXTURE = "corpus/build/aes_unrelated_rand_strip"
NON_AES_FIXTURE = "corpus/build/non_aes_evp_strip"
DYNAMIC_OPERANDS_FIXTURE = "corpus/build/aes_dynamic_operands_strip"
RETURNED_KEY_FIXTURE = "corpus/build/aes_returned_key_strip"
COPIED_KEY_FIXTURE = "corpus/build/aes_copied_key_strip"
IGNORED_VERIFY_FIXTURE = "corpus/build/verification_ignored_strip"
CHECKED_VERIFY_FIXTURE = "corpus/build/verification_checked_strip"
AMBIGUOUS_CALLERS_FIXTURE = "corpus/build/aes_ambiguous_callers_strip"
IP_RNG_FIXTURE = "corpus/build/aes_ip_rng_strip"
RNG_AFTER_USE_FIXTURE = "corpus/build/aes_rng_after_use_strip"
RNG_OVERWRITTEN_FIXTURE = "corpus/build/aes_rng_overwritten_strip"
LOW_LEVEL_AES_FIXTURE = "corpus/build/aes_low_level_strip"
MD5_FIXTURE = "corpus/build/digest_md5_strip"
SHA256_FIXTURE = "corpus/build/digest_sha256_strip"


@pytest.mark.skipif(not os.path.exists(FIXTURE), reason="fixture not built")
def test_scanner_emits_hardcoded_key_for_stripped_aes_fixture():
    report = scan_binary(FIXTURE)
    findings = report.verified_facts

    assert report.target_sha256
    assert report.indicators == []
    assert {primitive.primitive for primitive in report.primitives} == {"AES"}
    assert any(
        finding.fact_type == "hardcoded_key"
        and finding.cwe == "CWE-321"
        and finding.tier == "VERIFIED_FACT"
        and finding.origin == "0x102010"
        for finding in findings
    )
def _fact_types(findings):
    return {finding.fact_type for finding in findings}


def test_only_aes_cipher_selectors_prove_aes():
    assert primitive_from_cipher_selector("EVP_aes_256_cbc") == "AES"
    assert primitive_from_cipher_selector("EVP_chacha20_poly1305") is None
    assert primitive_from_cipher_selector("EVP_not_aes_cipher") is None
    assert primitive_from_cipher_selector(None) is None


def test_generic_evp_anchor_does_not_claim_a_primitive():
    assert anchor_spec("EVP_EncryptInit_ex")["primitive"] is None


@pytest.mark.parametrize("machine", [62, 183])
def test_scanner_accepts_supported_64_bit_little_endian_elf_machines(tmp_path, machine):
    target = tmp_path / "target"
    target.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + machine.to_bytes(2, "little"))

    assert _validate_target(target) == {62: "x86_64", 183: "AArch64"}[machine]

@pytest.mark.skipif(not os.path.exists(FIXTURE), reason="fixture not built")
def test_ecb_fixture_has_no_static_iv_and_key_has_section():
    findings = scan_binary(FIXTURE).verified_facts

    assert "static_iv" not in _fact_types(findings)
    key = next(f for f in findings if f.fact_type == "hardcoded_key")
    assert key.section is not None

@pytest.mark.skipif(not os.path.exists(CBC_FIXTURE), reason="fixture not built")
def test_cbc_fixture_static_iv_has_section():
    findings = scan_binary(CBC_FIXTURE).verified_facts

    iv = next(f for f in findings if f.fact_type == "static_iv")
    assert iv.section is not None

@pytest.mark.skipif(not os.path.exists(WEAK_RNG_FIXTURE), reason="fixture not built")
def test_weak_rng_fixture_emits_weak_randomness_only():
    findings = scan_binary(WEAK_RNG_FIXTURE).verified_facts

    assert _fact_types(findings) == {"weak_randomness"}
    weak = findings[0]
    assert weak.section is None
    assert [step["kind"] for step in weak.provenance] == [
        "WEAK_RANDOM_SOURCE",
        "STORE",
        "OPERAND",
    ]


@pytest.mark.skipif(not os.path.exists(UNRELATED_RAND_FIXTURE), reason="fixture not built")
def test_unrelated_rand_does_not_emit_weak_randomness():
    findings = scan_binary(UNRELATED_RAND_FIXTURE).verified_facts

    assert "weak_randomness" not in _fact_types(findings)
    assert _fact_types(findings) == {"ecb_mode", "hardcoded_key"}


@pytest.mark.skipif(not os.path.exists(NON_AES_FIXTURE), reason="fixture not built")
def test_non_aes_evp_call_emits_no_aes_evidence_or_facts():
    report = scan_binary(NON_AES_FIXTURE)

    assert report.primitives == []
    assert report.verified_facts == []
    assert "UNRESOLVED_CIPHER_PRIMITIVE" in {
        diagnostic.code for diagnostic in report.diagnostics
    }


@pytest.mark.skipif(not os.path.exists(DYNAMIC_OPERANDS_FIXTURE), reason="fixture not built")
def test_runtime_generated_key_and_iv_emit_no_static_facts():
    report = scan_binary(DYNAMIC_OPERANDS_FIXTURE)

    assert {primitive.primitive for primitive in report.primitives} == {"AES"}
    assert "hardcoded_key" not in _fact_types(report.verified_facts)
    assert "static_iv" not in _fact_types(report.verified_facts)
    assert {(finding.fact_type, finding.origin) for finding in report.verified_facts} == {
        ("operand_origin", "RAND_bytes")
    }
    assert {indicator.operand for indicator in report.indicators} == {"key", "iv"}


@pytest.mark.skipif(not os.path.exists(RETURNED_KEY_FIXTURE), reason="fixture not built")
def test_key_returned_across_resolved_call_has_verified_provenance():
    report = scan_binary(RETURNED_KEY_FIXTURE)

    key = next(finding for finding in report.verified_facts if finding.fact_type == "hardcoded_key")
    assert any(step["kind"] == "RETURN_HOP" for step in key.provenance)


@pytest.mark.skipif(not os.path.exists(COPIED_KEY_FIXTURE), reason="fixture not built")
def test_key_copied_from_static_storage_has_verified_provenance():
    report = scan_binary(COPIED_KEY_FIXTURE)

    key = next(finding for finding in report.verified_facts if finding.fact_type == "hardcoded_key")
    assert any(step["kind"] == "BUFFER_COPY" for step in key.provenance)


@pytest.mark.skipif(not os.path.exists(IGNORED_VERIFY_FIXTURE), reason="fixture not built")
def test_unchecked_verification_result_is_indicator_only():
    report = scan_binary(IGNORED_VERIFY_FIXTURE)

    assert report.verified_facts == []
    assert [(item.tier, item.operand) for item in report.indicators] == [
        ("INDICATOR", "return_value")
    ]


@pytest.mark.skipif(not os.path.exists(CHECKED_VERIFY_FIXTURE), reason="fixture not built")
def test_checked_verification_result_is_not_flagged():
    assert scan_binary(CHECKED_VERIFY_FIXTURE).indicators == []


@pytest.mark.skipif(not os.path.exists(AMBIGUOUS_CALLERS_FIXTURE), reason="fixture not built")
def test_mixed_caller_origins_do_not_become_verified_fact():
    report = scan_binary(AMBIGUOUS_CALLERS_FIXTURE)

    assert "hardcoded_key" not in _fact_types(report.verified_facts)
    assert any(item.code == "UNRESOLVED_KEY_PROVENANCE" for item in report.diagnostics)


@pytest.mark.skipif(not os.path.exists(IP_RNG_FIXTURE), reason="fixture not built")
def test_rng_source_propagates_across_resolved_call():
    report = scan_binary(IP_RNG_FIXTURE)

    fact = next(item for item in report.verified_facts if item.fact_type == "operand_origin")
    assert fact.origin == "RAND_bytes"
    assert any(step["kind"] == "PARAM_HOP" for step in fact.provenance)


@pytest.mark.skipif(not os.path.exists(RNG_AFTER_USE_FIXTURE), reason="fixture not built")
def test_rng_write_after_crypto_call_is_not_operand_provenance():
    report = scan_binary(RNG_AFTER_USE_FIXTURE)

    assert "operand_origin" not in _fact_types(report.verified_facts)
    assert report.indicators == []


@pytest.mark.skipif(not os.path.exists(RNG_OVERWRITTEN_FIXTURE), reason="fixture not built")
def test_later_constant_write_replaces_rng_provenance():
    report = scan_binary(RNG_OVERWRITTEN_FIXTURE)

    assert "operand_origin" not in _fact_types(report.verified_facts)
    key = next(item for item in report.verified_facts if item.fact_type == "hardcoded_key")
    assert key.origin == "memset(0x0, 16 bytes)"


@pytest.mark.skipif(not os.path.exists(LOW_LEVEL_AES_FIXTURE), reason="fixture not built")
def test_low_level_aes_apis_prove_mode_and_static_iv():
    report = scan_binary(LOW_LEVEL_AES_FIXTURE)

    assert {(item.primitive, item.variant) for item in report.primitives} == {
        ("AES", "AES-ECB"),
        ("AES", "AES-CBC"),
    }
    assert {item.fact_type for item in report.verified_facts} >= {"ecb_mode", "static_iv"}


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_mlkem_api_symbol_proves_parameter_set():
    fixture_dir = "corpus/fixtures/mlkem_api"
    subprocess.run(["make"], cwd=fixture_dir, check=True, capture_output=True)

    report = scan_binary(f"{fixture_dir}/mlkem_api")

    assert any(p.primitive == "ML-KEM" and p.variant == "ML-KEM-768" for p in report.primitives)
    assert any(f.fact_type == "parameter_set" and f.origin == "ML-KEM-768" for f in report.verified_facts)


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_md5_digest_api_emits_known_weak_fact():
    subprocess.run(["make", "-C", "corpus/fixtures/digest_api"], check=True)

    report = scan_binary(MD5_FIXTURE)

    assert {primitive.primitive for primitive in report.primitives} == {"MD5"}
    assert {finding.fact_type for finding in report.verified_facts} == {"known_weak_algorithm"}


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_sha256_digest_api_is_inventory_without_weak_fact():
    subprocess.run(["make", "-C", "corpus/fixtures/digest_api"], check=True)

    report = scan_binary(SHA256_FIXTURE)

    assert {primitive.primitive for primitive in report.primitives} == {"SHA-256"}
    assert report.verified_facts == []


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_pqc_signature_symbols_prove_parameter_sets():
    fixture_dir = "corpus/fixtures/pqc_signatures"
    subprocess.run(["make"], cwd=fixture_dir, check=True, capture_output=True)

    report = scan_binary(f"{fixture_dir}/pqc_signatures")

    assert {(p.primitive, p.variant) for p in report.primitives} == {
        ("ML-DSA", "ML-DSA-65"),
        ("SLH-DSA", "SLH-DSA-SHA2-128s"),
    }
    assert {(f.primitive, f.origin) for f in report.verified_facts} == {
        ("ML-DSA", "ML-DSA-65"),
        ("SLH-DSA", "SLH-DSA-SHA2-128s"),
    }


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_mlkem_derandomized_api_traces_weak_randomness_operand():
    fixture_dir = "corpus/fixtures/mlkem_weak_randomness"
    subprocess.run(["make"], cwd=fixture_dir, check=True, capture_output=True)

    report = scan_binary(f"{fixture_dir}/mlkem_weak_randomness")

    weak = next(f for f in report.verified_facts if f.fact_type == "weak_randomness")
    assert weak.primitive == "ML-KEM"
    assert weak.operand == "randomness"
    assert weak.origin == "rand"


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_rsa_keygen_emits_constant_key_size_fact():
    subprocess.run(["make", "-C", "corpus/fixtures/rsa_keygen"], check=True)

    report = scan_binary("corpus/build/rsa_keygen")

    assert {primitive.primitive for primitive in report.primitives} == {"RSA"}
    size = next(f for f in report.verified_facts if f.fact_type == "key_size")
    assert size.origin == "2048"
    assert size.cwe is None


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_runtime_rsa_key_size_is_not_asserted():
    subprocess.run(["make", "-C", "corpus/fixtures/rsa_keygen"], check=True)

    report = scan_binary("corpus/build/rsa_keygen_dynamic")

    assert {primitive.primitive for primitive in report.primitives} == {"RSA"}
    assert "key_size" not in {finding.fact_type for finding in report.verified_facts}


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_ecc_constructor_emits_named_curve_fact():
    subprocess.run(["make", "-C", "corpus/fixtures/ecc_curve"], check=True)

    report = scan_binary("corpus/build/ecc_curve")

    assert {primitive.primitive for primitive in report.primitives} == {"ECC"}
    curve = next(f for f in report.verified_facts if f.fact_type == "parameter_set")
    assert curve.origin == "P-256"
    assert curve.cwe is None
    assert curve.operand == "curve"
    assert curve.provenance[-1]["kind"] == "CONST"


@pytest.mark.skipif(not os.environ.get("GHIDRA_INSTALL_DIR"), reason="Ghidra not configured")
def test_runtime_ecc_curve_is_not_asserted():
    subprocess.run(["make", "-C", "corpus/fixtures/ecc_curve"], check=True)

    report = scan_binary("corpus/build/ecc_curve_dynamic")

    assert {primitive.primitive for primitive in report.primitives} == {"ECC"}
    assert "parameter_set" not in {finding.fact_type for finding in report.verified_facts}
