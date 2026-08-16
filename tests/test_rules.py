import sys
from types import SimpleNamespace

sys.path.insert(0, "src")

from cipherfault import rules
from cipherfault.rules import hardcoded_key_finding, parameter_set_finding
from cipherfault.taint.tracer import ProvenancePath, Step
from cipherfault.rules import ecb_mode_finding

def _anchor():
    return SimpleNamespace(
        func_name="encrypt_record",
        callee="EVP_EncryptInit_ex",
        call_addr="00101234",
    )


def test_const_key_path_emits_hardcoded_key_finding():
    path = ProvenancePath()
    path.add(Step("CONST", "0x102010", "const"))
    path.terminal = "CONST"
    path.origin = "0x102010"

    finding = hardcoded_key_finding(_anchor(), path)

    assert finding is not None
    assert finding.tier == "VERIFIED_FACT"
    assert finding.primitive == "AES"
    assert finding.fact_type == "hardcoded_key"
    assert finding.cwe == "CWE-321"
    assert finding.function == "encrypt_record"
    assert finding.callee == "EVP_EncryptInit_ex"
    assert finding.call_addr == "00101234"
    assert finding.operand == "key"
    assert finding.origin == "0x102010"
    assert finding.provenance == [
        {"kind": "CONST", "detail": "0x102010", "varnode": "const"}
    ]


def test_non_const_key_path_emits_no_finding():
    path = ProvenancePath()
    path.add(Step("INPUT", "no def", "input"))
    path.terminal = "INPUT"
    assert hardcoded_key_finding(_anchor(), path) is None

def test_ecb_cipher_selector_emits_ecb_finding():
    finding = ecb_mode_finding(_anchor(), "EVP_aes_128_ecb")

    assert finding is not None
    assert finding.tier == "VERIFIED_FACT"
    assert finding.fact_type == "ecb_mode"
    assert finding.cwe == "CWE-327"
    assert finding.operand == "cipher"

def test_non_ecb_cipher_selector_emits_no_ecb_finding():
    assert ecb_mode_finding(_anchor(), "EVP_aes_128_cbc") is None

def test_ptradd_path_emits_no_hardcoded_key_finding():
    path = ProvenancePath()
    path.add(Step("OP", "PTRADD", "ptr"))
    path.terminal = "CONST"
    path.origin = "0x102010"

    assert hardcoded_key_finding(_anchor(), path) is None

def test_const_key_finding_carries_section():
    path = ProvenancePath()
    path.add(Step("CONST", "0x102010", "const"))
    path.terminal = "CONST"
    path.origin = "0x102010"

    finding = hardcoded_key_finding(_anchor(), path, section=".rodata")

    assert finding is not None
    assert finding.section == ".rodata"

def test_cycle_path_emits_no_hardcoded_key_finding():
    path = ProvenancePath()
    path.add(Step("CYCLE", "cycle", "ptr"))
    path.terminal = "CONST"
    path.origin = "0x102010"

    assert hardcoded_key_finding(_anchor(), path) is None


def test_md5_emits_verified_known_weak_algorithm_fact():
    assert callable(getattr(rules, "known_weak_algorithm_finding", None))
    finding = rules.known_weak_algorithm_finding(_anchor(), "MD5", "EVP_md5")

    assert finding is not None
    assert finding.tier == "VERIFIED_FACT"
    assert finding.fact_type == "known_weak_algorithm"
    assert finding.cwe == "CWE-327"
    assert finding.primitive == "MD5"


def test_sha256_does_not_emit_known_weak_algorithm_fact():
    assert callable(getattr(rules, "known_weak_algorithm_finding", None))
    assert rules.known_weak_algorithm_finding(_anchor(), "SHA-256", "EVP_sha256") is None


def test_parameter_fact_supports_mldsa():
    finding = parameter_set_finding(_anchor(), "ML-DSA-65", primitive="ML-DSA")

    assert finding.primitive == "ML-DSA"
    assert finding.origin == "ML-DSA-65"


def test_weak_randomness_fact_can_name_randomness_operand():
    path = ProvenancePath(
        terminal="WEAK_RNG",
        origin="rand",
        steps=[Step("WEAK_RANDOM_SOURCE", "rand", "value")],
    )

    finding = rules.weak_randomness_finding(
        _anchor(), path, primitive="ML-KEM", operand="randomness"
    )

    assert finding is not None
    assert finding.operand == "randomness"
    assert "randomness" in finding.summary


def test_numeric_parameter_fact_carries_provenance_without_cwe():
    path = ProvenancePath(
        terminal="CONST",
        origin="0x800",
        steps=[Step("CONST", "0x800", "value")],
    )

    finding = rules.numeric_parameter_finding(
        _anchor(), path, primitive="RSA", fact_type="key_size", operand="bits"
    )

    assert finding is not None
    assert finding.origin == "2048"
    assert finding.cwe is None
    assert finding.provenance[0]["kind"] == "CONST"


def test_rng_operand_origin_is_fact_but_quality_is_not_claimed():
    path = ProvenancePath(terminal="RNG", origin="getrandom", steps=[Step("RNG_SOURCE", "getrandom", "call")])

    finding = rules.operand_origin_finding(_anchor(), path, "AES", "key")

    assert finding.tier == "VERIFIED_FACT"
    assert finding.cwe is None
    assert finding.fact_type == "operand_origin"
    assert "not asserted" in finding.analyst_note
