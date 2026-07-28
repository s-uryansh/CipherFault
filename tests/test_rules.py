import sys
from types import SimpleNamespace

sys.path.insert(0, "src")

from cipherfault.rules import hardcoded_key_finding
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