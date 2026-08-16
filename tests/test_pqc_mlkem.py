import sys

sys.path.insert(0, "src")

from cipherfault.pqc.mlkem import (
    N,
    Q,
    parameter_set_by_name,
    parameter_sets_by_size,
    constants_match,
    parameter_fact_from_sizes,
)

def test_fips203_global_constants():
    assert N == 256
    assert Q == 3329

def test_mlkem_768_parameters():
    params = parameter_set_by_name("ML-KEM-768")

    assert params is not None
    assert params.k == 3
    assert params.eta1 == 2
    assert params.eta2 == 2
    assert params.du == 10
    assert params.dv == 4
    assert params.rbg_strength_bits == 192
    assert params.encapsulation_key_bytes == 1184
    assert params.decapsulation_key_bytes == 2400
    assert params.ciphertext_bytes == 1088
    assert params.shared_secret_bytes == 32

def test_lookup_parameter_set_by_encapsulation_key_size():
    assert [p.name for p in parameter_sets_by_size(encapsulation_key_bytes=800)] == [
        "ML-KEM-512"
    ]
    assert [p.name for p in parameter_sets_by_size(encapsulation_key_bytes=1184)] == [
        "ML-KEM-768"
    ]
    assert [p.name for p in parameter_sets_by_size(encapsulation_key_bytes=1568)] == [
        "ML-KEM-1024"
    ]

def test_lookup_parameter_set_by_ciphertext_size():
    assert [p.name for p in parameter_sets_by_size(ciphertext_bytes=768)] == [
        "ML-KEM-512"
    ]
    assert [p.name for p in parameter_sets_by_size(ciphertext_bytes=1088)] == [
        "ML-KEM-768"
    ]
    assert [p.name for p in parameter_sets_by_size(ciphertext_bytes=1568)] == [
        "ML-KEM-1024"
    ]

def test_size_lookup_can_disambiguate_1024_key_from_512_ciphertext_collision():
    assert [p.name for p in parameter_sets_by_size(encapsulation_key_bytes=1568)] == [
        "ML-KEM-1024"
    ]
    assert [p.name for p in parameter_sets_by_size(ciphertext_bytes=1568)] == [
        "ML-KEM-1024"
    ]

def test_constants_match_only_proves_family_signal():
    assert constants_match(n=256)
    assert constants_match(q=3329)
    assert constants_match(n=256, q=3329)
    assert not constants_match(n=255, q=3329)
    assert not constants_match()

def test_parameter_fact_from_exact_ciphertext_size():
    fact = parameter_fact_from_sizes(ciphertext_bytes=1088)

    assert fact is not None
    assert fact["tier"] == "VERIFIED_FACT"
    assert fact["primitive"] == "ML-KEM"
    assert fact["fact_type"] == "parameter_set"
    assert fact["parameter_set"] == "ML-KEM-768"

def test_parameter_fact_returns_none_for_ambiguous_or_absent_evidence():
    assert parameter_fact_from_sizes() is None
    assert parameter_fact_from_sizes(ciphertext_bytes=1234) is None
