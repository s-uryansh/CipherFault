"""FIPS 203 ML-KEM parameter metadata."""

from __future__ import annotations

from dataclasses import dataclass

N = 256
Q = 3329

@dataclass(frozen=True)
class MLKEMParameterSet:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    rbg_strength_bits: int
    encapsulation_key_bytes: int
    decapsulation_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int = 32


PARAMETER_SETS = {
    "ML-KEM-512": MLKEMParameterSet(
        name="ML-KEM-512",
        k=2,
        eta1=3,
        eta2=2,
        du=10,
        dv=4,
        rbg_strength_bits=128,
        encapsulation_key_bytes=800,
        decapsulation_key_bytes=1632,
        ciphertext_bytes=768,
    ),
    "ML-KEM-768": MLKEMParameterSet(
        name="ML-KEM-768",
        k=3,
        eta1=2,
        eta2=2,
        du=10,
        dv=4,
        rbg_strength_bits=192,
        encapsulation_key_bytes=1184,
        decapsulation_key_bytes=2400,
        ciphertext_bytes=1088,
    ),
    "ML-KEM-1024": MLKEMParameterSet(
        name="ML-KEM-1024",
        k=4,
        eta1=2,
        eta2=2,
        du=11,
        dv=5,
        rbg_strength_bits=256,
        encapsulation_key_bytes=1568,
        decapsulation_key_bytes=3168,
        ciphertext_bytes=1568,
    ),
}

def parameter_set_by_name(name: str) -> MLKEMParameterSet | None:
    return PARAMETER_SETS.get(name)

def parameter_sets_by_size(
    *,
    encapsulation_key_bytes: int | None = None,
    decapsulation_key_bytes: int | None = None,
    ciphertext_bytes: int | None = None,
    shared_secret_bytes: int | None = None,
) -> list[MLKEMParameterSet]:
    matches = []
    for params in PARAMETER_SETS.values():
        if encapsulation_key_bytes is not None and params.encapsulation_key_bytes != encapsulation_key_bytes:
            continue
        if decapsulation_key_bytes is not None and params.decapsulation_key_bytes != decapsulation_key_bytes:
            continue
        if ciphertext_bytes is not None and params.ciphertext_bytes != ciphertext_bytes:
            continue
        if shared_secret_bytes is not None and params.shared_secret_bytes != shared_secret_bytes:
            continue
        matches.append(params)
    return matches

def constants_match(n: int | None = None, q: int | None = None) -> bool:
    if n is not None and n != N:
        return False
    if q is not None and q != Q:
        return False
    return n is not None or q is not None

def parameter_fact_from_sizes(
    *,
    encapsulation_key_bytes: int | None = None,
    decapsulation_key_bytes: int | None = None,
    ciphertext_bytes: int | None = None,
    shared_secret_bytes: int | None = None,
) -> dict | None:
    matches = parameter_sets_by_size(
        encapsulation_key_bytes=encapsulation_key_bytes,
        decapsulation_key_bytes=decapsulation_key_bytes,
        ciphertext_bytes=ciphertext_bytes,
        shared_secret_bytes=shared_secret_bytes,
    )
    if len(matches) != 1:
        return None
    params = matches[0]
    return {
        "tier": "VERIFIED_FACT",
        "primitive": "ML-KEM",
        "fact_type": "parameter_set",
        "parameter_set": params.name,
        "summary": f"ML-KEM parameter set inferred from code-intrinsic size evidence: {params.name}",
        "analyst_note": "This is a parameter-set fact, not an exploitability claim.",
    }
