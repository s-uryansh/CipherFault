"""
Deterministic rules: provenance paths -> analyst-facing findings
"""

from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any


@dataclass(frozen=True)
class Finding:
    id: str
    tier: str
    primitive: str
    fact_type: str
    cwe: str | None
    summary: str
    function: str
    callee: str
    call_addr: str
    operand: str
    origin: str | None
    provenance: list[dict[str, str]]
    section: str | None = None
    analyst_note: str = "Exploitability requires context not present in the binary."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def serialize_provenance(path) -> list[dict[str, str]]:
    return [
        {
            "kind": str(getattr(step, "kind", "")),
            "detail": str(getattr(step, "detail", "")),
            "varnode": str(getattr(step, "varnode", "")),
        }
        for step in getattr(path, "steps", [])
    ]


def hardcoded_key_finding(
        anchor,
        path,
        primitive: str = "AES",
        section: str |None = None,
        ) -> Finding | None:
    if getattr(path, "terminal", None) != "CONST" or not _looks_like_static_origin(path):
        return None

    origin = getattr(path, "origin", None)
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    fact_type = "hardcoded_key"
    cwe = "CWE-321"
    tier = "VERIFIED_FACT"

    finding_id = _finding_id(
        primitive,
        fact_type,
        function,
        callee,
        call_addr,
        "key",
        str(origin),
    )

    return Finding(
        id=finding_id,
        tier=tier,
        primitive=primitive,
        fact_type=fact_type,
        cwe=cwe,
        summary=f"{primitive} key operand resolves to constant {origin}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand="key",
        origin=origin,
        provenance=serialize_provenance(path),
        section=section
    )


def ecb_mode_finding(anchor, cipher_name: str | None, primitive: str = "AES") -> Finding | None:
    if cipher_name is None or "_ecb" not in cipher_name.lower():
        return None

    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    fact_type = "ecb_mode"
    cwe = "CWE-327"
    tier = "VERIFIED_FACT"

    return Finding(
        id=_finding_id(primitive, fact_type, function, callee, call_addr, cipher_name),
        tier=tier,
        primitive=primitive,
        fact_type=fact_type,
        cwe=cwe,
        summary=f"{primitive} cipher selector resolves to ECB mode: {cipher_name}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand="cipher",
        origin=cipher_name,
        provenance=[
            {
                "kind": "CALL_TARGET",
                "detail": cipher_name,
                "varnode": "",
            }
        ],
    )

def static_iv_finding(
        anchor,
        path,
        primitive: str = "AES",
        section: str | None = None,
        ) -> Finding | None:
    if getattr(path, "terminal", None) != "CONST" or not _looks_like_static_origin(path):
        return None

    origin = getattr(path, "origin", None)
    if origin in (None, "0x0"):
        return None
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    fact_type = "static_iv"
    cwe = "CWE-329"
    tier = "VERIFIED_FACT"

    return Finding(
        id=_finding_id(primitive, fact_type, function, callee, call_addr, str(origin)),
        tier=tier,
        primitive=primitive,
        fact_type=fact_type,
        cwe=cwe,
        summary=f"{primitive} IV operand resolves to constant {origin}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand="iv",
        origin=origin,
        provenance=serialize_provenance(path),
        section=section,
    )


def implicit_zero_iv_finding(anchor, primitive: str = "AES") -> Finding:
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    return Finding(
        id=_finding_id(primitive, "static_iv", function, callee, call_addr, "implicit_zero_iv"),
        tier="VERIFIED_FACT",
        primitive=primitive,
        fact_type="static_iv",
        cwe="CWE-329",
        summary=f"{primitive} CBC helper uses an implicit all-zero IV",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand="iv",
        origin="implicit all-zero IV",
        provenance=[
            {
                "kind": "IMPLICIT_CONST",
                "detail": "CBC chain data initialized to all-zero block inside callee",
                "varnode": callee,
            }
        ],
    )


def weak_randomness_finding(
    anchor, path, primitive: str = "AES", operand: str = "key"
) -> Finding | None:
    source_name = getattr(path, "origin", None)
    if source_name is None or getattr(path, "terminal", None) not in {"TIME", "WEAK_RNG", "WEAK_RNG_SEED"}:
        return None
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    fact_type = "weak_randomness"
    cwe = "CWE-338"
    tier = "VERIFIED_FACT"
    return Finding(
        id=_finding_id(primitive, fact_type, function, callee, call_addr,
        source_name),
        tier=tier,
        primitive=primitive,
        fact_type=fact_type,
        cwe=cwe,
        summary=f"{primitive} {operand} is generated from weak randomness source: {source_name}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand=operand,
        origin=source_name,
        provenance=serialize_provenance(path),
    )


def parameter_set_finding(
    anchor,
    variant: str,
    primitive: str = "ML-KEM",
    path=None,
    operand: str = "callee",
) -> Finding:
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    return Finding(
        id=_finding_id(primitive, "parameter_set", function, callee, call_addr, variant),
        tier="VERIFIED_FACT",
        primitive=primitive,
        fact_type="parameter_set",
        cwe=None,
        summary=f"{primitive} parameter set resolves from the called API symbol: {variant}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand=operand,
        origin=variant,
        provenance=(
            serialize_provenance(path)
            if path is not None
            else [{"kind": "CALL_TARGET", "detail": callee, "varnode": ""}]
        ),
        analyst_note="This is a parameter-set fact, not an exploitability claim.",
    )


def known_weak_algorithm_finding(anchor, primitive: str, selector: str) -> Finding | None:
    if primitive not in {"MD5", "SHA-1", "DES"}:
        return None
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    return Finding(
        id=_finding_id(primitive, "known_weak_algorithm", function, callee, call_addr, selector),
        tier="VERIFIED_FACT",
        primitive=primitive,
        fact_type="known_weak_algorithm",
        cwe="CWE-327",
        summary=f"called algorithm selector resolves to known-weak {primitive}: {selector}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand="algorithm",
        origin=selector,
        provenance=[{"kind": "CALL_TARGET", "detail": selector, "varnode": ""}],
    )


def numeric_parameter_finding(anchor, path, primitive: str, fact_type: str, operand: str) -> Finding | None:
    if getattr(path, "terminal", None) != "CONST":
        return None
    value = int(str(path.origin), 0)
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    return Finding(
        id=_finding_id(primitive, fact_type, function, callee, call_addr, str(value)),
        tier="VERIFIED_FACT",
        primitive=primitive,
        fact_type=fact_type,
        cwe=None,
        summary=f"{primitive} {operand} operand resolves to constant {value}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand=operand,
        origin=str(value),
        provenance=serialize_provenance(path),
        analyst_note="This is a code-intrinsic parameter fact, not an exploitability claim.",
    )


def operand_origin_finding(anchor, path, primitive: str, operand: str) -> Finding | None:
    if getattr(path, "terminal", None) != "RNG":
        return None
    origin = str(path.origin)
    function = str(getattr(anchor, "func_name", ""))
    callee = str(getattr(anchor, "callee", ""))
    call_addr = str(getattr(anchor, "call_addr", ""))
    return Finding(
        id=_finding_id(primitive, "operand_origin", function, callee, call_addr, operand, origin),
        tier="VERIFIED_FACT",
        primitive=primitive,
        fact_type="operand_origin",
        cwe=None,
        summary=f"{primitive} {operand} operand is sourced from {origin}",
        function=function,
        callee=callee,
        call_addr=call_addr,
        operand=operand,
        origin=origin,
        provenance=serialize_provenance(path),
        analyst_note="The source call is code-intrinsic; runtime entropy quality is not asserted.",
    )

def _finding_id(*parts: str) -> str:
    raw = "|".join(parts).encode("utf-8", "replace")
    return sha256(raw).hexdigest()[:16]

def _looks_like_static_origin(path) -> bool:
    origin = getattr(path, "origin", None)

    if origin in (None, "0x0"):
        return False
    if str(origin).startswith("-"):
        return False

    steps = getattr(path, "steps", [])
    if any(getattr(step,"kind", "") == "CYCLE" for step in steps):
        return False
    if any(getattr(step, "detail", "") == "PTRADD" for step in steps):
        return False
    return True
