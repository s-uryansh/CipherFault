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
    cwe: str
    summary: str
    function: str
    callee: str
    call_addr: str
    operand: str
    origin: str | None
    provenance: list[dict[str, str]]

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


def hardcoded_key_finding(anchor, path, primitive: str = "AES") -> Finding | None:
    if getattr(path, "terminal", None) != "CONST":
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

def static_iv_finding(anchor, path, primitive: str = "AES") -> Finding | None:
    if getattr(path, "terminal", None) != "CONST":
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
    )

def _finding_id(*parts: str) -> str:
    raw = "|".join(parts).encode("utf-8", "replace")
    return sha256(raw).hexdigest()[:16]