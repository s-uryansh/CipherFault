"""Stable, JSON-serializable analysis result types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

from .rules import Finding
from .taint.tracer import MAX_INTERPROCEDURAL_HOPS


SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    address: str | None = None


@dataclass(frozen=True)
class PrimitiveEvidence:
    primitive: str
    address: str
    method: str
    confidence: float | None = None
    variant: str | None = None


@dataclass(frozen=True)
class Indicator:
    tier: str
    primitive: str
    pattern: str
    analyst_question: str
    function: str
    addresses: tuple[str, ...]
    operand: str


@dataclass(frozen=True)
class AnalysisPosture:
    sound: bool = False
    complete: bool = False
    exploitability_claim: bool = False
    scope: str = "cooperative software"
    platform: str = "Linux ELF x86_64/AArch64"
    limits: tuple[str, ...] = (
        "learned region recognition is precision-gated; low-confidence regions are candidates only",
        f"bounded inter-procedural provenance (maximum {MAX_INTERPROCEDURAL_HOPS} caller hops)",
        "buffer-source correlation follows resolved callers only within the depth bound",
        "indirect calls and ambiguous aliases may be missed",
    )


@dataclass
class AnalysisReport:
    target: str
    target_sha256: str
    target_arch: str = "x86_64"
    primitives: list[PrimitiveEvidence] = field(default_factory=list)
    recognition_candidates: list[PrimitiveEvidence] = field(default_factory=list)
    verified_facts: list[Finding] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    posture: AnalysisPosture = field(default_factory=AnalysisPosture)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def target_sha256(path: str | Path) -> str:
    digest = sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
