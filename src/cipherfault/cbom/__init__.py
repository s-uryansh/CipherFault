"""CycloneDX 1.6 CBOM serialization without vulnerability claims."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import gettempdir
from urllib.request import urlopen
from uuid import NAMESPACE_URL, uuid5

from cipherfault.report import AnalysisReport, PrimitiveEvidence


SCHEMA_URL = "https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json"
SCHEMA_SHA256 = "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"
SCHEMA_CACHE = Path(gettempdir()) / "cipherfault-bom-1.6.schema.json"


def validate_cbom(document: dict, schema_path: str | Path = SCHEMA_CACHE) -> None:
    """Validate a CBOM against the pinned official CycloneDX 1.6 schema."""
    import jsonschema

    schema = json.loads(_official_schema(Path(schema_path)))
    jsonschema.Draft7Validator(schema).validate(document)


def _official_schema(cache_path: Path) -> bytes:
    if cache_path.exists():
        cached = cache_path.read_bytes()
        if sha256(cached).hexdigest() == SCHEMA_SHA256:
            return cached

    with urlopen(SCHEMA_URL, timeout=30) as response:
        downloaded = response.read()
    digest = sha256(downloaded).hexdigest()
    if digest != SCHEMA_SHA256:
        raise ValueError(f"CycloneDX schema checksum mismatch: {digest}")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(downloaded)
    return downloaded


def report_to_cbom(report: AnalysisReport) -> dict:
    target_ref = f"target:{report.target_sha256}"
    assets = [_asset(report, primitive) for primitive in report.primitives]
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, report.target_sha256)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "file",
                "bom-ref": target_ref,
                "name": report.target,
                "hashes": [{"alg": "SHA-256", "content": report.target_sha256}],
            },
            "properties": [
                {"name": "cipherfault:schema_version", "value": report.schema_version},
                {"name": "cipherfault:analysis_posture", "value": json.dumps(report.to_dict()["posture"], sort_keys=True)},
            ],
        },
        "components": assets,
        "dependencies": [
            {"ref": target_ref, "dependsOn": [asset["bom-ref"] for asset in assets]}
        ],
    }


def _asset(report: AnalysisReport, primitive: PrimitiveEvidence) -> dict:
    ref = f"crypto:{report.target_sha256}:{primitive.primitive}:{primitive.address}"
    facts = [
        fact.to_dict()
        for fact in report.verified_facts
        if fact.primitive == primitive.primitive and fact.call_addr == primitive.address
    ]
    indicators = [
        asdict(indicator)
        for indicator in report.indicators
        if indicator.primitive == primitive.primitive and primitive.address in indicator.addresses
    ]
    kind = {
        "ML-KEM": "kem",
        "ML-DSA": "signature",
        "SLH-DSA": "signature",
        "RSA": "pke",
        "ECC": "other",
        "MD5": "hash",
        "SHA-1": "hash",
        "SHA-224": "hash",
        "SHA-256": "hash",
        "SHA-384": "hash",
        "SHA-512": "hash",
    }.get(primitive.primitive, "block-cipher")
    algorithm = {
        "primitive": kind,
        "implementationPlatform": report.target_arch,
    }
    if primitive.variant:
        algorithm["parameterSetIdentifier"] = primitive.variant
    mode = next((fact.origin.rsplit("_", 1)[-1].lower() for fact in report.verified_facts if fact.call_addr == primitive.address and fact.fact_type == "ecb_mode"), None)
    if mode:
        algorithm["mode"] = mode
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": primitive.variant or primitive.primitive,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm,
        },
        "properties": [
            {"name": "cipherfault:address", "value": primitive.address},
            {"name": "cipherfault:recognition_method", "value": primitive.method},
            {"name": "cipherfault:confidence", "value": str(primitive.confidence)},
            {"name": "cipherfault:verified_facts", "value": json.dumps(facts, sort_keys=True)},
            {"name": "cipherfault:indicators", "value": json.dumps(indicators, sort_keys=True)},
        ],
    }
