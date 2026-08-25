import json
import sys

sys.path.insert(0, "src")

from cipherfault.cbom import report_to_cbom, validate_cbom
from cipherfault.report import AnalysisReport, Indicator, PrimitiveEvidence
from cipherfault.rules import Finding


def _report():
    finding = Finding(
        id="abc",
        tier="VERIFIED_FACT",
        primitive="AES",
        fact_type="hardcoded_key",
        cwe="CWE-321",
        summary="AES key operand resolves to constant 0x102010",
        function="encrypt_record",
        callee="EVP_EncryptInit_ex",
        call_addr="00101234",
        operand="key",
        origin="0x102010",
        provenance=[],
        section=".rodata",
    )
    return AnalysisReport(
        target="aes_ecb_demo_strip",
        target_sha256="a" * 64,
        primitives=[PrimitiveEvidence("AES", "00101234", "resolved_api_anchor", 1.0)],
        verified_facts=[finding],
        indicators=[Indicator("INDICATOR", "AES", "same IV", "multiple sessions?", "encrypt_record", ("00101234",), "iv")],
    )


def test_report_to_cbom_exports_crypto_asset_not_vulnerability():
    bom = report_to_cbom(_report())

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["name"] == "aes_ecb_demo_strip"
    assert "vulnerabilities" not in bom
    asset = bom["components"][0]
    assert asset["type"] == "cryptographic-asset"
    assert asset["cryptoProperties"]["assetType"] == "algorithm"
    facts = next(p["value"] for p in asset["properties"] if p["name"] == "cipherfault:verified_facts")
    assert json.loads(facts)[0]["id"] == "abc"
    indicators = next(p["value"] for p in asset["properties"] if p["name"] == "cipherfault:indicators")
    assert json.loads(indicators)[0]["tier"] == "INDICATOR"


def test_report_to_cbom_validates_against_official_schema():
    validate_cbom(report_to_cbom(_report()))


def test_validate_cbom_uses_bundled_schema_without_network(monkeypatch, tmp_path):
    def fail_network(*_args, **_kwargs):
        raise AssertionError("network should not be used")

    monkeypatch.setattr("cipherfault.cbom.urlopen", fail_network)

    validate_cbom(report_to_cbom(_report()), schema_path=tmp_path / "missing-schema.json")


def test_mlkem_asset_carries_parameter_set_identifier():
    report = AnalysisReport(
        target="kem",
        target_sha256="b" * 64,
        primitives=[PrimitiveEvidence("ML-KEM", "00100000", "resolved_api_anchor", 1.0, "ML-KEM-768")],
    )

    algorithm = report_to_cbom(report)["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["primitive"] == "kem"
    assert algorithm["parameterSetIdentifier"] == "ML-KEM-768"


def test_digest_asset_uses_hash_primitive():
    report = AnalysisReport(
        target="digest",
        target_sha256="c" * 64,
        primitives=[PrimitiveEvidence("SHA-256", "00100000", "resolved_api_anchor", 1.0)],
    )

    algorithm = report_to_cbom(report)["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["primitive"] == "hash"


def test_pqc_signature_assets_use_signature_primitive():
    report = AnalysisReport(
        target="signatures",
        target_sha256="d" * 64,
        primitives=[
            PrimitiveEvidence("ML-DSA", "00100000", "resolved_api_anchor", 1.0, "ML-DSA-65"),
            PrimitiveEvidence("SLH-DSA", "00100010", "resolved_api_anchor", 1.0, "SLH-DSA-SHA2-128s"),
        ],
    )

    assets = report_to_cbom(report)["components"]

    assert {asset["cryptoProperties"]["algorithmProperties"]["primitive"] for asset in assets} == {"signature"}


def test_rsa_asset_uses_public_key_encryption_primitive():
    report = AnalysisReport(
        target="rsa",
        target_sha256="e" * 64,
        primitives=[PrimitiveEvidence("RSA", "00100000", "resolved_api_anchor", 1.0)],
    )

    algorithm = report_to_cbom(report)["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["primitive"] == "pke"


def test_ecc_constructor_asset_does_not_guess_usage_primitive():
    report = AnalysisReport(
        target="ecc",
        target_sha256="f" * 64,
        primitives=[PrimitiveEvidence("ECC", "00100000", "resolved_api_anchor", 1.0)],
    )

    algorithm = report_to_cbom(report)["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["primitive"] == "other"


def test_aes_variant_sets_cbom_mode():
    report = AnalysisReport(
        target="cbc",
        target_sha256="1" * 64,
        primitives=[PrimitiveEvidence("AES", "00100000", "resolved_api_anchor", 1.0, "AES-CBC")],
    )

    algorithm = report_to_cbom(report)["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["mode"] == "cbc"
    assert "parameterSetIdentifier" not in algorithm


def test_low_level_ecb_symbol_sets_ecb_mode_not_encrypt():
    finding = Finding(
        id="ecb",
        tier="VERIFIED_FACT",
        primitive="AES",
        fact_type="ecb_mode",
        cwe="CWE-327",
        summary="AES cipher selector resolves to ECB mode: AES_ecb_encrypt",
        function="main",
        callee="AES_ecb_encrypt",
        call_addr="00100000",
        operand="cipher",
        origin="AES_ecb_encrypt",
        provenance=[],
    )
    report = AnalysisReport(
        target="ecb",
        target_sha256="2" * 64,
        primitives=[PrimitiveEvidence("AES", "00100000", "resolved_api_anchor", 1.0)],
        verified_facts=[finding],
    )

    algorithm = report_to_cbom(report)["components"][0]["cryptoProperties"]["algorithmProperties"]

    assert algorithm["mode"] == "ecb"
