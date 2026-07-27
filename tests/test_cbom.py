import sys

sys.path.insert(0, "src")

from cipherfault.cbom import findings_to_cbom
from cipherfault.rules import Finding


def test_findings_to_cbom_exports_cyclonedx_shape():
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
    )

    bom = findings_to_cbom([finding], "aes_ecb_demo_strip")

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["name"] == "aes_ecb_demo_strip"
    assert bom["vulnerabilities"][0]["id"] == "abc"
    assert bom["vulnerabilities"][0]["cwes"] == [321]
