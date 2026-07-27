import os
import sys

import pytest

sys.path.insert(0, "src")

pytest.importorskip("pyghidra")

from cipherfault.scanner import scan_binary


FIXTURE = "corpus/build/aes_ecb_demo_strip"


@pytest.mark.skipif(not os.path.exists(FIXTURE), reason="fixture not built")
def test_scanner_emits_hardcoded_key_for_stripped_aes_fixture():
    findings = scan_binary(FIXTURE)

    assert any(
        finding.fact_type == "hardcoded_key"
        and finding.cwe == "CWE-321"
        and finding.tier == "VERIFIED_FACT"
        and finding.origin == "0x102010"
        for finding in findings
    )
