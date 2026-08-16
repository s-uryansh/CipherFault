import sys

sys.path.insert(0, "src")

from cipherfault.cbom import validate_cbom
from cipherfault.sbom import distribution_sbom


def test_distribution_sbom_is_valid_cyclonedx():
    sbom = distribution_sbom("cipherfault")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert sbom["metadata"]["component"]["name"] == "cipherfault"
    assert {component["name"] for component in sbom["components"]} >= {
        "networkx",
        "pyghidra",
    }
    validate_cbom(sbom)
