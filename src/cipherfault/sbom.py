"""Deterministic CycloneDX inventory for the installed CipherFault package."""

from importlib import metadata
import re
from uuid import NAMESPACE_URL, uuid5


def distribution_sbom(distribution_name: str) -> dict:
    distribution = metadata.distribution(distribution_name)
    name = distribution.metadata["Name"]
    version = distribution.version
    root_ref = f"pkg:pypi/{name.lower()}@{version}"
    dependencies = []
    for requirement in distribution.requires or ():
        if "extra ==" in requirement:
            continue
        dependency_name = re.split(r"[\s[(<>=!~;]", requirement, maxsplit=1)[0]
        try:
            dependency_version = metadata.version(dependency_name)
        except metadata.PackageNotFoundError:
            continue
        dependencies.append({
            "type": "library",
            "bom-ref": f"pkg:pypi/{dependency_name.lower()}@{dependency_version}",
            "name": dependency_name,
            "version": dependency_version,
            "purl": f"pkg:pypi/{dependency_name.lower()}@{dependency_version}",
        })
    dependencies.sort(key=lambda component: component["name"].lower())
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, root_ref)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": name,
                "version": version,
                "purl": root_ref,
            }
        },
        "components": dependencies,
        "dependencies": [{
            "ref": root_ref,
            "dependsOn": [component["bom-ref"] for component in dependencies],
        }],
    }
