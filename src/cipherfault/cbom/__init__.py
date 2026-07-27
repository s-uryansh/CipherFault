"""Minimal CycloneDX-compatible CBOM export"""

import json
from datetime import datetime, timezone

from cipherfault.rules import Finding


def findings_to_cbom(findings: list[Finding], target: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "file",
                "name": target,
            },
            "properties": [
                {
                    "name": "cipherfault:analysis_posture",
                    "value": "static evidence engine; no exploitability claim",
                }
            ],
        },
        "components": [],
        "vulnerabilities": [
            {
                "id": finding.id,
                "source": {"name": "CipherFault"},
                "ratings": [{"method": "other", "severity": "unknown"}],
                "cwes": [_cwe_number(finding.cwe)],
                "description": finding.summary,
                "properties": [
                    {"name": "cipherfault:tier", "value": finding.tier},
                    {"name": "cipherfault:primitive", "value": finding.primitive},
                    {"name": "cipherfault:fact_type", "value": finding.fact_type},
                    {"name": "cipherfault:function", "value": finding.function},
                    {"name": "cipherfault:callee", "value": finding.callee},
                    {"name": "cipherfault:call_addr", "value": finding.call_addr},
                    {"name": "cipherfault:operand", "value": finding.operand},
                    {"name": "cipherfault:origin", "value": str(finding.origin)},
                    {
                        "name": "cipherfault:provenance",
                        "value": json.dumps(finding.provenance, sort_keys=True),
                    },
                ],
            }
            for finding in findings
        ],
    }


def _cwe_number(cwe: str) -> int:
    return int(cwe.removeprefix("CWE-"))
