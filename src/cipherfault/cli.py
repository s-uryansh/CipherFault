"""CipherFault command line interface."""

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .cbom import report_to_cbom
from .scanner import scan_binary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cipherfault",
        description="Extract evidence from cooperative x86_64/AArch64 ELF binaries; no exploitability claim.",
        epilog="Posture: recognizer precision-tuned; rules recall-tuned; analysis is neither sound nor complete.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a binary for verified crypto facts")
    scan.add_argument("binary", type=Path)
    scan.add_argument(
        "--fingerprint-reference",
        type=Path,
        help="unstripped matching build used to recover names in a stripped static binary",
    )
    scan.add_argument(
        "--format",
        choices=("text", "json", "cbom"),
        default="text",
        help="output format",
    )
    sub.add_parser("saas-init", help="create first-run SaaS database structure")

    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            report = scan_binary(args.binary, fingerprint_reference=args.fingerprint_reference)
        except Exception as exc:
            print(f"cipherfault: analysis failed: {exc}", file=sys.stderr)
            return 1
        if args.format == "cbom":
            print(
                json.dumps(
                    report_to_cbom(report),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.format == "json":
            print(
                json.dumps(
                    report.to_dict(),
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for primitive in report.primitives:
                print(
                    f"PRIMITIVE {primitive.primitive} {primitive.address} "
                    f"via {primitive.method}"
                )
            for candidate in report.recognition_candidates:
                print(
                    f"CANDIDATE {candidate.primitive} {candidate.address} "
                    f"confidence={candidate.confidence:.3f} via {candidate.method}"
                )
            for finding in report.to_dict()["verified_facts"]:
                cwe = f" {finding['cwe']}" if finding["cwe"] else ""
                print(
                    f"{finding['tier']}{cwe} "
                    f"{finding['function']}@{finding['call_addr']}: "
                    f"{finding['summary']}"
                )
            for indicator in report.indicators:
                print(
                    f"INDICATOR {indicator.function}@{','.join(indicator.addresses)}: "
                    f"{indicator.pattern}; {indicator.analyst_question}"
                )
            for diagnostic in report.diagnostics:
                location = f" @{diagnostic.address}" if diagnostic.address else ""
                print(f"DIAGNOSTIC {diagnostic.code}{location}: {diagnostic.message}")
        return 0

    if args.command == "saas-init":
        try:
            from .api.bootstrap import init_structured_data

            print(json.dumps(init_structured_data(), sort_keys=True))
            return 0
        except Exception as exc:
            print(f"cipherfault: SaaS init failed: {exc}", file=sys.stderr)
            return 1

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
