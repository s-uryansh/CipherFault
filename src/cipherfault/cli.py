"""CipherFault command line interface."""

import argparse
import json
from pathlib import Path

from .cbom import findings_to_cbom
from .scanner import findings_as_dicts, scan_binary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cipherfault")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a binary for verified crypto facts")
    scan.add_argument("binary", type=Path)
    out = scan.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="emit JSON findings")
    out.add_argument("--cbom", action="store_true", help="emit CycloneDX JSON")

    args = parser.parse_args(argv)
    if args.command == "scan":
        findings = scan_binary(args.binary)
        if args.cbom:
            print(
                json.dumps(
                    findings_to_cbom(findings, str(args.binary)),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.json:
            print(
                json.dumps(
                    {"findings": findings_as_dicts(findings)},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for finding in findings_as_dicts(findings):
                print(
                    f"{finding['tier']} {finding['cwe']} "
                    f"{finding['function']}@{finding['call_addr']}: "
                    f"{finding['summary']}"
                )
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
