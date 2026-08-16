#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, "src")

from cipherfault.cbom import validate_cbom
from cipherfault.sbom import distribution_sbom


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("reports/cipherfault.sbom.json"))
    args = parser.parse_args(argv)
    document = distribution_sbom("cipherfault")
    validate_cbom(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
