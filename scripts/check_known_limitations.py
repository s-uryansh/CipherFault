#!/usr/bin/env python3
"""Check expected limitations that are not promoted to verified facts."""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, "src")

from cipherfault.scanner import scan_binary


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    case_dir = ROOT / "corpus" / "eval" / "CVE-2017-3225"
    target = case_dir / "target_uboot_cve_2017_3225_allstrip.o"
    reference = case_dir / "target_uboot_cve_2017_3225_reference.o"
    if not target.exists() or not reference.exists():
        raise SystemExit("known-limitation fixture is missing; run scripts/build_cve_fixtures.sh")

    report = scan_binary(target, fingerprint_reference=reference)
    if report.verified_facts:
        raise SystemExit("fully stripped U-Boot relocatable unexpectedly emitted verified facts")
    print("known limitations ok: fully stripped U-Boot relocatable emits no Tier-1 facts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
