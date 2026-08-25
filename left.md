# Technical Work Left

This file tracks only technical implementation and validation work for the local
binary-analysis project.

## Goal

Get CipherFault technically complete for the currently implemented cooperative Linux
ELF pipeline, with claims backed by repeatable tests and external validation.

## Remaining Technical Work

| Area | What is left | Done when |
|---|---|---|
| Real-binary evaluation | Add more public, reproducible real-binary evaluation cases beyond the current local/external/demo/U-Boot/Moonlight gate. | `scripts/verify.sh` covers several independent real binaries with expected findings and negative controls. |
| CVE coverage | Add more confirmed crypto-misuse CVE fixtures where source and build steps are public and reproducible. | CVE manifest includes multiple classical and PQC-relevant cases, all built and checked automatically. |
| Static-anchor validation | Stress static/fingerprint anchors on stripped and statically linked binaries where PLT/symbol recovery is weak. | Manifest cases prove API/static anchors still populate Tier-1 facts without relying on easy symbols. |
| Name-independent recognition | Reduce dependence on the symbol-name head for RSA, ECC, SHA, and SLH-DSA. | All-class recognizer gate still passes when symbol-name evidence is absent or ablated on a held-out split. |
| PQC evaluation | Add public optimized PQC binaries for ML-KEM, ML-DSA, and SLH-DSA beyond the current liboqs/PQClean/corpus mix. | PQC manifest validates parameter extraction and randomness-origin facts on independent optimized implementations. |

## Useful External Inputs

Human help is useful only for finding good public fixtures, not for normal coding.
Best candidates have a public source revision, deterministic build commands, a small
Linux ELF target, and an expected crypto-usage fact that can be checked by manifest.

- Real binaries: small open-source projects that call OpenSSL, mbedTLS, wolfSSL, or
  liboqs and can be built without accounts or private dependencies.
- CVE fixtures: confirmed crypto-misuse fixes where the vulnerable revision and build
  path are public, preferably producing a focused object or binary.
- Static-anchor cases: stripped or statically linked binaries where symbol/PLT evidence
  is intentionally weak but the expected usage fact is known.
- PQC cases: optimized liboqs, AWS-LC, BoringSSL, or equivalent ML-KEM/ML-DSA/SLH-DSA
  binaries with known parameter set and randomness wiring.

## Public Fixture Leads

These are candidate leads found so far. They still need local build scripts and
manifest expectations before they count as completed evaluation coverage.

| Lead | Why it helps | Expected use |
|---|---|---|
| liboqs `tests/example_kem.c` / `tests/example_sig.c` | Small public PQC examples with documented POSIX compile commands. | Added as focused ML-KEM/ML-DSA parameter evaluation in `manifest.pqc.json`. |
| BoringSSL ML-KEM add commit `500fa1f9d274d06ddfc112e1815ad5dc5ce92234` | Public optimized ML-KEM implementation landing point. | Optimized PQC recognition and parameter extraction stress case. |
| OpenSSL `apps/speed.c` | Real OpenSSL program with a global IV buffer passed into EVP cipher setup. | Real-binary static-IV/operand-origin positive or benchmark-only fixture. |
| Moonlight `PlatformCrypto.c` | Small C crypto wrapper using OpenSSL AES-GCM and AES-CBC. | Added as a real-code dynamic-operand negative fixture in `manifest.real.json`. |
| OpenSSL CVE-2023-5363 | Public OpenSSL CVE about IV length handling with referenced fix commits. | Future length/parameter rule candidate, not covered by current Tier-1 rules. |
| OpenSSL CVE-2016-2107 | Public OpenSSL CVE with fix commit references. | Future padding-oracle/verification behavior research case, not a current provenance fact. |

## Completed During Current Hardening Pass

- Recognizer slice gates now fail the artifact gate if any supported architecture,
  compiler, or optimization slice drops below the configured precision floor.
- Positive manifests now enforce `--min-recall 1.0` in local verification and CI.
- CI now runs the all-class recognizer metric gate, local/negative/CVE/demo manifests,
  the known-limitation check, wheel install, SBOM generation, and container smoke checks.
- Fully symbol-stripped U-Boot relocatable behavior is covered by
  `scripts/check_known_limitations.py`.
- A MITRE CWE-329 external-reference fixture is compiled to stripped Linux ELF and
  checked with manifest recall 1.0.
- Public Moonlight and liboqs example fixtures are fetched at pinned commits, built as
  focused ELF objects, and checked in the release-style gate.
- [REPRODUCIBILITY.md](REPRODUCIBILITY.md) records source revisions, toolchain checksums,
  rebuild commands, and expected outputs.

## Current Verified Baseline

- Overall technical completion estimate: **90%**.
- `python -m pytest -q tests`: **129 passed**.
- `bash scripts/verify.sh`: **passed**.
- All-class recognizer artifact gate: **passed** for AES, RSA, ECC, SHA, ML-KEM,
  ML-DSA, and SLH-DSA.
- Local positive, negative-control, external-reference, independent demo, and U-Boot
  CVE-2017-3225 manifests pass.
- Wheel install and offline SBOM/CBOM schema validation pass.

## Deferred Product Work

- SaaS conversion.
