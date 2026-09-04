# CipherFault

**A crypto-usage evidence engine for compiled software.**

![status](https://img.shields.io/badge/status-active%20development-blue)
![python](https://img.shields.io/badge/python-3.13-blue)
![platform](https://img.shields.io/badge/platform-ELF%20x86__64%20%7C%20AArch64-informational)
![lifter](https://img.shields.io/badge/lifter-Ghidra%20P--code-orange)
![cbom](https://img.shields.io/badge/CBOM-CycloneDX%201.6-informational)

CipherFault recognizes classical and post-quantum cryptography in compiled software,
then extracts code-intrinsic usage evidence with an auditable provenance path. It is
designed for cooperative supply-chain binaries: vendor components, third-party
dependencies, firmware, and legacy software that is not actively fighting analysis.

CipherFault is **not a vulnerability detector** and makes **no exploitability claim**.
Exploitability depends on runtime and protocol context that a binary alone does not
provide.

## Evidence tiers

The tiers are structurally separate in JSON and CBOM output.

### `VERIFIED_FACT`

A code-intrinsic fact derived from the binary with a provenance path. Current examples:

- AES ECB selected through EVP or a recognized low-level AES API (`CWE-327`).
- AES key resolved to `.rodata`, a returned constant, a resolved buffer copy, or a
  constant buffer fill (`CWE-321`).
- AES-CBC IV resolved to static storage, a constant buffer fill, or an implicit
  all-zero helper state (`CWE-329`).
- Key, IV, or ML-KEM randomness traced to a named RNG source.
- `rand()`/time-derived data reaching key or encapsulation randomness (`CWE-338`).
- MD5 and SHA-1 selected through resolved digest APIs (`CWE-327`).
- RSA key size, ECC named curve, and ML-KEM/ML-DSA/SLH-DSA parameter set.

### `INDICATOR`

A runtime-dependent pattern phrased as an analyst question, never as a fact:

- RNG source observed: is it correctly configured and seeded at runtime?
- Same IV/key operand reused in function scope: does the function span independent
  sessions or encapsulations?
- Signature-verification result has no observed enforcement: is it enforced elsewhere?

## Architecture

```text
Linux ELF (x86_64 / AArch64)
        |
        v
Ghidra P-code + CFG/DFG lifting
        |
        +-------------------------------+
        v                               v
Static/API fingerprint anchors     Eight-class region recognizer
                                   (precision-gated)
        |                               |
        +---------------+---------------+
                        v
      bounded deterministic provenance and last-writer checks
                        |
          +-------------+-------------+
          v                           v
   Tier 1 VERIFIED_FACT       Tier 2 INDICATOR
          |                           |
          +-------------+-------------+
                        v
       JSON + usage-aware CycloneDX 1.6 CBOM
       + explicit machine-readable analysis posture
```

The recognizer classifies regions as `AES`, `RSA`, `ECC`, `SHA`, `ML-KEM`,
`ML-DSA`, `SLH-DSA`, or `none`. Runtime assertions are restricted to labels that
pass the source-family-held-out precision gate recorded in
`models/recognizer.metrics.json`. The current artifact passes that all-class gate.

## Installation

Python 3.13, Java, and a local Ghidra installation are required.

```bash
git clone <cipherfault-repository-url>
cd cipherfault
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

All commands below assume the virtual environment is active. If `pyghidra.start()`
fails, verify `GHIDRA_INSTALL_DIR`, Java, and the Ghidra installation.

## Usage

Verify the installed command:

```bash
cipherfault --version
cipherfault --help
cipherfault scan --help
```

Scan any supported ELF binary:

```bash
cipherfault scan ./path/to/binary
```

Default text output prints recognized primitives, low-confidence recognition
candidates, Tier-1 `VERIFIED_FACT` entries, Tier-2 `INDICATOR` questions, and
diagnostics. Use machine-readable output for automation:

```bash
cipherfault scan ./path/to/binary --format json > evidence.json
cipherfault scan ./path/to/binary --format cbom > cbom.cdx.json
```

For stripped or statically linked targets where matching unstripped build output is
available, pass it as a fingerprint reference:

```bash
cipherfault scan ./target-stripped --fingerprint-reference ./target-with-symbols
```

To run against a known local fixture from this repository:

```bash
bash scripts/build_fixtures.sh
cipherfault scan corpus/build/fixtures/aes_cbc_static_iv/target
cipherfault scan corpus/build/fixtures/aes_cbc_static_iv/target --format json
cipherfault scan corpus/build/fixtures/aes_cbc_static_iv/target --format cbom
```

The CLI exits `0` when analysis completes, even if it reports findings or diagnostics.
It exits non-zero only when analysis cannot run, for example an unsupported input file,
missing target, or Ghidra startup/lifting failure.

Supported inputs are currently 64-bit little-endian Linux ELF binaries for x86_64 and
AArch64. PE, Mach-O, ARM32, MIPS, adversarial obfuscation, packers, and malware are not
yet supported.

## Example verified fact

```json
{
  "tier": "VERIFIED_FACT",
  "primitive": "AES",
  "fact_type": "static_iv",
  "cwe": "CWE-329",
  "summary": "AES IV operand resolves to constant 0x6012c0",
  "origin": "0x6012c0",
  "section": ".rodata",
  "provenance": [
    {"kind": "OP", "detail": "PTRSUB", "varnode": "..."},
    {"kind": "CONST", "detail": "0x6012c0", "varnode": "..."}
  ],
  "analyst_note": "Exploitability requires context not present in the binary."
}
```

## Corpus and recognizer

The current matrix contains **9,295 successful artifacts**:

- GCC 11, 12, and 13; Clang 15, 16, and 17.
- x86_64 and AArch64.
- GCC: O0, O1, O2, O3, Os.
- Clang: O0, O1, O2, O3, Os, Oz.
- Classical implementations from OpenSSL, BoringSSL, BearSSL, libsodium, mbedTLS,
  wolfSSL, and independent AES sources.
- PQC implementations from PQClean, liboqs, OpenSSL, and BoringSSL, including optimized
  AVX2/NEON-relevant families rather than reference C alone.
- Non-crypto hard negatives from SQLite, zlib, libpng, and other independent sources.

Training, calibration, and test families are source-disjoint. Labels use DWARF
subprogram/inline ranges before stripping, and graphs retain typed CFG/DFG edges,
instruction/P-code features, referenced read-only bytes, compiler, optimization, and
architecture metadata.

```bash
bash scripts/fetch_corpus.sh
bash scripts/fetch_toolchains.sh
python scripts/build_matrix.py
python scripts/build_recognizer_dataset.py
python scripts/train_recognizer.py
python scripts/check_recognizer_artifacts.py --require-artifacts --require-all-class
```

`build_matrix.py` writes `corpus/build/matrix/metadata.jsonl` directly for a local
one-shot build. Use `merge_matrix_metadata.py` only when you intentionally built
separate shard files under `corpus/build/matrix/shards/`; stale shards from an older
matrix can fail validation with a source-count mismatch.

See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for pinned source revisions, toolchain
checksums, and expected gate outputs for the current baseline.

The current recognizer baseline run produced 78,071 regions. Dataset generation is
resource-heavy and training is CPU-only today. The current artifacts are
precision-gated and deployable only for labels listed in
`models/recognizer.metrics.json` under `deployable_labels`. In the current run, the
all-class source-heldout gate passes for AES, RSA, ECC, SHA, ML-KEM, ML-DSA, and
SLH-DSA.

When at least one label is precision-gated, `scripts/train_recognizer.py` writes
`models/recognizer.pt` and `models/recognizer.semantic.joblib`. Some classes are
gated by a conservative symbol-name head; those assertions require matching symbol or
fingerprint-equivalent name evidence at runtime. To use an already-built model outside
`models/`, set:

```bash
export CIPHERFAULT_RECOGNIZER_MODEL=/path/to/recognizer.pt
```

## Evaluation

Current manifests contain nine local positive cases, six negative-control cases, one
MITRE CWE-329 external-reference case, one public real-code negative case, three public
PQC API-style cases from liboqs/BoringSSL, one independently sourced demo, and one
genuine CVE gate for U-Boot CVE-2017-3225.

```bash
python scripts/evaluate_manifest.py corpus/eval/manifest.local.json
python scripts/evaluate_manifest.py corpus/eval/manifest.negative.json
python scripts/evaluate_manifest.py corpus/eval/manifest.external.json
python scripts/evaluate_manifest.py corpus/eval/manifest.real.json
python scripts/evaluate_manifest.py corpus/eval/manifest.pqc.json
python scripts/evaluate_manifest.py corpus/eval/manifest.demo.json
bash scripts/build_cve_fixtures.sh
python scripts/evaluate_manifest.py corpus/eval/manifest.cve.json
```

The CVE gate builds U-Boot commit `d85ca029f257b53a96da6c2fb421e78a003a9943`
from ignored upstream source into a debug-stripped relocatable object and checks that
the AES-CBC helper emits `CWE-329` with origin `implicit all-zero IV`. Fully
symbol-stripped relocatable U-Boot objects are still a fingerprinting limitation.

## Testing

```bash
bash scripts/build_fixtures.sh
python -m pytest -q tests
bash scripts/verify.sh
```

The full release-style check currently passes with local/negative/external/real/PQC/CVE/demo
manifest evaluation, positive-manifest recall thresholds, wheel install, offline SBOM
generation, the expected-limitation check, and the all-class recognizer gate checked
with `--require-all-class`.

The SaaS API and worker images are defined in `docker/api.Dockerfile` and
`docker/worker.Dockerfile`.

## Repository layout

```text
cipherfault/
├── src/cipherfault/
│   ├── lifting/       # Ghidra CFG/DFG lifting
│   ├── recognizer/    # Region features, GNN model, runtime gate
│   ├── taint/         # Anchors and bounded provenance
│   ├── rules/         # Deterministic Tier-1 findings
│   ├── indicators.py  # Structurally separate Tier-2 questions
│   ├── pqc/           # PQC parameter metadata
│   └── cbom/          # CycloneDX 1.6 export
├── corpus/
│   ├── config/        # Corpus build configuration
│   ├── fixtures/      # Known-answer fixtures
│   ├── eval/          # Evaluation manifests; downloaded sources ignored
│   └── build/         # Generated artifacts and caches; ignored
├── models/            # Model cards/metrics; binary checkpoints ignored
├── scripts/           # Corpus, training, evaluation, and release checks
├── tests/
├── requirement.txt
└── pyproject.toml
```

## Analysis posture

- **Soundness:** not guaranteed. Unresolved aliasing, indirect calls, and unsupported
  transforms are cut and reported rather than promoted to Tier 1.
- **Completeness:** not guaranteed. Depth bounds, conservative last-writer checks, and
  recognizer errors can miss facts.
- **Recognizer operating point:** precision-first; low-confidence regions are triage
  candidates, never verified usage facts.
- **Rule operating point:** recall-oriented, but a Tier-1 fact still requires a concrete
  provenance path.
- **Scope:** cooperative software only.
- **Exploitability:** never claimed.

## License and commercial use

CipherFault is public source under the custom CipherFault Public Source License. See
`LICENSE` for controlling terms. The repository does not constitute a patent
freedom-to-operate opinion; obtain qualified counsel before commercial distribution.
