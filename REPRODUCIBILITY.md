# Reproducibility

This file records the current technical baseline for rebuilding and auditing the
CipherFault cooperative Linux ELF pipeline. Product packaging, hosted service work,
and commercial decisions are tracked separately from this technical baseline.

## Environment

- Python: 3.13
- Java: required by Ghidra
- Ghidra: 12.1.2 public build in CI
- Host targets: Linux ELF, x86_64 and AArch64
- Native compilers: GCC 11/12/13 and Clang 15/16/17
- AArch64 cross toolchains:
  - `arm-gnu-toolchain-11.3.rel1`, SHA-256 `50cdef6c5baddaa00f60502cc8b59cc11065306ae575ad2f51e412a9b2a90364`
  - `arm-gnu-toolchain-12.3.rel1`, SHA-256 `960ec0bce309528f603639d8228ef39e6fb9185289ff42b01aa3b4de315accef`
  - `arm-gnu-toolchain-13.3.rel1`, SHA-256 `322f0b4482fc0d9fa0bb468134841f08d8c554c54ff5aa29a13a7a24bf7e1eb5`

## Source Revisions

These are the revisions used by the current corpus/evaluation baseline.

| Source | Revision |
|---|---|
| OpenSSL | `799252f3b67d0429e64736f922a3c2860135facb` |
| BoringSSL | `f1f2556a5dfa59e147d9d47279cc3f7f8a18b433` |
| libsodium | `2ce4d906a68eae82b27b4867f3d4172ec508cb27` from `scripts/fetch_corpus.sh`; local tree has no `.git` metadata |
| liboqs | `9d20051143544daa348bc0bbdcef5ef121e385d3` |
| PQClean | `202a8f96315f9ed219387a50f7e40d04af037ea8` |
| AWS-LC | `3c23b445e5ef21a32e46f36ee9704c1ebb3bd2f1` |
| zlib | `e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca` |
| libpng | `d1d0abeffede1cc898ddc3d0e600839cf026d749` |
| SQLite | `da7dc33fb2075dc9a9376679889f6843c33d6cb9` |
| mbedTLS | `ce0384b99949b5c8e80548d3b311c39ed0d5eb7a` |
| tiny-AES-c | `23856752fbd139da0b8ca6e471a13d5bcc99a08d` |
| wolfSSL | `ac01707f552c611fbd135cc723b2682b3e7f80f2` |
| BearSSL | `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f` |
| PalmTree | `4a87e058a2f16835ecaa18b2674d5db3aff16c49` |
| U-Boot CVE-2017-3225 fixture | `d85ca029f257b53a96da6c2fb421e78a003a9943` |
| cpp-goof demo fixture | `f0ec7300e74b4d15922dd9e893f6389834e1ca55` |
| MITRE CWE-329 external reference | `https://cwe.mitre.org/data/definitions/329.html` |
| Moonlight common C real-code fixture | `874ac9548f1bd6f095ef2b435c42cdde460e7821` |
| liboqs examples fixture | `8979276ad1eb008215aa78a3c56b3649f604bbb1` |
| BoringSSL ML-KEM API-style fixture | `f1f2556a5dfa59e147d9d47279cc3f7f8a18b433` |

## Rebuild Commands

```bash
bash scripts/fetch_corpus.sh
bash scripts/fetch_toolchains.sh
python scripts/build_matrix.py
python scripts/merge_matrix_metadata.py corpus/build/matrix/shards/*.jsonl --output corpus/build/matrix/metadata.jsonl
python scripts/build_recognizer_dataset.py
python scripts/train_recognizer.py
bash scripts/verify.sh
```

## Current Expected Outputs

- Matrix: 9,295 successful artifacts.
- Recognizer dataset: 78,071 regions.
- Deployable labels: AES, RSA, ECC, SHA, ML-KEM, ML-DSA, SLH-DSA.
- All-class recognizer gate: pass.
- Slice gate: pass for supported architecture/compiler/optimization slices with at least
  30 examples.
- Public PQC evaluation manifest: 3 cases, 4 expected facts, recall 1.0.
- Held-out primitive precision:
  - AES: 1.000
  - RSA: 1.000
  - ECC: 1.000
  - SHA: 0.995
  - ML-KEM: 1.000
  - ML-DSA: 1.000
  - SLH-DSA: 1.000
- `none` false-positive rate: 0.000045.
- `python -m pytest -q tests`: 129 tests expected.
- `bash scripts/verify.sh`: expected to pass.
- `scripts/verify.sh` includes local, negative, MITRE CWE-329 external-reference,
  Moonlight real-code, liboqs PQC example, U-Boot CVE, and cpp-goof demo manifest gates.

## Expected Limitation

`scripts/build_cve_fixtures.sh` also creates a fully symbol-stripped U-Boot relocatable
object. `scripts/check_known_limitations.py` verifies that this object emits no Tier-1
facts today. This keeps the limitation explicit and tested instead of silently
overclaiming support.
