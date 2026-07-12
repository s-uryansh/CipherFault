# CipherFault

**A crypto-usage evidence engine for compiled software.**

![status](https://img.shields.io/badge/status-active%20development-blue)
![stage](https://img.shields.io/badge/stage-Tier--1%20taint%20verified-success)
![python](https://img.shields.io/badge/python-3.13-blue)
![lifter](https://img.shields.io/badge/lifter-Ghidra%20P--code-orange)
![ml](https://img.shields.io/badge/ML-PyTorch%20Geometric-red)
![license](https://img.shields.io/badge/license-TBD-lightgrey)

CipherFault recognizes cryptographic primitives classical and post-quantum in
**stripped, optimized binaries**, then extracts code-intrinsic usage facts with full
provenance. Findings arrive in two epistemically separated tiers: **verified facts**
the tool stands behind, and **indicators** flagged for analyst review. The tool makes
no exploitability claim; that judgment belongs to the analyst.

> **Scope:** cooperative software supply-chain, vendor-supplied, third-party, and
> legacy binaries that are *not* actively fighting analysis. Malware and deliberately
> obfuscated binaries are explicitly out of scope.

---

## The Problem

SBOM/CBOM tooling tells you *what* cryptography is present (AES, RSA, SHA-256 are
linked in). None of it tells you *how it is used* and usage is where exploitable
cryptographic failure lives:

- AES running in **ECB mode**, leaking block structure.
- An IV that is a **hardcoded constant in `.rodata`** rather than entropy-derived.
- A key that is a **compiled-in constant**.
- Key-generation randomness traceable to a **`time()`-seeded PRNG** instead of a CSPRNG.
- **ML-KEM** shipped with encapsulation randomness from a non-cryptographic source.

Recovering these facts today needs source access (often unavailable), a week of manual
reverse engineering per binary, or opaque commercial tooling. **No open, transparent,
methodology-auditable tool extracts provenance-carrying cryptographic usage facts from
compiled binaries without source.** That is the gap CipherFault fills.

---

## What Makes It Different

| Dimension | Existing tools | CipherFault |
|---|---|---|
| Works on stripped third-party binaries | Source-only tools can't; signature tools fail under optimization | Recognizer degrades gracefully |
| Reports *usage*, not just presence | Inventory only | Provenance-carrying usage facts |
| Methodology transparency | Commercial tools closed/patented | Open, auditable provenance paths |
| Epistemic honesty | Detectors overclaim and get muted | Two tiers (facts vs. indicators), never blended |
| PQC usage facts | None post-FIPS-2024 | First-mover structural PQC coverage |
| Trust model | "We find your vulnerabilities" | "Here is what we can prove, here is what to check" |

The core commitment: CipherFault is an **evidence engine, not a vulnerability detector.**
A detector competes with the analyst and overclaims on every false positive. An evidence
engine extends the analyst and never gets muted.

---

## Architecture

```
Binary (ELF / PE / Mach-O)
        │
        ▼
Disassembly Ghidra P-code IR           (architecture-independent)
        │
        ▼
Function Fingerprinting                   (recover anchors on stripped/static binaries)
        │
        ▼
CFG + DFG Construction
        │
        ├───────────────────────────────┐
        ▼                                ▼
Primitive Recognizer (GNN)        Taint Engine (deterministic)
region → primitive class          tag operands: CONST / RNG / TIME / USER / NETWORK
(the ML contribution)             intra- + bounded inter-procedural
        │                                │
        └───────────────┬────────────────┘
                        ▼
          Provenance + Rule Layer (deterministic)
          primitive class × operand taint → usage fact
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
   Tier 1 VERIFIED_FACT       Tier 2 INDICATOR
   (code-intrinsic,           (runtime-dependent,
    provenance path)           analyst question)
          │                           │
          └─────────────┬─────────────┘
                        ▼
          Usage-aware CBOM (CycloneDX v1.6)
          + declared analysis posture
```

**Two design decisions do the heavy lifting:**

1. **The GNN recognizes only.** Once taint tags an operand `CONST` and the recognizer
   says `AES`, deriving "hardcoded key" is a deterministic rule not a classification
   problem. This keeps every finding backed by an auditable provenance path, not a softmax.

2. **Two tiers by architecture, not by disclaimer.** Code-intrinsic properties are
   statically derivable; runtime-dependent ones are not (Rice's theorem). That decidability
   boundary is encoded as *separate output channels* the entire credibility play.

---

## Findings to Date

Development is deliberately sequenced by **risk retired per hour**: prove the riskiest
assumptions on small known-answer fixtures before scaling.

### ✅ Deterministic Tier-1 provenance **verified**

The tool can trace a cipher's key operand back to its origin in a **stripped, `-O2`
binary**, with no symbols and no reliance on the recognizer:

| Case | Result |
|---|---|
| Intra-procedural (key inlined) | `EVP_EncryptInit_ex` key operand → `COPY` → `CONST 0x102010` → `.rodata` → planted key bytes ✔ |
| Inter-procedural hop (`main → do_encrypt`) | key param → caller arg → `PTRSUB` → `CONST 0x102010` → `.rodata` ✔ |
| Survives optimization | Inter-procedural chain holds at `-O2 -s` ✔ |

Both cases are locked under regression test. **This is the project's central de-risking
result:** the deterministic provenance engine the half no existing tool provides works
end-to-end on the real target (stripped, optimized, cross-boundary).

### ⚠️ Recognizer featurization ceiling **characterized**

An honest cross-compiler evaluation (train on GCC, test on Clang, function-disjoint,
leak-audited) established that **the current mnemonic-count features are the bottleneck,
not the model:**

| Task | Logistic Regression (histogram) | GNN (GraphSAGE) |
|---|---|---|
| crypto vs. none | 0.94 | 0.94 |
| multi-class (AES / bignum / none) | **0.90** | 0.87 |

The GNN does not yet beat a linear model on summed instruction counts graph structure
provides no lift *at this featurization*. This is a useful negative result: it says
semantic node embeddings (not richer topology) are the next lever, and it was found on
cheap fixtures before any large-scale training investment.

---

## Roadmap

Sequenced by **decidability class**, not difficulty. Two tracks run in parallel.

### Track A Deterministic (Tier-1) · *de-risked, advancing to deliverable*

- [x] **Phase 0** Taint feasibility: intra- + inter-procedural key trace on stripped/`-O2` binaries
- [x] **Phase 1** Promote spike → `taint/anchors.py` + `taint/tracer.py` (structured provenance paths)
- [ ] **Phase 4** Rule layer: `(primitive × operand taint)` → `VERIFIED_FACT` + CWE + provenance
  - Hardcoded key (CWE-321), ECB mode (CWE-327), static IV (CWE-329), weak randomness (CWE-338)
- [ ] **CBOM export** CycloneDX v1.6 with usage facts attached
- [ ] **CLI** `cipherfault scan ./binary` (Click) + declared analysis posture
- [ ] **Go/no-go gate** Tier-1 recall on a CVE evaluation set (e.g. CVE-2021-3711, CVE-2016-2107)

### Track B Learned (recognition) · *open research bet*

- [x] **Phase 2** Honest kill-shot: non-XOR crypto source, extended vocab, clang holdout, LR-vs-GNN baseline
- [ ] **Phase 2e** Semantic node features (custom / PalmTree-initialized embeddings); re-run head-to-head
      *(decision gate: if the GNN still ties LR, the recognizer may not need a GNN)*
- [ ] **Phase 3** Stripped-binary evaluation path (currently object-file corpus)
- [ ] Scale corpus (OpenSSL / libsodium / BoringSSL / PQClean / liboqs) once featurization is settled
- [ ] Grow to full class set: AES / RSA / ECC / SHA / ML-KEM / ML-DSA / SLH-DSA / none

---

## Repository Layout

```
cipherfault/
├── src/cipherfault/
│   ├── lifting/       # Ghidra P-code → LiftedFunction (all-function, symbol-independent)
│   ├── regions/       # CFG → candidate regions (SCC/loop-based)
│   ├── recognizer/    # region → PyG graph; GNN primitive recognizer
│   ├── taint/         # anchors.py (crypto-init sites) + tracer.py (provenance paths)
│   ├── rules/         # (primitive × taint) → VERIFIED_FACT / INDICATOR   [in progress]
│   ├── graph/         # DFG construction                                   [planned]
│   └── cbom/          # CycloneDX v1.6 export                              [planned]
├── corpus/
│   ├── fixtures/      # known-answer C sources (tiny_aes, aes_ecb_demo, bignum, noncrypto)
│   └── build/         # compiled artifacts + Ghidra projects (gitignored, reproducible)
├── experiments/       # numbered spikes: 01_cfg → 11_multiclass (chronological research log)
├── tests/             # regression guards (test_taint.py)
├── scripts/
├── pyproject.toml
└── README.md
```

`experiments/` is an ordered research log each numbered directory is a spike that
retired one question, kept for provenance. `src/cipherfault/` is the shippable package;
spikes never import into it.

---

## Development Workflow

CipherFault is built on a strict, repeatable loop designed for correctness over speed:

1. **Prove on a known-answer fixture first.** Every capability is validated against a
   tiny binary whose ground truth is documented (`corpus/fixtures/*/README.md`) before
   it touches real code.
2. **Retire the riskiest assumption earliest.** Feasibility probes (e.g. "can P-code
   trace an operand to `.rodata` on a stripped binary?") run before any dependent
   engineering.
3. **Spike, then promote.** Research happens in `experiments/NN_*`; only proven
   mechanisms graduate into `src/cipherfault/` as data-returning modules.
4. **Read the result don't accept it.** Node/edge counts, taint terminals, and
   accuracy numbers are verified by reasoning about the source, not assumed.
5. **Guard with regression.** Verified behaviors (e.g. key → `.rodata 0x102010`) are
   pinned in `tests/` so they can't silently break.

---

## Tech Stack

| Component | Technology |
|---|---|
| Binary lifting | Ghidra (P-code) via `pyghidra` |
| Graph construction | NetworkX → PyTorch Geometric |
| Recognizer (GNN) | PyTorch Geometric (GraphSAGE / GAT) |
| Taint + rule layer | Deterministic Python over the DFG |
| CBOM output | CycloneDX (planned) |
| CLI | Click (planned) |
| Evaluation | scikit-learn metrics + calibration |
| Languages | Python (pipeline) · C (synthetic corpus) |

---

## Analysis Posture

CipherFault states its epistemic position rather than implying perfection:

- **Not sound** aliasing, indirect calls, and complex control flow cause missed facts.
- **Not complete** taint approximation and recognizer misclassification cause false positives.
- **Per-stage tuning** the recognizer is tuned toward *precision* (the `none` class
  dominates any real binary); the rule layer toward *recall* (a missed misuse costs more
  than a false alarm, because the provenance path makes triage fast).
- **No exploitability claims** exploitability depends on data sensitivity, attacker
  observability, and protocol context, none of which are present in the binary.

---

## Status

Early active development. The deterministic provenance engine is verified end-to-end on
stripped/optimized fixtures; the rule layer and CLI are the next deliverable. The learned
recognizer is an open research question with a characterized featurization bottleneck.

*This README reflects the state of a project and will evolve as findings land.*