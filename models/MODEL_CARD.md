# CipherFault primitive recognizer

Deployment gate: **PASS**.

All-class gate: **PASS**. Deployable labels: AES, RSA, ECC, SHA, ML-KEM, ML-DSA, SLH-DSA.

The model is trained and evaluated over AES, RSA, ECC, SHA, ML-KEM, ML-DSA, SLH-DSA, and none regions in cooperative x86_64 and AArch64 ELF binaries. Runtime assertions are restricted to deployable labels only. Evaluation holds out boringssl-aes, boringssl-ecc, boringssl-rsa, boringssl-sha, liboqs, liboqs-ML-DSA, liboqs-SLH-DSA, libpng, libsodium by source project. Confidence is temperature-scaled on held-out PQClean, PQClean-ML-DSA, PQClean-SLH-DSA, bearssl, bearssl-ecc, bearssl-rsa, bearssl-sha, mbedtls, tiny-AES-c, zlib projects. It is not calibrated for distribution shift, obfuscation, or adversarial binaries.

Some deployable classes are gated by a conservative symbol-name head. Those runtime assertions require matching symbol or fingerprint-equivalent name evidence; the model does not claim name-independent recovery for every class in fully stripped binaries.

Held-out primitive precision: AES=1.000, RSA=1.000, ECC=1.000, SHA=0.995, ML-KEM=1.000, ML-DSA=1.000, SLH-DSA=1.000; `none` false-positive rate: 0.000.

The deployment gate, complete metrics, thresholds, support, and split are recorded in `recognizer.metrics.json`. The linear control is recorded in `baseline.metrics.json`.
