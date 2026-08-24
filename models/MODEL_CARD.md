# CipherFault primitive recognizer

Deployment gate: **PASS**.

All-class gate: **FAIL**. Deployable labels: AES, ML-KEM.

The model recognizes AES, RSA, ECC, SHA, ML-KEM, ML-DSA, and SLH-DSA regions in cooperative x86_64 and AArch64 ELF binaries. Evaluation holds out boringssl-aes, boringssl-ecc, boringssl-rsa, boringssl-sha, liboqs, liboqs-ML-DSA, liboqs-SLH-DSA, libpng, libsodium by source project. Confidence is temperature-scaled on held-out PQClean, PQClean-ML-DSA, PQClean-SLH-DSA, bearssl, bearssl-ecc, bearssl-rsa, bearssl-sha, mbedtls, tiny-AES-c, zlib projects. It is not calibrated for distribution shift, obfuscation, or adversarial binaries.

Held-out primitive precision: AES=1.000, RSA=0.000, ECC=0.000, SHA=0.692, ML-KEM=0.976, ML-DSA=0.500, SLH-DSA=0.000; `none` false-positive rate: 0.001.

The deployment gate, complete metrics, thresholds, support, and split are recorded in `recognizer.metrics.json`. The linear control is recorded in `baseline.metrics.json`.
