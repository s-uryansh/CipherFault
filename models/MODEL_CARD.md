# CipherFault primitive recognizer

Deployment gate: **PASS**.

The model recognizes AES and ML-KEM regions in cooperative x86_64 ELF binaries. Evaluation holds out boringssl-aes, liboqs, libpng, libsodium by source project. Confidence is temperature-scaled on held-out PQClean, bearssl, mbedtls, tiny-AES-c, zlib projects. It is not calibrated for distribution shift, obfuscation, or adversarial binaries.

Held-out AES precision: 1.000; ML-KEM precision: 1.000; `none` false-positive rate: 0.000.

The deployment gate, complete metrics, thresholds, support, and split are recorded in `recognizer.metrics.json`. The linear control is recorded in `baseline.metrics.json`.
