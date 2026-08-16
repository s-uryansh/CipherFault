# CipherFault primitive recognizer

Deployment gate: **FAIL**.

The model recognizes AES and ML-KEM regions in cooperative x86_64 ELF binaries. Evaluation holds out liboqs, libpng, libsodium, mbedtls by source project. Confidence is temperature-scaled on a function-group-disjoint validation split. It is not calibrated for distribution shift, obfuscation, or adversarial binaries.

Held-out AES precision: 0.447; ML-KEM precision: 0.000; `none` false-positive rate: 0.016.

The deployment gate, complete metrics, thresholds, support, and split are recorded in `recognizer.metrics.json`. The linear control is recorded in `baseline.metrics.json`.
