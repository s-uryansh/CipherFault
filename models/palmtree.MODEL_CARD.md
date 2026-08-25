# CipherFault primitive recognizer archived baseline

Status: **archived experimental baseline**. Do not use this card as the current
project status.

The model recognizes AES and ML-KEM regions in cooperative x86_64 ELF binaries. Evaluation holds out liboqs, libpng, libsodium, mbedtls by source project. Confidence is temperature-scaled on a function-group-disjoint validation split. It is not calibrated for distribution shift, obfuscation, or adversarial binaries.

Held-out AES precision: 1.000; ML-KEM precision: 0.455; `none` false-positive rate: 0.075.

This historical run failed its deployment gate. The current active recognizer status
is recorded in `MODEL_CARD.md` and `recognizer.metrics.json`.
