#!/usr/bin/env bash
set -euo pipefail

for fixture in \
    aes_ecb_demo \
    aes_cbc_static_iv \
    aes_weak_rng_key \
    aes_unrelated_rand \
    aes_dynamic_operands \
    aes_returned_key \
    aes_copied_key \
    verification_outcome \
    aes_ambiguous_callers \
    aes_ip_rng \
    aes_rng_after_use \
    aes_rng_overwritten \
    aes_low_level \
    non_aes_evp \
    mlkem_api \
    static_anchor \
    digest_api \
    pqc_signatures \
    mlkem_weak_randomness \
    rsa_keygen \
    ecc_curve
do
    make -C "corpus/fixtures/$fixture"
done
