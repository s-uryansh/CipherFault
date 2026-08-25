#!/usr/bin/env bash
set -euo pipefail

case_dir="corpus/eval/LIBOQS-EXAMPLES"
source_dir="$case_dir/source"
commit="8979276ad1eb008215aa78a3c56b3649f604bbb1"
stub_dir="${TMPDIR:-/tmp}/cipherfault-liboqs-stubs"
bssl_dir="corpus/eval/BORINGSSL-MLKEM"
bssl_source_dir="$bssl_dir/source"
bssl_commit="f1f2556a5dfa59e147d9d47279cc3f7f8a18b433"

mkdir -p "$case_dir" "$stub_dir/oqs"
if [ ! -d "$source_dir/.git" ]; then
    git clone --filter=blob:none https://github.com/open-quantum-safe/liboqs.git "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit"

cat > "$stub_dir/oqs/oqs.h" <<'EOF'
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int OQS_STATUS;
#define OQS_SUCCESS 0
#define OQS_ERROR 1

#define OQS_ENABLE_KEM_ml_kem_768 1
#define OQS_KEM_ml_kem_768_length_public_key 1184
#define OQS_KEM_ml_kem_768_length_secret_key 2400
#define OQS_KEM_ml_kem_768_length_ciphertext 1088
#define OQS_KEM_ml_kem_768_length_shared_secret 32
#define OQS_KEM_alg_ml_kem_768 "ML-KEM-768"

typedef struct OQS_KEM {
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
} OQS_KEM;

#define OQS_ENABLE_SIG_ml_dsa_65 1
#define OQS_SIG_ml_dsa_65_length_public_key 1952
#define OQS_SIG_ml_dsa_65_length_secret_key 4032
#define OQS_SIG_ml_dsa_65_length_signature 3309
#define OQS_SIG_alg_ml_dsa_65 "ML-DSA-65"

typedef struct OQS_SIG {
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
} OQS_SIG;

void OQS_init(void);
void OQS_destroy(void);
void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read);
void OQS_MEM_cleanse(void *ptr, size_t len);
void *OQS_MEM_malloc(size_t len);
void OQS_MEM_secure_free(void *ptr, size_t len);
void OQS_MEM_insecure_free(void *ptr);
OQS_KEM *OQS_KEM_new(const char *method_name);
void OQS_KEM_free(OQS_KEM *kem);
OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
OQS_STATUS OQS_KEM_ml_kem_768_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_ml_kem_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_ml_kem_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
OQS_SIG *OQS_SIG_new(const char *method_name);
void OQS_SIG_free(OQS_SIG *sig);
OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
OQS_STATUS OQS_SIG_ml_dsa_65_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_SIG_ml_dsa_65_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_STATUS OQS_SIG_ml_dsa_65_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
EOF

cc -O2 -g -I"$stub_dir" -c "$source_dir/tests/example_kem.c" \
    -o "$case_dir/target_example_kem_reference.o"
cp "$case_dir/target_example_kem_reference.o" "$case_dir/target_example_kem_strip.o"
strip --strip-debug "$case_dir/target_example_kem_strip.o"

cc -O2 -g -I"$stub_dir" -c "$source_dir/tests/example_sig.c" \
    -o "$case_dir/target_example_sig_reference.o"
cp "$case_dir/target_example_sig_reference.o" "$case_dir/target_example_sig_strip.o"
strip --strip-debug "$case_dir/target_example_sig_strip.o"

mkdir -p "$bssl_dir"
if [ ! -d "$bssl_source_dir/.git" ]; then
    git clone --filter=blob:none https://boringssl.googlesource.com/boringssl "$bssl_source_dir"
fi
if ! git -C "$bssl_source_dir" cat-file -e "$bssl_commit^{commit}" 2>/dev/null; then
    git -C "$bssl_source_dir" fetch --depth 1 origin "$bssl_commit"
fi
git -C "$bssl_source_dir" checkout --detach "$bssl_commit"

cat > "$bssl_dir/boringssl_mlkem_external_entropy.c" <<'EOF'
#include <stdint.h>
#include <stdlib.h>

#define MLKEM1024_CIPHERTEXT_BYTES 1568
#define MLKEM_SHARED_SECRET_BYTES 32
#define BCM_MLKEM_ENCAP_ENTROPY 32

struct MLKEM1024_public_key {
    uint8_t opaque[1632];
};

extern int BCM_mlkem1024_encap_external_entropy(
    uint8_t out_ciphertext[MLKEM1024_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const struct MLKEM1024_public_key *public_key,
    const uint8_t entropy[BCM_MLKEM_ENCAP_ENTROPY]);

int main(void) {
    uint8_t ciphertext[MLKEM1024_CIPHERTEXT_BYTES] = {0};
    uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES] = {0};
    struct MLKEM1024_public_key public_key = {{0}};
    uint8_t entropy[BCM_MLKEM_ENCAP_ENTROPY];
    for (int i = 0; i < BCM_MLKEM_ENCAP_ENTROPY; ++i) {
        entropy[i] = (uint8_t)rand();
    }
    return BCM_mlkem1024_encap_external_entropy(
        ciphertext, shared_secret, &public_key, entropy
    );
}
EOF

cc -O2 -g -c "$bssl_dir/boringssl_mlkem_external_entropy.c" \
    -o "$bssl_dir/target_mlkem_extentropy_reference.o"
cp "$bssl_dir/target_mlkem_extentropy_reference.o" "$bssl_dir/target_mlkem_extentropy_strip.o"
strip --strip-debug "$bssl_dir/target_mlkem_extentropy_strip.o"
