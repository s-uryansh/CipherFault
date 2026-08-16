#include <stddef.h>
#include <stdint.h>

__attribute__((noinline)) int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *key
) {
    sig[0] = msg[0] ^ key[0];
    *siglen = msglen;
    return 0;
}

__attribute__((noinline)) int PQCLEAN_SLHDSASHA2128SSIMPLE_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *key
) {
    sig[0] = msg[0] ^ key[0];
    *siglen = msglen;
    return 0;
}

int main(void) {
    uint8_t sig[64] = {0}, msg[1] = {1}, key[1] = {2};
    size_t siglen = 0;
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, &siglen, msg, 1, key)
        | PQCLEAN_SLHDSASHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, &siglen, msg, 1, key);
}
