#include <stdint.h>

__attribute__((noinline)) int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(
    uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key
) {
    ciphertext[0] = public_key[0];
    shared_secret[0] = public_key[0];
    return 0;
}

int main(void) {
    uint8_t ciphertext[1088] = {0}, secret[32] = {0}, key[1184] = {0};
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ciphertext, secret, key);
}
