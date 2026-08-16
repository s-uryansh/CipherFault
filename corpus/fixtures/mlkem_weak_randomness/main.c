#include <stdint.h>
#include <stdlib.h>

__attribute__((noinline)) int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
    uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key,
    const uint8_t *randomness
) {
    ciphertext[0] = public_key[0] ^ randomness[0];
    shared_secret[0] = randomness[1];
    return 0;
}

int main(void) {
    uint8_t ciphertext[1088] = {0}, secret[32] = {0}, key[1184] = {0};
    uint8_t randomness[32];
    for (int i = 0; i < 32; ++i) randomness[i] = (uint8_t)rand();
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
        ciphertext, secret, key, randomness
    );
}
