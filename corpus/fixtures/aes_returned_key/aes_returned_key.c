#include <openssl/evp.h>

static const unsigned char key[16] = {1, 2, 3, 4};

__attribute__((noinline)) static const unsigned char *key_source(void) {
    return key;
}

int main(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == 0) return 1;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), 0, key_source(), 0);
    EVP_CIPHER_CTX_free(ctx);
    return ok != 1;
}
