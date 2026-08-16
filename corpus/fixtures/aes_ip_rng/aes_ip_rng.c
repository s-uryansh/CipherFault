#include <openssl/evp.h>
#include <openssl/rand.h>

__attribute__((noinline))
static int encrypt_with(const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(void) {
    unsigned char key[16];
    if (RAND_bytes(key, sizeof key) != 1) return 1;
    return encrypt_with(key) == 1 ? 0 : 1;
}
