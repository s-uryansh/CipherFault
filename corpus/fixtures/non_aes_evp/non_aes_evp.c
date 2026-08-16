#include <openssl/evp.h>

int main(void) {
    static const unsigned char key[32] = {0};
    static const unsigned char nonce[16] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 1;
    int ok = EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1 ? 0 : 1;
}
