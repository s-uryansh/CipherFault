#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void) {
    unsigned char key[16];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    RAND_bytes(key, sizeof key);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1 ? 0 : 1;
}
