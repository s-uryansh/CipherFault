#include <openssl/evp.h>
#include <openssl/rand.h>

int main(void) {
    unsigned char key[16], iv[16];
    if (RAND_bytes(key, sizeof key) != 1 || RAND_bytes(iv, sizeof iv) != 1) return 1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 1;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1 ? 0 : 1;
}
