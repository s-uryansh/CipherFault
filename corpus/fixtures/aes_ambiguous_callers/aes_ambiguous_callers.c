#include <openssl/evp.h>

__attribute__((noinline))
static int encrypt_with(const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

__attribute__((noinline, used))
int runtime_caller(const unsigned char *key) {
    return encrypt_with(key);
}

int main(void) {
    static const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    return encrypt_with(key) == 1 ? 0 : 1;
}
