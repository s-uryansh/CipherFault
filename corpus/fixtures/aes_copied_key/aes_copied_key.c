#include <openssl/evp.h>
#include <string.h>

int main(void) {
    static const unsigned char compiled_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    unsigned char key[16];
    memcpy(key, compiled_key, sizeof key);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1 ? 0 : 1;
}
