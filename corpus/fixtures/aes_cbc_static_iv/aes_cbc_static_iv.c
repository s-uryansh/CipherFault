#include <openssl/evp.h>
#include <string.h>

int encrypt_record(const unsigned char *in, int len, unsigned char *out) {
    static const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    static const unsigned char iv[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int outlen = 0;
    EVP_EncryptUpdate(ctx, out, &outlen, in, len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

int main(void) {
    unsigned char in[32] = {0}, out[64];
    return encrypt_record(in, sizeof in, out) > 0 ? 0 : 1;
}