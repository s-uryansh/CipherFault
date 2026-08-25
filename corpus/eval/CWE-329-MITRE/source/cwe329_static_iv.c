#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

static const uint8_t kKey[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t kFixedIv[16] = {0};

int encrypt_with_static_iv(const uint8_t *in, size_t in_len, uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;

    if (ctx == NULL) {
        return 0;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, kKey, kFixedIv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (!EVP_EncryptUpdate(ctx, out, &out_len, in, (int)in_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (!EVP_EncryptFinal_ex(ctx, out + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return out_len + final_len;
}

int main(void) {
    uint8_t in[16] = {0};
    uint8_t out[32] = {0};
    return encrypt_with_static_iv(in, sizeof(in), out) > 0 ? 0 : 1;
}
