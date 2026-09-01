#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static const unsigned char PAYMENT_KEY[16] = {
    0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x2d,
    0x64, 0x65, 0x6d, 0x6f, 0x2d, 0x6b, 0x65, 0x79
};

static const unsigned char PAYMENT_IV[16] = {
    0x66, 0x69, 0x78, 0x65, 0x64, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x69, 0x76, 0x2d, 0x30, 0x31
};

static int encrypt_payment_record(const unsigned char *record, int len, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;

    if (ctx == NULL) {
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, PAYMENT_KEY, PAYMENT_IV) ||
        !EVP_EncryptUpdate(ctx, out, &out_len, record, len) ||
        !EVP_EncryptFinal_ex(ctx, out + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return out_len + final_len;
}

int main(void) {
    const unsigned char record[] = "card=4111111111111111;amount=42.00";
    unsigned char encrypted[128];
    int written = encrypt_payment_record(record, (int)strlen((const char *)record), encrypted);

    if (written < 0) {
        puts("payment encryption failed");
        return 1;
    }

    printf("encrypted payment record: %d bytes\n", written);
    return 0;
}
