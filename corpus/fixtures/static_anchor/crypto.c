struct cipher { int mode; };
static const struct cipher aes_128_ecb = {1};

__attribute__((noinline)) const struct cipher *EVP_aes_128_ecb(void) {
    return &aes_128_ecb;
}

__attribute__((noinline)) int EVP_EncryptInit_ex(
    void *ctx, const struct cipher *cipher, void *impl,
    const unsigned char *key, const unsigned char *iv
) {
    return ctx != 0 && cipher != 0 && impl == 0 && key != 0 && iv == 0;
}
