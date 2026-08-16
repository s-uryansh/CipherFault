struct cipher;
const struct cipher *EVP_aes_128_ecb(void);
int EVP_EncryptInit_ex(void *, const struct cipher *, void *, const unsigned char *, const unsigned char *);

static const unsigned char key[16] = {2};

int main(int argc, char **argv) {
    void *ctx = argc > 0 && argv != 0 ? (void *)1 : 0;
    return !EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), 0, key, 0);
}
