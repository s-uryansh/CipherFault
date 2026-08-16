struct cipher;
const struct cipher *EVP_aes_128_ecb(void);
int EVP_EncryptInit_ex(void *, const struct cipher *, void *, const unsigned char *, const unsigned char *);

static const unsigned char key[16] = {1};

int main(void) {
    return !EVP_EncryptInit_ex((void *)1, EVP_aes_128_ecb(), 0, key, 0);
}
