#include <openssl/aes.h>

int main(int argc, char **argv) {
    static const unsigned char raw_key[16] = {1};
    static unsigned char input[16] = {0}, output[16] = {0};
    static unsigned char iv[16] = {0};
    AES_KEY key;
    if (AES_set_encrypt_key(raw_key, 128, &key) != 0) return 1;
    if (argc > 1 && argv != 0)
        AES_ecb_encrypt(input, output, &key, AES_ENCRYPT);
    else
        AES_cbc_encrypt(input, output, sizeof input, &key, iv, AES_ENCRYPT);
    return 0;
}
