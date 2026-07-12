#include<openssl/evp.h>
#include<string.h>

int do_encrypt(const unsigned char * key, const unsigned char *in, int len, unsigned char *out){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    int outlen = 0;
    EVP_EncryptUpdate(ctx, out, &outlen, in, len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

int main(void){
    static const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    unsigned char in[32]={0}, out[64];
    return do_encrypt(key, in, sizeof in, out) > 0 ? 0 : 1;
}