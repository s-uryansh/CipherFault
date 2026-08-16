#include<openssl/evp.h>
#include<stdlib.h>
#include<time.h>

int encrypt_record(const unsigned char *in, int len, unsigned char *out){
    unsigned char key[16];
    unsigned char iv[16] = {0};

    srand((unsigned)time(NULL));
    for(int i = 0; i < 16; i++){
        key[i] = (unsigned char)rand();
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int outlen = 0;
    EVP_EncryptUpdate(ctx, out, &outlen, in, len);
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

int main(void){
    unsigned char in[32] = {0}, out[64];
    return encrypt_record(in, sizeof in, out) > 0 ? 0 : 1;
}