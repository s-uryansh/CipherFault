#include <openssl/evp.h>

int main(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == 0) return 1;
#ifdef USE_MD5
    const EVP_MD *algorithm = EVP_md5();
#else
    const EVP_MD *algorithm = EVP_sha256();
#endif
    int ok = EVP_DigestInit_ex(ctx, algorithm, 0);
    EVP_MD_CTX_free(ctx);
    return ok != 1;
}
