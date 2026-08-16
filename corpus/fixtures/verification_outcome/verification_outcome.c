#include <openssl/evp.h>
#include <stddef.h>

int main(int argc, char **argv) {
    unsigned char signature[1] = {0}, digest[1] = {0};
    int result = EVP_PKEY_verify(NULL, signature, sizeof signature, digest, sizeof digest);
#ifdef CHECK_RESULT
    return result == 1 ? 0 : 1;
#else
    (void)result;
    return argc == 123 && argv == NULL;
#endif
}
