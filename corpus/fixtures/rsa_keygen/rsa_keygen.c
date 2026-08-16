#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    BIGNUM *exponent = BN_new();
    RSA *key = RSA_new();
    if (exponent == 0 || key == 0) return 1;
    BN_set_word(exponent, RSA_F4);
#ifdef DYNAMIC_BITS
    int bits = argc > 1 ? atoi(argv[1]) : 2048;
    int ok = RSA_generate_key_ex(key, bits, exponent, 0);
#else
    int ok = RSA_generate_key_ex(key, 2048, exponent, 0);
#endif
    RSA_free(key);
    BN_free(exponent);
    return ok != 1;
}
