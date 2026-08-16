#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdlib.h>

int main(int argc, char **argv) {
#ifdef DYNAMIC_CURVE
    int curve = argc > 1 ? atoi(argv[1]) : NID_X9_62_prime256v1;
#else
    int curve = NID_X9_62_prime256v1;
#endif
    EC_KEY *key = EC_KEY_new_by_curve_name(curve);
    if (key == 0) return 1;
    EC_KEY_free(key);
    return 0;
}
