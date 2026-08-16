/* Corpus-only mlkem-native configuration: preserve functions for labeling. */
#ifndef CIPHERFAULT_MLKEM_CORPUS_CONFIG_H
#define CIPHERFAULT_MLKEM_CORPUS_CONFIG_H

#define MLK_CONFIG_NAMESPACE_PREFIX cipherfault_mlkem
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_FIPS202_CUSTOM_HEADER "../fips202_glue.h"
#define MLK_CONFIG_FIPS202X4_CUSTOM_HEADER "../fips202x4_glue.h"
#define MLK_CONFIG_CUSTOM_ZEROIZE

#include <stddef.h>
static inline void mlk_zeroize(void *pointer, size_t length) {
    volatile unsigned char *bytes = pointer;
    while (length--) *bytes++ = 0;
}

#endif
