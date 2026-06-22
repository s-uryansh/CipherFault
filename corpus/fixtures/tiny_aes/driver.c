#include "aes.h"
#include<string.h>

int main(void){
    struct AES_ctx ctx;
    uint8_t key[16]={0}, buf[16]={0};
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, buf);
    return buf[0];
}