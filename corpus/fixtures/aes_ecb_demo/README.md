A minimal libcrypto program with two planted crypto-misuse bugs.
Used to validate CipherFault findings against a known answer.


## Planted Bugs

| Location | Bug | Expected CWE | Expected tier |
| --- | --- | --- | --- |
| `encrypt_record`, key[] in .rodata | Hardcoded AES key | CWE-321 | VERIFIED_FACT |
| `encrypt_record`, EVP_aes_128_ecb() | ECB mode (no IV) | CWE-327 | VERIFIED_FACT |

## Build variants

- `aes_ecb_demo_dbg` : gcc -00 -g (symbols present - easy mode)
- `aes_ecb_demo_strip` : gcc -02 -s (Stripped, optimized -> real target)

## Notes

- The cipher choice (EVP_aes_128_ecb) is passed as an argument into a libcrypto call -> i.e. the misuse provenance crosses a call boundary, exercising the inter-procedural requirement of the taint engine.
- `main` calls `encrypt_record` ; the key lives in .rodata, not on the stack.