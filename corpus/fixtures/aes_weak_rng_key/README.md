# AES Weak RNG Key Fixture

Known-answer fixture for weak key randomness detection.

## Planted Bugs

| Location | Bug | Expected CWE | Expected tier |
|---|---|---|---|
| `encrypt_record`, `srand(time(NULL))` + `rand()` fills key | Weak key randomness | CWE-338 | VERIFIED_FACT |

## Notes

The IV is a zero stack buffer only to satisfy AES-CBC API shape. Do not use this fixture for static-IV validation.
