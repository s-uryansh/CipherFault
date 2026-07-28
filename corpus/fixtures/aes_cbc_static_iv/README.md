# AES CBC Static IV Fixture

Known-answer fixture for static IV detection.

## Planted Bugs

| Location | Bug | Expected CWE | Expected tier |
|---|---|---|---|
| `encrypt_record`, key[] in `.rodata` | Hardcoded AES key | CWE-321 | VERIFIED_FACT |
| `encrypt_record`, iv[] in `.rodata` | Static AES-CBC IV | CWE-329 | VERIFIED_FACT |
