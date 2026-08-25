"""Conservative symbol-name recognizer head."""

from __future__ import annotations

import re

import torch


NAME_PATTERNS = {
    0: re.compile(r"(?i)(aes|softaes)"),
    1: re.compile(r"(?i)(rsa|pkcs1|mgf1)"),
    2: re.compile(r"(?i)(ecdsa|(?:^|_)ec_|p256|fiat_p256|f256|curve|scalar)"),
    3: re.compile(r"(?i)(sha[0-9]+_final_impl|sha2(?:big|small)_round|br_sha[0-9]|^sha[0-9]|fips_186)"),
    4: re.compile(r"(?i)(mlkem|ml_kem|MLKEM)"),
    5: re.compile(r"(?i)(mldsa|ml_dsa|MLDSA)"),
    6: re.compile(r"(?i)wots_c(?:heck)?sum"),
}

ECC_EXCLUDES = re.compile(
    r"(?i)(ec_GFp_nistp256_point_get_affine_coordinates|ec_GFp_nistp256_point_mul_public|fiat_p256_point_add)"
)


def name_probabilities(graphs, classes: int = 8) -> torch.Tensor:
    result = torch.zeros((len(graphs), classes), dtype=torch.float)
    for row, graph in enumerate(graphs):
        function = getattr(graph, "function", "")
        for label, pattern in NAME_PATTERNS.items():
            if label == 2 and ECC_EXCLUDES.search(function):
                continue
            if label < classes and pattern.search(function):
                result[row, label] = 1.0
    return result
