"""Find cryptographic init call sites in a decompiled program."""

from dataclasses import dataclass
from collections import defaultdict
from collections import Counter
from difflib import SequenceMatcher
from math import sqrt
import re
from types import SimpleNamespace


CRYPTO_INITS = {
    "EVP_EncryptInit_ex": {"primitive": None, "operands": {"cipher": 2, "key": 4, "iv": 5}},
    "EVP_DecryptInit_ex": {"primitive": None, "operands": {"cipher": 2, "key": 4, "iv": 5}},
}

DIGEST_INITS = {
    "EVP_DigestInit_ex": {"primitive": "DIGEST", "operands": {"algorithm": 2}},
    "EVP_DigestInit_ex2": {"primitive": "DIGEST", "operands": {"algorithm": 2}},
}

KEYGEN_INITS = {
    "RSA_generate_key_ex": {"primitive": "RSA", "operands": {"bits": 2}},
    "EC_KEY_new_by_curve_name": {"primitive": "ECC", "operands": {"curve": 1}},
}

LOW_LEVEL_AES = {
    "AES_cbc_encrypt": {
        "primitive": "AES",
        "variant": "AES-CBC",
        "operands": {"key": 4, "iv": 5},
    },
    "AES_ecb_encrypt": {
        "primitive": "AES",
        "variant": "AES-ECB",
        "operands": {"key": 3},
    },
    "aes_cbc_encrypt_blocks": {
        "primitive": "AES",
        "variant": "AES-CBC",
        "operands": {"key": 1, "iv": 2},
    },
    "aes_cbc_decrypt_blocks": {
        "primitive": "AES",
        "variant": "AES-CBC",
        "operands": {"key": 1, "iv": 2},
    },
}

WEAK_RANDOM_SOURCES = {
    "time": "TIME",
    "clock": "TIME",
    "gettimeofday": "TIME",
    "rand": "WEAK_RNG",
    "srand": "WEAK_RNG_SEED",
}

RNG_SOURCES = {"getrandom", "RAND_bytes", "RAND_priv_bytes", "arc4random_buf"}

VERIFY_FUNCTIONS = {
    "EVP_DigestVerifyFinal",
    "EVP_PKEY_verify",
    "RSA_verify",
    "ECDSA_verify",
}

FINGERPRINT_NAMES = (
    set(CRYPTO_INITS)
    | set(DIGEST_INITS)
    | set(KEYGEN_INITS)
    | set(LOW_LEVEL_AES)
    | set(WEAK_RANDOM_SOURCES)
    | RNG_SOURCES
    | VERIFY_FUNCTIONS
    | {"memcpy", "memmove", "memset"}
    | {
        f"EVP_aes_{bits}_{mode}"
        for bits in (128, 192, 256)
        for mode in ("ecb", "cbc", "ctr", "gcm", "ccm", "ofb", "cfb", "cfb1", "cfb8")
    }
    | {"EVP_md5", "EVP_sha1", "EVP_sha224", "EVP_sha256", "EVP_sha384", "EVP_sha512"}
)


@dataclass
class Anchor:
    func_name: str
    callee: str
    call_addr: str
    operands: dict
    high: object
    primitive: str | None = None
    variant: str | None = None
    resolved_names: dict[str, str] | None = None
    resolution_method: str = "resolved_api_anchor"


def anchor_spec(callee: str | None) -> dict | None:
    if callee in CRYPTO_INITS:
        return CRYPTO_INITS[callee]
    if callee in DIGEST_INITS:
        return DIGEST_INITS[callee]
    if callee in KEYGEN_INITS:
        return KEYGEN_INITS[callee]
    if callee in LOW_LEVEL_AES:
        return LOW_LEVEL_AES[callee]
    match = re.search(r"(?:MLKEM|ML_KEM)[_-]?(512|768|1024).*(?:enc|encaps)", callee or "", re.IGNORECASE)
    if match:
        operands = {"key": 3}
        if "derand" in (callee or "").lower():
            operands["randomness"] = 4
        return {
            "primitive": "ML-KEM",
            "variant": f"ML-KEM-{match.group(1)}",
            "operands": operands,
        }
    match = re.search(r"ML[_-]?DSA[_-]?(44|65|87).*crypto_sign", callee or "", re.IGNORECASE)
    if match:
        return {"primitive": "ML-DSA", "variant": f"ML-DSA-{match.group(1)}", "operands": {}}
    match = re.search(
        r"SLH[_-]?DSA[_-]?(SHA2|SHAKE)[_-]?(128|192|256)[_-]?([SF]).*crypto_sign",
        callee or "",
        re.IGNORECASE,
    )
    if match:
        variant = f"SLH-DSA-{match.group(1).upper()}-{match.group(2)}{match.group(3).lower()}"
        return {"primitive": "SLH-DSA", "variant": variant, "operands": {}}
    return None


def match_fingerprints(functions, catalog: dict[str, tuple[str, ...]]) -> dict[str, str]:
    """Return high-similarity matches only when both sides are unambiguous."""
    proposals = defaultdict(list)
    for function in functions:
        scored = sorted(
            ((_fingerprint_similarity(function.tokens, shape), name) for name, shape in catalog.items()),
            reverse=True,
        )
        if not scored:
            continue
        best, name = scored[0]
        runner_up = scored[1][0] if len(scored) > 1 else 0.0
        if best >= 0.80 and best - runner_up >= 0.05:
            proposals[name].append(function.name)
    return {names[0]: name for name, names in proposals.items() if len(names) == 1}


def _fingerprint_similarity(left, right) -> float:
    left, right = tuple(left), tuple(right)
    if left == right:
        return 1.0
    if min(len(left), len(right)) < 8:
        return 0.0
    sequence = SequenceMatcher(None, left, right, autojunk=False).ratio()
    left_counts = Counter(_token_category(token) for token in left)
    right_counts = Counter(_token_category(token) for token in right)
    dot = sum(left_counts[key] * right_counts[key] for key in left_counts)
    norm = sqrt(sum(value * value for value in left_counts.values()) * sum(value * value for value in right_counts.values()))
    bag = dot / norm * sqrt(min(len(left), len(right)) / max(len(left), len(right)))
    return max(sequence, bag)


def _token_category(token: str) -> str:
    mnemonic = token.split(":", 1)[0]
    if mnemonic.startswith("J") or mnemonic.startswith("SET") or mnemonic in {"TEST", "CMP", "AND", "OR", "XOR"}:
        return "LOGIC"
    if mnemonic.startswith("MOV") or mnemonic in {"LEA", "PUSH", "POP"}:
        return "DATA"
    if mnemonic in {"ADD", "SUB", "MUL", "IMUL", "DIV", "IDIV", "INC", "DEC"}:
        return "ARITH"
    return mnemonic


def function_tokens(program, function) -> tuple[str, ...]:
    listing = program.getListing()
    return tuple(
        f"{instruction.getMnemonicString()}:"
        + ",".join(
            str(instruction.getOperandType(index))
            for index in range(instruction.getNumOperands())
        )
        for instruction in listing.getInstructions(function.getBody(), True)
    )


def build_fingerprint_catalog(program, names) -> dict[str, tuple[str, ...]]:
    wanted = set(names)
    return {
        str(function.getName()): function_tokens(program, function)
        for function in program.getFunctionManager().getFunctions(True)
        if str(function.getName()) in wanted
    }


def resolved_fingerprint_names(program, catalog) -> dict[str, str]:
    functions = [
        SimpleNamespace(
            name=str(function.getEntryPoint()),
            tokens=function_tokens(program, function),
        )
        for function in program.getFunctionManager().getFunctions(True)
    ]
    return match_fingerprints(functions, catalog)


def callee_name(program, target_vn, resolved_names=None):
    if not target_vn.isAddress():
        return None
    fn = program.getFunctionManager().getFunctionAt(target_vn.getAddress())
    if fn is None:
        return None
    name = str(fn.getName())
    return (resolved_names or {}).get(str(fn.getEntryPoint()), name)


def find_anchors(program, decomp, monitor, timeout=60, fingerprint_catalog=None):
    """Decompile each internal function and return crypto init anchors."""
    from ghidra.program.model.pcode import PcodeOp

    anchors = []
    resolved_names = resolved_fingerprint_names(program, fingerprint_catalog or {})
    fm = program.getFunctionManager()
    for f in fm.getFunctions(True):
        if f.isThunk() or f.isExternal():
            continue
        res = decomp.decompileFunction(f, timeout, monitor)
        if not res.decompileCompleted():
            continue
        high = res.getHighFunction()
        if high is None:
            continue

        for op in high.getPcodeOps():
            if op.getOpcode() != PcodeOp.CALL:
                continue
            callee = callee_name(program, op.getInput(0), resolved_names)
            spec = anchor_spec(callee)
            if spec is None:
                continue

            operands = {}
            for name, idx in spec["operands"].items():
                if op.getNumInputs() > idx:
                    operands[name] = op.getInput(idx)

            anchors.append(
                Anchor(
                    func_name=str(f.getName()),
                    callee=callee,
                    call_addr=str(op.getSeqnum().getTarget()),
                    operands=operands,
                    high=high,
                    primitive=spec["primitive"],
                    variant=spec.get("variant"),
                    resolved_names=resolved_names,
                    resolution_method=(
                        "normalized_fingerprint_anchor"
                        if str(op.getInput(0).getAddress()) in resolved_names
                        else "resolved_api_anchor"
                    ),
                )
            )
    return anchors
