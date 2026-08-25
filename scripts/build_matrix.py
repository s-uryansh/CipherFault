#!/usr/bin/env python3
"""Compile the pinned AES, ML-KEM, and non-crypto recognition matrix."""

from __future__ import annotations

import argparse
import fcntl
import json
import platform
import shutil
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "corpus" / "external"
BUILD = ROOT / "corpus" / "build" / "matrix"
META = BUILD / "metadata.jsonl"
COMMON_OPTS = ["-O0", "-O1", "-O2", "-O3", "-Os"]
DEFAULT_COMPILERS = [("gcc", "gcc", "g++", []), ("clang", "clang", "clang++", [])]


def _files(directory: str, pattern: str = "*.c") -> list[str]:
    return [str(path.relative_to(ROOT)) for path in sorted((ROOT / directory).glob(pattern))]


def _openssl_include(arch: str, *, prepare: bool = False) -> str:
    generated = BUILD / "generated" / "openssl" / arch
    marker = generated / ".complete"
    generated.mkdir(parents=True, exist_ok=True)
    if not prepare:
        return str(generated.relative_to(ROOT))
    with (generated / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not marker.exists():
            target = {"x86_64": "linux-x86_64", "aarch64": "linux-aarch64"}.get(arch)
            if target is None:
                raise ValueError(f"unsupported OpenSSL corpus architecture: {arch}")
            with tempfile.TemporaryDirectory() as temp_dir:
                subprocess.check_call(
                    [str(EXTERNAL / "openssl" / "Configure"), target, "no-shared"],
                    cwd=temp_dir,
                    stdout=subprocess.DEVNULL,
                )
                subprocess.check_call(["make", "build_generated"], cwd=temp_dir, stdout=subprocess.DEVNULL)
                shutil.copytree(EXTERNAL / "openssl" / "include", generated, dirs_exist_ok=True)
                shutil.copytree(Path(temp_dir) / "include", generated, dirs_exist_ok=True)
                marker.write_text("source-derived OpenSSL include tree\n", encoding="utf-8")
    return str(generated.relative_to(ROOT))


def jobs(arch: str, *, prepare: bool = False) -> list[dict]:
    libpng_config = BUILD / "generated" / "libpng" / "pnglibconf.h"
    libpng_config.parent.mkdir(parents=True, exist_ok=True)
    if prepare:
        shutil.copyfile(EXTERNAL / "libpng" / "pnglibconf.h.prebuilt", libpng_config)
    sqlite_header = EXTERNAL / "sqlite" / "sqlite3.h"
    if prepare and not sqlite_header.exists():
        subprocess.check_call(["./configure", "--disable-shared", "--disable-static"], cwd=EXTERNAL / "sqlite")
        subprocess.check_call(["make", "sqlite3.h"], cwd=EXTERNAL / "sqlite")

    pqclean_dir = "corpus/external/PQClean/crypto_kem/ml-kem-768/clean"
    awslc_dir = "corpus/external/aws-lc/crypto/fipsmodule/ml_kem/mlkem"
    oqs_variant = "aarch64" if arch == "aarch64" else "x86_64"
    oqs_root = f"corpus/external/liboqs/src/kem/ml_kem/mlkem-native_ml-kem-768_{oqs_variant}"
    oqs_dir = f"{oqs_root}/mlkem/src"
    oqs_config = f"{oqs_root}/integration/liboqs/config_{oqs_variant}.h"
    oqs_generated = "corpus/build/matrix/generated/liboqs-aarch64/include" if arch == "aarch64" else "corpus/build/liboqs/include"
    mldsa_root = f"corpus/external/liboqs/src/sig/ml_dsa/mldsa-native_ml-dsa-65_{oqs_variant}"
    mldsa_dir = f"{mldsa_root}/mldsa/src"
    mldsa_config = f"{mldsa_root}/integration/liboqs/config_{oqs_variant}.h"
    openssl_include = _openssl_include(arch, prepare=prepare)
    common = [
        {
            "source": "openssl", "path": "corpus/external/openssl/crypto/aes/aes_core.c",
            "language": "c", "labels": ["AES"],
            "includes": [openssl_include, "corpus/external/openssl/include", "corpus/external/openssl/crypto"],
            "include_symbol_patterns": ["(?i)AES_(set|encrypt|decrypt)"],
        },
        {
            "source": "libsodium", "path": "corpus/external/libsodium/src/libsodium/crypto_core/softaes/softaes.c",
            "language": "c", "labels": ["AES"],
            "includes": ["corpus/external/libsodium/src/libsodium/include", "corpus/external/libsodium/src/libsodium/include/sodium"],
            "commit": "2ce4d906a68eae82b27b4867f3d4172ec508cb27",
            "include_symbol_patterns": ["(?i)^softaes_"],
        },
        {
            "source": "boringssl", "path": "corpus/external/boringssl/crypto/aes/aes.cc",
            "language": "cxx", "labels": ["AES"],
            "includes": ["corpus/external/boringssl/include", "corpus/external/boringssl/crypto"],
            "exclude_symbol_patterns": ["^bcm_success$"],
        },
        {
            "source": "boringssl-aes", "repo": "boringssl",
            "path": "corpus/external/boringssl/crypto/fipsmodule/aes/aes_nohw.cc.inc",
            "language": "cxx", "labels": ["AES"],
            "includes": ["corpus/external/boringssl/include", "corpus/external/boringssl/crypto"],
            "extra_flags": ["-x", "c++"],
            "include_symbol_patterns": ["(?i)(aes|encrypt|decrypt|key)"],
        },
        {
            "source": "aws-lc-aes", "repo": "aws-lc",
            "path": "corpus/external/aws-lc/crypto/fipsmodule/aes/aes_nohw.c",
            "language": "c", "labels": ["AES"],
            "includes": [".", "corpus/external/aws-lc/include", "corpus/external/aws-lc/crypto"],
            "include_symbol_patterns": ["(?i)(aes|encrypt|decrypt|key)"],
        },
    ]
    common += [
        {
            "source": "mbedtls", "path": "corpus/external/mbedtls/tf-psa-crypto/drivers/builtin/src/aes.c",
            "language": "c", "labels": ["AES"],
            "includes": [
                "corpus/external/mbedtls/tf-psa-crypto/include",
                "corpus/external/mbedtls/tf-psa-crypto/core",
                "corpus/external/mbedtls/tf-psa-crypto/drivers/builtin/include",
                "corpus/external/mbedtls/tf-psa-crypto/drivers/builtin/src",
            ],
            "include_symbol_patterns": ["(?i)(setkey|internal_aes|gen_tables)"],
        },
        *[
            {
                "source": f"mbedtls-{label.lower()}",
                "repo": "mbedtls",
                "path": f"corpus/external/mbedtls/tf-psa-crypto/drivers/builtin/src/{name}",
                "language": "c",
                "labels": [label],
                "includes": [
                    "corpus/external/mbedtls/tf-psa-crypto/include",
                    "corpus/external/mbedtls/tf-psa-crypto/core",
                    "corpus/external/mbedtls/tf-psa-crypto/drivers/builtin/include",
                    "corpus/external/mbedtls/tf-psa-crypto/drivers/builtin/src",
                    "corpus/external/mbedtls/tf-psa-crypto/utilities",
                ],
            }
            for label, name in [
                ("RSA", "rsa.c"),
                ("ECC", "ecp.c"),
                ("SHA", "sha1.c"),
                ("SHA", "sha256.c"),
                ("SHA", "sha512.c"),
            ]
        ],
        {
            "source": "tiny-AES-c", "path": "corpus/external/tiny-AES-c/aes.c",
            "language": "c", "labels": ["AES"], "includes": ["corpus/external/tiny-AES-c"],
            "include_symbol_patterns": ["(?i)(KeyExpansion|Cipher|RoundKey|SubBytes|MixColumns)"],
        },
        {
            "source": "wolfssl", "path": "corpus/external/wolfssl/wolfcrypt/src/aes.c",
            "language": "c", "labels": ["AES"], "includes": ["corpus/external/wolfssl"],
            "include_symbol_patterns": ["(?i)(Aes(SetKey|Encrypt|Decrypt|Cbc)|AES_(set|encrypt|decrypt))"],
        },
        *[
            {
                "source": f"wolfssl-{label.lower()}",
                "repo": "wolfssl",
                "path": f"corpus/external/wolfssl/wolfcrypt/src/{name}",
                "language": "c",
                "labels": [label],
                "includes": ["corpus/external/wolfssl"],
            }
            for label, name in [
                ("RSA", "rsa.c"),
                ("ECC", "ecc.c"),
                ("SHA", "sha.c"),
                ("SHA", "sha256.c"),
                ("SHA", "sha512.c"),
            ]
        ],
        {
            "source": "aws-lc-ecc",
            "repo": "aws-lc",
            "path": "corpus/external/aws-lc/crypto/fipsmodule/ec/ec.c",
            "language": "c",
            "labels": ["ECC"],
            "includes": [".", "corpus/external/aws-lc/include", "corpus/external/aws-lc/crypto"],
        },
    ]
    common += [{
        "source": "bearssl", "path": path, "language": "c", "labels": ["AES"],
        "includes": ["corpus/external/bearssl/inc", "corpus/external/bearssl/src"],
    } for path in _files("corpus/external/bearssl/src/symcipher", "aes_*.c") if Path(path).stem in {
        "aes_big_dec", "aes_big_enc", "aes_common", "aes_ct", "aes_ct64",
        "aes_ct64_dec", "aes_ct64_enc", "aes_ct_dec", "aes_ct_enc",
        "aes_small_dec", "aes_small_enc", "aes_x86ni",
    }]
    for label, directory, names in [
        ("RSA", "rsa", {"rsa_gen.c", "rsa_ossl.c", "rsa_sign.c"}),
        ("ECC", "ec", {"ec_mult.c", "ecdsa_sign.c", "ecdsa_vrf.c"}),
        ("SHA", "sha", {"sha1dgst.c", "sha256.c", "sha512.c"}),
        ("ML-DSA", "ml_dsa", {"ml_dsa_ntt.c", "ml_dsa_sign.c", "ml_dsa_matrix.c", "ml_dsa_key_compress.c", "ml_dsa_sample.c"}),
        ("SLH-DSA", "slh_dsa", {"slh_dsa.c", "slh_fors.c", "slh_hypertree.c", "slh_wots.c", "slh_xmss.c"}),
    ]:
        common += [{
            "source": f"openssl-{label.lower()}", "repo": "openssl", "path": path,
            "language": "c", "labels": [label],
            "includes": [openssl_include, "corpus/external/openssl/include", "corpus/external/openssl/crypto", "corpus/external/openssl/providers/common/include"],
        } for path in _files(f"corpus/external/openssl/crypto/{directory}") if Path(path).name in names]
    for label, directory, names in [
        ("RSA", "rsa", {"rsa_i31_keygen_inner.c", "rsa_i31_priv.c", "rsa_i31_pub.c"}),
        ("ECC", "ec", {"ec_p256_m31.c", "ecdsa_i31_sign_raw.c", "ecdsa_i31_vrfy_raw.c"}),
        ("SHA", "hash", {"sha1.c", "sha2small.c", "sha2big.c"}),
    ]:
        common += [{
            "source": f"bearssl-{label.lower()}", "repo": "bearssl", "path": path,
            "language": "c", "labels": [label],
            "includes": ["corpus/external/bearssl/inc", "corpus/external/bearssl/src"],
        } for path in _files(f"corpus/external/bearssl/src/{directory}") if Path(path).name in names]
    for label, directory, names in [
        ("RSA", "rsa", {"rsa.cc.inc", "rsa_impl.cc.inc", "padding.cc.inc"}),
        ("ECC", "ec", {"p256.cc.inc", "scalar.cc.inc", "simple_mul.cc.inc"}),
        ("SHA", "sha", {"sha1.cc.inc", "sha256.cc.inc", "sha512.cc.inc"}),
    ]:
        common += [{
            "source": f"boringssl-{label.lower()}", "repo": "boringssl", "path": path,
            "language": "cxx", "labels": [label], "extra_flags": ["-x", "c++"],
            "includes": ["corpus/external/boringssl/include", "corpus/external/boringssl/crypto"],
        } for path in _files(f"corpus/external/boringssl/crypto/fipsmodule/{directory}", "*.cc.inc") if Path(path).name in names]
    mldsa_pqclean = "corpus/external/PQClean/crypto_sign/ml-dsa-65/clean"
    common += [{
        "source": "PQClean-ML-DSA", "repo": "PQClean", "path": path,
        "language": "c", "labels": ["ML-DSA"],
        "includes": ["corpus/external/PQClean/common", mldsa_pqclean],
        "exclude_symbol_patterns": ["(?i)(shake|randombytes)"],
    } for path in _files(mldsa_pqclean) if Path(path).name != "symmetric-shake.c"]
    slhdsa_pqclean = "corpus/external/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean"
    common += [{
        "source": "PQClean-SLH-DSA", "repo": "PQClean", "path": path,
        "language": "c", "labels": ["SLH-DSA"],
        "includes": ["corpus/external/PQClean/common", slhdsa_pqclean],
        "exclude_symbol_patterns": ["(?i)(sha2|randombytes)"],
    } for path in _files(slhdsa_pqclean) if Path(path).name in {"fors.c", "merkle.c", "sign.c", "utils.c", "utilsx1.c", "wots.c", "wotsx1.c"}]
    common += [{
        "source": "liboqs-ML-DSA", "repo": "liboqs", "path": path,
        "language": "c", "labels": ["ML-DSA"],
        "includes": [".", oqs_generated, "corpus/external/liboqs/src", "corpus/external/liboqs/src/common/pqclean_shims", mldsa_dir],
        "defines": ["MLD_CONFIG_PARAMETER_SET=65", f'MLD_CONFIG_FILE="{mldsa_config}"'],
        "exclude_symbol_patterns": ["(?i)(shake|randombytes)"],
    } for path in _files(mldsa_dir) if Path(path).name not in {"debug.c"}]
    slhdsa_liboqs = "corpus/external/liboqs/src/sig/slh_dsa/slh_dsa_c"
    common += [{
        "source": "liboqs-SLH-DSA", "repo": "liboqs", "path": f"{slhdsa_liboqs}/slh_dsa.c",
        "language": "c", "labels": ["SLH-DSA"], "includes": [oqs_generated, slhdsa_liboqs],
    }]
    common += [{
        "source": "PQClean", "path": path, "language": "c", "labels": ["ML-KEM"],
        "includes": ["corpus/external/PQClean/common", pqclean_dir],
        "exclude_symbol_patterns": ["(?i)(sha3|shake|randombytes)"],
    } for path in _files(pqclean_dir)]
    common += [{
        "source": "aws-lc", "path": path, "language": "c", "labels": ["ML-KEM"],
        "includes": [".", "corpus/external/aws-lc/include", "corpus/external/aws-lc/crypto", awslc_dir],
        "defines": ["MLK_CONFIG_PARAMETER_SET=768", 'MLK_CONFIG_FILE="corpus/config/mlkem_corpus_config.h"'],
        "exclude_symbol_patterns": ["(?i)(sha3|shake|randombytes)"],
    } for path in _files(awslc_dir) if Path(path).name not in {"debug.c", "mlkem_native_bcm.c"}]
    common += [{
        "source": "liboqs", "path": path, "language": "c", "labels": ["ML-KEM"],
        "includes": [".", oqs_generated, "corpus/external/liboqs/src", "corpus/external/liboqs/src/common/pqclean_shims", oqs_dir, oqs_dir.replace("/src", "/include")],
        "defines": ["MLK_CONFIG_PARAMETER_SET=768", f'MLK_CONFIG_FILE="{oqs_config}"'],
        "exclude_symbol_patterns": ["(?i)(sha3|shake|randombytes)"],
    } for path in _files(oqs_dir) if Path(path).name != "debug.c"]
    common += [
        {
            "source": "openssl", "path": "corpus/external/openssl/crypto/ml_kem/ml_kem.c",
            "language": "c", "labels": ["ML-KEM"],
            "includes": [openssl_include, "corpus/external/openssl/include", "corpus/external/openssl/crypto"],
            "exclude_symbol_patterns": ["(?i)(sha3|shake|randombytes)"],
        },
        {
            "source": "boringssl", "path": "corpus/external/boringssl/crypto/fipsmodule/mlkem/mlkem.cc.inc",
            "language": "cxx", "labels": ["ML-KEM"],
            "includes": ["corpus/external/boringssl/include", "corpus/external/boringssl/crypto"],
            "extra_flags": ["-x", "c++"],
            "exclude_symbol_patterns": ["(?i)(sha3|shake|randombytes|self_test)"],
        },
    ]
    common += [{
        "source": "zlib", "path": path, "language": "c", "labels": ["none"],
        "includes": ["corpus/external/zlib"], "extra_flags": ["-include", "unistd.h"],
    } for path in _files("corpus/external/zlib") if Path(path).name not in {"example.c", "minigzip.c"}]
    common += [{
        "source": "libpng", "path": path, "language": "c", "labels": ["none"],
        "includes": [str(libpng_config.parent.relative_to(ROOT)), "corpus/external/libpng", "corpus/external/zlib"],
    } for path in _files("corpus/external/libpng") if Path(path).name.startswith("png") and Path(path).name not in {"pngtest.c", "pngsimd.c"}]
    common += [{
        "source": "sqlite", "path": f"corpus/external/sqlite/ext/misc/{name}",
        "language": "c", "labels": ["none"],
        "includes": ["corpus/external/sqlite", "corpus/external/sqlite/src"],
    } for name in ["base64.c", "decimal.c", "regexp.c", "uuid.c", "percentile.c", "series.c"]]
    return common


def run_text(args: list[str], cwd: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def source_commit(job: dict) -> str:
    if "commit" in job:
        return job["commit"]
    return run_text(
        ["git", "-c", "safe.directory=*", "rev-parse", "HEAD"],
        EXTERNAL / job.get("repo", job["source"]),
    )


def build(job: dict, compiler: tuple[str, str, str, list[str]], opt: str, arch: str) -> dict:
    compiler_id, c_driver, cxx_driver, driver_flags = compiler
    driver = cxx_driver if job["language"] == "cxx" else c_driver
    source = ROOT / job["path"]
    out_dir = BUILD / arch / job["source"] / compiler_id / opt.removeprefix("-")
    out_dir.mkdir(parents=True, exist_ok=True)
    source_id = sha256(job["path"].encode()).hexdigest()[:10]
    artifact = out_dir / f"{source.stem}-{source_id}.so"
    with tempfile.TemporaryDirectory() as temp_dir:
        obj = Path(temp_dir) / "source.o"
        compile_command = [
            driver, *driver_flags, opt, "-g", "-fPIC", *job.get("extra_flags", []),
            *(["-std=c++17"] if job["language"] == "cxx" else []),
            *[f"-D{value}" for value in job.get("defines", [])],
            *[f"-I{ROOT / include}" for include in job["includes"]],
            "-c", str(source), "-o", str(obj),
        ]
        proc = subprocess.run(compile_command, cwd=ROOT, text=True, capture_output=True)
        if proc.returncode == 0:
            link_command = [
                driver, *driver_flags, "-shared", "-Wl,--unresolved-symbols=ignore-all",
                str(obj), "-o", str(artifact),
            ]
            proc = subprocess.run(link_command, cwd=ROOT, text=True, capture_output=True)
    error = " ".join((proc.stderr or proc.stdout).split())[:500] if proc.returncode else None
    return {
        "source": job["source"], "commit": source_commit(job), "source_file": job["path"],
        "compiler": compiler_id, "compiler_version": run_text([driver, "--version"]).splitlines()[0],
        "opt": opt, "arch": arch, "artifact": str(artifact.relative_to(ROOT)),
        "labels": job["labels"], "status": "ok" if proc.returncode == 0 else "failed", "error": error,
        "exclude_symbol_patterns": job.get("exclude_symbol_patterns", []),
        "include_symbol_patterns": job.get("include_symbol_patterns", []),
    }


def optimization_levels(compiler_id: str) -> list[str]:
    return [*COMMON_OPTS, *(["-Oz"] if compiler_id.startswith("clang-") or compiler_id == "clang" else [])]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler-id")
    parser.add_argument("--cc")
    parser.add_argument("--cxx")
    parser.add_argument("--target")
    parser.add_argument("--sysroot")
    parser.add_argument("--gcc-toolchain")
    parser.add_argument("--linker")
    parser.add_argument("--arch", default=platform.machine())
    parser.add_argument("--metadata", type=Path, default=META)
    args = parser.parse_args()
    if any((args.compiler_id, args.cc, args.cxx)) and not all((args.compiler_id, args.cc, args.cxx)):
        parser.error("--compiler-id, --cc, and --cxx must be supplied together")
    driver_flags = [
        *( [f"--target={args.target}"] if args.target else [] ),
        *( [f"--sysroot={args.sysroot}"] if args.sysroot else [] ),
        *( [f"--gcc-toolchain={args.gcc_toolchain}"] if args.gcc_toolchain else [] ),
        *( [f"-fuse-ld={args.linker}"] if args.linker else [] ),
    ]
    compilers = [(args.compiler_id, args.cc, args.cxx, driver_flags)] if args.compiler_id else DEFAULT_COMPILERS
    rows = [
        build(job, compiler, opt, args.arch)
        for job in jobs(args.arch, prepare=True)
        for compiler in compilers
        for opt in optimization_levels(compiler[0])
    ]
    metadata = args.metadata if args.metadata.is_absolute() else ROOT / args.metadata
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    ok = sum(row["status"] == "ok" for row in rows)
    print(f"[+] wrote {metadata.relative_to(ROOT)} rows={len(rows)} ok={ok} failed={len(rows)-ok}")
    for row in rows:
        if row["status"] == "failed":
            print(f"[failed] {row['source_file']} {row['compiler']} {row['opt']}: {row['error']}")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
