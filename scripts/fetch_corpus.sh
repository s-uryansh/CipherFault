#!/usr/bin/env bash
set -euo pipefail

mkdir -p corpus/external

clone_once() {
    url="$1"
    dir="$2"
    ref="$3"
    if [ -d "corpus/external/$dir" ]; then
        echo "[skip] $dir already exists"
    else
        git clone --filter=blob:none --no-checkout "$url" "corpus/external/$dir"
        git -C "corpus/external/$dir" fetch --depth 1 origin "$ref"
        git -C "corpus/external/$dir" checkout --detach FETCH_HEAD
    fi
}

clone_once https://github.com/openssl/openssl.git openssl 799252f3b67d0429e64736f922a3c2860135facb
clone_once https://boringssl.googlesource.com/boringssl.git boringssl f1f2556a5dfa59e147d9d47279cc3f7f8a18b433
clone_once https://github.com/jedisct1/libsodium.git libsodium 2ce4d906a68eae82b27b4867f3d4172ec508cb27
clone_once https://github.com/open-quantum-safe/liboqs.git liboqs 9d20051143544daa348bc0bbdcef5ef121e385d3
clone_once https://github.com/PQClean/PQClean PQClean 202a8f96315f9ed219387a50f7e40d04af037ea8
clone_once https://github.com/aws/aws-lc.git aws-lc 3c23b445e5ef21a32e46f36ee9704c1ebb3bd2f1
clone_once https://github.com/madler/zlib.git zlib e3dc0a85b7032e98380dec011bc8f2c2ee0d8fca
clone_once https://github.com/pnggroup/libpng.git libpng d1d0abeffede1cc898ddc3d0e600839cf026d749
clone_once https://github.com/sqlite/sqlite.git sqlite da7dc33fb2075dc9a9376679889f6843c33d6cb9
clone_once https://github.com/Mbed-TLS/mbedtls.git mbedtls ce0384b99949b5c8e80548d3b311c39ed0d5eb7a
git -C corpus/external/mbedtls submodule update --init --depth 1 tf-psa-crypto
clone_once https://github.com/kokke/tiny-AES-c.git tiny-AES-c 23856752fbd139da0b8ca6e471a13d5bcc99a08d
clone_once https://github.com/wolfSSL/wolfssl.git wolfssl ac01707f552c611fbd135cc723b2682b3e7f80f2
clone_once https://www.bearssl.org/git/BearSSL bearssl 7bea48e5e850ab4cafbe68d3765cdaba13a86d6f
clone_once https://github.com/palmtreemodel/PalmTree.git PalmTree 4a87e058a2f16835ecaa18b2674d5db3aff16c49
