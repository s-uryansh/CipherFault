#!/usr/bin/env bash
set -euo pipefail

root=corpus/toolchains
downloads="$root/downloads"
mkdir -p "$downloads"

fetch() {
    version="$1"
    archive="arm-gnu-toolchain-${version}-x86_64-aarch64-none-linux-gnu.tar.xz"
    checksum="$2"
    url="https://developer.arm.com/-/media/Files/downloads/gnu/${version}/binrel/${archive}"
    if [ ! -d "$root/${archive%.tar.xz}" ]; then
        curl -fL --retry 3 "$url" -o "$downloads/$archive"
        printf '%s  %s\n' "$checksum" "$downloads/$archive" | sha256sum -c -
        tar -xJf "$downloads/$archive" -C "$root"
    fi
}

fetch 11.3.rel1 50cdef6c5baddaa00f60502cc8b59cc11065306ae575ad2f51e412a9b2a90364
fetch 12.3.rel1 960ec0bce309528f603639d8228ef39e6fb9185289ff42b01aa3b4de315accef
fetch 13.3.rel1 322f0b4482fc0d9fa0bb468134841f08d8c554c54ff5aa29a13a7a24bf7e1eb5
