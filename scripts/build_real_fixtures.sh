#!/usr/bin/env bash
set -euo pipefail

case_dir="corpus/eval/MOONLIGHT-CRYPTO"
source_dir="$case_dir/source"
commit="874ac9548f1bd6f095ef2b435c42cdde460e7821"
stub_dir="${TMPDIR:-/tmp}/cipherfault-moonlight-stubs"

mkdir -p "$case_dir" "$stub_dir/enet"
if [ ! -d "$source_dir/.git" ]; then
    git clone --filter=blob:none https://github.com/moonlight-stream/moonlight-common-c.git "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit"

cat > "$stub_dir/enet/enet.h" <<'EOF'
#pragma once
typedef struct _ENetHost ENetHost;
typedef struct _ENetPeer ENetPeer;
typedef unsigned int enet_uint32;
typedef struct _ENetEvent { int type; } ENetEvent;
EOF

cc -O2 -g -I"$stub_dir" -I"$source_dir/src" \
    -c "$source_dir/src/PlatformCrypto.c" \
    -o "$case_dir/target_platform_crypto_reference.o" \
    -Wno-unused-function
cp "$case_dir/target_platform_crypto_reference.o" "$case_dir/target_platform_crypto_strip.o"
strip --strip-debug "$case_dir/target_platform_crypto_strip.o"
