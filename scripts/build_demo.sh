#!/usr/bin/env bash
set -euo pipefail

demo_dir="corpus/eval/DEMO-CPP-GOOF"
source_dir="$demo_dir/source"
commit="f0ec7300e74b4d15922dd9e893f6389834e1ca55"

if [ ! -d "$source_dir/.git" ]; then
    git clone --filter=blob:none https://github.com/Arvi3d/cpp-goof.git "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit"
g++ -O2 -s "$source_dir/src/cryptography_hardcoded_iv.cpp" \
    -o "$demo_dir/target_strip" -lcrypto
