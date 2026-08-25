#!/usr/bin/env bash
set -euo pipefail

case_dir="corpus/eval/CVE-2017-3225"
source_dir="$case_dir/source"
commit="d85ca029f257b53a96da6c2fb421e78a003a9943"
build_dir="${TMPDIR:-/tmp}/cipherfault-uboot-cve-2017-3225-build"
reference="$case_dir/target_uboot_cve_2017_3225_reference.o"
target="$case_dir/target_uboot_cve_2017_3225.o"
allstrip_target="$case_dir/target_uboot_cve_2017_3225_allstrip.o"

mkdir -p "$case_dir"
if [ ! -d "$source_dir/.git" ]; then
    git clone --filter=blob:none https://github.com/u-boot/u-boot.git "$source_dir"
fi
if ! git -C "$source_dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$source_dir" fetch --depth 1 origin "$commit"
fi
git -C "$source_dir" checkout --detach "$commit"

make -C "$source_dir" O="$build_dir" sandbox_defconfig
make -C "$source_dir" O="$build_dir" lib/aes.o cmd/aes.o

ld -r "$build_dir/cmd/aes.o" "$build_dir/lib/aes.o" -o "$reference"
cp "$reference" "$target"
strip --strip-debug "$target"
cp "$reference" "$allstrip_target"
strip --strip-all "$allstrip_target"
