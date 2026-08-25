#!/usr/bin/env bash
set -euo pipefail

mkdir -p corpus/eval/CWE-329-MITRE
cc -O2 -g corpus/eval/CWE-329-MITRE/source/cwe329_static_iv.c \
    -lcrypto -o corpus/eval/CWE-329-MITRE/target_dbg
cp corpus/eval/CWE-329-MITRE/target_dbg corpus/eval/CWE-329-MITRE/target_strip
strip -s corpus/eval/CWE-329-MITRE/target_strip
