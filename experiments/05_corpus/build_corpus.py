import sys, subprocess, os
sys.path.insert(0, "src")
import torch
import collections
from cipherfault.lifting.lifter import lift_binary
from cipherfault.regions.extractor import extract_regions
from cipherfault.recognizer.featurize import region_to_data

OPTS = ["-O0", "-O1", "-O2", "-O3"]
COMPILERS = ["gcc", "clang"]
BUILD = "corpus/build/_corpus"
os.makedirs(BUILD, exist_ok=True)

JOBS = [
    (["corpus/fixtures/tiny_aes/aes.c"], 1),
    (["corpus/fixtures/crypto2/bignum.c"], 2),
    (["corpus/fixtures/noncrypto/strutils.c"], 0),
    (["corpus/fixtures/noncrypto/mathutils.c"], 0),
]
LABEL_NAMES = {0: "none", 1: "aes", 2: "bignum"}

def compile_obj(cc, srcs, opt, tag):
    out = f"{BUILD}/{tag}_{cc}_{opt.strip('-')}.o"
    subprocess.run([cc, opt, "-g", "-c", *srcs, "-o", out], check=True)
    return out

dataset = []
for srcs, label in JOBS:
    tag = os.path.basename(srcs[0]).replace(".c", "")
    for cc in COMPILERS:
        for opt in OPTS:
            obj = compile_obj(cc, srcs, opt, tag)
            for lf in lift_binary(obj):
                for region in extract_regions(lf):
                    if len(region) < 1:
                        continue
                    d = region_to_data(lf, region, label)
                    d.fn_key = f"{tag}:{lf.name}"
                    d.compiler = cc
                    dataset.append(d)
    print(f"[+] {tag}: running total {len(dataset)} regions")

pos = sum(int(d.y.item()) for d in dataset)
counts = collections.Counter(int(d.y.item()) for d in dataset)

# print(f"[+] total {len(dataset)} regions: {pos} crypto / {len(dataset) - pos} none")
print(f"[+] total {len(dataset)} regions: " +
    ", ".join(f"{LABEL_NAMES[k]}={counts[k]}" for k in sorted(counts)))

torch.save(dataset, "corpus/build/dataset.pt")
print("[+] saved corpus/build/dataset.pt")