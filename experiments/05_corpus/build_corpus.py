import sys, itertools, subprocess, os
sys.path.insert(0, "src")
import torch
from cipherfault.lifting.lifter import lift_binary
from cipherfault.regions.extractor import extract_regions
from cipherfault.recognizer.featurize import region_to_data

OPTS = ["-O0", "-O1", "-O2", "-O3"]
BUILD = "corpus/build/_corpus"
os.makedirs(BUILD, exist_ok=True)

JOBS = [
    (["corpus/fixtures/tiny_aes/aes.c"], 1),
    (["corpus/fixtures/noncrypto/strutils.c"], 0),
    (["corpus/fixtures/noncrypto/mathutils.c"], 0),
]

def compile_obj(srcs, opt, tag):
    out = f"{BUILD}/{tag}_{opt.strip('-')}.o"
    subprocess.run(["gcc", opt, "-g", "-c", *srcs, "-o", out], check=True)
    return out

dataset = []
for srcs, label in JOBS:
    tag = os.path.basename(srcs[0]).replace(".c", "")
    for opt in OPTS:
        obj = compile_obj(srcs, opt, tag)
        for lf in lift_binary(obj):
            for region in extract_regions(lf):
                if len(region) < 1:
                    continue
                d = region_to_data(lf, region, label)
                d.fn_key = f"{tag}:{lf.name}"
                dataset.append(d)
    print(f"[+] {tag}: running total {len(dataset)} regions")

pos = sum(int(d.y.item()) for d in dataset)
print(f"[+] total {len(dataset)} regions: {pos} crypto / {len(dataset) - pos} none")
torch.save(dataset, "corpus/build/dataset.pt")
print("[+] saved corpus/build/dataset.pt")