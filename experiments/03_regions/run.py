import sys
sys.path.insert(0, "src")
from cipherfault.lifting.lifter import lift_binary
from cipherfault.regions.extractor import extract_regions

for lf in lift_binary(sys.argv[1]):
    regions = extract_regions(lf)
    if regions:
        print(f"{lf.name}: {lf.cfg.number_of_nodes()} blocks -> {len(regions)} loop-regions")
        for i, r in enumerate(regions):
            print(f"    region {i}: {len(r)} blocks")