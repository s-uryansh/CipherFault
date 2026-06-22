import sys
sys.path.insert(0, "src")
from cipherfault.lifting.lifter import lift_binary
from cipherfault.regions.extractor import extract_regions
from cipherfault.recognizer.featurize import region_to_data

for lf in lift_binary(sys.argv[1]):
    for i, region in enumerate(extract_regions(lf)):
        data = region_to_data(lf, region, label=0) # dummy label for now
        print(f"{lf.name} region {i}: x={tuple(data.x.shape)} edges={data.edge_index.shape[1]}")