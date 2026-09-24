import json
import glob
import os

results = {}
files = glob.glob("result_*.json")
for f in files:
    name = f.replace("result_", "").replace(".json", "")
    with open(f, "r") as fd:
        results[name] = json.load(fd)

out_file = "C:\\Users\\SHAMBHAVI PATIL\\.gemini\\antigravity\\brain\\e16a254b-f4a6-44eb-9d4b-75762019acdc\\JEV_GEMINI_RAW_RESULTS.json"
with open(out_file, "w") as fd:
    json.dump(results, fd, indent=2)
print("Saved to", out_file)
