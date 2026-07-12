import sys; sys.path.insert(0, "src")
import torch
from sklearn.linear_model import LogisticRegression
from cipherfault.recognizer.featurize import VOCAB

ds = torch.load("corpus/build/dataset.pt", weights_only=False)

def vec(d): return d.x.sum(0).numpy()
Xtr = [vec(d) for d in ds if d.compiler == "gcc"]
ytr = [int(d.y) for d in ds if d.compiler == "gcc"]
Xte = [vec(d) for d in ds if d.compiler == "clang"]
yte = [int(d.y) for d in ds if d.compiler == "clang"]
print(f"[+] train (gcc): {len(Xtr)}   test (clang): {len(Xte)}")

clf = LogisticRegression(max_iter=1000).fit(Xtr, ytr)
print(f"[+] LR train-gcc / test-clang acc: {clf.score(Xte, yte):.2f}")