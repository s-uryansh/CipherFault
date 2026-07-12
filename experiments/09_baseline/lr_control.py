import sys; sys.path.insert(0, "src")
import torch
from sklearn.linear_model import LogisticRegression
from cipherfault.recognizer.featurize import VOCAB

ds = torch.load("corpus/build/dataset.pt", weights_only=False)

# SAME function-disjoint split as train.py
keys = sorted({d.fn_key for d in ds})
g = torch.Generator().manual_seed(0)
kperm = torch.randperm(len(keys), generator=g)
train_keys = {keys[i] for i in kperm[:int(0.8*len(keys))].tolist()}

def vec(d): return d.x.sum(0).numpy() 
def split(in_train):
    X = [vec(d) for d in ds if (d.fn_key in train_keys) == in_train]
    y = [int(d.y) for d in ds if (d.fn_key in train_keys) == in_train]
    return X, y

Xtr, ytr = split(True)
Xte, yte = split(False)
clf = LogisticRegression(max_iter=1000).fit(Xtr, ytr)
print(f"[+] LR (histogram-only, NO graph) test acc: {clf.score(Xte, yte):.2f}")
print("[+] coefficients (crypto-positive = larger):")
for name, w in sorted(zip(VOCAB, clf.coef_[0]), key=lambda t: -abs(t[1])):
    print(f"      {name:6} {w:+.2f}")