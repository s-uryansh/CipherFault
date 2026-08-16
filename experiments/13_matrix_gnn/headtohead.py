#!/usr/bin/env python3
"""LR vs GraphSAGE on the same matrix-backed recognizer split."""

from __future__ import annotations

import collections
import random
import sys

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from torch_geometric.loader import DataLoader
from torch_geometric.nn import SAGEConv, global_mean_pool

sys.path.insert(0, "src")


DATASET = "corpus/build/recognizer_dataset.pt"
SEED = 0
EPOCHS = 100


def labels(ds):
    return [int(d.y.item()) for d in ds]


def vec(d):
    return d.x.sum(0).numpy()


def function_disjoint_split(ds, seed=SEED):
    keys = sorted({d.fn_key for d in ds})
    rng = random.Random(seed)
    rng.shuffle(keys)
    split = int(0.8 * len(keys))
    train_keys = set(keys[:split])
    return [d for d in ds if d.fn_key in train_keys], [d for d in ds if d.fn_key not in train_keys]


def compiler_holdout_split(ds):
    return (
        [d for d in ds if getattr(d, "compiler", None) == "gcc"],
        [d for d in ds if getattr(d, "compiler", None) == "clang"],
    )


def metric_line(y_true, pred):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        pred,
        average="macro",
        zero_division=0,
    )
    return accuracy_score(y_true, pred), precision, recall, f1


def run_lr(train, test):
    y_train = labels(train)
    y_test = labels(test)
    if len(set(y_train)) < 2:
        return None
    clf = LogisticRegression(max_iter=2000).fit(
        np.stack([vec(d) for d in train]),
        y_train,
    )
    pred = clf.predict(np.stack([vec(d) for d in test]))
    return pred, metric_line(y_test, pred), confusion_matrix(y_test, pred)


class GraphSage(torch.nn.Module):
    def __init__(self, in_dim, classes, hidden=32):
        super().__init__()
        self.c1 = SAGEConv(in_dim, hidden)
        self.c2 = SAGEConv(hidden, hidden)
        self.lin = torch.nn.Linear(hidden, classes)

    def forward(self, x, edge_index, batch):
        x = F.relu(self.c1(x, edge_index))
        x = F.relu(self.c2(x, edge_index))
        return self.lin(global_mean_pool(x, batch))


def run_gnn(train, test, classes):
    y_test = labels(test)
    if len(set(labels(train))) < 2:
        return None

    device = "cuda" if torch.cuda.is_available() else "cpu"
    torch.manual_seed(SEED)
    model = GraphSage(train[0].x.shape[1], classes).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.01)
    train_loader = DataLoader(train, batch_size=8, shuffle=True)
    test_loader = DataLoader(test, batch_size=8, shuffle=False)

    for _ in range(EPOCHS):
        model.train()
        for batch in train_loader:
            batch = batch.to(device)
            opt.zero_grad()
            loss = F.cross_entropy(model(batch.x, batch.edge_index, batch.batch), batch.y)
            loss.backward()
            opt.step()

    model.eval()
    preds = []
    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            preds.extend(model(batch.x, batch.edge_index, batch.batch).argmax(1).cpu().tolist())

    return preds, metric_line(y_test, preds), confusion_matrix(y_test, preds)


def print_result(model_name, result):
    if result is None:
        print(f"{model_name}: skipped, train split has fewer than two classes")
        return None
    _, metrics, cm = result
    acc, precision, recall, f1 = metrics
    print(f"{model_name}: accuracy={acc:.3f} precision_macro={precision:.3f} recall_macro={recall:.3f} f1_macro={f1:.3f}")
    print(cm)
    return f1


def evaluate(name, train, test, classes):
    print(f"\n[{name}] train={len(train)} test={len(test)}")
    if not train or not test:
        print("skipped: empty split")
        return
    print("train_labels", collections.Counter(labels(train)))
    print("test_labels", collections.Counter(labels(test)))
    lr_f1 = print_result("LR", run_lr(train, test))
    gnn_f1 = print_result("GNN", run_gnn(train, test, classes))
    if lr_f1 is not None and gnn_f1 is not None:
        print(f"delta_gnn_minus_lr_f1={gnn_f1 - lr_f1:+.3f}")


def main() -> int:
    ds = torch.load(DATASET, weights_only=False)
    classes = max(labels(ds)) + 1
    print(f"regions={len(ds)} classes={classes}")
    print("by_label", collections.Counter(labels(ds)))
    print("by_source", collections.Counter(getattr(d, "source", "?") for d in ds))
    evaluate("function_disjoint", *function_disjoint_split(ds), classes)
    evaluate("compiler_holdout_gcc_to_clang", *compiler_holdout_split(ds), classes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
