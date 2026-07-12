import sys; sys.path.insert(0, "src")
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from torch_geometric.nn import SAGEConv, global_mean_pool
from sklearn.linear_model import LogisticRegression

ds = torch.load("corpus/build/dataset.pt", weights_only=False)
n_classes = int(max(int(d.y.item()) for d in ds)) + 1
print(f"[+] {len(ds)} regions, {n_classes} classes")

# clang holdout: train gcc, test clang
tr = [d for d in ds if d.compiler == "gcc"]
te = [d for d in ds if d.compiler == "clang"]
print(f"[+] train(gcc)={len(tr)}  test(clang)={len(te)}")

# LR on histograms
def vec(d): return d.x.sum(0).numpy()
clf = LogisticRegression(max_iter=2000).fit([vec(d) for d in tr], [int(d.y) for d in tr])
lr_acc = clf.score([vec(d) for d in te], [int(d.y) for d in te])
print(f"[LR ] histogram-only  test-clang acc: {lr_acc:.2f}")

# GNN
device = "cuda" if torch.cuda.is_available() else "cpu"
tl = DataLoader(tr, batch_size=8, shuffle=True)
vl = DataLoader(te, batch_size=8)

class GNN(torch.nn.Module):
    def __init__(self, in_dim, hidden=32, classes=n_classes):
        super().__init__()
        self.c1 = SAGEConv(in_dim, hidden)
        self.c2 = SAGEConv(hidden, hidden)
        self.lin = torch.nn.Linear(hidden, classes)
    def forward(self, x, ei, b):
        x = F.relu(self.c1(x, ei)); x = F.relu(self.c2(x, ei))
        return self.lin(global_mean_pool(x, b))

torch.manual_seed(0)
m = GNN(ds[0].x.shape[1]).to(device)
opt = torch.optim.Adam(m.parameters(), lr=0.01)
def run(loader, train):
    m.train() if train else m.eval()
    corr = tot = 0
    for b in loader:
        b = b.to(device)
        if train: opt.zero_grad()
        out = m(b.x, b.edge_index, b.batch)
        loss = F.cross_entropy(out, b.y)
        if train: loss.backward(); opt.step()
        corr += (out.argmax(1) == b.y).sum().item(); tot += b.num_graphs
    return corr / tot
for ep in range(1, 101):
    a = run(tl, True)
    if ep % 20 == 0:
        print(f"[GNN] epoch {ep:3d} train {a:.2f}  test-clang {run(vl, False):.2f}")