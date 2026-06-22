import sys
sys.path.insert(0, "src")
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from torch_geometric.nn import SAGEConv, global_mean_pool

dataset = torch.load("corpus/build/dataset.pt", weights_only=False)
torch.manual_seed(0)

# function-disjoint split: every variant of a source function goes
# entirely to train OR entirely to test. prevents the same function at
# different -O levels appearing on both sides (which would leak).
keys = sorted({d.fn_key for d in dataset})
g = torch.Generator().manual_seed(0)
kperm = torch.randperm(len(keys), generator=g)
k_split = int(0.8 * len(keys))
train_keys = {keys[i] for i in kperm[:k_split].tolist()}
train_ds = [d for d in dataset if d.fn_key in train_keys]
test_ds = [d for d in dataset if d.fn_key not in train_keys]
print(f"[+] {len(keys)} source fns -> "
    f"{len(train_ds)} train / {len(test_ds)} test regions")
train_loader = DataLoader(train_ds, batch_size=8, shuffle=True)
test_loader = DataLoader(test_ds, batch_size=8)

device = "cuda" if torch.cuda.is_available() else "cpu"

class GNN(torch.nn.Module):
    def __init__(self, in_dim, hidden=32, classes=2):
        super().__init__()
        self.c1 = SAGEConv(in_dim, hidden)
        self.c2 = SAGEConv(hidden, hidden)
        self.lin = torch.nn.Linear(hidden, classes)
    def forward(self, x, edge_index, batch):
        x = F.relu(self.c1(x, edge_index))
        x = F.relu(self.c2(x, edge_index))
        x = global_mean_pool(x, batch)
        return self.lin(x)
model = GNN(in_dim=dataset[0].x.shape[1]).to(device)
opt = torch.optim.Adam(model.parameters(), lr=0.01)

def run(loader, train):
    model.train() if train else model.eval()
    correct = total = 0
    for batch in loader:
        batch = batch.to(device)
        if train: opt.zero_grad()
        out = model(batch.x, batch.edge_index, batch.batch)
        loss = F.cross_entropy(out, batch.y)
        if train:
            loss.backward();
            opt.step()
        correct += (out.argmax(1) == batch.y).sum().item()
        total += batch.num_graphs
    return correct / total

for epoch in range(1, 51):
    tr = run(train_loader, True)
    if epoch % 10 == 0:
        te = run(test_loader, False)
        print(f"epoch {epoch:3d} train_acc {tr:.2f} test_acc {te:.2f}")
