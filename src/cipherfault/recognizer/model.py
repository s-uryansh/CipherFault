"""Graph model used by the primitive recognizer."""

from __future__ import annotations

import torch
import torch.nn.functional as F
from torch_geometric.nn import RGCNConv, global_add_pool, global_max_pool, global_mean_pool


class PrimitiveGraphSAGE(torch.nn.Module):
    def __init__(self, input_dim: int, classes: int = 8, hidden: int = 64):
        super().__init__()
        self.convs = torch.nn.ModuleList(
            [
                RGCNConv(input_dim, hidden, num_relations=2),
                RGCNConv(hidden, hidden, num_relations=2),
                RGCNConv(hidden, hidden, num_relations=2),
            ]
        )
        self.output = torch.nn.Sequential(
            torch.nn.Linear(hidden * 2 + input_dim * 3, hidden),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.1),
            torch.nn.Linear(hidden, classes),
        )

    def forward(self, x, edge_index, edge_type, batch):
        raw = (x > 0).to(x.dtype)
        x = F.normalize(raw, p=1, dim=1)
        for conv in self.convs:
            x = F.relu(conv(x, edge_index, edge_type))
        pooled = torch.cat((
            global_mean_pool(x, batch), global_max_pool(x, batch),
            global_mean_pool(raw, batch), global_max_pool(raw, batch),
            torch.log1p(global_add_pool(raw, batch)),
        ), dim=1)
        return self.output(pooled)
