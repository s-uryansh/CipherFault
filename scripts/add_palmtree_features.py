#!/usr/bin/env python3
"""Append official PalmTree block embeddings to the recognizer dataset."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import torch


ROOT = Path(__file__).resolve().parents[1]
PALMTREE = ROOT / "corpus/external/PalmTree"
INPUT = ROOT / "corpus/build/recognizer_dataset.pt"
OUTPUT = ROOT / "corpus/build/recognizer_palmtree_dataset.pt"


def load_model():
    source = PALMTREE / "src"
    pretrained = PALMTREE / "pre-trained_model"
    sys.path[:0] = [str(source), str(pretrained)]
    root = importlib.import_module("palmtree")
    sys.modules["bert_pytorch"] = root
    modules = [
        "model", "model.bert", "model.embedding", "model.embedding.bert",
        "model.embedding.token", "model.embedding.position", "model.embedding.segment",
        "model.transformer", "model.attention", "model.attention.multi_head",
        "model.attention.single", "model.utils", "model.utils.feed_forward",
        "model.utils.gelu", "model.utils.sublayer", "model.utils.layer_norm",
    ]
    for name in modules:
        sys.modules[f"bert_pytorch.{name}"] = importlib.import_module(f"palmtree.{name}")
    model = torch.load(
        pretrained / "palmtree/transformer.ep19", weights_only=False, map_location="cpu"
    )
    vocab = importlib.import_module("vocab").WordVocab.load_vocab(pretrained / "palmtree/vocab")
    model.eval()
    return model, vocab


def encode(model, vocab, instructions: list[str], batch_size: int = 512) -> torch.Tensor:
    result = []
    for start in range(0, len(instructions), batch_size):
        batch = instructions[start:start + batch_size]
        sequences = []
        for instruction in batch:
            tokens = instruction.lower().replace(",", " ").split()
            sequence = [3, *vocab.to_seq(" ".join(tokens)), 2][:20]
            sequences.append(sequence + [0] * (20 - len(sequence)))
        sequence = torch.tensor(sequences, dtype=torch.long)
        segment = (sequence != 0).long()
        with torch.no_grad():
            result.append(model(sequence, segment).mean(dim=1))
        if start == 0 or start + batch_size >= len(instructions) or (start // batch_size + 1) % 20 == 0:
            print(f"[PalmTree] {min(start + batch_size, len(instructions))}/{len(instructions)} unique instructions", flush=True)
    return torch.cat(result)


def main() -> int:
    if not PALMTREE.exists():
        raise SystemExit("PalmTree missing; run bash scripts/fetch_corpus.sh")
    dataset = torch.load(INPUT, weights_only=False)
    all_instructions = [instruction for graph in dataset for block in graph._instructions for instruction in block]
    instructions = list(dict.fromkeys(all_instructions))
    indices = {instruction: index for index, instruction in enumerate(instructions)}
    model, vocab = load_model()
    encoded = encode(model, vocab, instructions)
    offset = 0
    for graph in dataset:
        block_embeddings = []
        for block in graph._instructions:
            count = len(block)
            if count:
                block_embeddings.append(encoded[[indices[instruction] for instruction in block]].mean(dim=0))
                offset += count
            else:
                block_embeddings.append(torch.zeros(model.hidden))
        graph.x = torch.cat((graph.x, torch.stack(block_embeddings)), dim=1)
    if offset != len(all_instructions):
        raise RuntimeError("PalmTree instruction alignment failed")
    torch.save(dataset, OUTPUT)
    print(f"[+] wrote {OUTPUT.relative_to(ROOT)} regions={len(dataset)} features={dataset[0].x.shape[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
