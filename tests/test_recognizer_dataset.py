import sys

import networkx as nx
import pytest
import torch

pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

sys.path.insert(0, "src")
sys.path.insert(0, "scripts")

from build_recognizer_dataset import LABELS as DATASET_LABELS, function_label
from merge_matrix_metadata import artifact_matches_arch, merge
from build_matrix import jobs, optimization_levels
from train_recognizer import LABELS, TEST_SOURCES, VALIDATION_SOURCES, ensemble_predictions, source_balanced_weights
from cipherfault.lifting.types import BasicBlock, LiftedFunction
from cipherfault.recognizer.dwarf import (
    SourceRange,
    _file_table,
    candidate_labeled_regions,
    labeled_regions,
)
from cipherfault.recognizer.featurize import SEMANTIC_BINS, VOCAB, block_features, region_to_data
from cipherfault.recognizer.model import PrimitiveGraphSAGE
from cipherfault.regions.extractor import extract_regions


def test_function_label_applies_explicit_symbol_exclusions():
    row = {"labels": ["AES"], "exclude_symbol_patterns": [r"^bcm_success$"]}

    assert function_label(row, "AES_encrypt") == 0
    assert function_label(row, "bcm_success") == DATASET_LABELS["none"]
    assert function_label({"labels": ["none"]}, "anything") == DATASET_LABELS["none"]


def test_function_label_requires_explicit_primitive_symbol_when_configured():
    row = {"labels": ["AES"], "include_symbol_patterns": [r"(?i)(encrypt|key)"]}

    assert function_label(row, "aes_encrypt") == 0
    assert function_label(row, "aes_self_test") == DATASET_LABELS["none"]


def test_training_weights_balance_each_source_and_label_group():
    graphs = [
        type("Graph", (), {"source": "large", "y": torch.tensor([0])})(),
        type("Graph", (), {"source": "large", "y": torch.tensor([0])})(),
        type("Graph", (), {"source": "small", "y": torch.tensor([1])})(),
    ]

    weights = source_balanced_weights(graphs)

    assert sum(weights[:2]) == pytest.approx(weights[2])


def test_matrix_merge_rejects_failed_builds(tmp_path):
    shard = tmp_path / "failed.jsonl"
    shard.write_text('{"status":"failed"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="failed builds"):
        merge([shard])


def test_matrix_artifact_architecture_check_reads_elf_machine(tmp_path):
    artifact = tmp_path / "target.so"
    artifact.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + (183).to_bytes(2, "little"))

    assert artifact_matches_arch(artifact, "aarch64")
    assert not artifact_matches_arch(artifact, "x86_64")


def test_compiler_matrix_uses_only_supported_optimization_levels():
    assert optimization_levels("gcc-11") == ["-O0", "-O1", "-O2", "-O3", "-Os"]
    assert optimization_levels("clang-17")[-1] == "-Oz"


def test_every_primitive_has_disjoint_train_validation_and_test_sources():
    sources = {
        label: {job["source"] for job in jobs("x86_64") if job["labels"] == [label]}
        for label in LABELS.values()
    }
    for primitive in set(LABELS.values()) - {"none"}:
        assert sources[primitive] - VALIDATION_SOURCES - TEST_SOURCES
        assert sources[primitive] & VALIDATION_SOURCES
        assert sources[primitive] & TEST_SOURCES


def test_precision_veto_requires_gnn_and_semantic_head_agreement():
    gnn = torch.tensor([
        [0.96, 0.01, 0.01, 0.0, 0.01, 0.0, 0.0, 0.01],
        [0.01, 0.96, 0.01, 0.0, 0.01, 0.0, 0.0, 0.01],
        [0.96, 0.01, 0.01, 0.0, 0.01, 0.0, 0.0, 0.01],
    ])
    semantic = torch.tensor([
        [0.97, 0.01, 0.01, 0.0, 0.0, 0.0, 0.0, 0.01],
        [0.01, 0.97, 0.01, 0.0, 0.0, 0.0, 0.0, 0.01],
        [0.01, 0.97, 0.01, 0.0, 0.0, 0.0, 0.0, 0.01],
    ])

    assert ensemble_predictions(gnn, semantic, {label: 0.9 for label in range(7)}).tolist() == [0, 1, 7]


def test_region_graph_keeps_cfg_and_dfg_edge_types_separate():
    function = LiftedFunction(
        name="demo",
        entry="a",
        blocks={
            "a": BasicBlock("a", ["COPY"], ["COPY"]),
            "b": BasicBlock("b", ["LOAD"], ["LOAD"]),
        },
        cfg=nx.DiGraph([("a", "b")]),
        dfg=nx.DiGraph([("b", "a")]),
    )

    data = region_to_data(function, {"a", "b"}, 0)

    assert data.edge_index.tolist() == [[0, 1], [1, 0]]
    assert data.edge_type.tolist() == [0, 1]


def test_recognizer_uses_cfg_and_dfg_as_distinct_relations():
    torch.manual_seed(17)
    model = PrimitiveGraphSAGE(input_dim=2, classes=3, hidden=4).eval()
    features = torch.tensor([[1.0, 0.0], [0.0, 1.0]])
    edges = torch.tensor([[0], [1]])
    batch = torch.zeros(2, dtype=torch.long)

    with torch.no_grad():
        cfg_logits = model(features, edges, torch.tensor([0]), batch)
        dfg_logits = model(features, edges, torch.tensor([1]), batch)

    assert not torch.equal(cfg_logits, dfg_logits)


def test_recognizer_is_invariant_to_basic_block_instruction_count_scale():
    torch.manual_seed(17)
    model = PrimitiveGraphSAGE(input_dim=2, classes=3, hidden=4).eval()
    for parameter in model.parameters():
        torch.nn.init.constant_(parameter, 0.1)
    features = torch.tensor([[1.0, 2.0], [3.0, 1.0]])
    edges = torch.tensor([[0], [1]])
    edge_types = torch.tensor([0])
    batch = torch.zeros(2, dtype=torch.long)

    with torch.no_grad():
        original = model(features, edges, edge_types, batch)
        scaled = model(features * 10, edges, edge_types, batch)

    assert torch.allclose(original, scaled)


def test_dwarf_regions_apply_image_bias_and_split_source_blocks():
    function = LiftedFunction(
        name="AES_encrypt",
        entry="00101100",
        blocks={
            "00101100": BasicBlock("00101100", ["COPY"] * 5, instruction_addresses=["00101100"]),
            "00101110": BasicBlock("00101110", ["LOAD"] * 5, instruction_addresses=["00101110"]),
        },
        cfg=nx.DiGraph([("00101100", "00101110")]),
    )
    ranges = [
        SourceRange(0x1100, 0x1110, "/src/aes.c", ("AES_encrypt",), False),
        SourceRange(0x1110, 0x1120, "/src/helper.h", ("helper",), True),
    ]

    regions = labeled_regions(function, ranges, "src/aes.c")

    assert {label for _, label in regions} == {False, True}


def test_candidate_regions_keep_loop_with_one_hop_context_and_target_label():
    function = LiftedFunction(
        name="cipher_loop",
        entry="00101100",
        blocks={
            "00101100": BasicBlock("00101100", ["COPY"] * 5, instruction_addresses=["00101100"]),
            "00101110": BasicBlock("00101110", ["INT_XOR"] * 5, instruction_addresses=["00101110"]),
            "00101120": BasicBlock("00101120", ["RETURN"] * 5, instruction_addresses=["00101120"]),
        },
        cfg=nx.DiGraph([
            ("00101100", "00101110"),
            ("00101110", "00101110"),
            ("00101110", "00101120"),
        ]),
    )
    ranges = [
        SourceRange(0x1100, 0x1130, "/vendor/wrapper.c", ("cipher_loop",), False),
        SourceRange(0x1110, 0x1120, "/src/aes_helpers.h", ("cipher_loop",), True),
    ]

    assert extract_regions(function) == [{"00101100", "00101110", "00101120"}]
    assert candidate_labeled_regions(function, ranges, "src/aes.c") == [
        ({"00101100", "00101110", "00101120"}, True)
    ]


def test_semantic_features_are_stable_and_ignore_large_addresses():
    first = block_features(["INT_ADD", "INT_XOR"], ["MOV EAX,0x401000", "XOR EAX,3329"])
    relocated = block_features(["INT_ADD", "INT_XOR"], ["MOV EAX,0x501000", "XOR EAX,3329"])
    different_constant = block_features(["INT_ADD", "INT_XOR"], ["MOV EAX,0x501000", "XOR EAX,7681"])

    assert len(first) == len(VOCAB) + SEMANTIC_BINS
    assert first == relocated
    assert first != different_constant


def test_semantic_features_include_referenced_read_only_content_not_its_address():
    contents = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"

    reader = lambda address: contents if address == 0x4100 else None
    first = block_features([], ["LEA RDX,[0x104100]"], reader, 0x100000)
    relocated = block_features([], ["LEA RDX,[0x204100]"], reader, 0x200000)
    without_content = block_features([], ["LEA RDX,[0x104100]"], lambda _: None, 0x100000)

    assert first == relocated
    assert first != without_content


def test_dwarf5_file_table_uses_zero_based_indices():
    class Entry:
        def __init__(self, name, directory=0):
            self.name = name.encode()
            self.dir_index = directory

    class Program:
        header = type("Header", (), {
            "version": 5,
            "include_directory": (),
            "file_entry": (Entry("source.c"), Entry("header.h")),
        })()

    class Dwarf:
        def line_program_for_CU(self, _cu):
            return Program()

    assert _file_table(Dwarf(), object()) == {0: "source.c", 1: "header.h"}
