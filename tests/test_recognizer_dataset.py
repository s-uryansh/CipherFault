import sys
from pathlib import Path

import networkx as nx
import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

sys.path.insert(0, "src")
sys.path.insert(0, "scripts")

from build_recognizer_dataset import LABELS as DATASET_LABELS, function_label
from merge_matrix_metadata import artifact_matches_arch, merge
from build_matrix import jobs, optimization_levels
from train_recognizer import (
    LABELS,
    TEST_SOURCES,
    VALIDATION_SOURCES,
    choose_threshold,
    combined_predictions,
    deployable_labels,
    ensemble_predictions,
    gate_failures,
    source_balanced_weights,
)
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


ROOT = Path(__file__).resolve().parents[1]
FULL_MATRIX_CORPUS_MARKERS = (
    ROOT / "corpus/external/openssl/crypto/aes/aes_core.c",
    ROOT / "corpus/external/boringssl/crypto/fipsmodule/aes/aes_nohw.cc.inc",
    ROOT / "corpus/external/bearssl/src/symcipher",
    ROOT / "corpus/external/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean",
    ROOT / "corpus/external/liboqs/src/sig/slh_dsa/slh_dsa_c/slh_dsa.c",
)


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


def test_matrix_merge_can_explicitly_allow_partial_source_expansion(monkeypatch):
    rows = []
    for compiler in ("gcc-11", "gcc-12", "gcc-13", "clang-15", "clang-16", "clang-17"):
        for arch in ("x86_64", "aarch64"):
            opts = ["-O0", "-O1", "-O2", "-O3", "-Os", *(["-Oz"] if compiler.startswith("clang-") else [])]
            for opt in opts:
                rows.append({
                    "status": "ok",
                    "artifact": "demo",
                    "arch": arch,
                    "compiler": compiler,
                    "opt": opt,
                    "source_file": "base.c",
                })
                if compiler == "gcc-13" and arch == "x86_64":
                    rows.append({
                        "status": "ok",
                        "artifact": "demo-extra",
                        "arch": arch,
                        "compiler": compiler,
                        "opt": opt,
                        "source_file": "extra.c",
                    })

    def fake_read_text(_encoding):
        return "".join(__import__("json").dumps(row) + "\n" for row in rows)

    monkeypatch.setattr("pathlib.Path.read_text", lambda self, encoding=None: fake_read_text(encoding))
    monkeypatch.setattr("merge_matrix_metadata.artifact_matches_arch", lambda path, arch: True)

    assert len(merge([__import__("pathlib").Path("matrix.jsonl")], allow_partial_source_counts=True)) == len(rows)
    with pytest.raises(ValueError, match="source count"):
        merge([__import__("pathlib").Path("matrix.jsonl")])


def test_matrix_artifact_architecture_check_reads_elf_machine(tmp_path):
    artifact = tmp_path / "target.so"
    artifact.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + (183).to_bytes(2, "little"))

    assert artifact_matches_arch(artifact, "aarch64")
    assert not artifact_matches_arch(artifact, "x86_64")


def test_compiler_matrix_uses_only_supported_optimization_levels():
    assert optimization_levels("gcc-11") == ["-O0", "-O1", "-O2", "-O3", "-Os"]
    assert optimization_levels("clang-17")[-1] == "-Oz"


def test_every_primitive_has_disjoint_train_validation_and_test_sources():
    if not all(path.exists() for path in FULL_MATRIX_CORPUS_MARKERS):
        pytest.skip("full recognizer source corpus is not checked out")

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


def test_combined_predictions_use_independently_gated_semantic_head():
    gnn = torch.tensor([
        [0.40, 0.01, 0.01, 0.0, 0.01, 0.0, 0.0, 0.57],
        [0.96, 0.01, 0.01, 0.0, 0.01, 0.0, 0.0, 0.01],
    ])
    semantic = torch.tensor([
        [0.97, 0.01, 0.01, 0.0, 0.0, 0.0, 0.0, 0.02],
        [0.01, 0.97, 0.01, 0.0, 0.0, 0.0, 0.0, 0.01],
    ])

    assert combined_predictions(
        gnn,
        semantic,
        {label: 0.9 for label in range(7)},
        {0: 0.9, **{label: 1.1 for label in range(1, 7)}},
    ).tolist() == [0, 7]


def test_combined_predictions_require_name_match_for_name_gated_labels():
    gnn = torch.tensor([
        [0.01, 0.96, 0.01, 0.0, 0.01, 0.0, 0.0, 0.02],
        [0.01, 0.96, 0.01, 0.0, 0.01, 0.0, 0.0, 0.02],
    ])
    semantic = torch.tensor([
        [0.01, 0.97, 0.01, 0.0, 0.0, 0.0, 0.0, 0.02],
        [0.01, 0.97, 0.01, 0.0, 0.0, 0.0, 0.0, 0.02],
    ])
    names = torch.tensor([
        [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    ])

    assert combined_predictions(
        gnn,
        semantic,
        {label: 0.9 for label in range(7)},
        {1: 0.9, **{label: 1.1 for label in (0, 2, 3, 4, 5, 6)}},
        names,
        {1: 1.0},
    ).tolist() == [7, 1]


def test_threshold_selection_calibrates_after_semantic_veto():
    gnn = torch.tensor([
        [0.99, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.01],
        [0.90, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.10],
        [0.89, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.11],
    ])
    labels = torch.tensor([DATASET_LABELS["none"], DATASET_LABELS["AES"], DATASET_LABELS["none"]])
    semantic = torch.tensor([
        [0.01, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.99],
        [0.96, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.04],
        [0.96, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.04],
    ])

    assert choose_threshold(gnn, labels, DATASET_LABELS["AES"], semantic) == pytest.approx(0.90)


def test_gate_failures_name_blocking_metrics():
    result = {
        "support": {name: 1000 for name in LABELS.values()},
        "precision": {name: 1.0 for name in LABELS.values()},
        "none_false_positive_rate": 0.0,
    }
    result["precision"]["AES"] = 0.0

    assert gate_failures(result) == [
        {"label": "AES", "metric": "precision", "observed": 0.0, "required": 0.95}
    ]


def test_gate_failures_include_supported_slice_precision():
    result = {
        "support": {name: 1000 for name in LABELS.values()},
        "asserted": {name: 1000 for name in LABELS.values()},
        "precision": {name: 1.0 for name in LABELS.values()},
        "none_false_positive_rate": 0.0,
        "slices": {
            "compiler": {
                "gcc-13": {
                    "support": {name: 100 for name in LABELS.values()},
                    "asserted": {name: 10 for name in LABELS.values()},
                    "precision": {name: 1.0 for name in LABELS.values()},
                    "recall": {name: 0.1 for name in LABELS.values()},
                    "none_false_positive_rate": 0.0,
                }
            }
        },
    }
    result["slices"]["compiler"]["gcc-13"]["precision"]["ECC"] = 0.9

    assert gate_failures(result) == [
        {"label": "ECC", "metric": "compiler:gcc-13.precision", "observed": 0.9, "required": 0.95}
    ]


def test_deployable_labels_require_assertions_and_precision():
    result = {
        "asserted": {name: 0 for name in LABELS.values()},
        "precision": {name: 1.0 for name in LABELS.values()},
    }
    result["asserted"]["AES"] = 3
    result["asserted"]["RSA"] = 3
    result["precision"]["RSA"] = 0.5

    assert deployable_labels(result) == ["AES"]


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
