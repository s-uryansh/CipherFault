import sys
import subprocess
import json

import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

sys.path.insert(0, "src")
sys.path.insert(0, "scripts")

from cipherfault.recognizer.featurize import ReadOnlyMemory
from cipherfault.recognizer.runtime import _deployable_label_ids, _recognized_label, default_model_path
import check_recognizer_artifacts


def _passed_metrics(labels=("AES",)):
    return {
        "passed": True,
        "deployable_labels": list(labels),
        "asserted": {label: 1 for label in labels},
        "precision": {label: 1.0 for label in labels},
        "gate": {"primitive_precision": 0.95},
    }


def test_recognizer_model_path_can_be_configured(monkeypatch, tmp_path):
    model = tmp_path / "recognizer.pt"

    monkeypatch.setenv("CIPHERFAULT_RECOGNIZER_MODEL", str(model))

    assert default_model_path() == model


def test_deployable_label_ids_default_to_legacy_all_primitives():
    assert _deployable_label_ids({}, 3) == {0, 1, 2}
    assert _deployable_label_ids({"deployable_label_ids": [4]}, 7) == {4}


def test_recognized_label_uses_semantic_fallback_for_deployable_label():
    scores = torch.tensor([0.4, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    semantic = torch.tensor([0.96, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])

    assert _recognized_label(
        scores,
        semantic,
        torch.zeros(8),
        {label: 0.9 for label in range(7)},
        {0: 0.95},
        {},
        {0},
        7,
    ) == (0, pytest.approx(0.96), "semantic-head")


def test_recognized_label_uses_precision_gated_symbol_name_head():
    scores = torch.tensor([0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.3])
    semantic = torch.tensor([0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.3])
    names = torch.tensor([0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])

    assert _recognized_label(scores, semantic, names, {}, {}, {1: 1.0}, {1}, 7) == (
        1,
        pytest.approx(1.0),
        "symbol-name-head",
    )


def test_recognized_label_requires_name_match_for_name_gated_label():
    scores = torch.tensor([0.1, 0.99, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    semantic = torch.tensor([0.1, 0.99, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])

    assert _recognized_label(scores, semantic, torch.zeros(8), {1: 0.9}, {1: 0.9}, {1: 1.0}, {1}, 7)[0] is None


def test_recognized_label_ignores_undeployable_labels():
    scores = torch.tensor([0.99, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])
    semantic = torch.tensor([0.99, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1])

    assert _recognized_label(scores, semantic, torch.zeros(8), {0: 0.9}, {}, {}, set(), 7)[0] is None


def test_read_only_memory_accepts_relocatable_elf_without_load_segments(tmp_path):
    source = tmp_path / "tiny.c"
    obj = tmp_path / "tiny.o"
    source.write_text("int tiny(void) { return 7; }\n", encoding="utf-8")
    try:
        subprocess.run(["cc", "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
    except FileNotFoundError:
        pytest.skip("cc unavailable")

    memory = ReadOnlyMemory(obj)

    assert memory.minimum_load_address == 0


def test_recognizer_artifact_check_rejects_metric_checkpoint_mismatch(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    (models / "recognizer.metrics.json").write_text(
        json.dumps(_passed_metrics()),
        encoding="utf-8",
    )
    torch.save({"labels": {0: "AES", 1: "none"}, "deployable_label_ids": []}, models / "recognizer.pt")
    (models / "recognizer.semantic.joblib").write_bytes(b"placeholder")
    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="deployable label mismatch"):
        check_recognizer_artifacts.main([])


def test_recognizer_artifact_check_can_skip_missing_untracked_artifacts(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    (models / "recognizer.metrics.json").write_text(
        json.dumps(_passed_metrics()),
        encoding="utf-8",
    )
    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)

    assert check_recognizer_artifacts.main([]) == 0


def test_recognizer_artifact_check_can_require_artifacts(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    (models / "recognizer.metrics.json").write_text(
        json.dumps(_passed_metrics()),
        encoding="utf-8",
    )
    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="recognizer metrics passed but model or semantic artifact is missing"):
        check_recognizer_artifacts.main(["--require-artifacts"])


def test_recognizer_artifact_check_rejects_deployable_label_below_gate(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    metrics = _passed_metrics()
    metrics["precision"]["AES"] = 0.5
    (models / "recognizer.metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="deployable label below precision gate"):
        check_recognizer_artifacts.main([])


def test_recognizer_artifact_check_can_require_all_class_gate(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    metrics = _passed_metrics()
    metrics["all_class_gate_passed"] = False
    metrics["gate_failures"] = [
        {"label": "RSA", "metric": "precision", "observed": 0.0, "required": 0.95}
    ]
    (models / "recognizer.metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="RSA precision=0.0 required=0.95"):
        check_recognizer_artifacts.main(["--require-all-class"])


def test_recognizer_artifact_check_rejects_inconsistent_all_class_metrics(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    metrics = _passed_metrics()
    metrics["all_class_gate_passed"] = True
    metrics["gate_failures"] = [
        {"label": "SHA", "metric": "compiler:gcc-13.precision", "observed": 0.9, "required": 0.95}
    ]
    (models / "recognizer.metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)

    with pytest.raises(SystemExit, match="all-class gate passed with failures"):
        check_recognizer_artifacts.main([])
