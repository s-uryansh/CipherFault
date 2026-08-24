import builtins
import json
import sys

sys.path.insert(0, "scripts")

import check_recognizer_artifacts


def test_missing_artifact_check_does_not_import_torch(monkeypatch, tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    (models / "recognizer.metrics.json").write_text(
        json.dumps(
            {
                "passed": True,
                "deployable_labels": ["AES"],
                "asserted": {"AES": 1},
                "precision": {"AES": 1.0},
                "gate": {"primitive_precision": 0.95},
            }
        ),
        encoding="utf-8",
    )
    real_import = builtins.__import__

    def fail_torch_import(name, *args, **kwargs):
        if name == "torch":
            raise AssertionError("torch should not be imported for missing artifacts")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(check_recognizer_artifacts, "ROOT", tmp_path)
    monkeypatch.setattr(builtins, "__import__", fail_torch_import)

    assert check_recognizer_artifacts.main([]) == 0
