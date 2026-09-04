"""Production runtime checks for hosted inference."""

from __future__ import annotations

from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import os


MODEL_FILES = ("recognizer.pt", "recognizer.semantic.joblib", "recognizer.metrics.json")


def recognizer_artifacts() -> dict[str, str]:
    from cipherfault.recognizer.runtime import default_model_path

    model_path = default_model_path()
    model_dir = model_path.parent
    paths = {
        "recognizer.pt": model_path,
        "recognizer.semantic.joblib": model_path.with_suffix(".semantic.joblib"),
        "recognizer.metrics.json": model_dir / "recognizer.metrics.json",
    }
    missing = [name for name, path in paths.items() if not path.exists()]
    if missing:
        raise RuntimeError("missing recognizer artifact(s): " + ", ".join(missing))
    return {name: _sha256(path) for name, path in paths.items()}


def inference_metadata() -> dict[str, str]:
    from cipherfault.recognizer.runtime import default_model_path

    metadata = {f"sha256:{name}": digest for name, digest in recognizer_artifacts().items()}
    metadata["model_path"] = str(default_model_path())
    metadata["ghidra_install_dir"] = os.getenv("GHIDRA_INSTALL_DIR", "")
    try:
        metadata["cipherfault_version"] = version("cipherfault")
    except PackageNotFoundError:
        metadata["cipherfault_version"] = "editable"
    return metadata


def require_inference_ready() -> None:
    try:
        recognizer_artifacts()
    except ImportError as exc:
        raise RuntimeError("recognizer dependencies are required") from exc
    if not os.getenv("GHIDRA_INSTALL_DIR"):
        raise RuntimeError("GHIDRA_INSTALL_DIR is required")


def _sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
