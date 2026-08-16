"""Small pyghidra lifecycle wrapper that leaves no project beside the target."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import tempfile


@contextmanager
def analyzed_program(binary_path: str | Path):
    os.environ.setdefault("XDG_CONFIG_HOME", str(Path(tempfile.gettempdir()) / "cipherfault-ghidra-config"))
    # PyGhidra's import hook cannot run after JVM shutdown; preload Torch's
    # optional exit-report dependency while the interpreter is fully alive.
    if "torch" in sys.modules:
        import tabulate  # noqa: F401
    import pyghidra

    display = os.environ.pop("DISPLAY", None)
    try:
        pyghidra.start()
    finally:
        if display is not None:
            os.environ["DISPLAY"] = display
    monitor = pyghidra.task_monitor()
    with tempfile.TemporaryDirectory(prefix="cipherfault-ghidra-") as project_dir:
        with pyghidra.open_project(project_dir, "analysis", create=True) as project:
            loader = pyghidra.program_loader().project(project).source(str(binary_path))
            with loader.load() as loaded:
                program = loaded.getPrimaryDomainObject()
                pyghidra.analyze(program, monitor)
                yield program, monitor
