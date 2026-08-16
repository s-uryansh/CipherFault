#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-./.venv/bin/python}"

bash scripts/build_fixtures.sh
"$python_bin" -m pytest -q tests
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.local.json
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.negative.json
bash scripts/build_demo.sh
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.demo.json
wheel_dir="$(mktemp -d)"
install_dir="$(mktemp -d)"
"$python_bin" -m build --no-isolation --wheel --outdir "$wheel_dir"
"$python_bin" -m pip install --no-deps --target "$install_dir" "$wheel_dir"/*.whl
PYTHONPATH="$install_dir" "$python_bin" -m cipherfault.cli --version
"$python_bin" scripts/generate_sbom.py --output "$wheel_dir/cipherfault.sbom.json"
