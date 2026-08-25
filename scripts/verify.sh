#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-./.venv/bin/python}"

bash scripts/build_fixtures.sh
"$python_bin" -m pytest -q tests
"$python_bin" scripts/check_recognizer_artifacts.py --require-artifacts --require-all-class
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.local.json --min-recall 1.0
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.negative.json
bash scripts/build_external_fixtures.sh
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.external.json --min-recall 1.0
bash scripts/build_real_fixtures.sh
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.real.json
bash scripts/build_pqc_eval_fixtures.sh
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.pqc.json --min-recall 1.0
if [ -d corpus/eval/CVE-2017-3225/source/.git ]; then
    bash scripts/build_cve_fixtures.sh
    "$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.cve.json --min-recall 1.0
    "$python_bin" scripts/check_known_limitations.py
else
    echo "skipping CVE manifest; corpus/eval/CVE-2017-3225/source is not present"
fi
bash scripts/build_demo.sh
"$python_bin" scripts/evaluate_manifest.py corpus/eval/manifest.demo.json --min-recall 1.0
wheel_dir="$(mktemp -d)"
install_dir="$(mktemp -d)"
"$python_bin" -m build --no-isolation --wheel --outdir "$wheel_dir"
"$python_bin" -m pip install --no-deps --target "$install_dir" "$wheel_dir"/*.whl
PYTHONPATH="$install_dir" "$python_bin" -m cipherfault.cli --version
"$python_bin" scripts/generate_sbom.py --output "$wheel_dir/cipherfault.sbom.json"
