# Deploying Frozen Inference

Production should run scans with a frozen recognizer. Do not train on the SaaS
worker that handles user uploads.

Local training produces:

```bash
python scripts/train_recognizer.py --device auto --batch-size 16
python scripts/check_recognizer_artifacts.py --require-artifacts --require-all-class
```

`--device auto` uses CUDA when PyTorch can see the GPU, otherwise CPU. On a 4 GB
RTX 3050, start with `--batch-size 16`; drop to `8` if CUDA runs out of memory.
Ghidra lifting, dataset loading, and the semantic-head training still use CPU.

Required deploy artifacts:

```text
models/recognizer.pt
models/recognizer.semantic.joblib
models/recognizer.metrics.json
```

Build an inference image from a checkout that already has those files:

```bash
docker build -t cipherfault:inference .
docker run --rm cipherfault:inference --version
```

Runtime check:

```bash
python scripts/check_deploy_runtime.py
```

The image installs `.[recognizer]`, sets `CIPHERFAULT_RECOGNIZER_MODEL`, and
copies local `models/` into the image. GitHub cannot store the current
`recognizer.semantic.joblib` as a normal Git blob because it is over 100 MB; use
Git LFS, a GitHub Release artifact, or deployment storage, then download it into
`models/` before building the image.

For GitHub + Git LFS:

```bash
sudo apt-get install git-lfs
git lfs install
git add .gitattributes models/recognizer.pt models/recognizer.semantic.joblib
```

Do not add the `.joblib` file before Git LFS is installed; it is too large for a
normal GitHub push.
