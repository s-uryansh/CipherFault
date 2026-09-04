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

For a first-time database, create the SaaS structure automatically:

```bash
cipherfault saas-init
```

For an older database created before the SaaS hardening pass, apply the migration
before starting production API/worker containers:

```bash
psql "$CIPHERFAULT_DATABASE_URL" -f migrations/001_saas_hardening.sql
```

Required production settings:

```text
CIPHERFAULT_DATABASE_URL=postgresql+psycopg://...
CIPHERFAULT_REDIS_URL=redis://...
CIPHERFAULT_STORAGE_BACKEND=supabase
CIPHERFAULT_SUPABASE_URL=...
CIPHERFAULT_SUPABASE_KEY=...
CIPHERFAULT_SUPABASE_BUCKET=...
CIPHERFAULT_REQUIRE_RECOGNIZER=1
CIPHERFAULT_MAX_UPLOAD_BYTES=104857600
CIPHERFAULT_FREE_TIER_MONTHLY_SCANS=25
CIPHERFAULT_RATE_LIMIT_REQUESTS=60
CIPHERFAULT_RATE_LIMIT_WINDOW_SECONDS=60
CIPHERFAULT_KEEPALIVE_ENABLED=1
CIPHERFAULT_KEEPALIVE_INTERVAL_SECONDS=120
```

Keep `CIPHERFAULT_RUN_JOBS_INLINE=0` in production. API containers should enqueue
jobs only; worker containers own Ghidra and recognizer inference.

Build an inference image from a checkout that already has those files:

```bash
docker build -t cipherfault:inference .
docker run --rm cipherfault:inference --version
```

Runtime check:

```bash
python scripts/check_deploy_runtime.py
```

The worker image runs this check during `docker build`, so missing model artifacts
fail before deployment.

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

Production readiness:

```bash
curl -f "$API_URL/healthz"
curl -f "$API_URL/readyz"
```

`/healthz` only confirms the API process is alive. `/readyz` checks database,
Redis when jobs are queued, and recognizer artifacts when
`CIPHERFAULT_REQUIRE_RECOGNIZER=1`.

## Render Docker Deployment

Use two Render services:

- `cipherfault-api`: web service from `docker/api.Dockerfile`.
- `cipherfault-worker`: background worker from `docker/worker.Dockerfile`.

The API image intentionally does not include the model/Ghidra stack. Set
`CIPHERFAULT_REQUIRE_RECOGNIZER=0` on the API service and `1` on the worker.
The worker performs the AI scan and writes results back to Postgres.

Render health check path:

```text
/readyz
```

For GitHub keepalive, add this GitHub Actions secret after Render gives you a
public URL:

```text
RENDER_API_URL=https://your-render-service.onrender.com
```

`.github/workflows/keepalive.yml` hits `/healthz` every 5 minutes. On failure it
tries 3 more times at 15-minute intervals.

For GitHub-triggered Render deploys, add deploy hook secrets from each Render
service:

```text
RENDER_API_DEPLOY_HOOK_URL=...
RENDER_WORKER_DEPLOY_HOOK_URL=...
```

On pushes to `main`, CI builds/tests deployable backend images first, then calls both
Render deploy hooks.

API docs are in [API_REFERENCE.md](API_REFERENCE.md).
