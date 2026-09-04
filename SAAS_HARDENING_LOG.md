# SaaS Hardening Log

Date: 2026-09-04

## Moves

1. Audited the existing API, worker, storage, auth, DB models, Dockerfiles, and deployment docs.
2. Confirmed scans already run through frozen inference rather than training on user requests.
3. Added `cipherfault.api.runtime` for recognizer artifact checks and runtime hash metadata.
4. Made worker jobs fail fast when required model artifacts or `GHIDRA_INSTALL_DIR` are missing.
5. Added upload size and ELF-header validation before persisting user files.
6. Scoped uploaded object paths by `org_id` for local and Supabase storage.
7. Blocked externally supplied scan paths unless the path belongs to the authenticated org.
8. Added free-tier monthly quota enforcement using existing `UsageEvent` rows.
9. Added API-key lifecycle fields: prefix, expiration, revocation, and last-used timestamp.
10. Added scan runtime metadata persistence for model/artifact auditability.
11. Added `/readyz` for DB, Redis, and recognizer readiness checks.
12. Made the worker image run `scripts/check_deploy_runtime.py` at build time.
13. Added Docker Compose worker CPU-abuse guardrails: memory, PID, no-new-privileges, and dropped capabilities.
14. Added plain SQL migration `migrations/001_saas_hardening.sql`.
15. Added API-key list/create/revoke endpoints.
16. Moved quota accounting to `scan_created` usage events so queued jobs count before worker completion.
17. Kept usage events after scan deletion by making `usage_events.scan_id` nullable with `ON DELETE SET NULL`.
18. Updated `DEPLOYMENT.md` with migration, required env vars, readiness checks, and API/worker separation.
19. Ran focused API/storage/service/recognizer tests: 23 passed.
20. Ran full test suite: 140 passed.
21. Built `cipherfault-worker:saas-hardening`; build passed the in-image deploy runtime check.
22. Built `cipherfault-api:saas-hardening`; API-only image installed without recognizer dependencies.
23. Ran API image import smoke test: `healthz()` returned `{"status": "ok"}`.
24. Added `cipherfault saas-init` to create first-run SaaS database structure and seed `CIPHERFAULT_DEV_API_KEY` when set.
25. Added Redis-backed common API rate limiting middleware.
26. Added structured request/error logging and explicit DB/Redis/model readiness failures.
27. Updated Docker commands to respect Render `PORT` and `CIPHERFAULT_REDIS_URL`.
28. Added `API_REFERENCE.md` and `render.yaml` for Render Docker deployment.
29. Added GitHub Actions keepalive workflow using `RENDER_API_URL`.
30. Added CI deploy job that triggers Render API and worker deploy hooks after deployability checks pass on `main`.
31. Added startup env set/unset logging without secret values.
32. Added background keepalive for database, Redis, and Supabase every `CIPHERFAULT_KEEPALIVE_INTERVAL_SECONDS`.
33. Added `/health/dependencies` to run the dependency keepalive on demand.
34. Made GitHub Render deploy/keepalive workflows skip cleanly until their secrets are configured.

## Pre-Existing Dirty Files

- `.gitignore` already had an uncommitted `.env.dev` ignore entry.
- `docker-compose.dev.yml` already pointed services at `.env.dev` instead of `.env.dev.example`.

## Deliberate Skips

- Did not add Alembic yet. Plain SQL is enough until the hosting target and migration runner are chosen.
- Did not add billing integration. Quotas are enforced from existing org tier and usage rows.
- Did not add online training, model registry, or per-customer fine-tuning. SaaS should ship frozen inference first.
