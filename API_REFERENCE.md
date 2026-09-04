# CipherFault SaaS API

Base URL: your Render web service URL.

Authentication: pass `X-API-Key` on every `/v1/*` request.

Rate limit: default `60` requests per `60` seconds per API key or client IP. Configure with
`CIPHERFAULT_RATE_LIMIT_REQUESTS` and `CIPHERFAULT_RATE_LIMIT_WINDOW_SECONDS`.

## Health

### `GET /healthz`

Process liveness. No auth.

Response:

```json
{"status": "ok"}
```

### `GET /readyz`

Production readiness. No auth. Checks database, Redis when jobs are queued, and recognizer
artifacts when `CIPHERFAULT_REQUIRE_RECOGNIZER=1`.

Response:

```json
{"status": "ready"}
```

Failure: `503` with the failed component in `detail`.

### `GET /health/dependencies`

Runs the same dependency keepalive check used by the background loop: database
insert/read/delete, Redis ping, and Supabase storage request.

Response:

```json
{"database": "ok", "redis": "ok", "supabase": "ok"}
```

## Scans

### `POST /v1/scans/upload`

Upload a 64-bit little-endian Linux ELF binary and enqueue a scan.

Headers:

```text
X-API-Key: <api key>
Content-Type: multipart/form-data
```

Form field:

```text
file=<binary>
```

Response `202`:

```json
{"scan_id": "...", "job_id": "...", "status": "queued"}
```

Errors:

- `400`: empty, non-ELF, or oversized upload.
- `401`: missing/invalid API key.
- `429`: org monthly quota or common API rate limit exceeded.
- `503`: queue/storage unavailable.

### `POST /v1/scans`

Create a scan from an already uploaded org-owned storage path.

Body:

```json
{"storage_path": "uploads/<org_id>/<object>", "filename": "target.out"}
```

Response `202`:

```json
{"scan_id": "...", "job_id": "...", "status": "queued"}
```

### `GET /v1/scans/{scan_id}`

Return scan status and runtime metadata.

Response:

```json
{
  "id": "...",
  "filename": "target.out",
  "status": "queued|running|complete|failed",
  "stage": "scanning",
  "error": null,
  "runtime": null,
  "created_at": "...",
  "updated_at": "..."
}
```

### `GET /v1/scans/{scan_id}/findings`

Return the JSON analysis report after completion.

Failure: `409` if the scan is not complete.

### `GET /v1/scans/{scan_id}/cbom`

Return the CycloneDX CBOM after completion.

Failure: `409` if the scan is not complete.

### `DELETE /v1/scans/{scan_id}`

Delete scan row and uploaded object. Usage events are retained for quota/audit.

Response: `204`.

## Org

### `GET /v1/orgs/{org_id}/scans`

List latest 100 scans for the authenticated org.

### `GET /v1/orgs/{org_id}/usage`

Return completed scan count and current monthly quota usage.

Response:

```json
{"org_id": "...", "tier": "free", "scans_completed": 1, "monthly_limit": 25, "monthly_used": 1}
```

## API Keys

### `GET /v1/orgs/{org_id}/api-keys`

List API key metadata. Raw keys are never returned.

### `POST /v1/orgs/{org_id}/api-keys`

Create an API key.

Body:

```json
{"name": "ci", "expires_at": null}
```

Response:

```json
{"id": "...", "name": "ci", "key_prefix": "cf_...", "api_key": "cf_..."}
```

Save `api_key` when it is returned; it is not shown again.

### `DELETE /v1/orgs/{org_id}/api-keys/{key_id}`

Revoke an API key.

Response: `204`.
