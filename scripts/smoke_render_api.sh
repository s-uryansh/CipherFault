#!/usr/bin/env bash
set -euo pipefail

: "${API_URL:?set API_URL, for example https://cipherfault.onrender.com}"
: "${API_KEY:?set API_KEY}"
: "${BINARY:?set BINARY to a 64-bit little-endian ELF fixture path}"

poll_seconds="${POLL_SECONDS:-2}"
timeout_seconds="${TIMEOUT_SECONDS:-900}"

json_get() {
  python -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

curl -fsS "$API_URL/healthz" >/dev/null
curl -fsS "$API_URL/readyz" >/dev/null
curl -fsS "$API_URL/health/dependencies" >/dev/null

upload_response="$(
  curl -fsS -X POST "$API_URL/v1/scans/upload" \
    -H "X-API-Key: $API_KEY" \
    -F "file=@$BINARY"
)"

scan_id="$(printf '%s' "$upload_response" | json_get scan_id)"
deadline=$((SECONDS + timeout_seconds))

while [ "$SECONDS" -lt "$deadline" ]; do
  status_response="$(curl -fsS "$API_URL/v1/scans/$scan_id" -H "X-API-Key: $API_KEY")"
  scan_status="$(printf '%s' "$status_response" | json_get status)"
  printf 'scan %s status=%s\n' "$scan_id" "$scan_status"

  case "$scan_status" in
    complete)
      curl -fsS "$API_URL/v1/scans/$scan_id/findings" -H "X-API-Key: $API_KEY" >/tmp/cipherfault-findings.json
      curl -fsS "$API_URL/v1/scans/$scan_id/cbom" -H "X-API-Key: $API_KEY" >/tmp/cipherfault-cbom.json
      printf 'ok: findings=/tmp/cipherfault-findings.json cbom=/tmp/cipherfault-cbom.json\n'
      exit 0
      ;;
    failed)
      printf '%s\n' "$status_response" >&2
      exit 1
      ;;
  esac

  sleep "$poll_seconds"
done

printf 'timed out waiting for scan %s\n' "$scan_id" >&2
exit 1
