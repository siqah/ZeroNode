#!/usr/bin/env bash
# Soak test: sustained load against read-only endpoints.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DURATION="${SOAK_DURATION_SECONDS:-300}"
CONCURRENCY="${SOAK_CONCURRENCY:-8}"
BASE_URL="${SOAK_BASE_URL:-http://127.0.0.1:8000}"

echo "Soak test: ${DURATION}s at concurrency ${CONCURRENCY} against ${BASE_URL}"
python3 "$ROOT/scripts/load_test.py" \
  --base-url "$BASE_URL" \
  --duration "$DURATION" \
  --concurrency "$CONCURRENCY" \
  --max-error-rate "${SOAK_MAX_ERROR_RATE:-0.01}"
