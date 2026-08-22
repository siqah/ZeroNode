#!/usr/bin/env bash
# Regenerate pinned Python dependencies for reproducible API/worker images.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="$ROOT/apps/api"
VENV="${VENV:-$API/.venv}"

if [[ ! -x "$VENV/bin/pip-compile" ]]; then
  "$VENV/bin/pip" install pip-tools
fi

"$VENV/bin/pip-compile" \
  --extra=dev \
  --output-file="$API/requirements.lock" \
  "$API/pyproject.toml"

echo "Wrote $API/requirements.lock"
