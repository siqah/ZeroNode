#!/usr/bin/env bash
#
# Run the device integration tests against the emulator, from anywhere.
#
#   scripts/lab_device_test.sh [extra pytest args]
#
# Starts the emulator, waits for it to accept connections, runs the tests with
# the project's interpreter, and takes the emulator down again on the way out.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="$ROOT/apps/api"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml" --profile lab)

PYTEST="$API/.venv/bin/pytest"
if [[ ! -x "$PYTEST" ]]; then
  echo "No virtualenv at $API/.venv" >&2
  echo "Create one and install the devices extra:" >&2
  echo "  python3 -m venv $API/.venv" >&2
  echo "  $API/.venv/bin/pip install -e '$API[dev,devices]'" >&2
  exit 1
fi

if ! "$API/.venv/bin/python" -c "import netmiko" >/dev/null 2>&1; then
  echo "netmiko is missing from the virtualenv; these tests would skip." >&2
  echo "  $API/.venv/bin/pip install -e '$API[devices]'" >&2
  exit 1
fi

started=0
cleanup() {
  if [[ $started -eq 1 ]]; then
    "${COMPOSE[@]}" down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Starting the device emulator ..."
"${COMPOSE[@]}" up -d fake-asa >/dev/null
started=1

HOST="${FAKE_ASA_HOST:-127.0.0.1}"
PORT="${FAKE_ASA_PORT:-2222}"

# The container is up before sshd is listening; without this the tests skip
# themselves and the run looks like a pass.
for _ in $(seq 1 30); do
  if "$API/.venv/bin/python" - "$HOST" "$PORT" <<'PY' >/dev/null 2>&1
import socket, sys
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1):
    pass
PY
  then
    break
  fi
  sleep 1
done

echo "Running device integration tests against $HOST:$PORT"
cd "$API"
FAKE_ASA_HOST="$HOST" FAKE_ASA_PORT="$PORT" \
  "$PYTEST" tests/test_integration_device.py "$@"
