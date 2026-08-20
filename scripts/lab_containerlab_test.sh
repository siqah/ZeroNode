#!/usr/bin/env bash
# Deploy the public SR Linux lab and close the Phase 2 execution gate.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOPOLOGY="$ROOT/infra/containerlab/zeronode.clab.yml"
SRL_IMAGE="${SRL_IMAGE:-ghcr.io/nokia/srlinux:24.10.4}"
CLAB_IMAGE="${CLAB_IMAGE:-ghcr.io/srl-labs/clab:0.78.2}"
PYTHON="$ROOT/apps/api/.venv/bin/python"
deployed=0

if ! docker image inspect "$SRL_IMAGE" >/dev/null 2>&1; then
  echo "Pulling the public SR Linux image $SRL_IMAGE ..."
  docker pull "$SRL_IMAGE"
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "Missing $PYTHON; create the API virtualenv and install .[dev,devices]." >&2
  exit 2
fi
if ! "$PYTHON" -c "import netmiko" >/dev/null 2>&1; then
  echo "Netmiko is missing; install the devices extra in apps/api/.venv." >&2
  exit 2
fi

clab() {
  docker run --rm --privileged \
    --network host \
    --pid host \
    -e "SRL_IMAGE=$SRL_IMAGE" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/run/netns:/var/run/netns \
    -v /var/lib/docker/containers:/var/lib/docker/containers \
    -v "$ROOT:$ROOT" \
    -w "$ROOT" \
    "$CLAB_IMAGE" containerlab "$@"
}

cleanup() {
  status=$?
  if [[ $deployed -eq 1 ]]; then
    echo "Destroying the Containerlab topology ..."
    clab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

echo "Validating $TOPOLOGY with $CLAB_IMAGE ..."
clab validate -t "$TOPOLOGY"

echo "Deploying the three-node topology ..."
deployed=1
clab deploy -t "$TOPOLOGY"

echo "Waiting for the SR Linux SSH service on localhost:2223 ..."
ready=0
for _ in $(seq 1 180); do
  if "$PYTHON" - <<'PY' >/dev/null 2>&1
import socket
with socket.create_connection(("127.0.0.1", 2223), timeout=1):
    pass
PY
  then
    ready=1
    break
  fi
  sleep 2
done
if [[ $ready -ne 1 ]]; then
  echo "SR Linux did not expose SSH within six minutes." >&2
  docker logs clab-zeronode-fw >&2 || true
  exit 1
fi

echo "Running read, packet, apply, verification and rollback checks ..."
SRL_HOST=127.0.0.1 SRL_PORT=2223 \
  SRL_USERNAME="${SRL_USERNAME:-admin}" \
  SRL_PASSWORD="${SRL_PASSWORD:-NokiaSrl1!}" \
  "$PYTHON" "$ROOT/scripts/validate_containerlab.py"

echo "Phase 2 L4 validation passed."
