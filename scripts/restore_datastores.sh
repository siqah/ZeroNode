#!/usr/bin/env bash
# Restore a backup created by backup_datastores.sh into the Compose volumes.
# Refuses to run without --confirm so a stray invocation cannot wipe live data.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="${COMPOSE:-docker compose}"

if [[ $# -lt 2 || "$2" != "--confirm" ]]; then
  cat >&2 <<EOF
Usage: $0 /path/to/backup-dir --confirm

Restores Postgres and Neo4j from a directory produced by
scripts/backup_datastores.sh. This overwrites the live Compose volumes.
EOF
  exit 2
fi

SRC="$1"
if [[ ! -f "$SRC/manifest.json" || ! -f "$SRC/postgres.dump" ]]; then
  echo "Missing manifest.json or postgres.dump in $SRC" >&2
  exit 2
fi

python3 - <<PY
import hashlib, json, pathlib, sys
src = pathlib.Path("$SRC")
manifest = json.loads((src / "manifest.json").read_text())
for name, meta in manifest["files"].items():
    path = src / name
    if not path.exists():
        print(f"missing {name}", file=sys.stderr)
        sys.exit(1)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != meta["sha256"]:
        print(f"checksum mismatch for {name}", file=sys.stderr)
        sys.exit(1)
print("manifest checksums ok")
PY

echo "Stopping API/worker clients before Postgres restore ..."
$COMPOSE stop api worker 2>/dev/null || true

echo "Restoring Postgres ..."
$COMPOSE exec -T postgres psql -U zeronode -d postgres -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'zeronode' AND pid <> pg_backend_pid();" \
  >/dev/null
$COMPOSE exec -T postgres dropdb -U zeronode --if-exists zeronode
$COMPOSE exec -T postgres createdb -U zeronode zeronode
$COMPOSE exec -T postgres pg_restore -U zeronode -d zeronode --clean --if-exists < "$SRC/postgres.dump" \
  || true  # pg_restore returns 1 on some benign warnings

if [[ -f "$SRC/neo4j.dump" ]]; then
  echo "Restoring Neo4j ..."
  $COMPOSE stop neo4j
  docker run --rm \
    -v "${COMPOSE_PROJECT_NAME:-zeronode}_neo4j_data:/data" \
    -v "$SRC:/backup" \
    neo4j:5.26-community \
    neo4j-admin database load neo4j --from-path=/backup --overwrite-destination=true
  $COMPOSE start neo4j
fi

if [[ -f "$SRC/audit_anchors.jsonl" ]]; then
  echo "Restoring audit anchor ..."
  $COMPOSE exec -T api sh -c "mkdir -p \"$(dirname "${AUDIT_ANCHOR_FILE:-/var/lib/zeronode/anchors.jsonl}")\" && cat > \"${AUDIT_ANCHOR_FILE:-/var/lib/zeronode/anchors.jsonl}\"" < "$SRC/audit_anchors.jsonl" \
    || cp "$SRC/audit_anchors.jsonl" "$ROOT/audit_anchors.jsonl"
fi

echo "Restarting API/worker ..."
$COMPOSE up -d api worker 2>/dev/null || true

echo "Restore complete from $SRC"
