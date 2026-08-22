#!/usr/bin/env bash
# Backup Neo4j, Postgres, and the audit anchor into a versioned directory with a
# checksummed manifest. Restores are separate and require an explicit --confirm flag.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${BACKUP_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="${1:-$ROOT/backups/$STAMP}"
COMPOSE="${COMPOSE:-docker compose}"
ANCHOR_FILE="${AUDIT_ANCHOR_FILE:-/var/lib/zeronode/anchors.jsonl}"

mkdir -p "$OUT"

echo "Backing up Postgres into $OUT/postgres.dump ..."
$COMPOSE exec -T postgres pg_dump -U zeronode -d zeronode -Fc > "$OUT/postgres.dump"

echo "Backing up Neo4j into $OUT/neo4j.dump ..."
$COMPOSE stop neo4j
docker run --rm \
  -v "${COMPOSE_PROJECT_NAME:-zeronode}_neo4j_data:/data" \
  -v "$OUT:/backup" \
  neo4j:5.26-community \
  neo4j-admin database dump neo4j --to-path=/backup --overwrite-destination=true
$COMPOSE start neo4j

if $COMPOSE ps api >/dev/null 2>&1; then
  echo "Backing up audit anchor into $OUT/audit_anchors.jsonl ..."
  $COMPOSE exec -T api sh -c "test -f '$ANCHOR_FILE' && cat '$ANCHOR_FILE'" > "$OUT/audit_anchors.jsonl" || true
fi

python3 - <<PY
import hashlib, json, pathlib
out = pathlib.Path("$OUT")
files = {}
for path in sorted(out.iterdir()):
    if path.name == "manifest.json":
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    files[path.name] = {"sha256": digest, "bytes": path.stat().st_size}
manifest = {
    "created_at": "$STAMP",
    "postgres_image": "postgres:16-alpine",
    "neo4j_image": "neo4j:5.26-community",
    "files": files,
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\\n")
print(json.dumps(manifest, indent=2))
PY

echo "Backup complete: $OUT"
