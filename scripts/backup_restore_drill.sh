#!/usr/bin/env bash
# Disposable backup/restore drill against Compose volumes.
# Creates a marker row, backs up, destroys it, restores, and checks it returned.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="${COMPOSE:-docker compose}"
MARKER="phase3-backup-drill-$(date -u +%Y%m%d%H%M%S)"
OUT="$ROOT/backups/drill-$MARKER"

cd "$ROOT"
$COMPOSE up -d postgres neo4j
$COMPOSE exec -T postgres psql -U zeronode -d zeronode -c \
  "CREATE TABLE IF NOT EXISTS backup_drill (id text primary key, note text);
   INSERT INTO backup_drill(id, note) VALUES ('$MARKER', 'present')
   ON CONFLICT (id) DO UPDATE SET note = EXCLUDED.note;"

"$ROOT/scripts/backup_datastores.sh" "$OUT"

$COMPOSE exec -T postgres psql -U zeronode -d zeronode -c \
  "DELETE FROM backup_drill WHERE id = '$MARKER';"

"$ROOT/scripts/restore_datastores.sh" "$OUT" --confirm

FOUND="$($COMPOSE exec -T postgres psql -U zeronode -d zeronode -Atc \
  "SELECT note FROM backup_drill WHERE id = '$MARKER';")"
if [[ "$FOUND" != "present" ]]; then
  echo "Drill failed: marker row missing after restore" >&2
  exit 1
fi

echo "Backup/restore drill passed ($MARKER)"
