#!/usr/bin/env bash
# Run real Postgres/Neo4j integration tests locally.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/docker-compose.yml")

"${COMPOSE[@]}" up -d postgres neo4j
"${COMPOSE[@]}" up neo4j-init

export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgresql://zeronode:zeronode@localhost:5433/zeronode}"
export TEST_NEO4J_URI="${TEST_NEO4J_URI:-bolt://localhost:7687}"
export TEST_NEO4J_USER=neo4j
export TEST_NEO4J_PASSWORD=zeronode

PYTHON="${ROOT}/apps/api/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON=python3
fi

"$PYTHON" "$ROOT/scripts/ci_wait_postgres.py"
"$PYTHON" "$ROOT/scripts/ci_seed_neo4j.py"

cd "$ROOT/apps/api"
if [[ -x .venv/bin/pytest ]]; then
  .venv/bin/pytest -q -m integration "$@"
else
  pytest -q -m integration "$@"
fi
