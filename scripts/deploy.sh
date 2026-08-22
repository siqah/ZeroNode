#!/usr/bin/env bash
# Reproducible local or single-host deploy using pinned compose overrides.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
if [[ -f infra/deploy/pins.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source infra/deploy/pins.env
  set +a
fi

usage() {
  cat <<'EOF'
Usage: scripts/deploy.sh [up|down|pull|status]

  up      Build and start the production compose stack (default)
  down    Stop and remove containers (volumes preserved)
  pull    Pull pinned base images referenced in infra/deploy/pins.env
  status  Show service health and /health summary
EOF
}

cmd="${1:-up}"
case "$cmd" in
  up)
    python3 "$ROOT/scripts/validate_production_config.py" || {
      echo "Fix production configuration before deploy." >&2
      exit 1
    }
    docker compose "${COMPOSE_FILES[@]}" up -d --build --remove-orphans
    echo "Waiting for API /health ..."
    for _ in $(seq 1 30); do
      if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
        curl -fsS http://localhost:8000/health | python3 -m json.tool
        exit 0
      fi
      sleep 2
    done
    echo "API did not become healthy in time; check: docker compose logs api" >&2
    exit 1
    ;;
  down)
    docker compose "${COMPOSE_FILES[@]}" down
    ;;
  pull)
    docker pull "${NEO4J_IMAGE:-neo4j:5.26-community}"
    docker pull "${POSTGRES_IMAGE:-postgres:16-alpine}"
    docker pull "${API_BASE_IMAGE:-python:3.12-slim}"
    docker pull "${WEB_BASE_IMAGE:-node:22-alpine}"
    ;;
  status)
    docker compose "${COMPOSE_FILES[@]}" ps
    curl -fsS http://localhost:8000/health 2>/dev/null | python3 -m json.tool || true
    ;;
  *)
    usage
    exit 1
    ;;
esac
