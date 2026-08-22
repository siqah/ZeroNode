# Upgrade runbook

## Before you start

1. Back up data: `scripts/backup_datastores.sh`
2. Run CI locally or confirm the PR is green (lint, pytest, eval, image scan)
3. Note current git tag/commit and image IDs

## Python dependency bump

```bash
# edit apps/api/pyproject.toml
./scripts/regenerate_lock.sh
cd apps/api && ruff check . && pytest -q && python -m app.eval
```

Commit `requirements.lock` with the pyproject change. CI fails if the lock drifts.

## Application upgrade

```bash
git pull
./scripts/deploy.sh down
./scripts/deploy.sh pull
./scripts/deploy.sh up
./scripts/deploy.sh status
```

If Neo4j seed or Postgres schema changed, read release notes in the commit; run restore only when instructed.

## Post-upgrade checks

| Check | Command |
| --- | --- |
| Health | `curl -fsS localhost:8000/health` |
| Worker heartbeat | `/health` → `queue.live_workers >= 1` |
| Eval corpus | `python -m app.eval` |
| Load smoke | `python scripts/load_test.py --duration 15` |
| Audit chain | `GET /api/v1/audit/verify` |

## Pin refresh

Third-party image tags are documented in `infra/deploy/pins.env`. Bump tags deliberately after testing in a staging stack; rebuild with `./scripts/deploy.sh up`.
