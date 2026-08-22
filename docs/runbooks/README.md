# ZeroNode runbooks

Operational guides for running ZeroNode in production-like environments.

| Runbook | When to use |
| --- | --- |
| [Deploy](deploy.md) | First install, redeploy, or rollback a compose stack |
| [Upgrade](upgrade.md) | Version bumps, dependency updates, image refreshes |
| [On-call](on-call.md) | Alerts, `/health` degradations, queue saturation, failed jobs |

Quick checks:

```bash
curl -fsS http://localhost:8000/health | jq .
curl -fsS http://localhost:8000/metrics | head
docker compose ps
docker compose logs --tail=100 worker
```

Load/soak gates before a release:

```bash
python scripts/load_test.py --duration 30 --concurrency 8
SOAK_DURATION_SECONDS=300 scripts/soak_test.sh
```
