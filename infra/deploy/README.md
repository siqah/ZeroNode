# Deploy layout

Reproducible single-host production deploys use three pieces:

| File | Role |
| --- | --- |
| `docker-compose.yml` | Base stack (api, worker, web, neo4j, postgres) |
| `docker-compose.prod.yml` | Production overrides: restart policy, no DB host ports, JSON logs |
| `pins.env` | Documented third-party image tags |

```bash
./scripts/deploy.sh up
```

See [docs/runbooks/deploy.md](../../docs/runbooks/deploy.md) for the full procedure.
