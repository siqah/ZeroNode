# Deploy runbook

## Prerequisites

- Docker and Compose
- `.env` populated from `.env.example` (secrets, bootstrap admin, `JWT_SECRET`, `AUDIT_SIGNING_KEY`, `AUDIT_ANCHOR_FILE`)
- `PRODUCTION_BASELINE=true`, `COOKIE_SECURE=true`, `STRICT_DEPENDENCIES=true`, `WORKER_EMBEDDED=false`
- Self-hosted inference reachable from the API/worker containers (`INFERENCE_BACKEND=ollama` with Ollama on the host, or `INFERENCE_BACKEND=vllm` with vLLM/TGI on your network — no specific model family required)
- `SERVICE_TOKEN` for inbound alert webhooks; `PAGERDUTY_WEBHOOK_SECRET` if using PagerDuty

## Production preflight

Before deploy, validate configuration locally:

```bash
export PRODUCTION_BASELINE=true
export JWT_SECRET="$(openssl rand -base64 48)"
export AUDIT_SIGNING_KEY="<from python -m app.audit.keys generate>"
export AUDIT_ANCHOR_FILE=/var/lib/zeronode/anchors.jsonl
export COOKIE_SECURE=true
python scripts/validate_production_config.py
```

`scripts/deploy.sh up` runs this check automatically and refuses to start on failure.

## Reproducible deploy

Production-oriented overrides live in `docker-compose.prod.yml` and `infra/deploy/pins.env`.

```bash
cp .env.example .env
# edit .env

chmod +x scripts/deploy.sh
./scripts/deploy.sh pull    # optional: prefetch pinned bases
./scripts/deploy.sh up
./scripts/deploy.sh status
```

The script builds api, worker, and web; waits for `/health`; prints JSON status.

## Verify after deploy

1. `/health` returns `200` with `"ok": true`
2. `docker compose ps` shows api, worker, postgres, neo4j healthy
3. Sign in to the dashboard; trigger a test incident (dry-run path)
4. `curl -fsS http://localhost:8000/api/v1/audit/verify | jq .` shows `chain_ok` and `protected`
5. `python -m app.eval` passes (scripted corpus, no live model)
6. Optional release gate: `python scripts/eval_live.py --probe-only` (against your configured inference backend)
7. Optional datastore gate: `scripts/lab_stores_test.sh`

## Inbound webhooks

Configure alerting systems to POST to:

- `https://<host>/api/v1/webhooks/generic` — custom JSON
- `https://<host>/api/v1/webhooks/alertmanager` — Prometheus Alertmanager v4
- `https://<host>/api/v1/webhooks/pagerduty` — PagerDuty v3 (HMAC signed)

All routes except PagerDuty require `Authorization: Bearer $SERVICE_TOKEN`. Set
`WEBHOOKS_ENABLED=true` and tune `WEBHOOK_RATE_LIMIT` / `WEBHOOK_MAX_BODY_BYTES` as needed.

## Rollback

```bash
./scripts/deploy.sh down
git checkout <previous-tag>
./scripts/deploy.sh up
```

Restore data if schema changed: `scripts/restore_datastores.sh backups/<stamp> --confirm`

The restore script also restores `audit_anchors.jsonl`. After restore, verify the ledger:

```bash
curl -fsS http://localhost:8000/api/v1/audit/verify | jq .
```
