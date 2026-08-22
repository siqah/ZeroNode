# On-call runbook

## Severity guide

| Signal | Likely cause | First action |
| --- | --- | --- |
| `/health` → `503` | Degraded dependency | Read `degradations[]` in the JSON body |
| `audit: anchor mismatch` | Ledger tampered or anchor missing | Check `AUDIT_ANCHOR_FILE` volume; do not disable anchoring |
| Webhook `429` / no incident | Rate limit or duplicate delivery | Check `zeronode_webhook_*` metrics; verify `SERVICE_TOKEN` |
| Webhook `401` on PagerDuty | Bad HMAC secret | Rotate `PAGERDUTY_WEBHOOK_SECRET` and update PagerDuty subscription |
| `topology: stale` | NetBox ingest lag | Check `NETBOX_*` env; run `scripts/ingest_netbox.py --dry-run` |
| `worker: no live investigation worker heartbeat` | Worker down | `docker compose logs worker`; restart worker service |
| `queue: saturated` | Job backlog | Raise `WORKER_CONCURRENCY` or scale workers; check Ollama latency |
| `inference: circuit_open` | Model failures | Check Ollama/vLLM; inspect `zeronode_model_calls_total` |
| Incident stuck `running` | Job lease / graph error | `GET /api/v1/incidents/{id}/status`; check worker logs for thread_id |
| `rollback_failed` on incident | Device write issue | **Do not re-approve**; manual device remediation per change ticket |

## Triage commands

```bash
curl -fsS http://localhost:8000/health | jq .
curl -fsS http://localhost:8000/api/v1/audit/verify | jq .
curl -fsS http://localhost:8000/metrics | rg zeronode_
docker compose ps
docker compose logs --tail=200 api worker
```

## Safe interventions

- Restart worker: `docker compose restart worker`
- Restart API (brief outage): `docker compose restart api`
- Drain queue: stop triggers at the source; wait for in-flight jobs to finish
- Fail loud: prefer `/health` 503 over silent fixture fallback (`STRICT_DEPENDENCIES=true`)

## Escalation data to capture

- Incident `thread_id` and ledger hash from the approval record
- `/health` JSON and last 200 lines of api + worker logs
- Whether the change was dry-run or live (`EXECUTION_ENABLED`, device in `EXECUTION_DEVICES`)
- Topology freshness block from `/health` if graph-related

## Not on-call scope

- Production firewall changes without an approved ZeroNode ticket
- Bypassing MFA or approval gates
- Disabling audit anchoring to “get things working”
