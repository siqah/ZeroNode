# ZeroNode

Self-hosted network AI agent: LangGraph + pluggable local inference (Ollama or self-hosted vLLM), Neo4j Graph-RAG, and zero-trust human-in-the-loop. **v0 proves a cross-zone connectivity failure** from alert → specialist → approval gate. Writes are dry-run by default. Execution is opt-in per device, and a change that does not verify against the device afterwards is rolled back automatically. Telemetry stays local unless an operator explicitly enables an outbound ticket or notification webhook.

How it works, and what production needs: [docs/how-it-works.md](docs/how-it-works.md)
How to use it in your work (including **before you start**): [docs/using-zeronode.md](docs/using-zeronode.md)
What remains before production: [docs/roadmap.md](docs/roadmap.md)
Product thesis: [docs/architecture.md](docs/architecture.md)

## What v0 does

- Supervisor agent queries topology (`security_boundary_check`, `trace_network_path`) then hands off to a firewall specialist
- Seeded lab path: `Web_App → SW_DMZ → FW_Edge → SW_TRUST → DB_Primary` (DMZ / TRUST)
- Every proposed change is simulated against the ACL first: a permit shadowed by an existing deny, or one broader than the evidence supports, never reaches the approval gate
- Every proposal carries a rollback command, and the rollback is simulated back to the pre-change verdict before the change can be queued
- Approvals answer to a change window and freeze calendar; an admin can break glass, with a reason sealed into the approval record
- Alert text is treated as untrusted input: control markers and hidden characters are stripped, it is fenced as data, and steering attempts are flagged to the approver
- Firewall access sits behind a read-only interface with five backends: lab fixtures by default, plus Cisco ASA, Cisco IOS, Arista EOS and Nokia SR Linux over SSH. Read sessions can only issue `show` commands. Object-groups and named objects are resolved, and a translated flow makes the simulator decline a verdict instead of judging the wrong addresses
- `python -m app.firewall.probe` validates a real device read-only and reports exactly which ACL lines the parser could not model
- Approving a change requires an authenticated human with the `approver` role and a second factor; machine credentials can open incidents but can never approve one
- Sessions are httpOnly cookies with CSRF protection, login is throttled, and repeated failures lock the account
- Every decision is sealed into a hash-chained, Ed25519-signed, append-only ledger, anchored outside the database so deletion is detectable, and can be re-verified with `GET /api/v1/audit/verify`
- Graph **interrupts before** `execute_change`
- Next.js NOC dashboard shows thinking, path, CLI diff, simulation verdict, Approve / Reject
- Approve logs a dry-run by default. Execution needs two switches — `EXECUTION_ENABLED` and a device named in `EXECUTION_DEVICES` — and only one class in the codebase can write; every read path still refuses anything but `show`
- An executed change is read back off the device, and if the flow is not actually permitted it is rolled back automatically. A rollback that itself fails is a loud terminal state, not a log line
- Pending approvals go to a Slack, Teams or Mattermost webhook, and incidents, decisions and execution outcomes are written back to a ServiceNow or Jira endpoint
- Credentials can point at a secret manager (`file:`, `env:`, `vault:`, `exec:`) instead of holding a value, and an unreachable store fails startup rather than quietly swapping in fixtures
- Inbound alert webhooks normalize generic, Prometheus Alertmanager v4, and PagerDuty v3 payloads into the same trigger path as manual incidents, with rate limits, deduplication, and signature verification
- Production baseline mode (`PRODUCTION_BASELINE=true`) fails closed on missing auth, JWT, audit key, external anchor, TLS cookies, strict dependencies, or embedded worker mode

## Prerequisites

- Python 3.11+
- Node 20+
- Docker (Neo4j + Postgres)
- **Optional:** a live inference server, only if you want the agent to run investigations (not needed for `python scripts/golden_path.py`)

ZeroNode does **not** require Gemma or Ollama. Inference is a pluggable adapter controlled by
`INFERENCE_BACKEND`. All backends are **self-hosted on your network** — there is no cloud model
API and no vendor lock-in to a specific model family:

| Backend | When to use | Configure |
| --- | --- | --- |
| **`ollama`** (default) | Local CPU/GPU via [Ollama](https://ollama.com) on the host | `INFERENCE_BACKEND=ollama`, `OLLAMA_MODEL=<any model your Ollama serves>` |
| **`vllm`** | Self-hosted [vLLM](https://docs.vllm.ai/) or TGI on your own GPU host | `INFERENCE_BACKEND=vllm`, `VLLM_BASE_URL`, `VLLM_MODEL` |

Example — Ollama (optional):

```bash
ollama pull gemma4:e4b    # example only; any tool-capable model works
ollama serve
```

Example — self-hosted vLLM on your GPU host (optional):

```env
INFERENCE_BACKEND=vllm
VLLM_BASE_URL=http://gpu-host:8000/v1
VLLM_MODEL=your-local-model-id
VLLM_API_KEY=EMPTY
```

The model name in `.env.example` (`gemma4:e4b`) is a **default example**, not a requirement. Pick
any model your backend serves that can follow tool-calling instructions (native `tool_calls` or
XML-wrapped JSON). Smaller models may hit the state-driven fallback more often; see
[how-it-works.md](docs/how-it-works.md).

## Run locally

```bash
cp .env.example .env
```

Set at least these in `.env` before starting the API, or you will not be able to sign in:

```bash
JWT_SECRET=$(openssl rand -base64 48)
# Local runs have no Neo4j or Postgres until compose is up:
# STRICT_DEPENDENCIES=false
BOOTSTRAP_ADMIN_EMAIL=you@example.com
BOOTSTRAP_ADMIN_PASSWORD=at-least-12-characters
# Persist the ledger signing key, or approvals cannot be verified after a restart:
# cd apps/api && .venv/bin/python -m app.audit.keys generate
AUDIT_SIGNING_KEY=
# Anchor the ledger head outside Postgres, so deleting the table is detectable:
# In Compose this path is on the audit_anchors volume:
AUDIT_ANCHOR_FILE=/var/lib/zeronode/anchors.jsonl
```

Approvers need a second factor. After signing in, the dashboard prompts for enrolment: add the key
to an authenticator app, confirm one code, and sign in again. To run without it — local
experiments only — set `MFA_REQUIRED_FOR_APPROVERS=false`.

The simplest complete run uses Compose. Start inference **only if** you want live agent
investigations; the stack itself (login, dashboard, user management, scripted golden path) runs
without it:

```bash
docker compose up -d --build
curl -fsS http://localhost:8000/health
```

`/health` checks whichever inference backend is configured (`ollama` or self-hosted `vllm`) as
well as the durable stores. It returns `503` if inference is configured but unreachable, so an
incident cannot silently remain `running` behind a healthy status. If you have not started a
model server yet, use `python scripts/golden_path.py` for a full workflow test without live AI.

For host-based development, start the data stores first:

```bash
docker compose up -d neo4j postgres neo4j-init
```

API (in a venv):

```bash
cd apps/api
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

Web:

```bash
cd apps/web
npm install
npm run dev
```

Open [http://localhost:3000/dashboard](http://localhost:3000/dashboard).

Sign in at [http://localhost:3000/login](http://localhost:3000/login) with the bootstrap admin.

### Golden alert (live agent)

```bash
ZERONODE_PASSWORD='at-least-12-characters' ./scripts/trigger_golden_alert.sh
```

The script signs in, carries the session cookie and echoes the CSRF token; set `SERVICE_TOKEN` instead to call it the way an alerting system would. If the account has a second factor, pass `ZERONODE_TOTP=123456`.

Then open [http://localhost:3000/incidents/INC-1001](http://localhost:3000/incidents/INC-1001). The thread should pause with a proposed ACL on `FW_Edge`. Approve records a dry-run and a signed ledger entry (or applies the change, if you have enabled execution for that device); Reject sends feedback back to the specialist. Verify the ledger at any time:

```bash
curl -sS -H "Authorization: Bearer $SERVICE_TOKEN" http://localhost:8000/api/v1/audit/verify
```

Rotating the signing key keeps old records verifiable; `python -m app.audit.keys rotate` prints the
new `AUDIT_SIGNING_KEY` and the `AUDIT_RETIRED_KEYS` to keep alongside it, and the rotation is
written into the chain on the next start.

### Pointing at a real device

Validate it read-only before the agent ever reads it:

```bash
cd apps/api && pip install -e ".[devices]"
.venv/bin/python -m app.firewall.probe --backend cisco_asa \
  --host 192.0.2.10 --username readonly --flow 10.10.1.10,10.20.1.50,443
```

The probe reports how much of the policy the parser could model, whether NAT touches the flow, and
that the read-only guard held. Then set `FIREWALL_BACKEND=cisco_asa`, `cisco_ios`,
`arista_eos` or `nokia_srl`.

The device password may not be an inline value: point it at a secret manager, for example
`FIREWALL_PASSWORD=file:/run/secrets/asa_password`, `vault:secret/data/zeronode#asa_password` or
`exec:<command>`. It is resolved when a session opens and cached for `SECRET_CACHE_SECONDS`, so
rotating at the source needs no restart. `REQUIRE_MANAGED_SECRETS=false` accepts the risk.

### Inbound alert webhooks

All webhook routes require `SERVICE_TOKEN` (Bearer) except PagerDuty, which verifies the v3 HMAC
signature with `PAGERDUTY_WEBHOOK_SECRET`. Firing alerts enqueue an investigation; resolved or
acknowledged events are ignored.

```bash
curl -sS -X POST http://localhost:8000/api/v1/webhooks/generic \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"ALERT-42","description":"Web_App cannot reach DB_Primary:443","severity":"high"}'
```

| Route | Source |
| --- | --- |
| `POST /api/v1/webhooks/generic` | Custom JSON or `{ "event": "incident.opened", "incident": {...} }` |
| `POST /api/v1/webhooks/alertmanager` | Prometheus Alertmanager v4 webhook |
| `POST /api/v1/webhooks/pagerduty` | PagerDuty v3 incident webhook (HMAC signed) |

### Golden path without live inference (CI / sanity)

```bash
python scripts/golden_path.py
python scripts/eval_incidents.py   # score the full golden corpus
python scripts/eval_live.py        # live model gate (needs a configured inference backend)
cd apps/api && pytest -q -m "not integration"
scripts/lab_stores_test.sh         # real Postgres + Neo4j integration gate
```

The scripted LLM walks the same tool sequence and asserts interrupt before `execute_change`.

### Full local walkthrough

With the Compose stack and a configured inference backend running, this exercises health, login, MFA
enrolment, a live-model investigation, HITL approval, dry-run execution and
signed-ledger verification:

```bash
ZERONODE_EMAIL=you@example.com \
ZERONODE_PASSWORD='your-bootstrap-password' \
apps/api/.venv/bin/python scripts/e2e_walkthrough.py
```

The password is read from the environment so it does not need to be stored in
the repository. A live investigation on CPU can take several minutes depending on model and backend.

### Hardware-free test environments

```bash
# Real SSH transport, prompts, config mode, verification and rollback:
scripts/lab_device_test.sh

# NetBox source-of-truth profile:
docker compose --profile netbox up -d
python scripts/ingest_netbox.py --token "$NETBOX_TOKEN" --dry-run
```

The Containerlab topology is in `infra/containerlab/`. It uses Nokia SR Linux,
a genuine network OS whose official test image is public and requires no vendor
account or licence download.

```bash
scripts/lab_containerlab_test.sh
```

The script pulls the pinned SR Linux image, boots the routed three-node lab,
proves the seeded deny with a real packet, verifies a shadowed change is
automatically rolled back, verifies a correctly positioned change passes, and
destroys the lab.

## Docker Compose (API + worker + web)

When using `INFERENCE_BACKEND=ollama`, Ollama typically runs on the host. The container reads
`OLLAMA_BASE_URL_DOCKER` (default `host.docker.internal:11434`) rather than `OLLAMA_BASE_URL`, so
the host setting in `.env` cannot leak in and point the container at itself. When using
`INFERENCE_BACKEND=vllm`, point `VLLM_BASE_URL` at a **self-hosted** vLLM or TGI instance on
your network — no Ollama required. Everything stays on infrastructure you operate.

```bash
docker compose up -d --build
```

- API: http://localhost:8000/health — lists any degradation and returns `503` while one is active
- Metrics: http://localhost:8000/metrics
- Neo4j browser: http://localhost:7474 (neo4j / zeronode)
- Web: http://localhost:3000

Compose starts a dedicated `worker` service that leases investigation jobs from
Postgres. Without it, `/health` reports `worker: no live investigation worker
heartbeat`. For single-process local runs only, set `WORKER_EMBEDDED=true`.

Backup and restore (includes the audit anchor file):

```bash
scripts/backup_datastores.sh
scripts/restore_datastores.sh backups/<stamp> --confirm
scripts/backup_restore_drill.sh
```

Production deploy (runs config preflight, uses `docker-compose.prod.yml`):

```bash
cp .env.example .env   # set JWT_SECRET, AUDIT_SIGNING_KEY, PRODUCTION_BASELINE=true, COOKIE_SECURE=true
./scripts/deploy.sh up
```

## API

| Method | Path | Role |
| --- | --- | --- |
| POST | `/api/v1/incidents/trigger` | Dispatch a thread (`ticket_id` = LangGraph `thread_id`) |
| POST | `/api/v1/webhooks/generic` | Normalized generic alert webhook (`SERVICE_TOKEN`) |
| POST | `/api/v1/webhooks/alertmanager` | Prometheus Alertmanager v4 webhook (`SERVICE_TOKEN`) |
| POST | `/api/v1/webhooks/pagerduty` | PagerDuty v3 webhook (HMAC signature) |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/{id}/status` | Pause flag, path, proposed actions, trace |
| POST | `/api/v1/incidents/{id}/resume` | `{ "decision": "approve" \| "reject", "feedback": "" }`. Outside a change window an admin may add `override_window` and `override_reason` |
| GET | `/api/v1/audit/verify` | Ledger verification (`chain_ok`, `protected`) |

## Repo

```
docs/how-it-works.md  system walkthrough + production plan
docs/using-zeronode.md how to use ZeroNode in day-to-day work (by role)
docs/runbooks/        deploy, upgrade, and on-call guides
docs/architecture.md  product thesis
docker-compose.yml
docker-compose.prod.yml  production overrides (no public DB ports)
infra/deploy/pins.env    pinned third-party image tags
infra/neo4j/          schema + DMZ/TRUST seed
infra/fakeasa/        device-shaped SSH test server
infra/containerlab/   three-node Nokia SR Linux lab (public image)
apps/api/             FastAPI, LangGraph, tools, change simulator, tests
apps/web/             Next.js HITL dashboard
scripts/golden_path.py    scripted end-to-end run, no live model needed
scripts/eval_incidents.py golden incident corpus + scorers (CI gate)
scripts/eval_live.py       live model eval against your configured backend (manual release gate)
scripts/e2e_walkthrough.py authenticated live-model walkthrough
scripts/ingest_netbox.py  read NetBox topology into Neo4j
scripts/lab_device_test.sh run SSH execution tests safely
scripts/lab_containerlab_test.sh validate Phase 2 against Nokia SR Linux
scripts/backup_datastores.sh      versioned Neo4j + Postgres backup
scripts/restore_datastores.sh     guarded restore (requires --confirm)
scripts/backup_restore_drill.sh   disposable backup/restore proof
scripts/deploy.sh             reproducible prod compose deploy
scripts/lab_stores_test.sh    real Postgres + Neo4j integration tests
scripts/lab_device_test.sh    SSH device integration tests (fake-asa emulator)
scripts/ci_wait_fake_asa.py   wait for fake-asa in CI/device runs
scripts/validate_production_config.py  production preflight checker
scripts/load_test.py          read-only load test (/health, /metrics)
scripts/soak_test.sh          sustained load gate
scripts/regenerate_lock.sh    refresh apps/api/requirements.lock
scripts/probe_turn.py     print the model's raw reply for one turn
```

## Before publishing to GitHub

- Never add `.env`, signing keys, service tokens, webhook URLs, device
  credentials, ledger anchors, packet captures, database files or network OS
  images.
- Keep real device output out of fixtures unless addresses, hostnames, serial
  numbers, usernames and public IPs have been anonymized.
- Review ignored files with `git status --short --ignored`.
- Review staged content before every push with `git diff --cached`.
- If a secret was ever committed, ignoring it is not enough: rotate it and
  remove it from Git history before publishing.

See [SECURITY.md](SECURITY.md) for the repository security policy.
