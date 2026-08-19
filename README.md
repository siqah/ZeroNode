# ZeroNode

Self-hosted network AI agent: LangGraph + local Gemma (Ollama), Neo4j Graph-RAG, and zero-trust human-in-the-loop. **v0 proves a cross-zone connectivity failure** from alert → specialist → approval gate. Writes are dry-run only: device access is read-only by construction, and no code path can change a device. Telemetry does not leave the machine.

How it works, and what production needs: [docs/how-it-works.md](docs/how-it-works.md)
Product thesis: [docs/architecture.md](docs/architecture.md)

## What v0 does

- Supervisor agent queries topology (`security_boundary_check`, `trace_network_path`) then hands off to a firewall specialist
- Seeded lab path: `Web_App → SW_DMZ → FW_Edge → SW_TRUST → DB_Primary` (DMZ / TRUST)
- Every proposed change is simulated against the ACL first: a permit shadowed by an existing deny, or one broader than the evidence supports, never reaches the approval gate
- Every proposal carries a rollback command, and the rollback is simulated back to the pre-change verdict before the change can be queued
- Approvals answer to a change window and freeze calendar; an admin can break glass, with a reason sealed into the approval record
- Alert text is treated as untrusted input: control markers and hidden characters are stripped, it is fenced as data, and steering attempts are flagged to the approver
- Firewall access sits behind a read-only interface with three backends: lab fixtures by default, or a live Cisco ASA or IOS device over SSH that can only issue `show` commands. Object-groups and named objects are resolved, and a translated flow makes the simulator decline a verdict instead of judging the wrong addresses
- `python -m app.firewall.probe` validates a real device read-only and reports exactly which ACL lines the parser could not model
- Approving a change requires an authenticated human with the `approver` role and a second factor; machine credentials can open incidents but can never approve one
- Sessions are httpOnly cookies with CSRF protection, login is throttled, and repeated failures lock the account
- Every decision is sealed into a hash-chained, Ed25519-signed, append-only ledger, anchored outside the database so deletion is detectable, and can be re-verified with `GET /api/v1/audit/verify`
- Graph **interrupts before** `execute_change`
- Next.js NOC dashboard shows thinking, path, CLI diff, simulation verdict, Approve / Reject
- Approve logs a dry-run; it does **not** push config
- Credentials can point at a secret manager (`file:`, `env:`, `vault:`, `exec:`) instead of holding a value, and an unreachable store fails startup rather than quietly swapping in fixtures

## Prerequisites

- Python 3.11+
- Node 20+
- Docker (Neo4j + Postgres)
- [Ollama](https://ollama.com) on the host, for live inference

```bash
ollama pull gemma4:e4b
```

ZeroNode talks to Ollama via `OLLAMA_MODEL`. Recommended local pick: **`gemma4:e4b`** (best structured tool-calling of the small Gemma 4 family). Fallback if RAM or latency is painful: `batiai/gemma4-e2b:q4`. Skip `gemma:2b` for this agent.

## Run locally

```bash
cp .env.example .env
docker compose up -d neo4j postgres neo4j-init
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
AUDIT_ANCHOR_FILE=./.zeronode/anchors.jsonl
```

Approvers need a second factor. After signing in, the dashboard prompts for enrolment: add the key
to an authenticator app, confirm one code, and sign in again. To run without it — local
experiments only — set `MFA_REQUIRED_FOR_APPROVERS=false`.

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

Then open [http://localhost:3000/incidents/INC-1001](http://localhost:3000/incidents/INC-1001). The thread should pause with a proposed ACL on `FW_Edge`. Approve records a dry-run and a signed ledger entry; Reject sends feedback back to the specialist. Verify the ledger at any time:

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
that the read-only guard held. Then set `FIREWALL_BACKEND=cisco_asa` (or `cisco_ios`).

The device password may not be an inline value: point it at a secret manager, for example
`FIREWALL_PASSWORD=file:/run/secrets/asa_password`, `vault:secret/data/zeronode#asa_password` or
`exec:<command>`. It is resolved when a session opens and cached for `SECRET_CACHE_SECONDS`, so
rotating at the source needs no restart. `REQUIRE_MANAGED_SECRETS=false` accepts the risk.

### Golden path without Ollama (CI / sanity)

```bash
python scripts/golden_path.py
cd apps/api && pytest -q
```

The scripted LLM walks the same tool sequence and asserts interrupt before `execute_change`.

## Docker Compose (API + web)

Ollama stays on the host. The container reads `OLLAMA_BASE_URL_DOCKER` (default
`host.docker.internal:11434`) rather than `OLLAMA_BASE_URL`, so the host setting in `.env` cannot
leak in and point the container at itself.

```bash
docker compose up --build
```

- API: http://localhost:8000/health — lists any degradation and returns `503` while one is active
- Neo4j browser: http://localhost:7474 (neo4j / zeronode)
- Web: http://localhost:3000

## API

| Method | Path | Role |
| --- | --- | --- |
| POST | `/api/v1/incidents/trigger` | Dispatch a thread (`ticket_id` = LangGraph `thread_id`) |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/{id}/status` | Pause flag, path, proposed actions, trace |
| POST | `/api/v1/incidents/{id}/resume` | `{ "decision": "approve" \| "reject", "feedback": "" }`. Outside a change window an admin may add `override_window` and `override_reason` |

## Repo

```
docs/how-it-works.md  system walkthrough + production plan
docs/architecture.md  product thesis
docker-compose.yml
infra/neo4j/          schema + DMZ/TRUST seed
apps/api/             FastAPI, LangGraph, tools, change simulator, tests
apps/web/             Next.js HITL dashboard
scripts/golden_path.py    scripted end-to-end run, no Ollama needed
scripts/probe_turn.py     print the model's raw reply for one turn
```
