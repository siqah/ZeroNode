# ZeroNode

Self-hosted network AI agent: LangGraph + local Gemma (Ollama), Neo4j Graph-RAG, and zero-trust human-in-the-loop. **v0 proves a cross-zone connectivity failure** from alert → specialist → approval gate. Writes are dry-run only. Nothing is SSH'd. Telemetry does not leave the machine.

How it works, and what production needs: [docs/how-it-works.md](docs/how-it-works.md)
Product thesis: [docs/architecture.md](docs/architecture.md)

## What you get in this slice

- Supervisor agent queries topology (`security_boundary_check`, `trace_network_path`) then hands off to a firewall specialist
- Seeded lab path: `Web_App → SW_DMZ → FW_Edge → SW_TRUST → DB_Primary` (DMZ / TRUST)
- Every proposed change is simulated against the ACL first: a permit shadowed by an existing deny, or one broader than the evidence supports, never reaches the approval gate
- Graph **interrupts before** `execute_change`
- Next.js NOC dashboard shows thinking, path, CLI diff, simulation verdict, Approve / Reject
- Approve logs a dry-run; it does **not** push config

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

### Golden alert (live agent)

```bash
curl -sS -X POST http://localhost:8000/api/v1/incidents/trigger \
  -H 'Content-Type: application/json' \
  -d '{"ticket_id":"INC-1001","description":"Web_App cannot reach DB_Primary:443","severity":"high"}'
```

Then open [http://localhost:3000/incidents/INC-1001](http://localhost:3000/incidents/INC-1001). The thread should pause with a proposed ACL on `FW_Edge`. Approve records dry-run; Reject sends feedback back to the specialist.

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

- API: http://localhost:8000/health
- Neo4j browser: http://localhost:7474 (neo4j / zeronode)
- Web: http://localhost:3000

## API

| Method | Path | Role |
| --- | --- | --- |
| POST | `/api/v1/incidents/trigger` | Dispatch a thread (`ticket_id` = LangGraph `thread_id`) |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/{id}/status` | Pause flag, path, proposed actions, trace |
| POST | `/api/v1/incidents/{id}/resume` | `{ "decision": "approve" \| "reject", "feedback": "" }` |

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
