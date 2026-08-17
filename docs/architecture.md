# ZeroNode Architecture

Sovereign, self-hosted network AI for production operations.

The model is a commodity. The product is a **governable execution harness**: opinionated tools, topological Graph-RAG, interruptible state, and human approval before any mutation. ZeroNode is not a chatbot that summarizes vendor manuals.

---

## 1. Problem

Network teams sit on two compounding gaps.

**Operational gap.** Engineers lack a unified, queryable picture of the network, and most are not software developers who can turn tribal runbooks into automation. Headcount is shrinking while topology complexity is exploding. Institutional knowledge walks out with retiring CCIEs.

**Agent gap.** Enterprises are deploying agents into environments that have no agent identity, no standard agent-to-agent protocol, and no economic or trust layer. In network operations, that governance void is fatal: 83% of organizations plan to deploy agentic AI, and only 29% feel ready to do it securely.

Trust is the blocker. Topology, BGP tables, and firewall policy are classified. Sending them to a managed API is a months-long security review. Granting an LLM raw SSH is a non-starter.

---

## 2. Product

ZeroNode is a **vendor-agnostic, self-hosted network agent platform**.

Copilot UX is not the product. **Governed execution** is:

- The agent reasons; Python tools act (or refuse).
- The agent queries a knowledge graph; it does not ingest the topology.
- Mutations freeze the graph until an L3 engineer injects a decision.
- Nothing network-shaped leaves the customer perimeter.

Incumbents (NetBox Copilot, Juniper Marvis) are vendor-locked, API-hosted, and late to write-path governance. ZeroNode starts from read-only dry-run and earns write access.

---

## 3. Four pillars

### Compute — pluggable inference, CPU orchestration

LangGraph + FastAPI run on CPU and stay cheap. Inference is an adapter:

| Stage | Engine | Constraint |
| --- | --- | --- |
| v0 (now) | Local Ollama (Gemma 4, or the largest Gemma that fits) | No guided decoding. Reliability = XML tool calls + Pydantic + retry. |
| Later | vLLM + guided JSON (Outlines), optional serverless GPU | Syntax errors drop to zero. Scale-to-zero idle cost. |

The agent never gets a shell. It gets typed tools.

### Memory — the agent is a query engine

| Tier | Store | Holds | Never holds |
| --- | --- | --- | --- |
| Working | LangGraph state + Postgres checkpointer | Ticket, scratchpad, device pointers, proposed actions | Raw configs, full topology, telemetry dumps |
| Topological | Neo4j Graph-RAG | Devices, interfaces, `CONNECTS_TO`, security zones | Runbooks |
| Semantic | Deferred (pgvector) | Runbooks, post-mortems, tickets | — |

Just-in-time retrieval. The LLM sees short strings (`Web_App -> SW_DMZ -> FW_Edge -> SW_TRUST -> DB_Primary`), not 10k-line configs.

### Governance — freeze, review, thaw

- Read-only / dry-run by default.
- `interrupt_before=["execute_change"]` persists state in Postgres. GPU/CPU can idle for hours.
- Next.js approval gate shows `<thinking>` traces, blast-radius path, and a CLI/policy diff.
- Engineer may inject feedback; reject loops the specialist. Approve records a dry-run audit (v0 does **not** push config).
- Thinking vs doing: a hallucinated command never reaches a device; the execute node is gated and, today, is a no-op logger.

### Reliability — prove the loop before eval factories

v0: one **golden incident** (cross-zone block) + deterministic mocks + a scripted-LLM test that asserts the graph pauses with a proposed action.

Later: Containerlab digital twin, Batfish control-plane proofs, LangSmith trajectory grades, Pass@K gates. Not in this slice.

---

## 4. Target workflow (v0)

**Incident.** `Web_App` in `DMZ` cannot reach `DB_Primary` in `TRUST` on TCP/443. Denied by `FW_Edge`.

**Actors.** A triage supervisor (dispatcher only) and one specialist (`firewall_specialist`).

```
Alert  →  Supervisor queries Neo4j (path + security boundary)
       →  crosses_boundary = true  →  handoff to firewall specialist
       →  Specialist reads mocked denied flows / ACL hits
       →  Specialist proposes an ACL exception
       →  Graph interrupts before execute_change
       →  L3 reviews diff in the dashboard (approve / reject + feedback)
       →  Approve: dry-run audit log. Reject: specialist re-plans.
```

No SSH. No packets. No vendor APIs.

### Roles that will use this

- **L1 NOC** — opens a ticket that already has a path, a zone check, and a suspected deny rule.
- **L3 architect** — reviews the exact policy diff, injects a constraint, approves.
- **NetDevOps** — adds a strictly typed tool; the agent inherits it without prompt rewrites.

---

## 5. v0 system

```
Alert / curl
    → FastAPI (CPU)
        → LangGraph (Postgres checkpointer)
            → Ollama (host) for XML tool calls
            → Neo4j for path / blast radius / zone checks
            → Mock firewall fixtures (denied flows, ACLs)
        → interrupt → Next.js HITL dashboard
```

Services: Ollama on the host; Neo4j, Postgres, API, and web in Docker Compose.

### API contract

| Method | Path | Role |
| --- | --- | --- |
| POST | `/api/v1/incidents/trigger` | Start a thread (`ticket_id` = `thread_id`) |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/{thread_id}/status` | State, pause flag, proposed actions, trace |
| POST | `/api/v1/incidents/{thread_id}/resume` | `{ decision, feedback }` thaw |

Golden trigger: `{ "ticket_id": "INC-1001", "description": "Web_App cannot reach DB_Primary:443" }`.

---

## 6. Non-goals (v0)

- Live SSH / NAPALM / pyATS against real boxes
- Write-path execution (v0 dry-run only)
- Slack / Teams ChatOps
- Modal, Fargate, vLLM, AWQ, guided decoding
- LangSmith / Containerlab / Batfish eval factory
- Semantic (vector) memory
- Multi-specialist fleet (BGP, hardware, load-balancer)
- Agent identity / PKI
- 100k-device scale

Those are phase-2. The moat starts when the HITL loop is demoable and auditable.

---

## 7. What must be true for the demo

1. Seeded path `Web_App → SW_DMZ → FW_Edge → SW_TRUST → DB_Primary` with `DMZ` / `TRUST` zones.
2. Supervisor calls topology tools before it may delegate.
3. Firewall specialist returns a minified deny summary and a proposed change.
4. Graph pauses before any mutate node.
5. Dashboard renders thinking, path, and diff.
6. Approve logs dry-run; reject + feedback resumes the specialist.
7. No packets. No SSH.
