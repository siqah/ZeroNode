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
- Nothing network-shaped leaves the customer perimeter unless the operator
  explicitly configures an outbound ticket or notification endpoint.

Incumbents (NetBox Copilot, Juniper Marvis) are vendor-locked, API-hosted, and late to write-path governance. ZeroNode starts from read-only dry-run and earns write access one guarantee at a time.

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

- Read-only investigation; dry-run by default, execution opt-in per device.
- `interrupt_before=["execute_change"]` persists state in Postgres. GPU/CPU can idle for hours.
- Next.js approval gate shows `<thinking>` traces, blast-radius path, and a CLI/policy diff.
- Engineer may inject feedback; reject loops the specialist. Approve records a signed audit entry and, unless execution has been enabled for that device, changes nothing.
- Thinking vs doing: a hallucinated command never reaches a device. The gap between the two is enforced structurally — investigation cannot write at all, and execution refuses anything that was not simulated, has no verified rollback, or is not a policy line the simulator can model.

### Reliability — prove the loop before eval factories

v0: one **golden incident** (cross-zone block), a scripted-LLM test that asserts the graph pauses with a proposed action, a policy suite run against captured device output, and an SSH device emulator that exercises the real transport, config session, post-change verification and rollback without hardware.

The NetBox ingest and Containerlab/cEOS topology are built as the next test rungs. They still need runs against populated NetBox and a real cEOS image. Later: Batfish control-plane proofs, trajectory grades and Pass@K gates.

---

## 4. Target workflow (v0)

**Incident.** `Web_App` in `DMZ` cannot reach `DB_Primary` in `TRUST` on TCP/443. Denied by `FW_Edge`.

**Actors.** A triage supervisor (dispatcher only) and one specialist (`firewall_specialist`).

```
Alert  →  Supervisor queries Neo4j (path + security boundary)
       →  crosses_boundary = true  →  handoff to firewall specialist
       →  Specialist reads denied flows / ACL hits over the read-only firewall interface
       →  Specialist proposes an ACL exception
       →  Graph interrupts before execute_change
       →  L3 reviews diff in the dashboard (approve / reject + feedback)
       →  Approve: signed dry-run by default, or guarded execution for an allowlisted device
       →  Post-change read-back; automatic rollback on failed verification
       →  Reject: specialist re-plans
```

Investigation is read-only throughout. Device read sessions can issue `show` commands and nothing else. A separate config-session class exists only in the execution layer, and is constructed only when execution is enabled for an allowlisted device after signed human approval.

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
            → FirewallStore (fixtures, Cisco ASA/IOS or Arista EOS read-only SSH)
            → Executor (dry-run, or guarded device config + verification/rollback)
        → interrupt → Next.js HITL dashboard
        → signed approval ledger + optional ticket/notification webhooks
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

## 6. Current boundaries

- Unattended execution: a change is only ever sent after a signed human approval, to a device named in advance, and is reversed automatically if it fails its post-change check
- Broad multi-vendor coverage beyond ASA, IOS and the lab-focused EOS adapter
- Bidirectional Slack / Teams ChatOps; current integrations are outbound webhooks
- Modal, Fargate, vLLM, AWQ, guided decoding
- LangSmith / Batfish eval factory
- Semantic (vector) memory
- Multi-specialist fleet (BGP, hardware, load-balancer)
- Agent identity / PKI
- 100k-device scale

The next reliability work is a durable job runner, model timeouts and retries,
backpressure, observability, backup/restore drills and CI regression gates.

---

## 7. Acceptance criteria for v0

1. Seeded path `Web_App → SW_DMZ → FW_Edge → SW_TRUST → DB_Primary` with `DMZ` / `TRUST` zones.
2. Supervisor calls topology tools before it may delegate.
3. Firewall specialist returns a minified deny summary and a proposed change.
4. Graph pauses before any mutate node.
5. Dashboard renders thinking, path, and diff.
6. Approve logs a dry run, or applies and verifies the change where execution is enabled; reject + feedback resumes the specialist.
7. Every proposed change is simulated against device policy before it reaches the gate.
8. Investigation cannot write. One class can, it is constructed only when execution is enabled for the named device, and what it does is verified and reversible.
