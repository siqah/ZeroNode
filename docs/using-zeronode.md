# Using ZeroNode in your work

ZeroNode is a self-hosted assistant for network incidents. It does not replace your judgment — it
does the repetitive investigation work (trace the path, read the firewall, simulate a fix) and
stops at a human gate before anything can change a device.

This guide explains how different people use it day to day. For system internals, see
[how-it-works.md](how-it-works.md). For on-call triage, see [runbooks/on-call.md](runbooks/on-call.md).

---

## What problem it solves

When connectivity breaks across a security zone, an engineer normally:

1. Confirms which path the traffic takes
2. Checks whether it crosses a firewall boundary
3. Reads deny logs and ACL counters on the edge device
4. Proposes a minimal permit rule in the correct line position
5. Gets a second pair of eyes before applying it

ZeroNode automates steps 1–4 with deterministic tools and a local LLM orchestrator. Step 5 stays
with you. By default, even an approved change is **logged only** (dry-run). Live execution is a
separate, explicit opt-in per device.

---

## Who does what

ZeroNode has four roles. You sign in at `/login`; alerting systems use a service token instead.

| Role | Typical job title | What you do in ZeroNode |
| --- | --- | --- |
| **Viewer** | Manager, auditor, trainee | Read incidents, reasoning traces, and the audit ledger. Cannot trigger or approve. |
| **Operator** | NOC engineer, monitoring integration | Receive alerts, open incidents, watch investigations run. Cannot approve changes. |
| **Approver** | Senior network engineer, change approver | Everything an operator can do, plus **Approve** or **Reject** at the gate. Requires MFA. |
| **Admin** | Platform owner, team lead | Manage users, unlock accounts, break glass outside change windows (with a recorded reason). |

**Important:** A monitoring webhook or `SERVICE_TOKEN` can open incidents but can **never**
approve a change. Approvals always require a human with MFA.

---

## How an incident flows through your team

```mermaid
flowchart TD
    A[Alert arrives] --> B[ZeroNode opens incident]
    B --> C[Agent investigates]
    C --> D{Proposed fix?}
    D -->|No| E[Incident stays running or resolves]
    D -->|Yes| F[Pause at approval gate]
    F --> G[Approver reviews evidence]
    G -->|Reject| H[Agent revises with feedback]
    H --> C
    G -->|Approve| I[Dry-run logged by default]
    I --> J{Execution enabled?}
    J -->|No| K[Done — change recorded, not sent]
    J -->|Yes| L[Apply, verify, rollback if needed]
```

### 1. Alert intake (usually automatic)

Incidents arrive from:

- **Prometheus Alertmanager** → `POST /api/v1/webhooks/alertmanager`
- **PagerDuty** → `POST /api/v1/webhooks/pagerduty`
- **Custom monitoring** → `POST /api/v1/webhooks/generic`
- **Manual trigger** → dashboard or `POST /api/v1/incidents/trigger`

Example alert: *"Web_App cannot reach DB_Primary on tcp/443."*

ZeroNode sanitizes the alert text, assigns a stable incident ID, writes it to Postgres, and queues
a background job. You do not need to paste alert text into a chat window.

### 2. Investigation (automatic)

The agent:

- Traces the network path in Neo4j (`Web_App → SW_DMZ → FW_Edge → SW_TRUST → DB_Primary`)
- Confirms the path crosses a security zone boundary
- Reads denied flows and ACL hits from the firewall (read-only `show` commands)
- Proposes a minimal ACL change with a simulated verdict and a rollback command

You can follow this live on the incident page: reasoning trace, topology path, denied flows,
simulation result, and the exact CLI diff it wants to apply.

### 3. Approval gate (your main job as approver)

When the agent is ready, the incident status becomes **awaiting approval**. The dashboard shows:

| What you review | Why it matters |
| --- | --- |
| Traced path and zones | Confirms the agent looked at the right topology |
| Denied flows | Evidence for why traffic is blocked |
| Proposed command + position | The actual change; position matters (a permit after a deny does nothing) |
| Simulation verdict | PASS/FAIL from the policy simulator — not the model's opinion |
| Rollback command | What would undo the change |
| Alert flags | Anything suspicious in the original alert text (injection, "skip approval", etc.) |

**Approve** if the evidence supports the change and the change window is open.

**Reject** with feedback if the proposal is wrong — the agent gets your note and tries again.

Approvers need TOTP (authenticator app). Enrol on first login if prompted.

### 4. After approval (usually automatic)

- **Default (dry-run):** The approved change is written to the signed audit ledger and logged. Nothing is sent to the device.
- **Execution enabled:** The change is applied to a named device, read back for verification, and automatically rolled back if verification fails.

Every approval is sealed in an Ed25519-signed, hash-chained ledger before the agent resumes.

---

## A typical day by role

### NOC operator

**Morning:** Check `/health` and the dashboard for stuck incidents.

**When an alert fires:**

1. Confirm the incident appeared (from webhook or manual trigger)
2. Open `/incidents/{thread_id}` and watch the investigation
3. If it reaches **awaiting approval**, ping the on-call approver
4. Do not SSH to the firewall to "help" — that bypasses the audit trail

**You use:** dashboard, incident list, incident status polling.

**You do not:** approve changes, edit device config directly for incidents ZeroNode owns.

### Senior engineer / approver

**When paged for approval:**

1. Open the incident link from Slack/Teams/PagerDuty notification (if configured)
2. Read the path, deny evidence, simulation verdict, and CLI diff
3. Check alert flags and change window status
4. Approve or reject with a short note

**Outside a change window:** Only an admin can override, and must provide a break-glass reason that is recorded in the ledger.

**After approving:** Optionally verify the ledger:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/audit/verify | jq .
```

### Platform admin

**Setup (once):**

- Copy `.env.example` → `.env`, set secrets, bootstrap admin, audit key, anchor path
- Start stack: `docker compose up -d --build` or `./scripts/deploy.sh up`
- Point Alertmanager/PagerDuty at webhook URLs
- Optionally configure ticket and notification webhooks

**Ongoing:**

- Create users and assign roles
- Rotate `JWT_SECRET`, `AUDIT_SIGNING_KEY`, webhook secrets
- Run backups: `scripts/backup_datastores.sh`
- Monitor `/health` degradations (worker down, stale topology, queue saturated)

See [runbooks/deploy.md](runbooks/deploy.md) and [runbooks/on-call.md](runbooks/on-call.md).

### Auditor / compliance

**Read-only access** with the `viewer` role:

- `GET /api/v1/audit/approvals` — full approval history
- `GET /api/v1/audit/verify` — chain integrity and external anchor status
- Incident pages — what the approver saw at decision time (evidence is sealed in the ledger)

The ledger answers: *who approved what, when, with what evidence, and whether the record chain is intact.*

---

## Where you work in the UI

| URL | Purpose |
| --- | --- |
| `/login` | Sign in; enrol MFA for approvers |
| `/dashboard` | Incident list and overview |
| `/incidents/{thread_id}` | Live investigation, approval gate, execution outcome |

On the incident page you will see:

- **Reasoning trace** — step-by-step agent decisions
- **Path visualizer** — topology path across devices and zones
- **Approval gate** — proposed change, simulation, Approve/Reject buttons
- **Execution outcome** — dry-run log or live apply/rollback result

---

## How alerts connect to your existing tools

ZeroNode fits into a normal NOC stack without replacing it:

| Your tool | How ZeroNode uses it |
| --- | --- |
| **Alertmanager / PagerDuty** | Inbound webhooks open incidents automatically |
| **ServiceNow / Jira** | Outbound ticket webhook records incident, decision, and outcome |
| **Slack / Teams / Mattermost** | Notification webhook pings approvers when a change waits at the gate |
| **NetBox** | Topology ingest keeps Neo4j aligned with inventory (optional) |
| **Ollama / vLLM** | Local inference — alert and topology data stay on your network |

Nothing leaves your perimeter unless you configure those outbound webhooks.

---

## What ZeroNode will not do for you

- **Replace change management.** It enforces windows and freezes; it does not write your CAB ticket.
- **Approve itself.** Machines can trigger; only humans with MFA can approve.
- **Silently fail.** If Postgres, Neo4j, the worker, or inference is degraded, `/health` returns 503.
- **Apply changes by default.** Dry-run is the default. Live execution requires `EXECUTION_ENABLED` and the device named in `EXECUTION_DEVICES`.
- **Trust alert text blindly.** Alerts are sanitized and flagged; the agent still reads policy from the device, not from the alert.

---

## Quick start for a new user

```bash
# 1. Start the stack
cp .env.example .env   # edit secrets and bootstrap admin
docker compose up -d --build

# 2. Sign in
open http://localhost:3000/login

# 3. Trigger a test incident (as operator)
ZERONODE_PASSWORD='your-password' ./scripts/trigger_golden_alert.sh

# 4. Review and approve
open http://localhost:3000/incidents/INC-1001
```

For a scripted walkthrough without waiting on the live model:

```bash
python scripts/golden_path.py
```

---

## Related docs

- [how-it-works.md](how-it-works.md) — technical walkthrough
- [architecture.md](architecture.md) — product thesis and design pillars
- [runbooks/deploy.md](runbooks/deploy.md) — production deployment
- [runbooks/on-call.md](runbooks/on-call.md) — incident response when ZeroNode itself is unhealthy
- [roadmap.md](roadmap.md) — what is not built yet (e.g. production hardware validation)
