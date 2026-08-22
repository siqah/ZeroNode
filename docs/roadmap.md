# Roadmap to production

Phases 1–6 in [how-it-works.md](how-it-works.md) are done in code and lab: auth, MFA and RBAC;
the signed ledger; read-only device adapters; secret references; change windows; simulation with
verified rollbacks; dry-run-default execution with automatic reversal; durable jobs; budgets,
metrics and backups; the eval corpus and CI gates; NetBox ingest; load, soak and backup drills;
runbooks and deploy pins. The definition of done for v1 is met everywhere except its third
clause: nothing here has executed against hardware a customer owns.

That clause is the axis of this document. The safety core is built; what remains between this
repository and a production deployment is **validation against real devices**, **enterprise
identity depth**, **verification breadth**, and **operational closure**. Phases below continue
the numbering in how-it-works.md and are ordered by what blocks a first pilot.

| Phase | Theme | Blocks |
| --- | --- | --- |
| 7 | Prove the write path on real hardware | First pilot |
| 8 | Authorisation scoping, then identity depth | Multi-customer pilot |
| 9 | Verification depth | Trust in the auto-rollback claim |
| 10 | Breadth: vendors, scenarios, topology | Generalisation beyond the golden incident |
| 11 | Operational closure | Running it as a service, not a demo |

Every item lands the way everything so far has: with tests, and with this document or
how-it-works.md updated to say *met in code*, *met in lab*, or *met on hardware* — never just
claimed.

---

## Phase 7 — Real-hardware validation (blocking)

The parsers have met captured output, an emulator and Containerlab SR Linux. None has met a
vendor appliance in a customer network. Everything else in this roadmap assumes the device
models are right; this phase is where that assumption gets tested, one read-only command at a
time.

| Item | Why |
| --- | --- |
| Run `python -m app.firewall.probe` against every target appliance class (ASA, IOS first) and record parser coverage per OS version | A parser claim backed by a probe exit code is evidence; one backed by fixtures is hope. Exit `0` means fully modelled, `1` lists exactly which lines need parser work, `2` means the transport itself failed |
| Turn probe results into parser tickets, not observations | An unmodelled line is safe (`INCONCLUSIVE`) but caps coverage. Each printed line is a spec for the regex that closes it |
| Decide startup-config persistence | Executed changes stay in running-config; a reload silently undoes a fix. Either add an operator-controlled save step after verified application, or record the exposure on the ticket and in the runbook so nobody discovers it during an outage |
| Publish a supported-device matrix (vendor, model, OS version, probe date, coverage) | "Cisco ASA is supported" is not a claim a network team can act on. A matrix with dates is |
| Dry-run-only soak period per site before `EXECUTION_DEVICES` names a real device | Enabling execution is a change-management act, not a config flip. The two-switch design already demands this separation; the process should say how long the soak lasts and what it measures |

**Done when:** a probe has run on every device class in pilot scope; one full
apply → read-back verify → rollback cycle has passed on real hardware per vendor; the
startup-config decision is implemented or explicitly signed off; the matrix exists and says what
is not covered.

---

## Phase 8 — Authorisation and identity depth (blocking for multi-customer pilots)

The security model is built around one privileged action and it shows: four ordered roles, no
per-object scoping, sessions that cannot be revoked, local accounts only. Adequate for one team
proving the loop; inadequate the moment two customers share an instance. This phase splits in
two on purpose. The scoping half is small, independent of identity-provider work, and is the
difference between a demo and something an MSP can sell — so it ships first.

### Phase 8a — Structural scoping

| Item | Why |
| --- | --- |
| Bind the execution target to the incident, structurally | Today the executor sends configuration to whatever host the backend was constructed with (`FIREWALL_HOST`, `app/firewall/devices.py`), and the guard compares the proposal's device *label* against `EXECUTION_DEVICES` strings (`app/execute/guard.py`). Nothing ties either to the incident's site or customer: a mistyped environment variable points a customer A investigation at customer B's firewall, and the simulation passes — because it simulates against the policy that same backend returns. A device registry keyed by `(site, device_id)`, holding host, backend and credentials, makes the target derivable from the incident's own evidence and turns the guard's allowlist check into registry membership |
| Approver scopes by site and device | Any approver can approve any change anywhere today. `site` already exists on incidents and scopes topology queries (`app/store/site_scoped.py`); extend the same boundary to the resume decision in `app/auth/deps.py`, refusing with a reason rather than a bare 403 |
| Second-person rule for high-blast-radius changes | Reuse the simulator's own scope arithmetic: a permit covering more host pairs than a configured threshold requires a second, distinct approver. The number the scope finding computes is exactly the number the rule needs |

One boundary should be stated plainly while this lands: multi-tenancy is currently **query-level,
not storage-level**. All sites share one Neo4j graph and one Postgres; `site` filters rows and
scopes tool queries. That is correct within one trusted deployment, and "customer A can never
read customer B's data" remains a property of running separate instances per customer until
row-level isolation exists. Say so in the pitch before someone assumes otherwise.

### Phase 8b — Identity depth

| Item | Why |
| --- | --- |
| OIDC single sign-on with group-to-role mapping | Onboarding and offboarding are manual today, so there is no central place to revoke access — the control auditors ask about first. Keep the local bootstrap admin as break-glass, sealed into the ledger like any other actor |
| Revocable sessions | A JWT is valid until `exp`, so a stolen laptop is a valid approver until the clock runs out. Check a server-side session record or per-user token version at request time; add an admin revoke and logout-everywhere |
| Per-client service tokens with rotation | One static `SERVICE_TOKEN` shared by every alerting system cannot be rotated without breaking all of them, and cannot be attributed per caller |

**Done when (8a):** the device an approved change reaches is derived from the incident's own
evidence rather than process-wide environment state; an approver outside a site's scope is
refused with a reason; a wide change demonstrably needs two people.
**Done when (8b):** identities come from the directory, and a session can be killed before its
`exp`.

---

## Phase 9 — Verification depth

Post-change verification answers "did the device take the rule", not "did the outage end". Both
matter; only the first is automated. This phase widens what the system can prove on its own, so
human attention goes where judgement is actually required.

| Item | Why |
| --- | --- |
| Service-level verification as an optional post-check | After the policy check passes, optionally run a synthetic flow (a TCP connect from the source side, via an agent or a probe host) and record the result in the execution outcome and the ledger. Hit counters cannot stand in for this — they need traffic to move |
| Incremental NAT resolution | Translated flows currently return `INCONCLUSIVE` and fall back to a human, every time. Resolve static, unambiguous translations automatically and keep the fallback for dynamic/PAT ambiguity; measure the residual rate |
| Whole-policy rollback proof | The reversal is verified as an inverse for the one flow. Compare the full pre/post policy snapshots instead, so collateral line changes are detected and reported rather than out of scope |
| Track INCONCLUSIVE and fallback rates as health metrics | The honest number for "how much does this system still need a human for" should be visible in `/metrics`, not discovered anecdotally |

**Done when:** an applied change can carry evidence the *service* recovered, NAT no longer forces
a human for the common static case, and a rollback that disturbs anything else is caught before
it is called clean.

---

## Phase 10 — Breadth: vendors, scenarios, topology

One scenario, five seeded devices and two production-grade parsers prove the workflow, not the
product. This phase generalises along the three axes the lab deliberately froze.

| Item | Why |
| --- | --- |
| Parsers for NX-OS, Palo Alto and Fortinet, each onboarded probe-first | Every new vendor starts with `probe` on a real device, then parser work against its output — the Phase 7 discipline applied at build time, so "supported" never precedes evidence |
| Routing/BGP and MTU specialists | The eval corpus already contains `mtu_blackhole` and `asymmetric_return_path` incidents scored as unmet; the supervisor's delegate pattern exists, the specialist nodes do not |
| Promote NetBox ingest from built-unrun to the default topology path | L3 answered "does the graph survive an inventory that does not cooperate" in principle, never in practice. Run it continuously against a real NetBox, with freshness degradation already surfaced by `/health` |
| LLDP/SNMP discovery feeding the same normaliser | NetBox is a source of truth, not a source of reality. Cabling facts from the network itself close the gap between what is documented and what is plugged in |

**Done when:** a second vendor passes its full lab ladder, a non-ACL scenario reaches the gate
and passes the corpus scorers, and topology freshness reflects an automated pipeline rather than
a seed script.

---

## Phase 11 — Operational closure

The loop is open on the network side and closed on the process side only in one direction.
Tickets go out and nothing comes back; webhooks fail quietly; approvals raised during a freeze
wait for a person to notice. None of this threatens safety — all of it erodes trust in daily
use.

| Item | Why |
| --- | --- |
| Bidirectional ticketing: poll inbound state and reconcile | Closing INC-1001 in ServiceNow does not close it here. Poll ticket state, reconcile both directions idempotently, and record the reconciliation in the ledger like every other decision |
| Reliable outbound delivery | Ticket and notification webhooks are fire-and-log today. Queue deliveries in Postgres with retries and dead-letter visibility, reusing the job infrastructure that already exists |
| Schedule approvals to the next window | Change windows are enforced at the gate only, so an incident raised during a freeze strands. With override declined, enqueue the resume for the next opening — the durable job store makes this a scheduling problem, not a new state machine |
| GPU inference profile | Self-hosted vLLM via `INFERENCE_BACKEND=vllm` is implemented; a sized vLLM deployment in Compose prod does not ship yet. Publish latency/concurrency numbers for your chosen model/backend and wire `scripts/eval_live.py` into the release process as the gate it was built to be |
| Secret-reference support for `DATABASE_URL` | Every credential can be a `file:`/`env:`/`vault:`/`exec:` reference except the Postgres connection string. Accept a reference or a URL built from parts, so the last inline password goes away |
| A stated policy for flagged alerts | Prompt injection remains mitigation, by design. What is missing is procedure: alerts with `alert_flags` route to a named review path, flag counts appear in metrics, and the runbook says who looks and when |

**Done when:** a ticket closed upstream resolves the incident here, no webhook loss is silent,
an approval raised on Friday night executes itself in Tuesday's window, and the release gate
runs the live-model eval without a human remembering to.

---

## Definition of done for a production pilot

1. Parser coverage on every target device is proven by a dated probe run. **Requires Phase 7.**
2. Approvers are bound to sites and devices by structure, not convention; identities come from
   the directory and sessions can be revoked. **Requires Phase 8a for a multi-customer pilot,
   8b for production.**
3. Applied changes carry policy-level evidence always, service-level evidence where enabled.
   **Requires Phase 7 + 9.**
4. Auto-rollback is trusted because reversals are proven against whole policies, not flows.
   **Requires Phase 9.**
5. At least two vendors and two scenario classes pass the corpus. **Requires Phase 10.**
6. The operational loop closes in both directions without silent loss. **Requires Phase 11.**

Items 1–3 gate a pilot. Items 4–6 gate calling it production.
