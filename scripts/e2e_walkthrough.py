#!/usr/bin/env python
"""Drive one incident end to end against a running stack.

    python scripts/e2e_walkthrough.py

Logs in, enrols a second factor if the account has none, triggers the cross-zone
alert, waits for the graph to pause for approval, approves it, and reports what
the device layer did and what the audit ledger recorded. Everything it does is
what the dashboard does, so a failure here is a failure a user would hit.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))

from app.auth.totp import code_at  # noqa: E402


class Client:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.csrf = ""

    def call(self, path: str, data=None, method: str | None = None):
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=body,
            method=method or ("POST" if data is not None else "GET"),
        )
        request.add_header("Content-Type", "application/json")
        if self.csrf:
            request.add_header("x-csrf-token", self.csrf)
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")


def step(text: str) -> None:
    print(f"\n=== {text}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument(
        "--email", default=os.environ.get("ZERONODE_EMAIL", "admin@example.com")
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ZERONODE_PASSWORD", ""),
        help="Prefer ZERONODE_PASSWORD so the password does not enter shell history.",
    )
    parser.add_argument(
        "--totp",
        default=os.environ.get("ZERONODE_TOTP", ""),
        help="Current TOTP code when MFA is already enrolled (or ZERONODE_TOTP).",
    )
    parser.add_argument("--decision", default="approve", choices=["approve", "reject"])
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    if not args.password:
        parser.error("set ZERONODE_PASSWORD or pass --password")

    client = Client(args.api)

    step("Health")
    status, health = client.call("/health")
    print(f"  {status} ok={health.get('ok')} degradations={health.get('degradations')}")
    for name, value in (health.get("components") or {}).items():
        print(f"    {name}: {value}")

    step("Login")
    login_payload = {"email": args.email, "password": args.password}
    if args.totp:
        login_payload["totp_code"] = args.totp
    status, body = client.call("/api/v1/auth/login", login_payload)
    if status != 200:
        print(f"  failed: {status} {body}")
        if status == 401 and body.get("detail") == "mfa_required":
            print("  Hint: pass --totp / ZERONODE_TOTP for an enrolled account.")
        return 1
    client.csrf = body.get("csrf_token", "")
    print(f"  {body['email']} as {body['role']}, mfa={body.get('mfa')}")

    status, me = client.call("/api/v1/auth/me")
    if not me.get("can_approve"):
        step("Enrolling a second factor (approvers must have one)")
        status, enrol = client.call("/api/v1/auth/mfa/enrol", {})
        if status != 200:
            print(f"  enrol failed: {status} {enrol}")
            return 1
        secret = enrol["secret"]
        status, activated = client.call(
            "/api/v1/auth/mfa/activate", {"totp_code": code_at(secret)}
        )
        print(f"  {status} {activated}")
        status, body = client.call(
            "/api/v1/auth/login",
            {
                "email": args.email,
                "password": args.password,
                "totp_code": code_at(secret),
            },
        )
        client.csrf = body.get("csrf_token", client.csrf)
        status, me = client.call("/api/v1/auth/me")
        print(f"  re-login {status}, can_approve={me.get('can_approve')}")

    step("Triggering the cross-zone alert")
    status, incident = client.call(
        "/api/v1/incidents/trigger",
        {
            "ticket_id": f"E2E-{int(time.time())}",
            "description": (
                "Web_App cannot reach DB_Primary on port 443. Users report "
                "checkout failures since 14:20."
            ),
            "severity": "high",
        },
    )
    if status not in (200, 201, 202):
        print(f"  failed: {status} {incident}")
        return 1
    thread_id = incident["thread_id"]
    print(f"  {thread_id}")

    step("Waiting for the agent to pause for approval")
    deadline = time.time() + args.timeout
    state = {}
    seen = 0
    while time.time() < deadline:
        status, state = client.call(f"/api/v1/incidents/{thread_id}/status")
        trace = state.get("reasoning_trace") or []
        for line in trace[seen:]:
            print(f"  · {str(line)[:150]}")
        seen = len(trace)

        if state.get("awaiting_approval") or state.get("status") == "awaiting_approval":
            break
        if state.get("status") in ("resolved", "failed"):
            break
        time.sleep(5)

    print(f"\n  status={state.get('status')} awaiting={state.get('awaiting_approval')}")
    for action in state.get("proposed_actions") or []:
        print(f"  proposed: {json.dumps(action)[:300]}")
    for line in state.get("verification") or []:
        print(f"  verify: {line}")

    if not (state.get("awaiting_approval") or state.get("status") == "awaiting_approval"):
        print("\n  Never reached the approval gate; nothing to approve.")
        return 1

    step(f"Submitting decision: {args.decision}")
    payload = {"decision": args.decision, "feedback": "End-to-end walkthrough."}
    status, decision = client.call(
        f"/api/v1/incidents/{thread_id}/resume", payload
    )
    print(f"  {status} {json.dumps(decision)[:300]}")

    step("Waiting for the run to finish")
    deadline = time.time() + 300
    while time.time() < deadline:
        status, state = client.call(f"/api/v1/incidents/{thread_id}/status")
        if state.get("status") in ("resolved", "failed") and not state.get("awaiting_approval"):
            break
        time.sleep(5)

    print(f"  status={state.get('status')}")
    print(f"  summary: {str(state.get('findings_summary'))[:400]}")
    execution = state.get("execution")
    if execution:
        print(f"  execution mode={execution.get('mode')} state={execution.get('state')}")
        for line in execution.get("lines") or []:
            print(f"    {line}")
        for line in execution.get("verification") or []:
            print(f"    {line}")

    step("Audit ledger")
    status, verified = client.call("/api/v1/audit/verify")
    print(f"  verify: {status} {json.dumps(verified)[:300]}")
    status, approvals = client.call(f"/api/v1/audit/approvals?thread_id={thread_id}")
    for record in (approvals if isinstance(approvals, list) else approvals.get("records", [])):
        print(
            f"  {record.get('created_at')} {record.get('actor')} "
            f"{record.get('decision')} hash={str(record.get('hash'))[:16]}"
        )

    print(f"\nDashboard: http://localhost:3000/incidents/{thread_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
