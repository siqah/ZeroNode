"""Tickets and notifications: useful when they work, harmless when they do not."""

import asyncio
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.audit.anchor import NullAnchorSink
from app.audit.keys import KeySet
from app.audit.ledger import Signer
from app.auth.models import Role
from app.outbound.http import _safe, post_json
from app.outbound.notify import NullNotifier, WebhookNotifier, pending_approval_message
from app.outbound.tickets import NullTicketSink, WebhookTicketSink
from app.routers.incidents import router as incidents_router
from tests.test_api_rbac import SECRET, StubGraph, auth

ACTIONS = [
    {
        "device": "FW_Edge",
        "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443",
        "verified": True,
    }
]


class Recorder:
    """Stands in for both sinks; records instead of calling out."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def describe(self) -> str:
        return "recorder"

    async def send(self, text, context=None):
        self.events.append(("notify", text))

    async def opened(self, thread_id, description, severity):
        self.events.append(("opened", thread_id))

    async def commented(self, thread_id, text, context):
        self.events.append(("comment", text))

    async def closed(self, thread_id, summary):
        self.events.append(("closed", thread_id))


class ConfigurableGraph(StubGraph):
    """A stub that can stop somewhere different after a decision.

    Approving runs the graph to the end; rejecting sends the specialist back and
    stops at the same gate again. Both have to be expressible here, because the
    difference is exactly what the ticket and the notification key off.
    """

    next: tuple[str, ...] = ("execute_change",)
    next_after_resume: tuple[str, ...] = ("execute_change",)

    async def aget_state(self, config):
        snapshot = await super().aget_state(config)
        return type(snapshot)(snapshot.values, self.next)

    async def ainvoke(self, command, config):
        await super().ainvoke(command, config)
        self.next = self.next_after_resume


def settle(predicate, timeout: float = 2.0) -> bool:
    """Wait for the background resume task to do its work.

    The router resumes the graph off the request path on purpose, so everything
    that follows a decision happens after the response has already been sent.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(incidents_router)
    app.state.graph = ConfigurableGraph()
    app.state.pool = None
    app.state.memory_incidents = {}
    app.state.auth_enabled = True
    app.state.jwt_secret = SECRET
    app.state.jwt_ttl_minutes = 60
    app.state.service_token = "service-token-value"
    app.state.mfa_required_for_approvers = True
    app.state.keyset = KeySet(Signer(Signer.generate_seed()))
    app.state.anchor_sink = NullAnchorSink()
    app.state.tickets = Recorder()
    app.state.notifier = Recorder()
    from app.jobs.dispatcher import InMemoryDispatcher
    from app.jobs.runner import InvestigationRunner

    dispatcher = InMemoryDispatcher()
    app.state.dispatcher = dispatcher

    async def drain() -> None:
        runner = InvestigationRunner(app.state)
        while True:
            job = await dispatcher.claim("test-worker", lease_seconds=60)
            if job is None:
                return
            try:
                await runner.run_job(job)
                await dispatcher.complete(job.id)
            except Exception as exc:  # noqa: BLE001
                await dispatcher.fail(job, error=str(exc), retry_delay_seconds=0)

    app.state.drain_jobs = drain
    with TestClient(app) as test_client:
        yield test_client


def drain(client) -> None:
    asyncio.run(client.app.state.drain_jobs())


def test_the_pending_message_carries_what_a_decision_needs():
    text = pending_approval_message(
        "INC-1", ACTIONS, "https://zeronode.example", window_reason="", alert_flags=[]
    )
    assert "INC-1" in text
    assert "FW_Edge" in text
    assert "permit tcp host 10.10.1.10" in text
    assert "Simulation: passed" in text
    assert "https://zeronode.example/incidents/INC-1" in text


def test_an_unverified_proposal_says_so_in_the_message():
    actions = [{**ACTIONS[0], "verified": False}]
    text = pending_approval_message("INC-1", actions, "")
    assert "DID NOT PASS" in text


def test_a_closed_window_and_a_flagged_alert_reach_the_reader():
    text = pending_approval_message(
        "INC-1",
        ACTIONS,
        "",
        window_reason="a change freeze is in effect",
        alert_flags=["instruction override"],
    )
    assert "change freeze" in text
    assert "instruction override" in text


def test_triggering_an_incident_opens_a_ticket(client):
    client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-1", "description": "Web_App cannot reach DB_Primary"},
        headers=auth(Role.OPERATOR),
    )
    assert ("opened", "INC-1") in client.app.state.tickets.events


def test_a_decision_is_written_back_to_the_ticket(client):
    client.app.state.auth_enabled = False  # no ledger in this test; skip the 503
    client.post("/api/v1/incidents/INC-1/resume", json={"decision": "reject", "feedback": "too wide"})
    comments = [text for kind, text in client.app.state.tickets.events if kind == "comment"]
    assert any("rejected the proposed change" in text for text in comments)
    assert any("too wide" in text for text in comments)


def test_every_proposal_is_notified_not_just_the_first(client):
    """A rejection sends the specialist back, and the revised change stops at the
    same gate. Notifying only the first proposal trains people to ignore it."""
    client.app.state.auth_enabled = False

    client.post(
        "/api/v1/incidents/INC-1/resume", json={"decision": "reject", "feedback": "narrow it"}
    )
    drain(client)

    told = settle(lambda: any(kind == "notify" for kind, _ in client.app.state.notifier.events))
    assert told, "the re-proposal reached the gate with nobody told"


def test_a_finished_incident_closes_its_ticket(client):
    """Opening tickets and never closing them teaches people the queue is noise."""
    client.app.state.auth_enabled = False
    client.app.state.graph.next_after_resume = ()

    client.post("/api/v1/incidents/INC-1/resume", json={"decision": "approve"})
    drain(client)

    assert settle(lambda: any(kind == "closed" for kind, _ in client.app.state.tickets.events))


def test_a_dead_webhook_never_raises():
    """An outage in chat must not become an outage in the workflow."""
    assert asyncio.run(post_json("http://127.0.0.1:1/hook", {"text": "hello"})) is False


def test_transient_webhook_failures_are_retried(monkeypatch):
    calls = {"count": 0}

    class FakeResponse:
        status_code = 503

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, *_args, **_kwargs):
            calls["count"] += 1
            if calls["count"] < 3:
                return FakeResponse()
            ok = FakeResponse()
            ok.status_code = 200
            return ok

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FakeClient())

    assert asyncio.run(
        post_json(
            "https://hooks.example/hook",
            {"text": "hello"},
            max_retries=2,
            retry_backoff_seconds=0,
        )
    )
    assert calls["count"] == 3


def test_only_the_host_of_a_webhook_url_is_ever_logged():
    """A Slack webhook URL is itself a credential."""
    assert _safe("https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX") == "hooks.slack.com"


def test_the_null_sinks_describe_what_is_missing():
    assert "not recorded in a ticket system" in NullTicketSink().describe()
    assert "only visible in the dashboard" in NullNotifier().describe()


def test_the_webhook_sinks_describe_where_they_point():
    assert WebhookNotifier("https://hooks.slack.com/services/x").describe() == (
        "webhook to hooks.slack.com"
    )
    assert WebhookTicketSink("https://jira.example/rest/x").describe() == "webhook to jira.example"
