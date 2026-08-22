"""The approval endpoint answers to the change window, and says so."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.audit.anchor import NullAnchorSink
from app.audit.keys import KeySet
from app.audit.ledger import Signer
from app.auth.models import Role
from app.routers.incidents import router as incidents_router
from app.schedule import ChangeSchedule
from tests.test_api_rbac import SECRET, StubGraph, auth

# A freeze covering the whole of the test's "now", whenever that is.
ALWAYS_FROZEN = ChangeSchedule(freezes="2000-01-01..2999-12-31", timezone="UTC")
ALWAYS_OPEN = ChangeSchedule()


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(incidents_router)
    app.state.graph = StubGraph()
    app.state.pool = None
    app.state.memory_incidents = {}
    app.state.auth_enabled = True
    app.state.jwt_secret = SECRET
    app.state.jwt_ttl_minutes = 60
    app.state.service_token = "service-token-value"
    app.state.mfa_required_for_approvers = True
    app.state.keyset = KeySet(Signer(Signer.generate_seed()))
    app.state.anchor_sink = NullAnchorSink()
    app.state.schedule = ALWAYS_FROZEN
    from app.jobs.dispatcher import InMemoryDispatcher

    app.state.dispatcher = InMemoryDispatcher()
    with TestClient(app) as test_client:
        yield test_client


def approve(client, body: dict, role: Role = Role.APPROVER):
    return client.post(
        "/api/v1/incidents/INC-1/resume",
        json=body,
        headers=auth(role, subject="alice@example.com"),
    )


def test_an_approval_during_a_freeze_is_blocked(client):
    response = approve(client, {"decision": "approve"})
    assert response.status_code == 409
    assert "freeze" in response.json()["detail"]
    assert client.app.state.graph.invocations == []


def test_a_rejection_is_never_blocked(client):
    """Declining a change is always safe, so the window does not apply to it."""
    response = approve(client, {"decision": "reject", "feedback": "wrong subnet"})
    # Past the window, and refused only because there is no ledger in this test.
    assert response.status_code == 503


def test_an_approver_cannot_override_the_window(client):
    response = approve(
        client,
        {
            "decision": "approve",
            "override_window": True,
            "override_reason": "sev1 outage, payments down",
        },
    )
    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


def test_an_admin_override_needs_a_written_reason(client):
    response = approve(
        client, {"decision": "approve", "override_window": True, "override_reason": "urgent"}, Role.ADMIN
    )
    assert response.status_code == 422
    assert "reason" in response.json()["detail"]


def test_an_admin_with_a_reason_gets_through(client):
    response = approve(
        client,
        {
            "decision": "approve",
            "override_window": True,
            "override_reason": "sev1 outage, payments down, CAB chair notified",
        },
        Role.ADMIN,
    )
    # Through the window gate; stopped later only by the missing ledger.
    assert response.status_code == 503


def test_an_open_window_needs_no_override(client):
    client.app.state.schedule = ALWAYS_OPEN
    assert approve(client, {"decision": "approve"}).status_code == 503


def test_the_status_endpoint_shows_the_window_before_anyone_clicks(client):
    body = client.get(
        "/api/v1/incidents/INC-1/status", headers=auth(Role.VIEWER)
    ).json()
    assert body["change_window"]["open"] is False
    assert "freeze" in body["change_window"]["reason"]
    assert body["change_window"]["next_open"] == "3000-01-01"
