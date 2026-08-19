"""End-to-end checks that the real routers enforce roles."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.audit.anchor import NullAnchorSink
from app.audit.keys import KeySet
from app.audit.ledger import Signer
from app.auth.models import Principal, Role
from app.auth.sessions import CSRF_HEADER, SESSION_COOKIE, new_csrf_token
from app.auth.tokens import issue_token
from app.routers.incidents import router as incidents_router

SECRET = "test-secret-value"


class Snapshot:
    def __init__(self, values: dict, nxt: tuple) -> None:
        self.values = values
        self.next = nxt


class StubGraph:
    """Stands in for the compiled graph, paused at the approval gate."""

    def __init__(self) -> None:
        self.invocations: list = []

    async def aget_state(self, _config):
        return Snapshot(
            {
                "pending_actions": [
                    {"device": "FW_Edge", "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"}
                ],
                "verification": ["PASS flow restored"],
                "denied_flows": [],
                "findings_summary": "",
                "topology_context": "Web_App -> FW_Edge -> DB_Primary",
            },
            ("execute_change",),
        )

    async def ainvoke(self, command, config):
        self.invocations.append((command, config))


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
    with TestClient(app) as test_client:
        yield test_client


def auth(
    role: Role, kind: str = "user", subject: str = "user@example.com", mfa: bool = True
) -> dict:
    token, _ = issue_token(Principal(subject, role, kind), SECRET, 60, mfa=mfa)
    return {"Authorization": f"Bearer {token}"}


def session(role: Role, subject: str = "user@example.com", mfa: bool = True) -> tuple[dict, dict]:
    """A browser-style session: httpOnly cookie plus the CSRF value to echo."""
    csrf = new_csrf_token()
    token, _ = issue_token(Principal(subject, role), SECRET, 60, csrf=csrf, mfa=mfa)
    return {SESSION_COOKIE: token}, {CSRF_HEADER: csrf}


def test_unauthenticated_requests_are_rejected(client):
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.post("/api/v1/incidents/INC-1/resume", json={"decision": "approve"}).status_code == 401
    assert client.post(
        "/api/v1/incidents/trigger", json={"ticket_id": "INC-1", "description": "x"}
    ).status_code == 401


def test_garbage_token_is_rejected(client):
    response = client.get("/api/v1/incidents", headers={"Authorization": "Bearer nonsense"})
    assert response.status_code == 401


def test_viewer_can_read_but_not_trigger(client):
    assert client.get("/api/v1/incidents", headers=auth(Role.VIEWER)).status_code == 200
    response = client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-1", "description": "x"},
        headers=auth(Role.VIEWER),
    )
    assert response.status_code == 403
    assert "operator" in response.json()["detail"]


def test_operator_can_trigger_but_not_approve(client):
    triggered = client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-1", "description": "x"},
        headers=auth(Role.OPERATOR),
    )
    assert triggered.status_code == 200

    response = client.post(
        "/api/v1/incidents/INC-1/resume",
        json={"decision": "approve"},
        headers=auth(Role.OPERATOR),
    )
    assert response.status_code == 403


def test_a_machine_credential_can_never_approve(client):
    """The service token opens incidents; an approval must belong to a person."""
    triggered = client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-2", "description": "x"},
        headers={"Authorization": "Bearer service-token-value"},
    )
    assert triggered.status_code == 200

    # Even carrying the approver role, a machine principal is refused.
    response = client.post(
        "/api/v1/incidents/INC-2/resume",
        json={"decision": "approve"},
        headers=auth(Role.APPROVER, kind="service", subject="robot"),
    )
    assert response.status_code == 403
    assert "human" in response.json()["detail"]


def test_approval_is_refused_when_it_cannot_be_recorded(client):
    """No ledger, no approval: an unrecorded decision binds nobody."""
    response = client.post(
        "/api/v1/incidents/INC-3/resume",
        json={"decision": "approve"},
        headers=auth(Role.APPROVER, subject="alice@example.com"),
    )
    assert response.status_code == 503
    assert "unrecorded" in response.json()["detail"]
    assert client.app.state.graph.invocations == []


def test_disabling_auth_opens_everything(client):
    """The escape hatch exists, and this test documents exactly how wide it is."""
    client.app.state.auth_enabled = False
    assert client.get("/api/v1/incidents").status_code == 200
    assert client.post(
        "/api/v1/incidents/INC-4/resume", json={"decision": "approve"}
    ).status_code == 200


def test_an_approver_without_a_second_factor_is_refused(client):
    response = client.post(
        "/api/v1/incidents/INC-5/resume",
        json={"decision": "approve"},
        headers=auth(Role.APPROVER, subject="alice@example.com", mfa=False),
    )
    assert response.status_code == 403
    assert "second factor" in response.json()["detail"]


def test_the_mfa_requirement_can_be_turned_off_deliberately(client):
    client.app.state.mfa_required_for_approvers = False
    response = client.post(
        "/api/v1/incidents/INC-5/resume",
        json={"decision": "approve"},
        headers=auth(Role.APPROVER, subject="alice@example.com", mfa=False),
    )
    # Past the MFA gate, and refused only because there is no ledger to write to.
    assert response.status_code == 503


def test_a_cookie_session_works_when_it_carries_the_csrf_header(client):
    cookies, headers = session(Role.OPERATOR)
    response = client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-6", "description": "x"},
        cookies=cookies,
        headers=headers,
    )
    assert response.status_code == 200


def test_a_cookie_alone_cannot_change_anything(client):
    """What another site can make the browser do: send the cookie, not the header."""
    cookies, _ = session(Role.OPERATOR)
    response = client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-7", "description": "x"},
        cookies=cookies,
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_a_mismatched_csrf_token_is_rejected(client):
    cookies, _ = session(Role.OPERATOR)
    response = client.post(
        "/api/v1/incidents/trigger",
        json={"ticket_id": "INC-8", "description": "x"},
        cookies=cookies,
        headers={CSRF_HEADER: new_csrf_token()},
    )
    assert response.status_code == 403


def test_reads_do_not_need_the_csrf_header(client):
    cookies, _ = session(Role.VIEWER)
    assert client.get("/api/v1/incidents", cookies=cookies).status_code == 200
