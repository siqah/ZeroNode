"""Tests for /health topology freshness degradation."""

from __future__ import annotations

import pytest
from starlette.responses import Response

from app.config import settings


@pytest.mark.asyncio
async def test_health_reports_missing_topology_metadata(monkeypatch):
    from app.firewall.mock import MockFirewall
    from app.main import app, health

    monkeypatch.setattr(settings, "netbox_url", "http://netbox.example")
    monkeypatch.setattr(settings, "netbox_token", "token")
    monkeypatch.setattr(settings, "topology_stale_seconds", 3600.0)
    monkeypatch.setattr("app.main._inference_status", lambda: (True, "ok"))

    app.state.degradations = []
    app.state.topology_freshness = None
    app.state.topology = object()
    app.state.dispatcher = None
    app.state.circuit = None
    app.state.metrics = None
    app.state.firewall = MockFirewall()
    app.state.executor = None
    app.state.tickets = None
    app.state.notifier = None

    response = Response()
    body = await health(response)

    assert response.status_code == 503
    assert any(
        "NetBox configured but graph has no ingest metadata" in item
        for item in body["degradations"]
    )


@pytest.mark.asyncio
async def test_health_reports_stale_topology(monkeypatch):
    from app.firewall.mock import MockFirewall
    from app.main import app, health

    monkeypatch.setattr(settings, "netbox_url", "")
    monkeypatch.setattr(settings, "netbox_token", "")
    monkeypatch.setattr(settings, "topology_stale_seconds", 3600.0)
    monkeypatch.setattr("app.main._inference_status", lambda: (True, "ok"))

    class StaleTopology:
        def freshness(self):
            return {"source": "netbox", "ingested_at": "2020-01-01T00:00:00Z"}

        def age_seconds(self):
            return 7200.0

    app.state.degradations = []
    app.state.topology_freshness = None
    app.state.topology = StaleTopology()
    app.state.dispatcher = None
    app.state.circuit = None
    app.state.metrics = None
    app.state.firewall = MockFirewall()
    app.state.executor = None
    app.state.tickets = None
    app.state.notifier = None

    response = Response()
    body = await health(response)

    assert response.status_code == 503
    assert any("topology: stale" in item for item in body["degradations"])


@pytest.mark.asyncio
async def test_health_reports_missing_worker_heartbeat(monkeypatch):
    from app.firewall.mock import MockFirewall
    from app.main import app, health

    monkeypatch.setattr("app.main._inference_status", lambda: (True, "ok"))

    class QueueDispatcher:
        async def health(self, stale_after_seconds: int = 120):
            return {
                "backend": "postgres",
                "live_workers": 0,
                "depth": 0,
                "capacity": 10,
                "saturated": False,
            }

    app.state.degradations = []
    app.state.topology_freshness = {"source": "seed"}
    app.state.topology = object()
    app.state.dispatcher = QueueDispatcher()
    app.state.circuit = None
    app.state.metrics = None
    app.state.firewall = MockFirewall()
    app.state.executor = None
    app.state.tickets = None
    app.state.notifier = None

    response = Response()
    body = await health(response)

    assert response.status_code == 503
    assert any("worker: no live investigation worker heartbeat" in item for item in body["degradations"])


@pytest.mark.asyncio
async def test_health_reports_queue_saturation(monkeypatch):
    from app.firewall.mock import MockFirewall
    from app.main import app, health

    monkeypatch.setattr("app.main._inference_status", lambda: (True, "ok"))

    class SaturatedDispatcher:
        async def health(self, stale_after_seconds: int = 120):
            return {
                "backend": "postgres",
                "live_workers": 1,
                "depth": 10,
                "capacity": 10,
                "saturated": True,
            }

    app.state.degradations = []
    app.state.topology_freshness = {"source": "seed"}
    app.state.topology = object()
    app.state.dispatcher = SaturatedDispatcher()
    app.state.circuit = None
    app.state.metrics = None
    app.state.firewall = MockFirewall()
    app.state.executor = None
    app.state.tickets = None
    app.state.notifier = None

    response = Response()
    body = await health(response)

    assert response.status_code == 503
    assert any("queue: saturated" in item for item in body["degradations"])
