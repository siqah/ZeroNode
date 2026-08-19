"""Startup refuses to degrade quietly, and device credentials must be managed."""

import asyncio

import pytest

from app.firewall.devices import make_device_firewall
from app.main import make_topology, open_pool
from app.secretref import SecretResolver


class Unreachable:
    """A topology backend that fails the way an unreachable Neo4j does."""

    def __init__(self, *_args, **_kwargs):
        raise RuntimeError("connection refused")


@pytest.fixture
def broken_neo4j(monkeypatch):
    import app.store.neo4j_store as neo4j_store

    monkeypatch.setattr(neo4j_store, "Neo4jTopology", Unreachable)


def test_strict_mode_refuses_to_start_without_the_real_topology(broken_neo4j):
    with pytest.raises(RuntimeError, match="describes the lab, not your network"):
        make_topology(strict=True, resolver=SecretResolver())


def test_relaxed_mode_degrades_but_says_so(broken_neo4j):
    store, degradation = make_topology(strict=False, resolver=SecretResolver())
    assert store.__class__.__name__ == "InMemoryTopology"
    assert "in-memory lab fixture" in degradation


UNREACHABLE = "postgresql://nobody@127.0.0.1:1/none?connect_timeout=1"


def test_strict_mode_refuses_to_start_without_postgres(monkeypatch):
    monkeypatch.setattr("app.config.settings.database_url", UNREACHABLE)
    with pytest.raises(RuntimeError, match="nothing is durable"):
        asyncio.run(open_pool(strict=True, timeout=2))


def test_relaxed_mode_reports_the_loss_of_durability(monkeypatch):
    monkeypatch.setattr("app.config.settings.database_url", UNREACHABLE)
    pool, degradation = asyncio.run(open_pool(strict=False, timeout=2))
    assert pool is None
    assert "lost on restart" in degradation


def test_an_inline_device_password_is_refused(monkeypatch):
    monkeypatch.setattr("app.config.settings.firewall_host", "192.0.2.10")
    monkeypatch.setattr("app.config.settings.firewall_password", "hunter2")
    monkeypatch.setattr("app.config.settings.require_managed_secrets", True)

    with pytest.raises(RuntimeError, match="inline value"):
        make_device_firewall("cisco_asa")


def test_a_managed_device_password_is_accepted_and_resolved_lazily(monkeypatch, tmp_path):
    path = tmp_path / "asa_password"
    path.write_text("from-the-secret-store")
    monkeypatch.setattr("app.config.settings.firewall_host", "192.0.2.10")
    monkeypatch.setattr("app.config.settings.firewall_password", f"file:{path}")
    monkeypatch.setattr("app.config.settings.secret_cache_seconds", 0)

    device = make_device_firewall("cisco_asa")
    # Nothing on the object is the password itself.
    assert callable(device._password)
    assert device._value(device._password) == "from-the-secret-store"

    path.write_text("rotated")
    assert device._value(device._password) == "rotated"


def test_an_interactive_password_bypasses_the_requirement(monkeypatch):
    """The probe prompts for a password; that is the one safe inline case."""
    monkeypatch.setattr("app.config.settings.firewall_host", "192.0.2.10")
    monkeypatch.setattr("app.config.settings.require_managed_secrets", True)

    device = make_device_firewall("cisco_ios", password="typed-at-the-prompt")
    assert device._value(device._password) == "typed-at-the-prompt"


def test_a_missing_device_password_fails_loudly(monkeypatch):
    monkeypatch.setattr("app.config.settings.firewall_host", "192.0.2.10")
    monkeypatch.setattr("app.config.settings.firewall_password", "")
    monkeypatch.setattr("app.config.settings.require_managed_secrets", True)

    with pytest.raises(RuntimeError, match="FIREWALL_PASSWORD is unset"):
        make_device_firewall("cisco_asa")
