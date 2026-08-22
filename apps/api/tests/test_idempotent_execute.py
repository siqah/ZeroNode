"""Idempotent device execution tests."""

from __future__ import annotations

from app.execute.base import APPLIED
from app.execute.idempotent import IdempotentDeviceExecutor
from tests.test_execute import FLOWS, FakeDevice, action


def test_apply_once_replays_cached_result():
    cached = {"mode": "device", "state": APPLIED, "lines": ["cached"], "steps": [], "verification": []}
    calls: list[tuple[str, str, dict]] = []

    def lookup(key: str):
        return cached if key == "op-1" else None

    def store(key: str, thread_id: str, payload: dict) -> None:
        calls.append((key, thread_id, payload))

    device = FakeDevice()
    executor = IdempotentDeviceExecutor(
        device,
        lambda _name: device,
        devices={"FW_Edge"},
        lookup=lookup,
        store=store,
    )
    result = executor.apply_once([action()], FLOWS, operation_key="op-1", thread_id="INC-1")

    assert result.state == APPLIED
    assert result.lines == ["cached"]
    assert device.sent == []
    assert calls == []


def test_apply_once_stores_successful_execution():
    stored: dict[str, dict] = {}

    def store(key: str, _thread_id: str, payload: dict) -> None:
        stored[key] = payload

    device = FakeDevice()
    executor = IdempotentDeviceExecutor(
        device,
        lambda _name: device,
        devices={"FW_Edge"},
        store=store,
    )
    result = executor.apply_once([action()], FLOWS, operation_key="op-2", thread_id="INC-2")

    assert result.state == APPLIED
    assert "op-2" in stored


def test_apply_once_skips_already_landed_rule():
    device = FakeDevice()
    from app.firewall.policy import AclRule

    device.rules.append(
        AclRule(
            line=39,
            action="permit",
            proto="tcp",
            src="10.10.1.10",
            dst="10.20.1.50",
            port=443,
            rule_id="ACL-DMZ-99",
        )
    )
    executor = IdempotentDeviceExecutor(
        device,
        lambda _name: device,
        devices={"FW_Edge"},
    )
    result = executor.apply_once([action()], FLOWS, operation_key="op-3", thread_id="INC-3")

    assert result.state == APPLIED
    assert device.sent == []
    assert any("skipped" in step.output for step in result.steps)
