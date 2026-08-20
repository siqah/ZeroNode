"""Execution of approved changes, dry-run unless deliberately enabled."""

from __future__ import annotations

import logging

from app.config import settings
from app.execute.base import (
    APPLIED,
    LOGGED,
    REFUSED,
    ROLLBACK_FAILED,
    ROLLED_BACK,
    ExecutionResult,
    ExecutionStep,
    Executor,
)
from app.execute.device import DeviceExecutor
from app.execute.dryrun import DryRunExecutor
from app.execute.session import ConfigSession, UnsafeCommand
from app.firewall.base import FirewallStore

logger = logging.getLogger(__name__)

__all__ = [
    "APPLIED",
    "LOGGED",
    "REFUSED",
    "ROLLBACK_FAILED",
    "ROLLED_BACK",
    "ConfigSession",
    "DeviceExecutor",
    "DryRunExecutor",
    "ExecutionResult",
    "ExecutionStep",
    "Executor",
    "UnsafeCommand",
    "make_executor",
]


def make_executor(firewall: FirewallStore) -> Executor:
    """Dry-run unless execution is enabled *and* devices are named for it.

    Two switches rather than one: turning the feature on is a deployment
    decision, choosing which devices it may touch is a change-management one,
    and conflating them is how a lab flag reaches production hardware.
    """
    if not settings.execution_enabled:
        return DryRunExecutor()

    devices = {name.strip() for name in settings.execution_devices.split(",") if name.strip()}
    if not devices:
        logger.warning(
            "EXECUTION_ENABLED is set but EXECUTION_DEVICES is empty, so every change "
            "stays a dry run. Name the devices execution may touch."
        )
        return DryRunExecutor()

    backend = (settings.firewall_backend or "mock").strip().lower()
    if backend == "mock":
        logger.error(
            "EXECUTION_ENABLED is set with FIREWALL_BACKEND=mock. There is no device to "
            "execute against, so changes stay dry runs."
        )
        return DryRunExecutor()

    from app.execute.factory import session_factory

    logger.warning(
        "LIVE EXECUTION IS ENABLED for %s. Approved changes will be written to hardware.",
        ", ".join(sorted(devices)),
    )
    return DeviceExecutor(
        firewall,
        session_factory(backend),
        devices=devices,
        auto_rollback=settings.execution_auto_rollback,
        platform=backend,
    )
