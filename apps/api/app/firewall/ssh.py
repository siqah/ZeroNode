"""Read-only SSH transport shared by the device backends.

The only guarantee that matters here is the one enforced in `_send`: a command
that is not a `show` never reaches a device. Netmiko's own session setup sends
`terminal pager 0` (ASA) or `terminal length 0` (IOS) to stop paging; those are
session-scoped and change no configuration, and they are the only non-`show`
commands that ever go over the wire.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Either the credential itself, or something that fetches it when needed.
Credential = str | Callable[[], str]


class ReadOnlyViolation(RuntimeError):
    """Raised if anything ever tries to send a non-`show` command."""


class SshDevice:
    """A reused SSH session with a read-only command guard."""

    device_type = "cisco_ios"

    def __init__(
        self,
        host: str,
        username: str,
        password: Credential = "",
        *,
        device_id: str = "FW_Edge",
        port: int = 22,
        timeout: int = 20,
        secret: Credential = "",
    ) -> None:
        self.host = host
        self.username = username
        # Held as a callable when it comes from a secret manager, so no plaintext
        # sits on the object and a rotated credential is picked up on reconnect.
        self._password = password
        self._secret = secret
        self.device_id = device_id
        self.port = port
        self.timeout = timeout
        self._conn: Any = None

    @staticmethod
    def _value(credential: Credential) -> str:
        return credential() if callable(credential) else credential

    def _connect(self) -> Any:
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "netmiko is required for device backends; install the 'devices' extra"
            ) from exc

        secret = self._value(self._secret)
        conn = ConnectHandler(
            device_type=self.device_type,
            host=self.host,
            username=self.username,
            password=self._value(self._password),
            secret=secret or None,
            port=self.port,
            conn_timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            fast_cli=False,
        )
        if secret:
            conn.enable()
        return conn

    def _send(self, command: str) -> str:
        """One `show` command over a reused session, retried once on a dropped pipe."""
        if not command.strip().lower().startswith("show "):
            raise ReadOnlyViolation(f"refusing non-show command: {command!r}")

        last_error: Exception | None = None
        for attempt in (1, 2):
            try:
                if self._conn is None:
                    self._conn = self._connect()
                return self._conn.send_command(command, read_timeout=self.timeout)
            except ReadOnlyViolation:
                raise
            except Exception as exc:  # noqa: BLE001 - transport errors are retryable once
                last_error = exc
                self.close()
                logger.warning(
                    "%s: '%s' failed on attempt %d: %s", self.device_id, command, attempt, exc
                )
        raise RuntimeError(f"{self.device_id}: '{command}' failed: {last_error}") from last_error

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001 - closing a broken session is best effort
                pass
            self._conn = None
