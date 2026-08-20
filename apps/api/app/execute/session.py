"""The only code in this repository that can change a device.

Everything else — every backend, every tool, the whole read path — goes through
`SshDevice`, which refuses anything that is not a `show`. That guarantee is not
relaxed for execution; a second, separate class exists instead, so "can this
touch configuration?" is answered by which class was constructed rather than by
reading a method for a flag.

It is constructed only by `DeviceExecutor`, only when `EXECUTION_ENABLED` is on,
and only for a device named in `EXECUTION_DEVICES`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.firewall.ssh import Credential, SshDevice

logger = logging.getLogger(__name__)

# Words that have no business in a policy change and every business in an
# outage. The command allowlist in `guard.py` is the real control; this is the
# backstop for anything that slips past it.
FORBIDDEN = (
    "reload",
    "erase",
    "format",
    "delete",
    "boot ",
    "shutdown",
    "clear config",
    "write erase",
    "copy ",
    "username",
    "aaa ",
    "crypto ",
)
SAFE_SRL_ACL_DELETE = re.compile(
    r"^delete / acl acl-filter [A-Za-z0-9_.:-]+ type ipv4 entry \d+$",
    re.IGNORECASE,
)


class UnsafeCommand(RuntimeError):
    """A command that will never be sent, whatever the configuration says."""


class ConfigSession(SshDevice):
    """A write-capable session, used for one change and then closed."""

    def __init__(
        self,
        host: str,
        username: str,
        password: Credential = "",
        *,
        device_type: str = "cisco_asa",
        device_id: str = "FW_Edge",
        port: int = 22,
        timeout: int = 30,
        secret: Credential = "",
    ) -> None:
        super().__init__(
            host,
            username,
            password,
            device_id=device_id,
            port=port,
            timeout=timeout,
            secret=secret,
        )
        self.device_type = device_type

    @staticmethod
    def screen(commands: list[str]) -> None:
        for command in commands:
            lowered = command.lower()
            for word in FORBIDDEN:
                if word in lowered:
                    if word == "delete" and SAFE_SRL_ACL_DELETE.fullmatch(
                        command.strip()
                    ):
                        continue
                    raise UnsafeCommand(f"refusing to send {command!r}: contains {word!r}")

    def send_config(self, commands: list[str]) -> str:
        """Push configuration lines and return the device's own transcript."""
        self.screen(commands)
        conn: Any = self._conn or self._connect()
        self._conn = conn
        logger.warning(
            "%s: sending %d configuration line(s) to a live device",
            self.device_id,
            len(commands),
        )
        output = conn.send_config_set(commands, read_timeout=self.timeout)
        if self.device_type == "nokia_srl":
            # SR Linux edits a private candidate. Without an explicit commit,
            # read-back correctly sees no change and every execution rolls back.
            output += conn.commit()
        return output

    def read(self, command: str) -> str:
        """Read back through the same guard the read path uses."""
        return self._send(command)
