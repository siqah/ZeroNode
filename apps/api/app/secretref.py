"""Resolving credentials from somewhere other than the environment.

A device password in an environment variable is readable by anything that can
list the process environment, ends up in `docker inspect`, and rotates only with
a restart. This module keeps configuration pointing at *where* a secret lives
rather than holding the secret itself:

    FIREWALL_PASSWORD=file:/run/secrets/asa_password
    FIREWALL_PASSWORD=vault:secret/data/zeronode#asa_password
    FIREWALL_PASSWORD=exec:aws secretsmanager get-secret-value --secret-id asa

A bare value still works, so nothing breaks for local runs, but the API refuses
to talk to a real device with one unless that check is deliberately turned off.
Values are resolved late and cached briefly, so rotating a secret at the source
takes effect without a restart.
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMES = ("env", "file", "vault", "exec")


class SecretError(RuntimeError):
    """A secret reference could not be resolved. Never carries the value."""


def scheme_of(reference: str) -> str:
    head, separator, rest = (reference or "").partition(":")
    if separator and head.lower() in SCHEMES and rest:
        return head.lower()
    return "literal"


def is_managed(reference: str) -> bool:
    """Whether the value comes from a secret manager rather than being inline."""
    return scheme_of(reference) != "literal"


def describe(reference: str) -> str:
    """Safe for logs and health output: says where, never what."""
    scheme = scheme_of(reference)
    if scheme == "literal":
        return "inline value" if reference else "unset"
    _, _, rest = reference.partition(":")
    if scheme == "exec":
        return "exec:<command>"
    return f"{scheme}:{rest.split('#')[0]}"


@dataclass
class _Cached:
    value: str
    expires_at: float


class SecretResolver:
    def __init__(self, ttl_seconds: int = 300, vault_addr: str = "", vault_token: str = "") -> None:
        self.ttl = ttl_seconds
        self.vault_addr = vault_addr.rstrip("/")
        self.vault_token = vault_token
        self._cache: dict[str, _Cached] = {}

    def resolve(self, reference: str) -> str:
        if not is_managed(reference):
            return reference

        now = time.monotonic()
        cached = self._cache.get(reference)
        if cached and cached.expires_at > now:
            return cached.value

        scheme, _, rest = reference.partition(":")
        try:
            value = getattr(self, f"_from_{scheme.lower()}")(rest)
        except SecretError:
            raise
        except Exception as exc:  # noqa: BLE001 - providers fail in many ways
            raise SecretError(f"could not resolve {describe(reference)}: {exc}") from exc

        if not value:
            raise SecretError(f"{describe(reference)} resolved to an empty value")

        self._cache[reference] = _Cached(value, now + self.ttl)
        return value

    def getter(self, reference: str):
        """A callable resolving the secret at the moment it is needed.

        Passing this instead of a string keeps the plaintext out of long-lived
        objects and lets a rotated secret take effect on the next use.
        """
        return lambda: self.resolve(reference)

    def _from_env(self, name: str) -> str:
        value = os.environ.get(name.strip(), "")
        if not value:
            raise SecretError(f"environment variable {name.strip()} is unset")
        return value

    def _from_file(self, path: str) -> str:
        target = Path(path.strip())
        if not target.exists():
            raise SecretError(f"secret file {target} does not exist")
        return target.read_text(encoding="utf-8").strip()

    def _from_exec(self, command: str) -> str:
        completed = subprocess.run(  # noqa: S603 - the command is operator-supplied config
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise SecretError(f"command exited {completed.returncode}")
        return completed.stdout.strip()

    def _from_vault(self, spec: str) -> str:
        """`vault:secret/data/zeronode#field`, KV v2 over the HTTP API."""
        if not self.vault_addr or not self.vault_token:
            raise SecretError("VAULT_ADDR and VAULT_TOKEN must be set to use vault: references")

        path, _, field = spec.partition("#")
        if not field:
            raise SecretError("a vault reference needs a #field suffix")

        import httpx

        response = httpx.get(
            f"{self.vault_addr}/v1/{path.strip('/')}",
            headers={"X-Vault-Token": self.vault_token},
            timeout=10,
        )
        if response.status_code != 200:
            raise SecretError(f"vault returned {response.status_code}")

        body = response.json().get("data", {})
        # KV v2 nests the payload under data.data; KV v1 does not.
        values = body.get("data", body)
        if field not in values:
            raise SecretError(f"field {field} is not present at that path")
        return str(values[field])
