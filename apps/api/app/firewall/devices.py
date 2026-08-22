"""Construction of the read-only device backends from settings.

Kept apart from the API so the probe command can build the same backend the
running service would, without importing the web application.
"""

from __future__ import annotations

import logging
from typing import Any

from app.config import settings
from app.secretref import SecretResolver, describe, is_managed

logger = logging.getLogger(__name__)

BACKENDS = ("mock", "cisco_asa", "cisco_ios", "arista_eos", "nokia_srl")


def _resolver() -> SecretResolver:
    return SecretResolver(
        ttl_seconds=settings.secret_cache_seconds,
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
    )


def _credential(
    reference: str, label: str, resolver: SecretResolver, *, required: bool, enforce: bool
):
    """Turn a configured reference into something the transport can use.

    An inline credential is refused for a real device when managed secrets are
    required: a password in an environment variable is visible to anything that
    can read the process, survives in `docker inspect`, and only rotates with a
    restart.
    """
    if not reference:
        if required and enforce:
            raise RuntimeError(
                f"{label} is unset. Point it at a secret manager, for example "
                f"{label}=file:/run/secrets/device_password"
            )
        return ""

    if is_managed(reference):
        logger.info("%s resolves from %s", label, describe(reference))
        return resolver.getter(reference)

    if enforce:
        raise RuntimeError(
            f"{label} holds an inline value. Use env:, file:, vault: or exec: so the "
            f"credential is not carried in the environment, or set "
            f"REQUIRE_MANAGED_SECRETS=false to accept the risk."
        )
    logger.warning("%s is an inline value; it will be readable in the process environment", label)
    return reference


def make_device_firewall(
    backend: str,
    *,
    host: str = "",
    username: str = "",
    password: str = "",
    secret: str = "",
    acl_name: str = "",
    device_id: str = "",
    port: int = 22,
    timeout: int = 20,
    enforce_managed_secrets: bool | None = None,
) -> Any:
    """Build an SSH backend, falling back to settings for anything not passed."""
    host = host or settings.firewall_host
    if not host:
        raise RuntimeError(f"FIREWALL_BACKEND={backend} requires FIREWALL_HOST")

    # An explicitly passed credential comes from an interactive prompt, which is
    # the one case where an inline value is the safe option.
    interactive = bool(password or secret)
    required = (
        settings.require_managed_secrets
        if enforce_managed_secrets is None
        else enforce_managed_secrets
    )
    enforce = required and not interactive

    resolver = _resolver()
    kwargs = {
        "host": host,
        "username": username or settings.firewall_username,
        "password": _credential(
            password or settings.firewall_password,
            "FIREWALL_PASSWORD",
            resolver,
            required=True,
            enforce=enforce,
        ),
        "secret": _credential(
            secret or settings.firewall_secret,
            "FIREWALL_SECRET",
            resolver,
            required=False,
            enforce=enforce,
        ),
        "acl_name": (acl_name or settings.firewall_acl) or None,
        "device_id": device_id or settings.firewall_device_id,
        "port": port if port != 22 else settings.firewall_port,
        "timeout": timeout,
    }

    if backend == "cisco_asa":
        from app.firewall.asa import CiscoAsaFirewall

        return CiscoAsaFirewall(**kwargs)
    if backend == "cisco_ios":
        from app.firewall.ios import CiscoIosFirewall

        return CiscoIosFirewall(**kwargs)
    if backend == "arista_eos":
        from app.firewall.eos import AristaEosFirewall

        return AristaEosFirewall(**kwargs)
    if backend == "nokia_srl":
        from app.firewall.srlinux import NokiaSrlinuxFirewall

        return NokiaSrlinuxFirewall(**kwargs)
    raise RuntimeError(f"Unknown device backend: {backend!r}")
