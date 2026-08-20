"""Building a write-capable session from the same settings the read path uses.

Separate from `devices.py` so that importing the read backends can never pull in
anything that writes.
"""

from __future__ import annotations

from collections.abc import Callable

from app.config import settings
from app.execute.session import ConfigSession
from app.firewall.devices import _credential, _resolver

DEVICE_TYPES = {
    "cisco_asa": "cisco_asa",
    "cisco_ios": "cisco_ios",
    "arista_eos": "arista_eos",
    "nokia_srl": "nokia_srl",
}


def session_factory(backend: str) -> Callable[[str], ConfigSession]:
    device_type = DEVICE_TYPES.get(backend)
    if device_type is None:
        raise RuntimeError(f"{backend} cannot execute changes")

    resolver = _resolver()
    enforce = settings.require_managed_secrets
    password = _credential(
        settings.firewall_password, "FIREWALL_PASSWORD", resolver, required=True, enforce=enforce
    )
    secret = _credential(
        settings.firewall_secret, "FIREWALL_SECRET", resolver, required=False, enforce=enforce
    )

    def build(device_id: str) -> ConfigSession:
        return ConfigSession(
            settings.firewall_host,
            settings.firewall_username,
            password,
            device_type=device_type,
            device_id=device_id,
            secret=secret,
        )

    return build
