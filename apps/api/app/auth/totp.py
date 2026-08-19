"""RFC 6238 time-based one-time passwords.

Implemented here rather than pulled in as a dependency: it is thirty lines of
HMAC, and the RFC publishes test vectors, so correctness is verifiable rather
than assumed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
# One step either side, to tolerate clock drift between phone and server.
DEFAULT_WINDOW = 1


def generate_secret(length: int = 20) -> str:
    """Base32, as expected by authenticator apps."""
    return base64.b32encode(secrets.token_bytes(length)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + padding, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**DIGITS)).zfill(DIGITS)


def code_at(secret_b32: str, timestamp: float | None = None) -> str:
    return _hotp(secret_b32, int((timestamp if timestamp is not None else time.time()) // PERIOD))


def verify(
    secret_b32: str,
    code: str,
    timestamp: float | None = None,
    window: int = DEFAULT_WINDOW,
) -> bool:
    candidate = (code or "").strip().replace(" ", "")
    if not candidate.isdigit() or len(candidate) != DIGITS:
        return False
    counter = int((timestamp if timestamp is not None else time.time()) // PERIOD)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + drift), candidate):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = "ZeroNode") -> str:
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(account)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1"
        f"&digits={DIGITS}&period={PERIOD}"
    )
