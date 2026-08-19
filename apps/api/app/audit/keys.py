"""Signing key set and rotation.

A ledger signed by a single key can only be verified for as long as that key
lives. Rotation therefore has to preserve the ability to verify everything
signed before it: the active key signs new records, retired public keys stay in
the trust set, and the moment of rotation is itself written into the chain so an
auditor can see where the key changed rather than inferring it.
"""

from __future__ import annotations

import hashlib
import logging

from app.audit.ledger import Signer

logger = logging.getLogger(__name__)


def key_id_for(public_key_b64: str) -> str:
    return hashlib.sha256(public_key_b64.encode()).hexdigest()[:16]


class KeySet:
    """The active signer plus every public key still trusted for verification."""

    def __init__(self, active: Signer, retired_public_keys: list[str] | None = None) -> None:
        self.active = active
        self._retired: dict[str, str] = {}
        for public_key in retired_public_keys or []:
            cleaned = public_key.strip()
            if cleaned:
                self._retired[key_id_for(cleaned)] = cleaned

    @classmethod
    def from_settings(cls, seed_b64: str, retired_csv: str = "") -> KeySet:
        retired = [item for item in (retired_csv or "").split(",") if item.strip()]
        return cls(Signer(seed_b64), retired)

    @property
    def trusted(self) -> dict[str, str]:
        """key_id -> public key, covering the active key and all retired ones."""
        return {**self._retired, self.active.key_id: self.active.public_key_b64}

    def describe(self) -> dict[str, object]:
        return {
            "active_key_id": self.active.key_id,
            "active_public_key": self.active.public_key_b64,
            "retired_key_ids": sorted(self._retired),
            "algorithm": "ed25519",
            "ephemeral": self.active.ephemeral,
        }

    def knows(self, key_id: str) -> bool:
        return key_id in self.trusted


def rotation_evidence(previous_key_id: str, new_key_id: str) -> dict[str, str]:
    return {
        "event": "signing_key_rotation",
        "previous_key_id": previous_key_id,
        "new_key_id": new_key_id,
        "note": (
            "Records before this point are signed with the previous key, which must "
            "stay in AUDIT_RETIRED_KEYS for the ledger to remain verifiable."
        ),
    }


def main() -> None:
    """`python -m app.audit.keys` prints the env for a fresh key or a rotation."""
    import argparse

    from app.config import settings

    parser = argparse.ArgumentParser(description="ZeroNode ledger signing keys")
    parser.add_argument(
        "command", choices=["generate", "rotate"], help="generate a first key, or rotate"
    )
    args = parser.parse_args()

    new_seed = Signer.generate_seed()
    new_public = Signer(new_seed).public_key_b64

    if args.command == "generate":
        print(f"AUDIT_SIGNING_KEY={new_seed}")
        return

    current = Signer(settings.audit_signing_key) if settings.audit_signing_key else None
    if current is None:
        print("No AUDIT_SIGNING_KEY is set; nothing to rotate. Use 'generate'.")
        return

    retired = [item for item in settings.audit_retired_keys.split(",") if item.strip()]
    retired.append(current.public_key_b64)
    print("# Replace both values, then restart the API.")
    print(f"AUDIT_SIGNING_KEY={new_seed}")
    print(f"AUDIT_RETIRED_KEYS={','.join(dict.fromkeys(retired))}")
    print(f"# New key id: {key_id_for(new_public)}")


if __name__ == "__main__":
    main()
