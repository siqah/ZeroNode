"""Signed, hash-chained approval records.

Two independent guarantees. The hash chain makes the log tamper-evident: every
record commits to its predecessor, so altering or removing one invalidates every
record after it. The Ed25519 signature makes it attributable: only the holder of
the signing key could have produced the record, so a row inserted directly into
the database by someone with SQL access does not verify.

Deliberately pure. Nothing here touches a database, so the guarantees can be
tested without one.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class ApprovalRecord:
    """The facts being attested to. Every field is covered by the hash."""

    thread_id: str
    decision: str
    feedback: str
    actor: str
    actor_role: str
    evidence: dict[str, Any]
    created_at: str
    prev_hash: str

    @staticmethod
    def now(
        thread_id: str,
        decision: str,
        feedback: str,
        actor: str,
        actor_role: str,
        evidence: dict[str, Any],
        prev_hash: str,
    ) -> ApprovalRecord:
        return ApprovalRecord(
            thread_id=thread_id,
            decision=decision,
            feedback=feedback,
            actor=actor,
            actor_role=actor_role,
            evidence=evidence,
            created_at=datetime.now(UTC).isoformat(),
            prev_hash=prev_hash,
        )


@dataclass(frozen=True)
class SealedApproval:
    record: ApprovalRecord
    hash: str
    signature: str
    key_id: str


@dataclass
class ChainReport:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str = ""


def canonical_bytes(record: ApprovalRecord) -> bytes:
    """Byte-for-byte stable serialisation; the hash is only as good as this."""
    return json.dumps(
        asdict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_hash(record: ApprovalRecord) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


class Signer:
    """Ed25519 signer. An absent key yields an ephemeral one, which is useless
    for audit and must be reported as such by the caller."""

    def __init__(self, seed_b64: str = "") -> None:
        if seed_b64:
            seed = base64.b64decode(seed_b64)
            self._key = Ed25519PrivateKey.from_private_bytes(seed)
            self.ephemeral = False
        else:
            self._key = Ed25519PrivateKey.generate()
            self.ephemeral = True

    @staticmethod
    def generate_seed() -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return base64.b64encode(raw).decode()

    @property
    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public_key_b64.encode()).hexdigest()[:16]

    def sign(self, digest_hex: str) -> str:
        return base64.b64encode(self._key.sign(digest_hex.encode())).decode()

    def seal(self, record: ApprovalRecord) -> SealedApproval:
        digest = record_hash(record)
        return SealedApproval(
            record=record,
            hash=digest,
            signature=self.sign(digest),
            key_id=self.key_id,
        )


def verify_signature(public_key_b64: str, digest_hex: str, signature_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature_b64), digest_hex.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_chain(rows: list[dict[str, Any]], public_keys: dict[str, str]) -> ChainReport:
    """Walk the ledger in insertion order, re-deriving every hash and signature.

    `rows` are dicts holding the record fields plus `hash`, `signature` and
    `key_id`. `public_keys` maps key_id to a base64 public key.
    """
    previous = GENESIS_HASH
    for index, row in enumerate(rows):
        record = ApprovalRecord(
            thread_id=row["thread_id"],
            decision=row["decision"],
            feedback=row["feedback"],
            actor=row["actor"],
            actor_role=row["actor_role"],
            evidence=row["evidence"],
            created_at=row["created_at"],
            prev_hash=row["prev_hash"],
        )
        if record.prev_hash != previous:
            return ChainReport(
                False,
                index,
                index,
                f"record {index} claims predecessor {record.prev_hash[:12]} "
                f"but the chain is at {previous[:12]}; a record was altered or removed",
            )

        expected = record_hash(record)
        if expected != row["hash"]:
            return ChainReport(
                False, index, index, f"record {index} contents do not match its hash"
            )

        public_key = public_keys.get(row.get("key_id", ""))
        if not public_key:
            return ChainReport(
                False,
                index,
                index,
                f"record {index} was signed with unknown key {row.get('key_id', '')!r}",
            )
        if not verify_signature(public_key, row["hash"], row["signature"]):
            return ChainReport(
                False, index, index, f"record {index} has an invalid signature"
            )

        previous = row["hash"]

    return ChainReport(True, len(rows))
