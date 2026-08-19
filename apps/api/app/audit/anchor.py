"""External anchoring of the ledger head.

The hash chain proves that no record was edited, and the database trigger blocks
UPDATE and DELETE. Neither survives someone with database ownership dropping the
table or restoring an older backup: the ledger that remains is internally
consistent, just shorter.

Anchoring closes that by writing the chain head and record count somewhere the
database cannot reach. Verification then compares the live chain against the
last anchor, so truncation and rollback become visible even though the remaining
records verify perfectly.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from app.audit.ledger import Signer, verify_signature

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Anchor:
    head_hash: str
    record_count: int
    anchored_at: str
    key_id: str
    signature: str = ""

    def payload(self) -> dict[str, Any]:
        return {
            "head_hash": self.head_hash,
            "record_count": self.record_count,
            "anchored_at": self.anchored_at,
            "key_id": self.key_id,
        }

    def digest(self) -> str:
        raw = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


def seal_anchor(head_hash: str, record_count: int, signer: Signer) -> Anchor:
    anchor = Anchor(
        head_hash=head_hash,
        record_count=record_count,
        anchored_at=datetime.now(UTC).isoformat(),
        key_id=signer.key_id,
    )
    return Anchor(**{**asdict(anchor), "signature": signer.sign(anchor.digest())})


class AnchorSink(Protocol):
    def write(self, anchor: Anchor) -> None: ...

    def latest(self) -> Anchor | None: ...

    def describe(self) -> str: ...


class NullAnchorSink:
    """No anchoring. Truncation of the ledger would go unnoticed."""

    def write(self, anchor: Anchor) -> None:
        logger.debug("ledger head %s (%d records)", anchor.head_hash[:12], anchor.record_count)

    def latest(self) -> Anchor | None:
        return None

    def describe(self) -> str:
        return "none (ledger truncation would not be detected)"


class FileAnchorSink:
    """Append-only JSON lines. Point it at a volume the database cannot write to."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, anchor: Anchor) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(anchor), sort_keys=True) + "\n")
        logger.info(
            "anchored ledger head %s at %d records", anchor.head_hash[:12], anchor.record_count
        )

    def latest(self) -> Anchor | None:
        if not self.path.exists():
            return None
        last: Anchor | None = None
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = Anchor(**json.loads(line))
                except (json.JSONDecodeError, TypeError):
                    logger.warning("skipping malformed anchor line in %s", self.path)
        return last

    def describe(self) -> str:
        return f"file {self.path}"


@dataclass
class AnchorCheck:
    ok: bool
    reason: str = ""
    anchored_count: int | None = None
    anchored_head: str | None = None
    anchor_present: bool = False


def check_against_anchor(
    rows: list[dict[str, Any]], anchor: Anchor | None, trusted_keys: dict[str, str]
) -> AnchorCheck:
    """Compare the live chain against the last anchor."""
    if anchor is None:
        return AnchorCheck(
            ok=True,
            reason="No anchor configured; deletion of the whole ledger would be undetectable.",
        )

    public_key = trusted_keys.get(anchor.key_id)
    if not public_key or not verify_signature(public_key, anchor.digest(), anchor.signature):
        return AnchorCheck(
            ok=False,
            reason="The anchor itself does not verify; it was altered or signed by an unknown key.",
            anchored_count=anchor.record_count,
            anchored_head=anchor.head_hash,
            anchor_present=True,
        )

    if len(rows) < anchor.record_count:
        return AnchorCheck(
            ok=False,
            reason=(
                f"The ledger holds {len(rows)} records but was anchored at "
                f"{anchor.record_count}: records were deleted or an older backup was restored."
            ),
            anchored_count=anchor.record_count,
            anchored_head=anchor.head_hash,
            anchor_present=True,
        )

    at_anchor = rows[anchor.record_count - 1] if anchor.record_count else None
    if at_anchor is not None and at_anchor["hash"] != anchor.head_hash:
        return AnchorCheck(
            ok=False,
            reason=(
                f"Record {anchor.record_count} does not match the anchored head: "
                "history was rewritten below the anchor point."
            ),
            anchored_count=anchor.record_count,
            anchored_head=anchor.head_hash,
            anchor_present=True,
        )

    return AnchorCheck(
        ok=True,
        anchored_count=anchor.record_count,
        anchored_head=anchor.head_hash,
        anchor_present=True,
    )
