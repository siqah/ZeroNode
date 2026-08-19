"""Key rotation and external anchoring."""

from dataclasses import asdict

from app.audit.anchor import (
    Anchor,
    FileAnchorSink,
    NullAnchorSink,
    check_against_anchor,
    seal_anchor,
)
from app.audit.keys import KeySet, key_id_for
from app.audit.ledger import GENESIS_HASH, ApprovalRecord, Signer, verify_chain


def seal_row(signer: Signer, prev_hash: str, thread_id: str) -> dict:
    record = ApprovalRecord.now(
        thread_id=thread_id,
        decision="approve",
        feedback="",
        actor="alice@example.com",
        actor_role="approver",
        evidence={},
        prev_hash=prev_hash,
    )
    sealed = signer.seal(record)
    return {
        **asdict(record),
        "hash": sealed.hash,
        "signature": sealed.signature,
        "key_id": sealed.key_id,
    }


def test_records_signed_before_a_rotation_still_verify():
    old = Signer(Signer.generate_seed())
    new = Signer(Signer.generate_seed())

    rows = [seal_row(old, GENESIS_HASH, "INC-1")]
    rows.append(seal_row(new, rows[-1]["hash"], "INC-2"))

    keyset = KeySet(active=new, retired_public_keys=[old.public_key_b64])
    assert verify_chain(rows, keyset.trusted).ok is True

    # Drop the retired key and the older half of the ledger becomes unverifiable.
    assert verify_chain(rows, KeySet(active=new).trusted).ok is False


def test_keyset_reports_every_trusted_key():
    old = Signer(Signer.generate_seed())
    new = Signer(Signer.generate_seed())
    keyset = KeySet(active=new, retired_public_keys=[old.public_key_b64])

    assert set(keyset.trusted) == {new.key_id, old.key_id}
    assert keyset.knows(key_id_for(old.public_key_b64))
    assert keyset.describe()["active_key_id"] == new.key_id


def test_keyset_from_settings_parses_a_csv_of_public_keys():
    old_a, old_b = Signer(Signer.generate_seed()), Signer(Signer.generate_seed())
    keyset = KeySet.from_settings(
        Signer.generate_seed(), f"{old_a.public_key_b64}, {old_b.public_key_b64}"
    )
    assert old_a.key_id in keyset.trusted
    assert old_b.key_id in keyset.trusted


def test_truncating_the_ledger_is_caught_by_the_anchor():
    """The remaining records verify perfectly; only the anchor reveals the loss."""
    signer = Signer(Signer.generate_seed())
    rows = [seal_row(signer, GENESIS_HASH, "INC-1")]
    rows.append(seal_row(signer, rows[-1]["hash"], "INC-2"))
    rows.append(seal_row(signer, rows[-1]["hash"], "INC-3"))
    anchor = seal_anchor(rows[-1]["hash"], len(rows), signer)

    survivors = rows[:1]
    keyset = KeySet(active=signer)
    assert verify_chain(survivors, keyset.trusted).ok is True

    check = check_against_anchor(survivors, anchor, keyset.trusted)
    assert check.ok is False
    assert "deleted or an older backup" in check.reason
    assert check.anchored_count == 3


def test_rewriting_history_below_the_anchor_is_caught():
    signer = Signer(Signer.generate_seed())
    rows = [seal_row(signer, GENESIS_HASH, "INC-1")]
    rows.append(seal_row(signer, rows[-1]["hash"], "INC-2"))
    anchor = seal_anchor(rows[-1]["hash"], 2, signer)

    # A fresh, internally valid chain of the same length but different content.
    replacement = [seal_row(signer, GENESIS_HASH, "INC-9")]
    replacement.append(seal_row(signer, replacement[-1]["hash"], "INC-8"))
    assert verify_chain(replacement, KeySet(active=signer).trusted).ok is True

    check = check_against_anchor(replacement, anchor, KeySet(active=signer).trusted)
    assert check.ok is False
    assert "history was rewritten" in check.reason


def test_a_tampered_anchor_does_not_verify():
    signer = Signer(Signer.generate_seed())
    rows = [seal_row(signer, GENESIS_HASH, "INC-1")]
    anchor = seal_anchor(rows[-1]["hash"], 1, signer)
    forged = Anchor(**{**asdict(anchor), "record_count": 1, "head_hash": "0" * 64})

    check = check_against_anchor(rows, forged, KeySet(active=signer).trusted)
    assert check.ok is False
    assert "does not verify" in check.reason


def test_growth_beyond_the_anchor_is_fine():
    signer = Signer(Signer.generate_seed())
    rows = [seal_row(signer, GENESIS_HASH, "INC-1")]
    anchor = seal_anchor(rows[-1]["hash"], 1, signer)
    rows.append(seal_row(signer, rows[-1]["hash"], "INC-2"))

    assert check_against_anchor(rows, anchor, KeySet(active=signer).trusted).ok is True


def test_file_sink_round_trip(tmp_path):
    signer = Signer(Signer.generate_seed())
    sink = FileAnchorSink(tmp_path / "anchors" / "ledger.jsonl")
    sink.write(seal_anchor("a" * 64, 1, signer))
    sink.write(seal_anchor("b" * 64, 2, signer))

    latest = sink.latest()
    assert latest is not None
    assert latest.record_count == 2
    assert latest.head_hash == "b" * 64


def test_missing_anchor_is_reported_rather_than_assumed_safe():
    check = check_against_anchor([], NullAnchorSink().latest(), {})
    assert check.ok is True
    assert check.anchor_present is False
    assert "undetectable" in check.reason
