import copy
from dataclasses import asdict

from app.audit.ledger import (
    GENESIS_HASH,
    ApprovalRecord,
    Signer,
    record_hash,
    verify_chain,
)

EVIDENCE = {
    "proposed_actions": [
        {"device": "FW_Edge", "command": "permit tcp host 10.10.1.10 host 10.20.1.50 eq 443"}
    ],
    "verification": ["PASS 10.10.1.10 -> 10.20.1.50:443/tcp now permitted by the proposed rule."],
}


def build_chain(signer: Signer, count: int = 3) -> list[dict]:
    rows: list[dict] = []
    previous = GENESIS_HASH
    for index in range(count):
        record = ApprovalRecord.now(
            thread_id=f"INC-100{index}",
            decision="approve",
            feedback="",
            actor="alice@example.com",
            actor_role="approver",
            evidence=copy.deepcopy(EVIDENCE),
            prev_hash=previous,
        )
        sealed = signer.seal(record)
        rows.append(
            {**asdict(record), "hash": sealed.hash, "signature": sealed.signature,
             "key_id": sealed.key_id}
        )
        previous = sealed.hash
    return rows


def keys(signer: Signer) -> dict[str, str]:
    return {signer.key_id: signer.public_key_b64}


def test_intact_chain_verifies():
    signer = Signer(Signer.generate_seed())
    report = verify_chain(build_chain(signer), keys(signer))
    assert report.ok is True
    assert report.checked == 3


def test_editing_a_record_breaks_its_hash():
    signer = Signer(Signer.generate_seed())
    rows = build_chain(signer)
    rows[1]["evidence"]["proposed_actions"][0]["command"] = "permit ip any any"

    report = verify_chain(rows, keys(signer))
    assert report.ok is False
    assert report.broken_at == 1
    assert "do not match its hash" in report.reason


def test_removing_a_record_breaks_the_chain():
    signer = Signer(Signer.generate_seed())
    rows = build_chain(signer)
    del rows[1]

    report = verify_chain(rows, keys(signer))
    assert report.ok is False
    assert report.broken_at == 1
    assert "altered or removed" in report.reason


def test_reordering_records_is_detected():
    signer = Signer(Signer.generate_seed())
    rows = build_chain(signer)
    rows[0], rows[1] = rows[1], rows[0]

    report = verify_chain(rows, keys(signer))
    assert report.ok is False


def test_a_forged_record_does_not_verify():
    """Someone with database access can insert a row, but cannot sign it."""
    signer = Signer(Signer.generate_seed())
    attacker = Signer(Signer.generate_seed())
    rows = build_chain(signer, count=1)

    forged = ApprovalRecord.now(
        thread_id="INC-9999",
        decision="approve",
        feedback="inserted directly into the database",
        actor="alice@example.com",
        actor_role="approver",
        evidence={},
        prev_hash=rows[-1]["hash"],
    )
    sealed = attacker.seal(forged)
    rows.append(
        {**asdict(forged), "hash": sealed.hash, "signature": sealed.signature,
         "key_id": sealed.key_id}
    )

    report = verify_chain(rows, keys(signer))
    assert report.ok is False
    assert report.broken_at == 1
    assert "unknown key" in report.reason


def test_signature_swapped_between_records_is_rejected():
    signer = Signer(Signer.generate_seed())
    rows = build_chain(signer)
    rows[2]["signature"] = rows[1]["signature"]

    report = verify_chain(rows, keys(signer))
    assert report.ok is False
    assert "invalid signature" in report.reason


def test_hash_is_stable_across_key_ordering():
    """The chain is only as trustworthy as the canonical serialisation."""
    record = ApprovalRecord.now(
        thread_id="INC-1001",
        decision="approve",
        feedback="",
        actor="alice@example.com",
        actor_role="approver",
        evidence={"b": 2, "a": 1},
        prev_hash=GENESIS_HASH,
    )
    reordered = ApprovalRecord(**{**asdict(record), "evidence": {"a": 1, "b": 2}})
    assert record_hash(record) == record_hash(reordered)


def test_an_absent_key_is_reported_as_ephemeral():
    assert Signer().ephemeral is True
    assert Signer(Signer.generate_seed()).ephemeral is False
