"""A chain can always recompute itself. It can never notice that there used to be more of it.

The audit trail catches interior tampering well: modify an entry and its hash stops matching,
delete one from the middle and the next entry no longer follows its predecessor. Tail truncation
is different in kind, because what is left links perfectly — and
:meth:`~nemesis.audit.trail.AppendOnlyAuditTrail.verify` catches it only by comparing the file
against counters *the running instance* holds.

That works while the process that wrote the entries is still alive. It does not survive a
restart, and `nemesis verify` is a restart by definition: it constructs a fresh trail from a
path, so its counters are whatever the file says. Measured on this branch before the anchor was
wired — the demo's audit log truncated from 72 entries to 60, and the command reported
``chain intact: True``.

:mod:`nemesis.authz.anchor` had specified the whole answer for months and nothing called it.
These tests cover the wiring that does, and they cover it from the *fresh reader's* position
throughout, because that is the position an attacker leaves the file in.

Brief cases 12 and 13. Covers AUDIT-01 and AUDIT-02.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import pytest

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.authz.anchor import (
    AnchorEpochError,
    AnchorIndependence,
    AnchorPlacementError,
    FileAnchorStore,
    LocalAnchorSigner,
    local_anchor_authority,
    registered_authorities,
)
from nemesis.authz.audit_anchor import (
    AUDIT_CHAIN,
    anchor_audit_trail,
    verify_audit_trail,
)
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.ports.storage import AuditEvent

pytestmark = pytest.mark.invariant


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


def _event(index: int) -> AuditEvent:
    return AuditEvent(
        audit_id=new_id(IdPrefix.AUDIT),
        occurred_at=utcnow(),
        actor="analyst-1",
        actor_kind="human",
        action="test.event",
        subject=f"subject-{index}",
        outcome="ok",
        inputs={"index": str(index)},
    )


class Anchored:
    """A trail with its anchor store, signer and registry, as a deployment would hold them."""

    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "audit.jsonl"
        self.trail = AppendOnlyAuditTrail(self.path)
        self.signer = LocalAnchorSigner(CapabilitySigningKey.generate())
        self.store = FileAnchorStore(root / "anchors.jsonl")
        self.authorities = registered_authorities(local_anchor_authority(self.signer.verifying_key))

    async def fill(self, count: int) -> None:
        for index in range(count):
            await self.trail.record(_event(index))

    async def anchor(self) -> None:
        await anchor_audit_trail(self.trail, store=self.store, signer=self.signer)

    async def verdicts(self) -> tuple[bool, tuple[str, ...]]:
        """The trail's own answer, from a **fresh** reader, and the anchor's answer.

        Fresh on purpose and in every test here: the whole finding is that the two disagree once
        the process that wrote the entries is gone, and a reader that reused ``self.trail``
        would be measuring the memory rather than the file.
        """
        fresh = AppendOnlyAuditTrail(self.path)
        report = await verify_audit_trail(fresh, store=self.store, authorities=self.authorities)
        return (await fresh.verify()).intact, report.defects


# --- the gap, measured --------------------------------------------------------------------


def test_a_fresh_reader_cannot_see_a_truncated_tail_and_the_anchor_can(tmp_path: Path) -> None:
    """Brief case 13, and the measurement this whole module exists for.

    Both verdicts are asserted, including the uncomfortable one. If the chain check alone were
    enough, the anchor would be ceremony; asserting that it reports ``intact`` on a trail missing
    a third of itself is what establishes that it is not.
    """

    async def scenario() -> tuple[bool, tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(9)
        await a.anchor()
        lines = a.path.read_text(encoding="utf-8").splitlines()
        a.path.write_text("\n".join(lines[:6]) + "\n", encoding="utf-8")
        return await a.verdicts()

    intact, defects = _run(scenario())
    assert intact is True, (
        "the chain check caught a truncation from a fresh reader; if this ever becomes possible "
        "the anchor is no longer the only thing that catches it and this test should be rewritten"
    )
    assert defects, "the anchor did not notice three entries removed from the end"
    assert any("removed after it was anchored" in defect for defect in defects)
    assert any("folds to" in defect for defect in defects)


def test_emptying_the_trail_entirely_is_caught(tmp_path: Path) -> None:
    """The cheapest version of the same attack, and the one an internal chain likes most.

    An empty chain is perfectly self-consistent. Only the record count disagrees.
    """

    async def scenario() -> tuple[bool, tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(5)
        await a.anchor()
        a.path.write_text("", encoding="utf-8")
        return await a.verdicts()

    intact, defects = _run(scenario())
    assert intact is True
    assert defects


def test_deleting_an_interior_entry_is_caught_twice(tmp_path: Path) -> None:
    """Brief case 12. Interior deletion breaks the links *and* the anchor.

    Two independent detections of one attack, which is worth having: the chain catches it
    without any external state, and the anchor catches it without trusting the chain. Asserted
    together so a change that quietly removed one of them shows up.
    """

    async def scenario() -> tuple[bool, tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(6)
        await a.anchor()
        lines = a.path.read_text(encoding="utf-8").splitlines()
        del lines[2]
        a.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return await a.verdicts()

    intact, defects = _run(scenario())
    assert intact is False
    assert defects


def test_a_careless_edit_is_caught_by_the_chain_and_not_by_the_anchor(tmp_path: Path) -> None:
    """AUDIT-01, and the boundary between the two controls, measured rather than assumed.

    An outcome edited from ``refused`` to ``permitted`` — the edit that matters, because a
    pattern of denied attempts is the security signal the field exists to carry. The editor does
    not recompute the hashes, so:

    * the **chain** catches it, because the entry no longer hashes to its stored ``entry_hash``;
    * the **anchor** does not, because the anchor folds the stored link hashes and those are
      untouched.

    The first version of this test asserted "caught twice" and failed on the second half. That
    was the test being wrong rather than the anchor: an anchor attests to a chain's *shape* —
    how long it is and in what order — and content integrity is the chain's own job. Writing
    down where each control stops is worth more than an assertion that quietly assumed they
    overlapped, and the next test is the case where the roles reverse.
    """

    async def scenario() -> tuple[bool, tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(6)
        await a.anchor()
        lines = a.path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[3])
        entry["outcome"] = "permitted"
        lines[3] = json.dumps(entry, separators=(",", ":"))
        a.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return await a.verdicts()

    intact, defects = _run(scenario())
    assert intact is False, "the chain missed an entry that no longer hashes to its stored value"
    assert defects == (), (
        "the anchor reported a defect for a content edit that left every link hash intact. If "
        "the anchor has grown content coverage this test should be rewritten, not deleted."
    )


def test_a_rewrite_that_recomputes_every_hash_is_caught_by_the_anchor_and_not_the_chain(
    tmp_path: Path,
) -> None:
    """The other half, and the one an actual attacker performs.

    The audit trail carries no per-record signature — unlike the revocation chain, where forging
    a row needs the Ed25519 key. So an attacker who edits an entry *and* recomputes every hash
    downstream leaves a chain that verifies perfectly. Measured here: ``intact`` comes back
    ``True`` on a trail whose fourth entry now says ``permitted`` where it said ``refused``.

    What defeats it is that recomputing the hashes changes the tip, and the tip was attested
    before the rewrite. Together with the test above this is the whole picture: the chain covers
    content and the anchor covers shape, neither covers both, and an attacker has to defeat
    them in opposite directions.
    """
    from nemesis.audit.trail import _entry_hash

    async def scenario() -> tuple[bool, tuple[str, ...], str]:
        a = Anchored(tmp_path)
        await a.fill(6)
        await a.anchor()

        events = [
            AuditEvent.model_validate(json.loads(line))
            for line in a.path.read_text(encoding="utf-8").splitlines()
        ]
        events[3] = events[3].model_copy(update={"outcome": "permitted"})
        previous: str | None = None
        rebuilt = []
        for event in events:
            relinked = event.model_copy(update={"previous_hash": previous, "entry_hash": None})
            sealed = relinked.model_copy(update={"entry_hash": _entry_hash(relinked)})
            previous = sealed.entry_hash
            rebuilt.append(sealed)
        a.path.write_text(
            "\n".join(event.model_dump_json() for event in rebuilt) + "\n", encoding="utf-8"
        )

        intact, defects = await a.verdicts()
        return intact, defects, rebuilt[3].outcome

    intact, defects, outcome = _run(scenario())
    assert outcome == "permitted"
    assert intact is True, (
        "the chain caught a fully recomputed rewrite; if it has grown a per-record signature "
        "this test should be rewritten to describe the new control"
    )
    assert defects, "the anchor missed a rewrite that changed the tip it had attested"
    assert any("folds to" in defect for defect in defects)


def test_reordering_entries_is_caught(tmp_path: Path) -> None:
    """Order is history. Two chains holding the same records in a different sequence are not
    the same chain, and the anchor's digest folds the links in order for exactly this."""

    async def scenario() -> tuple[bool, tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(6)
        await a.anchor()
        lines = a.path.read_text(encoding="utf-8").splitlines()
        lines[2], lines[4] = lines[4], lines[2]
        a.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return await a.verdicts()

    intact, defects = _run(scenario())
    assert intact is False
    assert defects


def test_deleting_the_anchor_is_reported_rather_than_read_as_silence(tmp_path: Path) -> None:
    """Otherwise the cheapest attack in the set is to remove the attestation.

    "No anchor exists" and "this chain matches its attestation" are different findings and only
    one of them is evidence. A verifier that treated the first as a pass would be defeated by
    ``rm``.
    """

    async def scenario() -> tuple[bool, tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(5)
        await a.anchor()
        (tmp_path / "anchors.jsonl").unlink()
        return await a.verdicts()

    intact, defects = _run(scenario())
    assert intact is True
    assert defects and "attested by nothing" in defects[0]


def test_replaying_a_stale_anchor_is_caught_when_the_verifier_retained_an_epoch(
    tmp_path: Path,
) -> None:
    """An older, validly-signed anchor presented to make an older state look current.

    The epoch is what orders anchors, and the check needs the verifier's own retained epoch —
    which is state the verifier holds, not state the store provides. Without it a stale anchor
    replays cleanly, and that is a property of the design rather than a defect: the store is
    exactly as trustworthy as its placement, and at ``NONE`` it is not trustworthy at all.
    """
    from nemesis.authz.anchor import verify_against_anchor

    async def scenario() -> tuple[tuple[str, ...], tuple[str, ...]]:
        a = Anchored(tmp_path)
        await a.fill(4)
        await a.anchor()
        stale = a.store.latest(AUDIT_CHAIN)
        assert stale is not None
        await a.fill(3)
        await a.anchor()

        links = await AppendOnlyAuditTrail(a.path).links()
        # The attacker rolls the file back to the state the stale anchor describes and presents
        # that anchor. Against a verifier with no memory it verifies; against one that retained
        # the newer epoch it does not.
        rolled_back = links[:4]
        without_memory = verify_against_anchor(rolled_back, stale, authorities=a.authorities)
        with_memory = verify_against_anchor(
            rolled_back, stale, authorities=a.authorities, retained_epoch=1
        )
        return without_memory, with_memory

    without_memory, with_memory = _run(scenario())
    assert without_memory == (), (
        "the rolled-back state disagreed with the stale anchor; this test is no longer "
        "demonstrating the replay it was written for"
    )
    assert any("older than" in defect for defect in with_memory)


# --- the store's own refusals ----------------------------------------------------------


def test_an_anchor_cannot_be_republished_at_an_epoch_that_does_not_advance(
    tmp_path: Path,
) -> None:
    """An anchor that could be replaced by an older one is one an attacker replaces."""

    async def scenario() -> None:
        a = Anchored(tmp_path)
        await a.fill(3)
        await a.anchor()
        from nemesis.authz.anchor import anchor_for

        links = await a.trail.links()
        a.store.publish(a.signer.sign(anchor_for(AUDIT_CHAIN, links, epoch=0)))

    with pytest.raises(AnchorEpochError):
        _run(scenario())


def test_a_store_beside_the_trail_cannot_publish_a_claim_of_independence(
    tmp_path: Path,
) -> None:
    """Writing a stronger word into a file is free, so the store refuses the word.

    The placement is declared by the deployment and cannot be verified by any code — nothing in
    Python can confirm a path sits behind an ACL this process cannot cross. What can be enforced
    is that a store constructed at one rung refuses to publish an attestation claiming another.
    """

    async def scenario() -> None:
        a = Anchored(tmp_path)
        await a.fill(3)
        await anchor_audit_trail(
            a.trail,
            store=a.store,
            signer=a.signer,
            independence=AnchorIndependence.THIRD_PARTY,
        )

    with pytest.raises(AnchorPlacementError):
        _run(scenario())


def test_a_clean_anchor_still_reports_that_it_defends_against_nobody(tmp_path: Path) -> None:
    """The honesty that keeps "anchored" from reading as the tier above.

    A sound report at ``NONE`` is a real result — it catches an accident, a partial restore, a
    chain rebuilt by a repair script — and it is not defensibility against an operator. The
    report says both, in separate fields, exactly as the vault does.
    """

    async def scenario() -> tuple[bool, bool, AnchorIndependence]:
        a = Anchored(tmp_path)
        await a.fill(5)
        await a.anchor()
        fresh = AppendOnlyAuditTrail(a.path)
        report = await verify_audit_trail(fresh, store=a.store, authorities=a.authorities)
        return report.sound, report.is_defensible_against_the_operator, report.independence

    sound, defensible, independence = _run(scenario())
    assert sound is True
    assert defensible is False
    assert independence is AnchorIndependence.NONE


def test_links_are_read_from_the_file_and_not_from_the_writers_memory(tmp_path: Path) -> None:
    """The property the whole wiring rests on, asserted on its own.

    ``links()`` reading ``self._count`` instead of the file would make every test above pass
    while the anchor measured the writer's beliefs rather than the bytes — an anchor over
    remembered state attests to nothing.
    """

    async def scenario() -> tuple[int, int]:
        a = Anchored(tmp_path)
        await a.fill(6)
        lines = a.path.read_text(encoding="utf-8").splitlines()
        a.path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        return len(await a.trail.links()), await a.trail.entry_count()

    from_file, from_memory = _run(scenario())
    assert from_file == 2
    assert from_memory == 6, "entry_count is the writer's memory and should still say six"
