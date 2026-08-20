"""The investigation must survive the process that ran it.

The evidence vault and the audit trail have always persisted. The graph and the claims did
not, so a restart lost what the platform believed and — worse — *why*: the supersession
history is what answers "what did we think in March, and what changed our minds?", and an
append-only store that evaporates is a store whose append-only-ness bought nothing.

These tests do the only thing that proves durability: write through one store, drop it, open
a second over the same directory, and interrogate the second. Nothing here asserts that a
journal file has lines in it — that would pass while the replay was broken.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest

from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent, utcnow
from nemesis.graph.journal import (
    JournalBackedClaimStore,
    JournalBackedGraphStore,
    JournalError,
)
from nemesis.ports.storage import GraphQuery


def _extent() -> TemporalExtent:
    moment = utcnow()
    return TemporalExtent(
        known_from=moment,
        known_until=moment + timedelta(days=1),
        possible_from=moment - timedelta(days=1),
        possible_until=moment + timedelta(days=2),
    )


def _domain(name: str) -> Entity:
    return Entity(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        natural_key=name,
        observed_form=name,
        extent=_extent(),
    )


def _edge(subject: Entity, obj: Entity) -> Relationship:
    return Relationship(
        edge_id=new_id(IdPrefix.EDGE),
        source_id=subject.entity_id,
        target_id=obj.entity_id,
        source_type=EntityType.DOMAIN,
        target_type=EntityType.DOMAIN,
        relation=RelationType.RESOLVES_TO,
        extent=_extent(),
        confidence=Opinion.from_evidence(supporting=4, contradicting=0),
        pivot_method=PivotMethod.SHARED_ATTRIBUTE,
    )


def _claim(text: str) -> Claim:
    return Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="domain:glass-anvil.example",
            predicate="resolves_to",
            obj="ip:198.51.100.23",
            natural_language=text,
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=utcnow(),
        valid_extent=_extent(),
        # An observation must cite evidence — invariant 3, enforced by the model. The
        # fixture obeys it rather than reaching for a claim kind that would not.
        supported_by_evidence=(f"evd_sha256-{'a' * 64}",),
    )


# --- The graph ----------------------------------------------------------------


def test_a_graph_written_by_one_process_is_read_by_the_next(tmp_path: Path) -> None:
    """Written through one store, read through a second opened over the same directory."""

    async def scenario() -> None:
        first = await JournalBackedGraphStore.open(tmp_path)
        left, right = _domain("glass-anvil.example"), _domain("anvil-works.example")
        await first.upsert_entity(left)
        await first.upsert_entity(right)
        await first.add_relationship(_edge(left, right))

        second = await JournalBackedGraphStore.open(tmp_path)

        assert await second.entity_count() == 2
        assert await second.relationship_count() == 1
        recovered = await second.find_entity(EntityType.DOMAIN, "glass-anvil.example")
        assert recovered is not None and recovered.entity_id == left.entity_id

    asyncio.run(scenario())


def test_the_recovered_graph_answers_a_traversal_the_same_way(tmp_path: Path) -> None:
    """The point of replaying through the public API rather than a second implementation.

    A SQL rewrite of the traversal would be a second set of answers to the same question,
    and the two would diverge silently. Here the traversal is the one already under test, so
    what has to be checked is that the *state* it runs against came back whole.
    """

    async def scenario() -> None:
        first = await JournalBackedGraphStore.open(tmp_path)
        left, right = _domain("a.example"), _domain("b.example")
        await first.upsert_entity(left)
        await first.upsert_entity(right)
        await first.add_relationship(_edge(left, right))
        before = await first.neighbourhood(GraphQuery(entity_id=left.entity_id, max_depth=2))

        second = await JournalBackedGraphStore.open(tmp_path)
        after = await second.neighbourhood(GraphQuery(entity_id=left.entity_id, max_depth=2))

        assert {e.entity_id for e in after.entities} == {e.entity_id for e in before.entities}
        assert len(after.relationships) == len(before.relationships)

    asyncio.run(scenario())


# --- The claims, and the history that makes them worth keeping ------------------


def test_claims_and_their_supersession_history_both_survive(tmp_path: Path) -> None:
    """A journal recording only current versions would lose the interesting half.

    "What do we believe now?" is the easy question. "What did we believe in March, and what
    changed our minds?" is the one an append-only store exists to answer, and it is the one
    that disappears if supersession is persisted as a rewritten claim.
    """

    async def scenario() -> None:
        first = await JournalBackedClaimStore.open(tmp_path)
        original = await first.record(_claim("the cluster resolves to 198.51.100.23"))
        replacement = _claim("the cluster resolved to 198.51.100.23 until it moved")
        await first.supersede(
            original.claim_id, replacement, reason="the address changed on 2026-03-04"
        )

        second = await JournalBackedClaimStore.open(tmp_path)

        assert await second.get(replacement.claim_id) is not None
        assert second.supersession_reason(original.claim_id) == "the address changed on 2026-03-04"

    asyncio.run(scenario())


def test_an_empty_directory_opens_as_an_empty_store(tmp_path: Path) -> None:
    """First run must not be a special case a deployment has to know about."""

    async def scenario() -> None:
        assert await (await JournalBackedGraphStore.open(tmp_path)).entity_count() == 0
        assert (await JournalBackedClaimStore.open(tmp_path)).claims() == ()

    asyncio.run(scenario())


# --- Failing closed -------------------------------------------------------------


def test_an_unreadable_journal_line_refuses_to_open(tmp_path: Path) -> None:
    """A store that skipped a line it could not read would come up believing something
    *narrower* than what was recorded, and would look perfectly healthy doing it.

    A graph missing one edge answers "why do you think these are connected?" with a smaller
    answer and no error — which is worse than refusing to start.
    """

    async def scenario() -> None:
        store = await JournalBackedGraphStore.open(tmp_path)
        await store.upsert_entity(_domain("glass-anvil.example"))

        journal = store.journal_path
        journal.write_text(journal.read_text() + "{not json at all\n")

        with pytest.raises(JournalError, match="not readable JSON"):
            await JournalBackedGraphStore.open(tmp_path)

    asyncio.run(scenario())


def test_a_line_that_would_replay_into_an_invalid_record_refuses_to_open(
    tmp_path: Path,
) -> None:
    """Replay goes through the same validators a live write does.

    So a journal cannot bring a store up in a state it could never have reached — which is
    the property that makes replaying through the public API worth the async signature.
    """

    async def scenario() -> None:
        store = await JournalBackedGraphStore.open(tmp_path)
        await store.upsert_entity(_domain("glass-anvil.example"))

        journal = store.journal_path
        journal.write_text(
            journal.read_text() + '{"op": "entity", "payload": {"entity_id": "nope"}}\n'
        )

        with pytest.raises(JournalError, match="does not replay into a valid record"):
            await JournalBackedGraphStore.open(tmp_path)

    asyncio.run(scenario())


def test_an_unknown_operation_refuses_to_open(tmp_path: Path) -> None:
    """A journal written by a newer build is not something to guess at."""

    async def scenario() -> None:
        store = await JournalBackedGraphStore.open(tmp_path)
        await store.upsert_entity(_domain("glass-anvil.example"))
        store.journal_path.write_text(
            store.journal_path.read_text() + '{"op": "teleport", "payload": {}}\n'
        )

        with pytest.raises(JournalError, match="unknown op"):
            await JournalBackedGraphStore.open(tmp_path)

    asyncio.run(scenario())


def test_replaying_does_not_double_the_journal(tmp_path: Path) -> None:
    """Opening a store must not rewrite its own history.

    Without the replay guard every open would append everything it just read, and the file
    would double on each restart — durability that destroys itself on the fourth deploy.
    """

    async def scenario() -> None:
        first = await JournalBackedGraphStore.open(tmp_path)
        await first.upsert_entity(_domain("glass-anvil.example"))
        lines = len(first.journal_path.read_text().splitlines())

        await JournalBackedGraphStore.open(tmp_path)
        await JournalBackedGraphStore.open(tmp_path)

        assert len(first.journal_path.read_text().splitlines()) == lines

    asyncio.run(scenario())


def test_an_edge_recorded_against_a_pre_merge_id_still_replays(tmp_path: Path) -> None:
    """The journal records the call, not the outcome — and the first version did not.

    `upsert_entity` merges a new record into an existing one under the existing id, and
    registers the pre-merge id in an alias map so an edge recorded against it is not
    orphaned. That map is built by the *sequence of calls*. Journalling merged results
    replayed a graph in which those aliases never existed, and every edge naming a pre-merge
    id refused to load — which the end-to-end run caught, because the real scenario does
    exactly this and a hand-written fixture did not.
    """

    async def scenario() -> None:
        first = await JournalBackedGraphStore.open(tmp_path)
        original = _domain("glass-anvil.example")
        await first.upsert_entity(original)

        # The same thing, seen again by another collector under a fresh identifier.
        second_sighting = original.model_copy(update={"entity_id": new_id(IdPrefix.ENTITY)})
        await first.upsert_entity(second_sighting)

        other = _domain("anvil-works.example")
        await first.upsert_entity(other)
        # Recorded against the pre-merge identifier, which is what a collector holds.
        edge = _edge(second_sighting, other)
        await first.add_relationship(edge)

        reopened = await JournalBackedGraphStore.open(tmp_path)
        assert await reopened.relationship_count() == 1
        assert await reopened.entity_count() == 2

    asyncio.run(scenario())
