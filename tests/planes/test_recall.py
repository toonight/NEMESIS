"""Recall: whether the accumulated graph pays off, and whether it lies about doing so.

The brief calls the Global Adversary Graph the long-term strategic asset. An audit found that
nothing ever queried it for prior knowledge, so every investigation began blind. These tests are
about the query — and about the one distinction that decides whether it means anything: an
entity this run just wrote is not memory, however genuinely it is now in the graph.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import TemporalExtent
from nemesis.graph.memory import InMemoryGraphStore
from nemesis.graph.recall import (
    RecallVerdict,
    Recollection,
    recall,
    recall_entity,
    resurgence_candidates,
)

NOW = datetime(2026, 8, 17, tzinfo=UTC)
OPENED = NOW - timedelta(hours=2)  # this investigation opened two hours ago


def _entity(
    entity_type: EntityType, form: str, *, first_seen: datetime, last_seen: datetime | None = None
) -> Entity:
    return Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=form,
        extent=TemporalExtent.between(first_seen, last_seen or first_seen),
        is_synthetic=True,
    )


async def _graph(*entities: Entity) -> InMemoryGraphStore:
    store = InMemoryGraphStore()
    for entity in entities:
        await store.upsert_entity(entity)
    return store


def _recall(store: InMemoryGraphStore, entity_type: EntityType, key: str) -> Recollection:
    return asyncio.run(
        recall_entity(store, entity_type, key, investigation_opened_at=OPENED, now=NOW)
    )


# --- The distinction the whole feature rests on -------------------------------


def test_an_entity_this_investigation_discovered_is_not_prior_knowledge() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    Once a run pivots, what it found is in the graph — so "is it in the graph?" answers yes for
    everything and means nothing. Getting this backwards would make every investigation report
    itself as corroborated by history.
    """
    fresh = _entity(EntityType.DOMAIN, "acme-invoice-portal.example", first_seen=NOW)
    store = asyncio.run(_graph(fresh))

    result = _recall(store, EntityType.DOMAIN, fresh.natural_key)

    assert result.verdict is RecallVerdict.FIRST_SEEN_IN_THIS_INVESTIGATION
    assert result.is_prior_knowledge is False
    assert "not prior knowledge" in result.render()


def test_an_entity_observed_before_the_investigation_opened_is_recall() -> None:
    old = _entity(EntityType.DOMAIN, "seen-before.example", first_seen=NOW - timedelta(days=30))
    store = asyncio.run(_graph(old))

    result = _recall(store, EntityType.DOMAIN, old.natural_key)

    assert result.verdict is RecallVerdict.KNOWN_BEFORE
    assert result.is_prior_knowledge
    assert result.known_for is not None and result.known_for.days == 30


def test_a_long_known_entity_is_distinguished_from_a_recently_seen_one() -> None:
    """ "We saw this during the incident" and "we have been watching this" are different claims
    about the same node."""
    ancient = _entity(EntityType.DOMAIN, "old-friend.example", first_seen=NOW - timedelta(days=400))
    store = asyncio.run(_graph(ancient))

    assert (
        _recall(store, EntityType.DOMAIN, ancient.natural_key).verdict is RecallVerdict.LONG_KNOWN
    )


def test_an_entity_the_graph_has_never_seen_is_unknown() -> None:
    store = asyncio.run(_graph())
    result = _recall(store, EntityType.DOMAIN, "never-seen.example")

    assert result.verdict is RecallVerdict.UNKNOWN
    assert result.entity_id is None
    assert result.is_prior_knowledge is False


# --- Recall reports facts, never a score --------------------------------------


def test_recall_carries_the_caution_that_recognition_is_not_corroboration() -> None:
    """The dangerous reading of this feature, refused in the object itself.

    An artifact an adversary planted and we observed twice is an artifact an adversary planted.
    Recall must not become a confidence input, so it ships no number to be mistaken for one.
    """
    old = _entity(EntityType.DOMAIN, "seen-before.example", first_seen=NOW - timedelta(days=30))
    result = _recall(asyncio.run(_graph(old)), EntityType.DOMAIN, old.natural_key)

    assert "not corroboration" in result.caution
    blob = result.model_dump()
    assert not any(key in blob for key in ("confidence", "score", "belief", "opinion", "weight")), (
        "recall exposed something a caller could mistake for a confidence figure"
    )


def test_recall_reports_attribute_names_and_not_their_values() -> None:
    """A recall summary is read in a pilot briefing and an analyst list. What is on file is the
    useful part; the values are whatever a connector wrote."""
    node = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form="with-attrs.example",
        attributes={"registrar": "BulletproofReg", "resolves_to": "198.51.100.23"},
        extent=TemporalExtent.at(NOW - timedelta(days=10)),
        is_synthetic=True,
    )
    result = _recall(asyncio.run(_graph(node)), EntityType.DOMAIN, node.natural_key)

    assert result.recorded_attributes == ("registrar", "resolves_to")
    assert "BulletproofReg" not in str(result.model_dump())


# --- Across a set, and honest when the graph contributed nothing --------------


def test_a_report_separates_what_was_known_from_what_is_new() -> None:
    known = _entity(EntityType.DOMAIN, "old.example", first_seen=NOW - timedelta(days=200))
    fresh = _entity(EntityType.DOMAIN, "new.example", first_seen=NOW)
    store = asyncio.run(_graph(known, fresh))

    report = asyncio.run(
        recall(
            store,
            ((EntityType.DOMAIN, known.natural_key), (EntityType.DOMAIN, fresh.natural_key)),
            investigation_opened_at=OPENED,
            now=NOW,
        )
    )

    assert [r.natural_key for r in report.prior] == [known.natural_key]
    assert [r.natural_key for r in report.novel] == [fresh.natural_key]
    assert report.graph_paid_off is True


def test_a_report_says_plainly_when_the_graph_contributed_nothing() -> None:
    """The honest answer on a young deployment, and a platform whose central promise is
    persistent memory should be able to say it rather than implying value it has not accrued."""
    fresh = _entity(EntityType.DOMAIN, "new.example", first_seen=NOW)
    store = asyncio.run(_graph(fresh))

    report = asyncio.run(
        recall(
            store,
            ((EntityType.DOMAIN, fresh.natural_key),),
            investigation_opened_at=OPENED,
            now=NOW,
        )
    )

    assert report.graph_paid_off is False
    assert "contributed nothing" in report.render()


def test_deliverable_only_drops_internal_class_nodes_from_a_report() -> None:
    """Recall about a person is still material about a person. The fact that it came from memory
    rather than from this run changes nothing — so a report that travels to a pilot, and thus to
    a hosted model vendor, must filter exactly as a briefing does."""
    person = _entity(
        EntityType.HUMAN_IDENTITY_LEAD, "John Doe", first_seen=NOW - timedelta(days=200)
    )
    domain = _entity(EntityType.DOMAIN, "old.example", first_seen=NOW - timedelta(days=200))
    store = asyncio.run(_graph(person, domain))

    targets = (
        (EntityType.HUMAN_IDENTITY_LEAD, person.natural_key),
        (EntityType.DOMAIN, domain.natural_key),
    )
    unfiltered = asyncio.run(recall(store, targets, investigation_opened_at=OPENED, now=NOW))
    filtered = asyncio.run(
        recall(store, targets, investigation_opened_at=OPENED, now=NOW, deliverable_only=True)
    )

    assert len(unfiltered.recollections) == 2
    assert len(filtered.recollections) == 1
    assert "doe" not in filtered.render().lower()


# --- Resurgence, without firing on every CDN ----------------------------------


def test_shared_infrastructure_is_not_a_resurgence_candidate() -> None:
    """A CDN address known for two years is prior knowledge and means nothing. Treating it as
    recall would raise a resurgence signal on every investigation touching a large provider —
    the failure mode the graph traversal already refuses to expand through."""
    # A plain IP is NOT inherently shared — the domain reserves that for types where
    # co-location implies nothing about common control. Using one here was my own wrong
    # premise, caught by this test; the real shared types are hosting providers, registrars,
    # ASNs, netblocks, exchanges, proxy and Tor infrastructure.
    shared = _entity(
        EntityType.HOSTING_PROVIDER, "BigCloud Hosting", first_seen=NOW - timedelta(days=700)
    )
    attacker = _entity(EntityType.DOMAIN, "returning.example", first_seen=NOW - timedelta(days=300))
    store = asyncio.run(_graph(shared, attacker))

    report = asyncio.run(
        recall(
            store,
            (
                (EntityType.HOSTING_PROVIDER, shared.natural_key),
                (EntityType.DOMAIN, attacker.natural_key),
            ),
            investigation_opened_at=OPENED,
            now=NOW,
        )
    )
    candidates = resurgence_candidates(report)

    assert attacker.natural_key in candidates
    assert shared.natural_key not in candidates, (
        "a shared-infrastructure node became a resurgence hit; every investigation touching a "
        "large provider would raise one"
    )
