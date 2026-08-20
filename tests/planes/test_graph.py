"""Adversarial tests for the in-memory graph and claim stores.

Each test here targets one control that, removed, would let a specific analytic failure
through: a duplicated node that turns three weak links into a cluster, a merge that erases
the interval which justified a pivot, a two-hop traversal through a registrar that returns
half the internet, a weak edge laundered by proximity to a strong one, or a poisoned
derivation chain that never terminates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

import pytest

from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.graph.memory import InMemoryClaimStore, InMemoryGraphStore, widen_extent
from nemesis.ports.storage import GraphQuery

MARCH_START = datetime(2026, 3, 1, tzinfo=UTC)
MARCH_END = datetime(2026, 3, 31, tzinfo=UTC)
DECEMBER = datetime(2026, 12, 1, tzinfo=UTC)
JULY = datetime(2026, 7, 1, tzinfo=UTC)

STRONG = Opinion(belief=0.90, disbelief=0.05, uncertainty=0.05, base_rate=0.10)
"""Projected probability 0.905."""

WEAK = Opinion(belief=0.02, disbelief=0.50, uncertainty=0.48, base_rate=0.10)
"""Projected probability 0.068 — below any threshold a real query would set."""

ANALYST = new_id(IdPrefix.ACTOR)


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Drive one store call to completion.

    The stores are ``async`` only because the ports declare them so: nothing in them awaits
    anything and no state is bound to an event loop, so a fresh loop per call is safe.
    """
    return asyncio.run(coroutine)


def _entity(
    entity_type: EntityType,
    observed_form: str,
    extent: TemporalExtent,
    *,
    entity_id: str | None = None,
    is_synthetic: bool = False,
    attributes: dict[str, str] | None = None,
) -> Entity:
    return Entity.create(
        entity_id=entity_id or new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=observed_form,
        attributes=attributes,
        extent=extent,
        is_synthetic=is_synthetic,
    )


def _edge(
    source: Entity,
    target: Entity,
    *,
    relation: RelationType = RelationType.RESOLVES_TO,
    extent: TemporalExtent,
    confidence: Opinion = STRONG,
) -> Relationship:
    return Relationship(
        edge_id=new_id(IdPrefix.EDGE),
        source_id=source.entity_id,
        target_id=target.entity_id,
        source_type=source.entity_type,
        target_type=target.entity_type,
        relation=relation,
        extent=extent,
        confidence=confidence,
        pivot_method=PivotMethod.DIRECT_OBSERVATION,
    )


def _claim(
    claim_id: str,
    *,
    text: str,
    derived_from: tuple[str, ...] = (),
    notes: str | None = None,
) -> Claim:
    """A claim with a caller-chosen id.

    Built through the model rather than through :meth:`Claim.create` because content
    addressing makes some of the shapes tested here — a derivation cycle above all —
    impossible to mint honestly. The store holds whatever it is handed, which is the
    situation under test.
    """
    return Claim(
        claim_id=claim_id,
        kind=ClaimKind.HYPOTHESIS,
        statement=Statement(
            subject="persona:GlassAnvil",
            predicate="same_operator_as",
            obj="persona:AnvilWorks",
            natural_language=text,
        ),
        derivation=DerivationKind.EXTERNAL_REPORT,
        asserted_by=ANALYST,
        asserted_at=MARCH_START,
        valid_extent=TemporalExtent.at(MARCH_START),
        derived_from_claims=derived_from,
        notes=notes,
    )


# --- merging on the natural key ----------------------------------------------


def test_a_december_observation_of_march_activity_widens_the_extent_backwards() -> None:
    store = InMemoryGraphStore()
    first_seen_in_december = _entity(
        EntityType.DOMAIN,
        "acme-invoice-portal.example",
        TemporalExtent.between(DECEMBER, DECEMBER),
    )
    learned_later_about_march = _entity(
        EntityType.DOMAIN,
        "acme-invoice-portal.example",
        TemporalExtent.between(MARCH_START, MARCH_END),
    )

    run(store.upsert_entity(first_seen_in_december))
    merged = run(store.upsert_entity(learned_later_about_march))

    # Overwriting instead of widening would erase the March window — the very interval
    # that made the pivot worth spending on.
    assert merged.extent.known_from == MARCH_START
    assert merged.extent.known_until == DECEMBER
    assert run(store.entity_count()) == 1


def test_widening_never_manufactures_a_bound_no_source_established() -> None:
    registrar_record = TemporalExtent.closed(MARCH_START, MARCH_END)
    passive_dns_sighting = TemporalExtent.between(JULY, JULY)

    widened = widen_extent(registrar_record, passive_dns_sighting)

    # One source bounded the interval, the other did not. Keeping the bounded value
    # because it is "more informative" would assert a start and an end that nothing
    # observed.
    assert widened.possible_from is None
    assert widened.possible_until is None
    assert widened.known_from == MARCH_START
    assert widened.known_until == JULY


@pytest.mark.parametrize("synthetic_first", [True, False])
def test_a_merge_never_clears_is_synthetic(synthetic_first: bool) -> None:
    store = InMemoryGraphStore()
    extent = TemporalExtent.at(MARCH_START)
    first = _entity(EntityType.IP_ADDRESS, "198.51.100.23", extent, is_synthetic=synthetic_first)
    second = _entity(
        EntityType.IP_ADDRESS, "198.51.100.23", extent, is_synthetic=not synthetic_first
    )

    run(store.upsert_entity(first))
    merged = run(store.upsert_entity(second))

    # A synthetic node that loses the flag corrupts every confidence figure downstream of
    # it, and nothing in the graph would show that it happened.
    assert merged.is_synthetic


def test_a_merge_keeps_every_identifier_the_thing_was_ever_known_by_resolvable() -> None:
    store = InMemoryGraphStore()
    extent = TemporalExtent.at(MARCH_START)
    from_pdns = _entity(EntityType.DOMAIN, "EVIL.Example.COM", extent)
    from_ct_log = _entity(EntityType.DOMAIN, "evil.example.com", extent)
    assert from_pdns.entity_id != from_ct_log.entity_id

    run(store.upsert_entity(from_pdns))
    run(store.upsert_entity(from_ct_log))

    # One real-world thing, one node — and an edge already recorded against the second id
    # must still resolve, or the merge silently shrinks the graph.
    assert run(store.entity_count()) == 1
    resolved = run(store.get_entity(from_ct_log.entity_id))
    assert resolved is not None
    assert resolved.entity_id == from_pdns.entity_id


# --- valid time --------------------------------------------------------------


def test_neighbourhood_as_of_returns_the_state_then_not_todays_state_filtered() -> None:
    store = InMemoryGraphStore()
    domain = _entity(
        EntityType.DOMAIN, "acme-invoice-portal.example", TemporalExtent.at(MARCH_START)
    )
    march_address = _entity(EntityType.IP_ADDRESS, "198.51.100.23", TemporalExtent.at(MARCH_START))
    current_address = _entity(EntityType.IP_ADDRESS, "192.0.2.77", TemporalExtent.at(JULY))
    for entity in (domain, march_address, current_address):
        run(store.upsert_entity(entity))

    # Ended in March and known to have ended: it holds at the March instant and cannot
    # hold now.
    run(
        store.add_relationship(
            _edge(domain, march_address, extent=TemporalExtent.closed(MARCH_START, MARCH_END))
        )
    )
    # Began in July, open-ended: it holds now and demonstrably did not hold in March.
    run(
        store.add_relationship(
            _edge(domain, current_address, extent=TemporalExtent.between(JULY, JULY))
        )
    )

    in_march = run(
        store.neighbourhood(GraphQuery(entity_id=domain.entity_id, max_depth=1, as_of=MARCH_START))
    )
    now = run(store.neighbourhood(GraphQuery(entity_id=domain.entity_id, max_depth=1)))

    march_ids = {entity.entity_id for entity in in_march.entities}
    now_ids = {entity.entity_id for entity in now.entities}
    assert march_ids == {domain.entity_id, march_address.entity_id}
    assert now_ids == {domain.entity_id, current_address.entity_id}


def test_neighbourhood_refuses_a_naive_as_of() -> None:
    store = InMemoryGraphStore()
    domain = _entity(EntityType.DOMAIN, "acme.example", TemporalExtent.at(MARCH_START))
    run(store.upsert_entity(domain))

    with pytest.raises(ValueError, match="timezone-aware"):
        run(
            store.neighbourhood(
                GraphQuery(
                    entity_id=domain.entity_id,
                    as_of=datetime(2026, 3, 1),  # noqa: DTZ001 — the defect under test
                )
            )
        )


# --- the shared-infrastructure boundary --------------------------------------


def _registrar_neighbourhood(*, exclude: bool) -> tuple[set[str], tuple[str, ...], str, str]:
    store = InMemoryGraphStore()
    extent = TemporalExtent.between(MARCH_START, MARCH_END)
    ours = _entity(EntityType.DOMAIN, "acme-invoice-portal.example", extent)
    registrar = _entity(EntityType.REGISTRAR, "BulletproofReg", extent)
    unrelated = _entity(EntityType.DOMAIN, "someone-elses-shop.example", extent)
    for entity in (ours, registrar, unrelated):
        run(store.upsert_entity(entity))
    for domain in (ours, unrelated):
        run(
            store.add_relationship(
                _edge(
                    domain,
                    registrar,
                    relation=RelationType.REGISTERED_THROUGH,
                    extent=extent,
                )
            )
        )

    result = run(
        store.neighbourhood(
            GraphQuery(
                entity_id=ours.entity_id,
                max_depth=2,
                exclude_shared_infrastructure=exclude,
            )
        )
    )
    return (
        {entity.entity_id for entity in result.entities},
        result.excluded_shared_infrastructure,
        registrar.entity_id,
        unrelated.entity_id,
    )


def test_traversal_stops_at_shared_infrastructure_and_says_where_it_stopped() -> None:
    reached, excluded, registrar_id, unrelated_id = _registrar_neighbourhood(exclude=True)

    # The registrar is visible as a leaf — an analyst must see it is there — but nothing
    # behind it is reachable. Two domains sharing a registrar share it with millions.
    assert registrar_id in reached
    assert unrelated_id not in reached
    assert excluded == (registrar_id,)


def test_the_shared_infrastructure_boundary_is_what_withholds_the_unrelated_domain() -> None:
    reached, excluded, _, unrelated_id = _registrar_neighbourhood(exclude=False)

    # Without the control the same query walks straight through and returns a stranger's
    # domain as part of the cluster. This is the test that would fail if the control were
    # a no-op.
    assert unrelated_id in reached
    assert excluded == ()


# --- confidence, applied before an edge is crossed ---------------------------


def _confidence_chain() -> tuple[InMemoryGraphStore, list[Entity]]:
    store = InMemoryGraphStore()
    extent = TemporalExtent.between(MARCH_START, MARCH_END)
    seed = _entity(EntityType.DOMAIN, "acme-invoice-portal.example", extent)
    address = _entity(EntityType.IP_ADDRESS, "198.51.100.23", extent)
    weakly_linked = _entity(EntityType.DOMAIN, "coincidence.example", extent)
    behind_it = _entity(EntityType.IP_ADDRESS, "203.0.113.88", extent)
    for entity in (seed, address, weakly_linked, behind_it):
        run(store.upsert_entity(entity))

    run(store.add_relationship(_edge(seed, address, extent=extent, confidence=STRONG)))
    run(store.add_relationship(_edge(weakly_linked, address, extent=extent, confidence=WEAK)))
    run(store.add_relationship(_edge(weakly_linked, behind_it, extent=extent, confidence=STRONG)))
    return store, [seed, address, weakly_linked, behind_it]


def test_min_confidence_cuts_the_weak_edge_before_it_is_crossed() -> None:
    store, (seed, address, weakly_linked, behind_it) = _confidence_chain()

    filtered = run(
        store.neighbourhood(GraphQuery(entity_id=seed.entity_id, max_depth=3, min_confidence=0.5))
    )

    reached = {entity.entity_id for entity in filtered.entities}
    assert reached == {seed.entity_id, address.entity_id}
    # The strong edge behind the weak one is the laundering risk: filtering the finished
    # result would still have collected it.
    assert behind_it.entity_id not in reached
    assert weakly_linked.entity_id not in reached


def test_without_the_threshold_the_same_traversal_reaches_everything() -> None:
    store, (seed, _address, _weak, behind_it) = _confidence_chain()

    unfiltered = run(
        store.neighbourhood(GraphQuery(entity_id=seed.entity_id, max_depth=3, min_confidence=0.0))
    )

    assert behind_it.entity_id in {entity.entity_id for entity in unfiltered.entities}


def test_explain_connection_terminates_on_a_cyclic_neighbourhood() -> None:
    store = InMemoryGraphStore()
    extent = TemporalExtent.between(MARCH_START, MARCH_END)
    ring = [_entity(EntityType.DOMAIN, f"node{index}.example", extent) for index in range(3)]
    for entity in ring:
        run(store.upsert_entity(entity))
    for index, entity in enumerate(ring):
        run(
            store.add_relationship(
                _edge(
                    entity,
                    ring[(index + 1) % len(ring)],
                    relation=RelationType.CO_OCCURS_WITH,
                    extent=extent,
                )
            )
        )

    explanations = run(store.explain_connection(ring[0].entity_id, ring[2].entity_id))

    # A cycle in the graph must bound the walk rather than exhaust the stack.
    assert explanations
    assert len({explanation.edge_id for explanation in explanations}) == len(explanations)


# --- the claim store ---------------------------------------------------------


def test_recording_the_same_claim_twice_does_not_create_a_second_one() -> None:
    store = InMemoryClaimStore()
    claim = Claim.create(
        kind=ClaimKind.HYPOTHESIS,
        statement=Statement(
            subject="persona:GlassAnvil",
            predicate="same_operator_as",
            obj="persona:AnvilWorks",
            natural_language="the two personas publish one PGP fingerprint",
        ),
        derivation=DerivationKind.EXTERNAL_REPORT,
        asserted_by=ANALYST,
        asserted_at=MARCH_START,
        valid_extent=TemporalExtent.at(MARCH_START),
    )
    restated = claim.model_copy(update={"notes": "restated by a second agent"})

    first = run(store.record(claim))
    second = run(store.record(restated))

    # A claim id is a content address. Storing a restatement as a second claim is how one
    # source starts looking like two agreeing ones the moment anything counts corroboration.
    assert second.claim_id == first.claim_id
    assert second.notes is None


def test_supersession_leaves_both_versions_readable() -> None:
    store = InMemoryClaimStore()
    original = _claim(content_id(IdPrefix.CLAIM, b"original"), text="registrant is A. Nonymous")
    correction = _claim(content_id(IdPrefix.CLAIM, b"correction"), text="registrant is redacted")
    run(store.record(original))

    stored = run(store.supersede(original.claim_id, correction, reason="registrar corrected it"))

    assert stored.version.supersedes == original.claim_id
    assert stored.version.revision == 2
    # Reading the old id follows the correction forward...
    current = run(store.get(original.claim_id))
    assert current is not None
    assert current.claim_id == correction.claim_id
    # ...while the superseded version itself is still there to be challenged.
    previous = store.get_version(original.claim_id)
    assert previous is not None
    assert previous.statement.natural_language == "registrant is A. Nonymous"
    assert previous.version.superseded_at is not None
    assert store.supersession_reason(original.claim_id) == "registrar corrected it"


def test_an_unexplained_correction_is_refused() -> None:
    store = InMemoryClaimStore()
    original = _claim(content_id(IdPrefix.CLAIM, b"original"), text="registrant is A. Nonymous")
    correction = _claim(content_id(IdPrefix.CLAIM, b"correction"), text="registrant is redacted")
    run(store.record(original))

    # A correction with no stated reason is indistinguishable from tampering.
    with pytest.raises(ValueError, match="unexplained edit is tampering"):
        run(store.supersede(original.claim_id, correction, reason="   "))


def test_derivation_chain_terminates_on_a_poisoned_cycle() -> None:
    store = InMemoryClaimStore()
    left_id = content_id(IdPrefix.CLAIM, b"left")
    right_id = content_id(IdPrefix.CLAIM, b"right")
    left = _claim(left_id, text="left rests on right", derived_from=(right_id,))
    right = _claim(right_id, text="right rests on left", derived_from=(left_id,))
    run(store.record(left))
    run(store.record(right))

    chain = run(store.derivation_chain(left_id))

    # Content addressing makes an honest cycle impossible, but the store holds whatever it
    # is handed. A poisoned graph must bound the walk, not exhaust the stack.
    assert [claim.claim_id for claim in chain] == [left_id, right_id]


def test_derivation_chain_walks_the_cited_versions_not_their_replacements() -> None:
    store = InMemoryClaimStore()
    premise_id = content_id(IdPrefix.CLAIM, b"premise")
    premise = _claim(premise_id, text="the kit names RedOctober")
    conclusion = _claim(
        content_id(IdPrefix.CLAIM, b"conclusion"),
        text="RedOctober is responsible",
        derived_from=(premise_id,),
    )
    correction = _claim(content_id(IdPrefix.CLAIM, b"retraction"), text="the string was planted")
    run(store.record(premise))
    run(store.record(conclusion))
    run(store.supersede(premise_id, correction, reason="assessed as a planted false flag"))

    chain = run(store.derivation_chain(conclusion.claim_id))

    # What was reasoned from, not what we believe now: following supersessions here would
    # rewrite the history the chain exists to preserve.
    assert [claim.claim_id for claim in chain] == [conclusion.claim_id, premise_id]
    assert chain[1].statement.natural_language == "the kit names RedOctober"
