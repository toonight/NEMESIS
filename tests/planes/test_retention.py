"""Retention: the control that bounds the blast radius of every other control failing.

`EntityCategory` claimed it "drives retention policy" and `is_personal_data` claimed it
"triggers retention limits". Both were true about the intent and false about the code. These
tests are about the policy that makes them true, and about the two ways a retention policy is
normally hollow: by never firing on the thing that matters, and by letting "still interesting"
masquerade as a legal basis.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from nemesis.core.entities import Entity, EntityCategory, EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.retention import (
    DEFAULT_RETENTION,
    RetentionVerdict,
    assess,
    retention_class,
    sweep,
)
from nemesis.core.temporal import TemporalExtent

NOW = datetime(2026, 8, 17, tzinfo=UTC)


def _entity(entity_type: EntityType, observed_form: str, *, last_seen: datetime) -> Entity:
    return Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=observed_form,
        extent=TemporalExtent.at(last_seen),
        is_synthetic=True,
    )


# --- The node the policy exists for ------------------------------------------


def test_a_stale_human_identity_lead_is_due_for_erasure() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    An uncorroborated accusation about a named natural person, held by a platform that already
    refused to promote it to an attribution. A year without re-observation means it never
    corroborated — and that is the single most damaging thing here to still be holding.
    """
    lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", last_seen=NOW - timedelta(days=400))

    verdict = assess(lead, now=NOW)

    assert verdict.verdict is RetentionVerdict.DUE
    assert verdict.must_erase
    assert verdict.overdue_by is not None and verdict.overdue_by.days == 35
    assert "past its" in verdict.render()


def test_a_recently_observed_lead_is_within_its_period() -> None:
    lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", last_seen=NOW - timedelta(days=100))
    assert assess(lead, now=NOW).verdict is RetentionVerdict.WITHIN_PERIOD


def test_re_observation_restarts_the_clock() -> None:
    """A node seen again is current intelligence, not the record of an old suspicion.

    The clock runs from the last defensible observation rather than from creation, so this is
    the behaviour the design intends — stated as a test so a future change to "creation" is a
    visible decision rather than a silent one.
    """
    stale = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", last_seen=NOW - timedelta(days=400))
    refreshed = stale.model_copy(update={"extent": TemporalExtent.at(NOW - timedelta(days=5))})

    assert assess(stale, now=NOW).must_erase
    assert not assess(refreshed, now=NOW).must_erase


# --- Only what can identify a person carries a period ------------------------


def test_infrastructure_has_no_limit() -> None:
    """Persistent adversary memory is the strategic asset. Forgetting a domain harms nobody,
    and forgetting an organization would defeat the resurgence loop invariant 14 requires."""
    for entity_type, form in (
        (EntityType.DOMAIN, "acme-invoice-portal.example"),
        (EntityType.IP_ADDRESS, "198.51.100.23"),
        (EntityType.ORGANIZATION, "GLASS ANVIL"),
    ):
        node = _entity(entity_type, form, last_seen=NOW - timedelta(days=4000))
        assert assess(node, now=NOW).verdict is RetentionVerdict.NO_LIMIT, entity_type


def test_a_persona_is_regulated_because_it_can_resolve_to_a_person() -> None:
    """Pseudonymous is not anonymous — and linking a persona to a person is precisely what this
    platform tries to do, so the category cannot be treated as infrastructure."""
    persona = _entity(EntityType.PERSONA, "GlassAnvil", last_seen=NOW - timedelta(days=1200))
    verdict = assess(persona, now=NOW)

    assert verdict.category is EntityCategory.DIGITAL_IDENTITY
    assert verdict.verdict is RetentionVerdict.DUE


def test_a_persona_is_regulated_despite_filing_under_the_actor_category() -> None:
    """THE HOLE THESE TESTS FOUND, pinned so it cannot reopen.

    `PERSONA` and `ALIAS` sit in `ACTOR` — deliberately, because an organization is a
    deliverable actor — and `ACTOR` carries no retention period. A table keyed only on category
    therefore held personas forever: pseudonymous data about what may be one natural person,
    in the exact category this platform tries hardest to resolve to a human.

    `disclosure.py` already hit this and answered it with `PERSONA_ENTITY_TYPES`. Retention
    reuses that constant, so the two policies cannot drift about what counts as a persona.
    """
    from nemesis.core.disclosure import PERSONA_ENTITY_TYPES

    for entity_type in PERSONA_ENTITY_TYPES:
        rule = retention_class(entity_type)
        assert rule.is_regulated, (
            f"{entity_type.value} carries no retention period; a persona held forever is "
            "pseudonymous personal data held forever"
        )

    # And an organization, which is genuinely not a natural person, still has none.
    assert not retention_class(EntityType.ORGANIZATION).is_regulated


def test_every_entity_type_has_a_policy() -> None:
    """Nothing falls through unassessed. A type with no rule would be a type held forever by
    accident, which is how retention policies become decoration."""
    for entity_type in EntityType:
        rule = retention_class(entity_type)
        assert rule.rationale, entity_type
        assert rule.period is None or rule.period.days > 0


def test_the_regulated_categories_are_exactly_the_ones_touching_a_person() -> None:
    """A tripwire on the table. Adding or removing a period is a decision about personal data,
    and this makes it a visible one."""
    regulated = {category for category, rule in DEFAULT_RETENTION.items() if rule.is_regulated}
    assert regulated == {
        EntityCategory.HUMAN_IDENTITY,
        EntityCategory.VICTIM,
        EntityCategory.DIGITAL_IDENTITY,
    }


# --- "Still interesting" is not a legal basis --------------------------------


def test_a_legal_hold_keeps_a_node_past_its_period_and_names_the_instrument() -> None:
    lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", last_seen=NOW - timedelta(days=400))

    held = assess(lead, now=NOW, legal_hold_reference="CASE-GLASS-ANVIL-2026-0042")

    assert held.verdict is RetentionVerdict.HELD_UNDER_LEGAL_BASIS
    assert held.must_erase is False
    assert held.legal_hold_reference == "CASE-GLASS-ANVIL-2026-0042"
    assert "CASE-GLASS-ANVIL-2026-0042" in held.render()


def test_an_empty_hold_reference_does_not_hold_anything() -> None:
    """The reference is what stops "this is still interesting" from being recorded as a legal
    basis, so an empty one must not work."""
    lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", last_seen=NOW - timedelta(days=400))
    assert assess(lead, now=NOW, legal_hold_reference="").must_erase
    assert assess(lead, now=NOW, legal_hold_reference=None).must_erase


# --- The sweep reports, and admits what it does not cover --------------------


def test_a_sweep_separates_the_due_from_the_held_and_the_unregulated() -> None:
    population = (
        _entity(EntityType.DOMAIN, "acme-invoice-portal.example", last_seen=NOW),
        _entity(EntityType.HUMAN_IDENTITY_LEAD, "A Person", last_seen=NOW - timedelta(days=400)),
        _entity(EntityType.HUMAN_IDENTITY_LEAD, "B Person", last_seen=NOW - timedelta(days=400)),
        _entity(EntityType.PERSONA, "GlassAnvil", last_seen=NOW - timedelta(days=10)),
    )
    holds = {population[2].entity_id: "COURT-2026-77"}

    report = sweep(population, now=NOW, legal_holds=holds)

    assert len(report.assessments) == 4
    assert len(report.regulated) == 3  # the domain is not
    assert [item.entity_id for item in report.due] == [population[1].entity_id]
    assert [item.entity_id for item in report.held] == [population[2].entity_id]


def test_the_sweep_states_that_the_vault_is_not_covered() -> None:
    """The conflict this policy cannot resolve, said out loud rather than implied away.

    Erasure is scoped to the graph, which is mutable by design. Sealed evidence is append-only
    and hash-chained (invariant 10); removing an entry would break the chain that makes the
    vault worth having. A sweep that reported "3 erased" while the vault still held the person's
    name would be worse than no sweep.
    """
    report = sweep((), now=NOW)

    assert "RETENTION IN THE VAULT: NOT IMPLEMENTED" in report.render()
    assert "founder decision" in report.vault_notice


def test_a_sweep_over_nothing_is_not_an_error() -> None:
    report = sweep((), now=NOW)
    assert report.due == () and report.held == ()
