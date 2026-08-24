"""The infrastructure-role model: ownership, control, use and responsibility kept apart.

The mission these tests protect is a single sentence: *observing an adversary use a piece of
infrastructure tells you nothing about whose it is*. Every test below is a way of getting that
wrong, written down so it cannot be got wrong quietly.

The four facets are separate objects rather than four fields on one, because the failure this
prevents is the one the disruption plane already made: ``OwnershipEvidence`` is named for
ownership and, in its only production construction, is derived from the attribution dimension
whose question is common *control*. One object with four fields would be filled in by whoever
had one of them.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from nemesis.core.authorization import OperationClass
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.infrastructure import (
    DISRUPTIVE_OPERATIONS,
    OBSERVE_AND_PRESERVE_OPERATIONS,
    ROLE_ATTRIBUTE,
    THIRD_PARTY_ENGAGEMENT_OPERATIONS,
    ControlFacet,
    FacetAssessment,
    InfrastructureRole,
    RoleAssessment,
    eligible_roles,
    is_role_eligible,
    role_attributes,
)
from nemesis.core.temporal import TemporalExtent

NOW = datetime(2026, 3, 10, tzinfo=UTC)


def facet(
    which: ControlFacet,
    *,
    holder: str = "actor:glass-anvil",
    belief: float = 0.8,
    sources: int = 3,
) -> FacetAssessment:
    return FacetAssessment(
        facet=which,
        holder=holder,
        opinion=Opinion(belief=belief, disbelief=0.05, uncertainty=1.0 - belief - 0.05),
        independent_source_count=sources,
        basis="a registrant record and two independent passive-DNS observations",
        extent=TemporalExtent.at(NOW),
    )


def assessment(
    role: InfrastructureRole,
    *facets: FacetAssessment,
    belief: float = 0.8,
) -> RoleAssessment:
    return RoleAssessment(
        entity_id=new_id(IdPrefix.ENTITY),
        natural_key="evil.example",
        role=role,
        opinion=Opinion(belief=belief, disbelief=0.05, uncertainty=1.0 - belief - 0.05),
        facets=facets,
        assessed_at=NOW,
    )


# -- the four facets are independent -----------------------------------------------


def test_the_four_facets_are_four_separate_questions() -> None:
    assert set(ControlFacet) == {
        ControlFacet.LEGAL_OWNERSHIP,
        ControlFacet.CURRENT_CONTROL,
        ControlFacet.OBSERVED_USE,
        ControlFacet.ATTRIBUTED_RESPONSIBILITY,
    }


def test_observed_use_alone_cannot_produce_an_actor_owned_role() -> None:
    """The mission's central distinction. MALICIOUS_USE != ATTACKER_OWNED."""
    with pytest.raises(ValidationError, match="legal_ownership"):
        assessment(InfrastructureRole.ACTOR_OWNED, facet(ControlFacet.OBSERVED_USE))


def test_observed_use_alone_cannot_produce_an_actor_controlled_role() -> None:
    """ATTACKER_CONTROLLED != OBSERVED_IN_ATTACK either."""
    with pytest.raises(ValidationError, match="current_control"):
        assessment(InfrastructureRole.ACTOR_CONTROLLED, facet(ControlFacet.OBSERVED_USE))


def test_control_evidence_does_not_establish_ownership() -> None:
    """A host the adversary controls today may be a company's, lawfully theirs tomorrow."""
    with pytest.raises(ValidationError, match="legal_ownership"):
        assessment(InfrastructureRole.ACTOR_OWNED, facet(ControlFacet.CURRENT_CONTROL))


def test_a_compromised_legitimate_host_needs_an_owner_who_is_not_the_actor() -> None:
    """Calling a host 'compromised legitimate' is a claim about who owns it."""
    with pytest.raises(ValidationError, match="legal_ownership"):
        assessment(InfrastructureRole.COMPROMISED_LEGITIMATE, facet(ControlFacet.CURRENT_CONTROL))


def test_a_compromised_legitimate_host_is_well_formed_with_both_facets() -> None:
    """The canonical §6 case: the adversary controls it, an innocent party owns it."""
    result = assessment(
        InfrastructureRole.COMPROMISED_LEGITIMATE,
        facet(ControlFacet.LEGAL_OWNERSHIP, holder="organization:initech"),
        facet(ControlFacet.CURRENT_CONTROL, holder="actor:glass-anvil"),
    )
    assert result.role is InfrastructureRole.COMPROMISED_LEGITIMATE
    assert result.owner() == "organization:initech"
    assert result.controller() == "actor:glass-anvil"
    assert result.owner() != result.controller()


def test_one_facet_may_not_be_asserted_twice() -> None:
    with pytest.raises(ValidationError, match="once"):
        assessment(
            InfrastructureRole.ACTOR_OWNED,
            facet(ControlFacet.LEGAL_OWNERSHIP),
            facet(ControlFacet.LEGAL_OWNERSHIP, holder="organization:someone-else"),
        )


# -- UNKNOWN is a first-class answer -----------------------------------------------


def test_unknown_is_valid_with_no_facets_at_all() -> None:
    """'We do not know' must be expressible, or the model forces a guess."""
    result = RoleAssessment(
        entity_id=new_id(IdPrefix.ENTITY),
        natural_key="unclassified.example",
        role=InfrastructureRole.UNKNOWN,
        opinion=Opinion.vacuous(),
        assessed_at=NOW,
    )
    assert result.role is InfrastructureRole.UNKNOWN
    assert result.facets == ()
    assert result.is_established is False


def test_a_classified_role_may_not_rest_on_nothing() -> None:
    with pytest.raises(ValidationError, match="at least one facet"):
        assessment(InfrastructureRole.ACTOR_CONTROLLED)


def test_a_classified_role_may_not_rest_on_a_vacuous_opinion() -> None:
    """Nobody looked is not a classification, however confident the label sounds."""
    with pytest.raises(ValidationError, match="vacuous"):
        RoleAssessment(
            entity_id=new_id(IdPrefix.ENTITY),
            natural_key="evil.example",
            role=InfrastructureRole.ACTOR_CONTROLLED,
            opinion=Opinion.vacuous(),
            facets=(facet(ControlFacet.CURRENT_CONTROL),),
            assessed_at=NOW,
        )


# -- facet strength ----------------------------------------------------------------


def test_a_single_sourced_facet_is_weak_however_confident_it_sounds() -> None:
    lone = facet(ControlFacet.LEGAL_OWNERSHIP, belief=0.94, sources=1)
    assert lone.is_single_sourced
    assert lone.is_weak
    assert "single-sourced" in lone.describe()


def test_a_facet_below_the_confidence_floor_is_weak() -> None:
    """Corroborated by four origins and still too thin: the floor is not a source count.

    The opinion here is mostly *disbelief*, not uncertainty — the sources agree, and what they
    agree on is that this party probably does not own it.
    """
    thin = FacetAssessment(
        facet=ControlFacet.LEGAL_OWNERSHIP,
        holder="actor:glass-anvil",
        opinion=Opinion(belief=0.30, disbelief=0.55, uncertainty=0.15),
        independent_source_count=4,
        basis="four registrant records naming somebody else",
        extent=TemporalExtent.at(NOW),
    )
    assert not thin.is_single_sourced
    assert thin.band is not ConfidenceBand.INSUFFICIENT_BASIS
    assert thin.opinion.projected_probability < 0.55
    assert thin.is_weak


def test_a_facet_with_no_basis_to_estimate_is_weak() -> None:
    vacuous = FacetAssessment(
        facet=ControlFacet.LEGAL_OWNERSHIP,
        holder="actor:glass-anvil",
        opinion=Opinion.vacuous(),
        independent_source_count=4,
        basis="nobody has looked",
        extent=TemporalExtent.at(NOW),
    )
    assert vacuous.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert vacuous.is_weak


def test_a_corroborated_confident_facet_is_not_weak() -> None:
    sound = facet(ControlFacet.LEGAL_OWNERSHIP, belief=0.8, sources=3)
    assert not sound.is_weak


# -- the eligibility table ---------------------------------------------------------


def test_every_operation_class_falls_in_exactly_one_tier() -> None:
    """A new operation class must be placed deliberately, not defaulted into eligibility."""
    tiers = (
        OBSERVE_AND_PRESERVE_OPERATIONS,
        THIRD_PARTY_ENGAGEMENT_OPERATIONS,
        DISRUPTIVE_OPERATIONS,
    )
    union: set[OperationClass] = set()
    for tier in tiers:
        assert not (union & tier), "an operation class appears in two tiers"
        union |= tier
    assert union == set(OperationClass)


def test_malicious_use_alone_never_authorizes_disruption() -> None:
    """The mission's core invariant, at the level of the table.

    Every role that means 'someone other than the adversary owns this, or we cannot tell'
    is refused for every disruptive operation.
    """
    protected = {
        InfrastructureRole.UNKNOWN,
        InfrastructureRole.COMPROMISED_LEGITIMATE,
        InfrastructureRole.ABUSED_LEGITIMATE_SERVICE,
        InfrastructureRole.VICTIM_INFRASTRUCTURE,
        InfrastructureRole.SHARED_INFRASTRUCTURE,
    }
    for operation in DISRUPTIVE_OPERATIONS:
        for role in protected:
            assert not is_role_eligible(operation, role), (
                f"{operation.value} must not be eligible against {role.value}"
            )


def test_only_actor_owned_and_actor_controlled_are_ever_disruption_eligible() -> None:
    for operation in DISRUPTIVE_OPERATIONS:
        assert eligible_roles(operation) == frozenset(
            {InfrastructureRole.ACTOR_OWNED, InfrastructureRole.ACTOR_CONTROLLED}
        )


def test_an_unclassified_target_may_still_be_observed_and_preserved() -> None:
    """§6 puts PRESERVE_EVIDENCE first, before anything is known. Failing closed on
    evidence preservation would destroy the record while we worked out whose host it is."""
    for operation in OBSERVE_AND_PRESERVE_OPERATIONS:
        assert is_role_eligible(operation, InfrastructureRole.UNKNOWN)


def test_an_unclassified_target_may_not_have_a_third_party_engaged_about_it() -> None:
    for operation in THIRD_PARTY_ENGAGEMENT_OPERATIONS:
        assert not is_role_eligible(operation, InfrastructureRole.UNKNOWN)


def test_a_compromised_legitimate_host_may_have_its_provider_notified() -> None:
    """The §6 answer: you do not take down a victim's server, you tell someone."""
    assert is_role_eligible(
        OperationClass.PROVIDER_NOTIFICATION, InfrastructureRole.COMPROMISED_LEGITIMATE
    )
    assert not is_role_eligible(
        OperationClass.TAKEDOWN_REQUEST_DRAFT, InfrastructureRole.COMPROMISED_LEGITIMATE
    )


def test_shared_hosting_is_not_a_dedicated_c2_however_malicious_the_traffic() -> None:
    """§31: shared hosting mistaken for dedicated C2."""
    shared = assessment(
        InfrastructureRole.SHARED_INFRASTRUCTURE,
        facet(ControlFacet.OBSERVED_USE, holder="actor:glass-anvil", belief=0.95, sources=6),
    )
    assert shared.role is InfrastructureRole.SHARED_INFRASTRUCTURE
    for operation in DISRUPTIVE_OPERATIONS:
        assert not is_role_eligible(operation, shared.role)


# -- the projection onto entity attributes -----------------------------------------


def test_the_role_projects_onto_an_entity_attribute() -> None:
    """The enforcement point sees a dict[str,str], so the role must survive as one."""
    result = assessment(InfrastructureRole.ACTOR_CONTROLLED, facet(ControlFacet.CURRENT_CONTROL))
    attributes = role_attributes(result)
    assert attributes[ROLE_ATTRIBUTE] == "actor_controlled"


def test_the_projection_round_trips_through_the_role_vocabulary() -> None:
    for role in InfrastructureRole:
        rendered = RoleAssessment.projected_role(role)
        assert InfrastructureRole(rendered) is role


def test_the_projection_of_an_unknown_role_is_present_and_says_unknown() -> None:
    """An absent attribute and an attribute saying 'unknown' must not be the same thing.

    Absent means nobody looked, and the effects boundary already refuses that. Present-and-
    unknown means somebody looked and could not tell, which is a different fact.
    """
    result = RoleAssessment(
        entity_id=new_id(IdPrefix.ENTITY),
        natural_key="unclassified.example",
        role=InfrastructureRole.UNKNOWN,
        opinion=Opinion.vacuous(),
        assessed_at=NOW,
    )
    assert role_attributes(result)[ROLE_ATTRIBUTE] == "unknown"


# -- invariant 1 on this surface: a model assertion does not establish ownership ----


def claim_of(kind: ClaimKind, derivation: DerivationKind) -> Claim:
    return Claim.create(
        kind=kind,
        statement=Statement(
            subject="domain:evil.example",
            predicate="controlled_by",
            obj="actor:glass-anvil",
            natural_language="The portal is operated by GLASS ANVIL.",
        ),
        derivation=derivation,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=TemporalExtent.at(NOW),
        # Observations and facts must rest on preserved material; hypotheses must not pretend to.
        supported_by_evidence=(
            (content_id(IdPrefix.EVIDENCE, b"a sealed WHOIS record"),)
            if kind in {ClaimKind.OBSERVATION, ClaimKind.FACT}
            else ()
        ),
        model_identifier="test-model" if derivation is DerivationKind.MODEL_ASSERTION else None,
    )


def test_a_facet_may_not_be_built_from_a_model_assertion() -> None:
    """Invariant 1, applied to the surface that decides whether an effect may run.

    A pilot can already state a belief; it is stored as a HYPOTHESIS derived from
    MODEL_ASSERTION and cannot outrank what it cites. Nothing stopped that claim being handed
    to an ownership facet, where it would have become the basis of a takedown.
    """
    model_said_so = claim_of(ClaimKind.HYPOTHESIS, DerivationKind.MODEL_ASSERTION)
    with pytest.raises(ValueError, match="model"):
        FacetAssessment.from_claims(
            facet=ControlFacet.LEGAL_OWNERSHIP,
            holder="actor:glass-anvil",
            opinion=Opinion(belief=0.8, disbelief=0.05, uncertainty=0.15),
            independent_source_count=3,
            basis="the pilot said so",
            claims=(model_said_so,),
            extent=TemporalExtent.at(NOW),
        )


def test_a_facet_built_from_an_authoritative_record_is_accepted() -> None:
    record = claim_of(ClaimKind.FACT, DerivationKind.AUTHORITATIVE_RECORD)
    built = FacetAssessment.from_claims(
        facet=ControlFacet.LEGAL_OWNERSHIP,
        holder="organization:initech",
        opinion=Opinion(belief=0.8, disbelief=0.05, uncertainty=0.15),
        independent_source_count=3,
        basis="the registrant record",
        claims=(record,),
        extent=TemporalExtent.at(NOW),
    )
    assert built.supporting_claims == (record.claim_id,)
    assert not built.is_weak


def test_one_model_claim_among_good_ones_still_refuses() -> None:
    """The tainted input must not be laundered by the company it keeps."""
    with pytest.raises(ValueError, match="model"):
        FacetAssessment.from_claims(
            facet=ControlFacet.CURRENT_CONTROL,
            holder="actor:glass-anvil",
            opinion=Opinion(belief=0.8, disbelief=0.05, uncertainty=0.15),
            independent_source_count=3,
            basis="two observations and a guess",
            claims=(
                claim_of(ClaimKind.OBSERVATION, DerivationKind.DIRECT_COLLECTION),
                claim_of(ClaimKind.HYPOTHESIS, DerivationKind.MODEL_ASSERTION),
            ),
            extent=TemporalExtent.at(NOW),
        )
