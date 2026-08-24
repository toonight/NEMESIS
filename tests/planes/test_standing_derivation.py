"""Deriving whose a node is from what the graph actually holds.

The rules here are deliberately harder to satisfy than they look, and the reason is a fact
about the world rather than a design preference: **registrant data is redacted**. The
project's own RDAP fixture returns ``entities.registrant: "REDACTED FOR PRIVACY"``, which is
what a real GDPR-era lookup returns too. So for a domain the adversary registered, the
platform can establish *control* and cannot establish *ownership*.

That is why the honest output for most adversary infrastructure is ``ACTOR_CONTROLLED`` rather
than ``ACTOR_OWNED``, and why ``COMPROMISED_LEGITIMATE`` — which needs a named owner who is not
the adversary — cannot be reached from collection alone. It needs somebody to say who owns the
host: an analyst submission or an authoritative record. Until then the answer is ``UNKNOWN``,
which blocks every disruptive operation, so the failure direction is safe.
"""

from __future__ import annotations

from datetime import UTC, datetime

from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.infrastructure import (
    OWNERSHIP_PREDICATE,
    ControlFacet,
    InfrastructureRole,
    derive_standing,
)
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent

NOW = datetime(2026, 3, 10, tzinfo=UTC)
EXTENT = TemporalExtent.at(NOW)

ADVERSARY = new_id(IdPrefix.ENTITY)
COMPANY = new_id(IdPrefix.ENTITY)


def node(entity_type: EntityType, observed: str) -> Entity:
    return Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=observed,
        extent=EXTENT,
        is_synthetic=True,
    )


def supporting_claim(asserter: str) -> Claim:
    return Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="domain:portal.example",
            predicate="observed",
            obj="something",
            natural_language="An observation backing an edge.",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=asserter,
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=(content_id(IdPrefix.EVIDENCE, asserter.encode()),),
    )


def edge(
    *,
    source: Entity,
    target: Entity,
    relation: RelationType,
    claims: tuple[Claim, ...],
    belief: float = 0.8,
) -> Relationship:
    return Relationship(
        edge_id=new_id(IdPrefix.EDGE),
        source_id=source.entity_id,
        target_id=target.entity_id,
        source_type=source.entity_type,
        target_type=target.entity_type,
        relation=relation,
        extent=EXTENT,
        confidence=Opinion(belief=belief, disbelief=0.05, uncertainty=1.0 - belief - 0.05),
        pivot_method=PivotMethod.DIRECT_OBSERVATION,
        supporting_claims=tuple(c.claim_id for c in claims),
        is_synthetic=True,
    )


def ownership_claim(*, subject: Entity, owner: str, derivation: DerivationKind) -> Claim:
    return Claim.create(
        kind=ClaimKind.FACT
        if derivation is DerivationKind.AUTHORITATIVE_RECORD
        else ClaimKind.INFERENCE,
        statement=Statement(
            subject=f"{subject.entity_type.value}:{subject.natural_key}",
            predicate=OWNERSHIP_PREDICATE,
            obj=owner,
            natural_language=f"{subject.natural_key} is owned by {owner}.",
        ),
        derivation=derivation,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=(
            (content_id(IdPrefix.EVIDENCE, b"a sealed corporate record"),)
            if derivation is DerivationKind.AUTHORITATIVE_RECORD
            else ()
        ),
        model_identifier="gpt-5-cyber" if derivation is DerivationKind.MODEL_ASSERTION else None,
    )


# -- the invariant: observed use establishes nothing about whose it is -------------


def test_observed_use_alone_yields_unknown() -> None:
    """The whole point, at the point where a classification is produced.

    Traffic to a C2, a redirect chain, delivery of a payload — every one of these is the node
    being *used*, and none of them says whose it is.
    """
    portal = node(EntityType.DOMAIN, "portal.example")
    c2 = node(EntityType.C2_INFRASTRUCTURE, "c2.example")
    claims = (supporting_claim(new_id(IdPrefix.ACTOR)),)

    standing = derive_standing(
        portal,
        relationships=(
            edge(source=portal, target=c2, relation=RelationType.COMMUNICATES_WITH, claims=claims),
        ),
        claims=claims,
        assessed_at=NOW,
    )

    assert standing.role is InfrastructureRole.UNKNOWN
    assert standing.facet_for(ControlFacet.OBSERVED_USE) is not None
    assert standing.facet_for(ControlFacet.CURRENT_CONTROL) is None
    assert not standing.is_established


def test_a_thousand_observations_of_use_still_yield_unknown() -> None:
    """Volume is not a different kind of evidence. It is the same kind, repeated."""
    portal = node(EntityType.DOMAIN, "portal.example")
    c2 = node(EntityType.C2_INFRASTRUCTURE, "c2.example")
    claims = tuple(supporting_claim(new_id(IdPrefix.ACTOR)) for _ in range(50))
    edges = tuple(
        edge(source=portal, target=c2, relation=RelationType.COMMUNICATES_WITH, claims=claims)
        for _ in range(20)
    )

    standing = derive_standing(portal, relationships=edges, claims=claims, assessed_at=NOW)
    assert standing.role is InfrastructureRole.UNKNOWN


# -- control, without ownership -----------------------------------------------------


def test_actor_control_without_ownership_is_actor_controlled_not_actor_owned() -> None:
    """The honest classification for a domain the adversary registered behind redaction.

    Bulletproof hosting is rented and registrant data is redacted, so control is what the
    platform can establish. Calling it ACTOR_OWNED would be asserting a fact about a registry
    nobody read.
    """
    portal = node(EntityType.DOMAIN, "portal.example")
    actor = node(EntityType.THREAT_ACTOR, "glass-anvil")
    claims = (supporting_claim(new_id(IdPrefix.ACTOR)), supporting_claim(new_id(IdPrefix.ACTOR)))

    standing = derive_standing(
        portal,
        relationships=(
            edge(source=actor, target=portal, relation=RelationType.CONTROLS, claims=claims),
        ),
        claims=claims,
        assessed_at=NOW,
    )

    assert standing.role is InfrastructureRole.ACTOR_CONTROLLED
    assert standing.controller() is not None
    assert standing.owner() is None


def test_control_by_a_company_is_not_adversary_infrastructure() -> None:
    """An ORGANIZATION controlling its own asset is a normal server, not a finding.

    EntityCategory.ACTOR contains ORGANIZATION alongside THREAT_ACTOR, so category alone
    cannot tell the adversary from a company. The derivation keys on entity *type*.
    """
    portal = node(EntityType.DOMAIN, "initech-payments.example")
    company = node(EntityType.ORGANIZATION, "Initech")
    claims = (supporting_claim(new_id(IdPrefix.ACTOR)),)

    standing = derive_standing(
        portal,
        relationships=(
            edge(source=company, target=portal, relation=RelationType.CONTROLS, claims=claims),
        ),
        claims=claims,
        assessed_at=NOW,
    )
    assert standing.role is not InfrastructureRole.ACTOR_CONTROLLED
    assert standing.role is not InfrastructureRole.ACTOR_OWNED


# -- the §6 case, which needs somebody to say who owns the host ---------------------


def test_a_compromised_legitimate_host_needs_an_ownership_claim() -> None:
    """Adversary control plus a named non-adversary owner. This is the case the mission
    exists for, and it cannot be reached from collection alone."""
    site = node(EntityType.DOMAIN, "initech-blog.example")
    actor = node(EntityType.THREAT_ACTOR, "glass-anvil")
    control_claims = (supporting_claim(new_id(IdPrefix.ACTOR)),)
    owner = ownership_claim(
        subject=site, owner="organization:Initech", derivation=DerivationKind.AUTHORITATIVE_RECORD
    )

    standing = derive_standing(
        site,
        relationships=(
            edge(source=actor, target=site, relation=RelationType.CONTROLS, claims=control_claims),
        ),
        claims=(*control_claims, owner),
        assessed_at=NOW,
    )

    assert standing.role is InfrastructureRole.COMPROMISED_LEGITIMATE
    assert standing.owner() == "organization:Initech"
    assert standing.controller() != standing.owner()


def test_a_model_asserted_owner_does_not_establish_ownership() -> None:
    """Invariant 1 at the producer. A pilot deciding who owns a host must not reclassify it.

    The consequence is the safe one: without an admissible ownership claim the node stays
    ACTOR_CONTROLLED, which is *more* permissive for disruption — so this is not the platform
    protecting itself, it is the platform refusing to launder a guess into a fact in either
    direction.
    """
    site = node(EntityType.DOMAIN, "initech-blog.example")
    actor = node(EntityType.THREAT_ACTOR, "glass-anvil")
    control_claims = (supporting_claim(new_id(IdPrefix.ACTOR)),)
    guessed = ownership_claim(
        subject=site, owner="organization:Initech", derivation=DerivationKind.MODEL_ASSERTION
    )

    standing = derive_standing(
        site,
        relationships=(
            edge(source=actor, target=site, relation=RelationType.CONTROLS, claims=control_claims),
        ),
        claims=(*control_claims, guessed),
        assessed_at=NOW,
    )
    assert standing.owner() is None
    assert standing.role is InfrastructureRole.ACTOR_CONTROLLED


def test_ownership_by_the_adversary_themselves_is_actor_owned() -> None:
    site = node(EntityType.DOMAIN, "glass-anvil-shop.example")
    actor = node(EntityType.THREAT_ACTOR, "glass-anvil")
    control_claims = (supporting_claim(new_id(IdPrefix.ACTOR)),)
    owner = ownership_claim(
        subject=site,
        owner=f"{EntityType.THREAT_ACTOR.value}:glass-anvil",
        derivation=DerivationKind.AUTHORITATIVE_RECORD,
    )

    standing = derive_standing(
        site,
        relationships=(
            edge(source=actor, target=site, relation=RelationType.CONTROLS, claims=control_claims),
        ),
        claims=(*control_claims, owner),
        assessed_at=NOW,
    )
    assert standing.role is InfrastructureRole.ACTOR_OWNED


# -- shared and victim infrastructure ----------------------------------------------


def test_shared_infrastructure_wins_over_observed_adversary_use() -> None:
    """§31: shared hosting mistaken for dedicated C2.

    A registrar carries tens of thousands of unrelated parties. Adversary traffic through it
    is not a reason to act against it, and the derivation must not let use outrank that.
    """
    registrar = node(EntityType.REGISTRAR, "bulletproofreg")
    actor = node(EntityType.THREAT_ACTOR, "glass-anvil")
    claims = (supporting_claim(new_id(IdPrefix.ACTOR)),)

    standing = derive_standing(
        registrar,
        relationships=(
            edge(source=actor, target=registrar, relation=RelationType.CONTROLS, claims=claims),
        ),
        claims=claims,
        assessed_at=NOW,
    )
    assert standing.role is InfrastructureRole.SHARED_INFRASTRUCTURE


def test_a_victim_node_is_victim_infrastructure() -> None:
    victim = node(EntityType.VICTIM, "acme-corp")
    standing = derive_standing(victim, relationships=(), claims=(), assessed_at=NOW)
    assert standing.role is InfrastructureRole.VICTIM_INFRASTRUCTURE


def test_a_node_with_nothing_known_about_it_is_unknown() -> None:
    orphan = node(EntityType.DOMAIN, "nothing-known.example")
    standing = derive_standing(orphan, relationships=(), claims=(), assessed_at=NOW)
    assert standing.role is InfrastructureRole.UNKNOWN
    assert standing.facets == ()


# -- the derivation is honest about how independent its sources are ----------------


def test_independent_origins_count_distinct_asserters() -> None:
    portal = node(EntityType.DOMAIN, "portal.example")
    actor = node(EntityType.THREAT_ACTOR, "glass-anvil")
    one = new_id(IdPrefix.ACTOR)
    claims = (
        supporting_claim(one),
        supporting_claim(one),
        supporting_claim(new_id(IdPrefix.ACTOR)),
    )

    standing = derive_standing(
        portal,
        relationships=(
            edge(source=actor, target=portal, relation=RelationType.CONTROLS, claims=claims),
        ),
        claims=claims,
        assessed_at=NOW,
    )
    control = standing.facet_for(ControlFacet.CURRENT_CONTROL)
    assert control is not None
    assert control.independent_source_count == 2
    assert "asserter" in control.basis
