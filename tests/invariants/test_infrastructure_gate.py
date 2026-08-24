"""Malicious use alone never authorizes disruption — enforced where it cannot be argued with.

The mission's central invariant. Observing an adversary use a piece of infrastructure tells
you nothing about whose it is, and a platform that acts on the observation alone will
eventually suspend a small company's neglected WordPress install and record it as a result.

These tests exercise the invariant at the **effects boundary**, not in the disruption planner.
The planner already reasons about ownership and it is the wrong place for enforcement twice
over: ``.importlinter`` forbids ``nemesis.effects`` from importing ``nemesis.disrupt``, so a
verdict computed there structurally cannot reach execution; and
``DisruptionOption.is_executable_now`` ignores ownership entirely, so a weakly-owned option
already appears in ``DisruptionPlan.executable_now``. What the planner produces is advice. What
``preflight`` produces is a refusal.

The mechanism is one this repository already built, signed and adversarially tested, and then
left inert: a classification is bound into ``TargetFingerprint.bound_attributes``, covered by
the capability's signature, and re-observed from the graph by the mediator at execution. The
pilot never supplies it, an approver cannot omit it for an operation that needs it, and if the
target's classification changes between approval and execution the fingerprint stops matching.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.authorization import (
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.infrastructure import (
    DISRUPTIVE_OPERATIONS,
    ROLE_ATTRIBUTE,
    InfrastructureRole,
)
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import EffectsRegistry, default_registry
from nemesis.ports.effects import EffectOutcome, EffectRequest
from tests.support.identity import elevated, hardware_backed_issuer, verifier_over

pytestmark = pytest.mark.invariant

IDENTITIES, _ = hardware_backed_issuer()
ACTORS = verifier_over(IDENTITIES)
REQUESTER = elevated(IDENTITIES, "Requester", Role.ANALYST, Role.INVESTIGATION_LEAD)
APPROVER = elevated(IDENTITIES, "Approver", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER)
SECOND_APPROVER = elevated(
    IDENTITIES, "Second approver", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER
)
"""Irreversible operations need dual control, and the sweep below covers all of them."""
REQUESTER_ID = ACTORS.verify(REQUESTER).actor_id

ENTITY_ID = new_id(IdPrefix.ENTITY)
NATURAL_KEY = "invoice-portal.example"


def target_for(
    role: InfrastructureRole | None, *, resolves_to: str = "198.51.100.23"
) -> TargetFingerprint:
    """A target fingerprint, optionally binding a classification into the signed digest."""
    bound = {"resolves_to": resolves_to}
    if role is not None:
        bound[ROLE_ATTRIBUTE] = role.value
    return TargetFingerprint.create(
        entity_id=ENTITY_ID,
        entity_type="domain",
        natural_key=NATURAL_KEY,
        bound_attributes=bound,
    )


def gateway() -> AuthorizationGateway:
    return AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)


def registry(gw: AuthorizationGateway) -> EffectsRegistry:
    return default_registry(verifying_key=gw.verifying_key, revocations=gw.revocations)


def issued(
    gw: AuthorizationGateway, target: TargetFingerprint, operation: OperationClass
) -> AuthorizationCapability:
    """A properly signed, dual-approved capability. Nothing here is forged."""
    request = gw.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=REQUESTER,
        justification="Prepare the abuse package for this target.",
        targets=(target,),
        operations=frozenset({operation}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ToS abuse channel",
        max_effect_description="One unsent draft.",
        lifetime=timedelta(hours=2),
    )
    gw.approve(
        request.capability_id,
        approver=APPROVER,
        rationale="Reversible, internal, synthetic target.",
    )
    if request.required_approvals > 1:
        gw.approve(
            request.capability_id,
            approver=SECOND_APPROVER,
            rationale="Dual control for an operation we could not undo.",
        )
    return gw.issue(request.capability_id)


def request_against(
    target: TargetFingerprint, operation: OperationClass, observed: dict[str, str]
) -> EffectRequest:
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=operation,
        target_fingerprint=target.fingerprint,
        target_natural_key=target.natural_key,
        current_target_attributes=observed,
        parameters={"purpose": "abuse report"},
        requested_by=REQUESTER_ID,
        requested_at=utcnow(),
    )


# -- the invariant ------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_compromised_legitimate_host_is_refused_a_takedown_draft() -> None:
    """The §6 case, end to end.

    Everything about this request is legitimate: a real signature, two real approvers, a
    target whose state is exactly what was approved. It is refused because the host belongs to
    somebody who is not the adversary.
    """
    gw = gateway()
    target = target_for(InfrastructureRole.COMPROMISED_LEGITIMATE)
    capability = issued(gw, target, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    result = await registry(gw).execute(
        request_against(
            target,
            OperationClass.TAKEDOWN_REQUEST_DRAFT,
            dict(target.bound_attributes),
        ),
        capability,
    )

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert "compromised_legitimate" in result.detail
    assert result.external_contact_made is False
    assert result.produced_artifacts == ()


@pytest.mark.anyio
async def test_every_disruptive_operation_is_refused_against_every_protected_role() -> None:
    """The invariant swept across the whole cross product, not spot-checked.

    ``TAKEDOWN_REQUEST_DRAFT`` is the only disruptive class with an adapter; the rest refuse
    earlier, for having none. Both are refusals, and asserting the sweep means a future adapter
    cannot arrive without this gate already standing in front of it.
    """
    protected = (
        InfrastructureRole.UNKNOWN,
        InfrastructureRole.COMPROMISED_LEGITIMATE,
        InfrastructureRole.ABUSED_LEGITIMATE_SERVICE,
        InfrastructureRole.VICTIM_INFRASTRUCTURE,
        InfrastructureRole.SHARED_INFRASTRUCTURE,
    )
    for operation in sorted(DISRUPTIVE_OPERATIONS, key=lambda o: o.value):
        for role in protected:
            gw = gateway()
            target = target_for(role)
            capability = issued(gw, target, operation)
            result = await registry(gw).execute(
                request_against(target, operation, dict(target.bound_attributes)),
                capability,
            )
            assert not result.succeeded, f"{operation.value} against {role.value} must not succeed"


@pytest.mark.anyio
async def test_an_actor_controlled_target_still_reaches_its_adapter() -> None:
    """The gate must refuse the wrong targets without breaking the right ones.

    A control that refuses everything is not a strict control; it is a broken one, and it stops
    protecting anything the day somebody removes it to make the demo work again.
    """
    gw = gateway()
    target = target_for(InfrastructureRole.ACTOR_CONTROLLED)
    capability = issued(gw, target, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    result = await registry(gw).execute(
        request_against(
            target, OperationClass.TAKEDOWN_REQUEST_DRAFT, dict(target.bound_attributes)
        ),
        capability,
    )
    assert result.outcome is EffectOutcome.DRAFTED
    assert result.external_contact_made is False


# -- the obligation: an approver cannot omit the classification ---------------------


@pytest.mark.anyio
async def test_a_disruptive_operation_with_no_bound_classification_is_refused() -> None:
    """Otherwise the gate is opt-in, and the way past it is to not mention it.

    This is the failure mode the one pre-existing target-nature control already had: a blocking
    stop condition nothing ever set. A check an approver can skip by omission protects nothing.
    """
    gw = gateway()
    target = target_for(None)
    capability = issued(gw, target, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    result = await registry(gw).execute(
        request_against(
            target, OperationClass.TAKEDOWN_REQUEST_DRAFT, dict(target.bound_attributes)
        ),
        capability,
    )
    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert ROLE_ATTRIBUTE in result.detail


@pytest.mark.anyio
async def test_an_unobserved_classification_is_not_an_absent_one() -> None:
    """A caller that simply does not look must not thereby pass.

    The existing bound-attribute rule already says an unobserved attribute is not an unchanged
    one. Binding the role puts the classification under that same rule for free.
    """
    gw = gateway()
    target = target_for(InfrastructureRole.ACTOR_CONTROLLED)
    capability = issued(gw, target, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    result = await registry(gw).execute(
        request_against(
            target,
            OperationClass.TAKEDOWN_REQUEST_DRAFT,
            {"resolves_to": "198.51.100.23"},  # role not observed
        ),
        capability,
    )
    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED
    assert ROLE_ATTRIBUTE in result.detail


@pytest.mark.anyio
async def test_learning_the_target_is_a_victim_after_approval_spends_the_grant_on_nothing() -> None:
    """The case that makes binding worth more than a check.

    A takedown is approved against a target believed actor-controlled. Before it executes, the
    investigation establishes the host belongs to an innocent party. Nobody has to remember to
    revoke: the classification is inside the signature, the observed one no longer matches, and
    the capability fails closed on its own.
    """
    gw = gateway()
    approved = target_for(InfrastructureRole.ACTOR_CONTROLLED)
    capability = issued(gw, approved, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    learned_later = {
        "resolves_to": "198.51.100.23",
        ROLE_ATTRIBUTE: InfrastructureRole.COMPROMISED_LEGITIMATE.value,
    }
    result = await registry(gw).execute(
        request_against(approved, OperationClass.TAKEDOWN_REQUEST_DRAFT, learned_later),
        capability,
    )

    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED
    assert result.external_contact_made is False


@pytest.mark.anyio
async def test_a_forged_classification_does_not_verify() -> None:
    """The classification is inside the signed digest, so editing it breaks the signature.

    An attacker who can reach the capability object cannot relabel the target: the fingerprint
    is recomputed from the bound attributes and compared, and the signature covers the targets.
    """
    gw = gateway()
    honest = target_for(InfrastructureRole.COMPROMISED_LEGITIMATE)
    capability = issued(gw, honest, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    relabelled = dict(honest.bound_attributes) | {
        ROLE_ATTRIBUTE: InfrastructureRole.ACTOR_CONTROLLED.value
    }
    result = await registry(gw).execute(
        request_against(honest, OperationClass.TAKEDOWN_REQUEST_DRAFT, relabelled),
        capability,
    )
    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED


# -- what the gate must NOT block ---------------------------------------------------


@pytest.mark.anyio
async def test_evidence_may_be_preserved_against_an_unclassified_target() -> None:
    """§6 preserves evidence first, before anyone knows whose host it is.

    Failing closed here would destroy the record while the classification was worked out — the
    gate would cause exactly the harm it exists to prevent.
    """
    gw = gateway()
    target = target_for(None)
    capability = issued(gw, target, OperationClass.EVIDENCE_EXPORT)

    result = await registry(gw).execute(
        request_against(target, OperationClass.EVIDENCE_EXPORT, dict(target.bound_attributes)),
        capability,
    )
    assert result.succeeded


@pytest.mark.anyio
async def test_a_provider_may_be_notified_that_their_customer_is_compromised() -> None:
    """The §6 answer to a compromised legitimate host is to tell somebody, not to take it down.

    A gate that refused this would leave NEMESIS able to identify a victim and unable to help
    them, which is worse than not classifying at all.
    """
    gw = gateway()
    target = target_for(InfrastructureRole.COMPROMISED_LEGITIMATE)
    capability = issued(gw, target, OperationClass.PROVIDER_NOTIFICATION)

    result = await registry(gw).execute(
        request_against(
            target, OperationClass.PROVIDER_NOTIFICATION, dict(target.bound_attributes)
        ),
        capability,
    )
    assert result.outcome is EffectOutcome.DRAFTED


@pytest.mark.anyio
async def test_a_provider_may_not_be_notified_about_a_target_nobody_classified() -> None:
    """Naming a host in a notification is a statement. We do not make ones we cannot stand
    behind."""
    gw = gateway()
    target = target_for(None)
    capability = issued(gw, target, OperationClass.PROVIDER_NOTIFICATION)

    result = await registry(gw).execute(
        request_against(
            target, OperationClass.PROVIDER_NOTIFICATION, dict(target.bound_attributes)
        ),
        capability,
    )
    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED


# -- producer and gate, end to end --------------------------------------------------


@pytest.mark.anyio
async def test_a_node_the_producer_could_not_classify_is_written_unknown_and_refused() -> None:
    """The two halves meeting: derivation writes what it found, the boundary acts on it.

    Observed use only — traffic to a C2 and nothing about whose the node is. The producer
    records ``unknown`` on the entity rather than leaving the attribute absent, because those
    are different facts; the boundary then refuses a takedown against it.

    This is the case the whole subsystem exists for, and it is worth being clear about which
    way it fails: NEMESIS cannot currently tell a compromised legitimate host from adversary
    infrastructure, because registrant data is redacted. What it can do is decline to call
    either one the adversary's, which turns an unrecoverable error into a refusal.
    """
    from nemesis.core.entities import Entity, EntityType
    from nemesis.core.temporal import TemporalExtent
    from nemesis.graph.memory import InMemoryGraphStore
    from nemesis.pursuit.standing import reassess_standing

    graph = InMemoryGraphStore()
    now = utcnow()
    portal = Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        observed_form="unclassified-portal.example",
        extent=TemporalExtent.at(now),
        is_synthetic=True,
    )
    stored = await graph.upsert_entity(portal)

    roles = await reassess_standing(graph, [stored.entity_id], claims=(), assessed_at=now)
    assert roles[stored.entity_id] is InfrastructureRole.UNKNOWN

    reread = await graph.get_entity(stored.entity_id)
    assert reread is not None
    assert reread.attributes[ROLE_ATTRIBUTE] == "unknown"

    gw = gateway()
    target = TargetFingerprint.create(
        entity_id=stored.entity_id,
        entity_type="domain",
        natural_key=stored.natural_key,
        bound_attributes=dict(reread.attributes),
    )
    capability = issued(gw, target, OperationClass.TAKEDOWN_REQUEST_DRAFT)
    result = await registry(gw).execute(
        request_against(target, OperationClass.TAKEDOWN_REQUEST_DRAFT, dict(reread.attributes)),
        capability,
    )
    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert "unknown" in result.detail


@pytest.mark.anyio
async def test_a_reclassification_strands_the_capability_signed_against_the_old_answer() -> None:
    """Nobody has to remember to revoke.

    A takedown is approved while a node reads ``actor_controlled``. An analyst then submits an
    authoritative ownership claim naming an innocent company, the producer reassesses, and the
    entity now reads ``compromised_legitimate``. The capability's target fingerprint covers the
    old value, so it stops matching and the grant is spent on nothing.

    ``merge_attributes`` keeps the previous answer under ``infrastructure_role@prior1``, so the
    change is auditable rather than silent.
    """
    from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
    from nemesis.core.confidence import Opinion
    from nemesis.core.entities import Entity, EntityType
    from nemesis.core.ids import content_id
    from nemesis.core.infrastructure import OWNERSHIP_PREDICATE
    from nemesis.core.relationships import PivotMethod, Relationship, RelationType
    from nemesis.core.temporal import TemporalExtent
    from nemesis.graph.memory import InMemoryGraphStore
    from nemesis.pursuit.standing import reassess_standing

    graph = InMemoryGraphStore()
    now = utcnow()
    extent = TemporalExtent.at(now)

    site = await graph.upsert_entity(
        Entity.create(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type=EntityType.DOMAIN,
            observed_form="initech-blog.example",
            extent=extent,
            is_synthetic=True,
        )
    )
    actor = await graph.upsert_entity(
        Entity.create(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type=EntityType.THREAT_ACTOR,
            observed_form="glass-anvil",
            extent=extent,
            is_synthetic=True,
        )
    )
    backing = Claim.create(
        kind=ClaimKind.OBSERVATION,
        statement=Statement(
            subject="domain:initech-blog.example",
            predicate="observed",
            obj="a web shell",
            natural_language="A web shell was served from the host.",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=now,
        valid_extent=extent,
        supported_by_evidence=(content_id(IdPrefix.EVIDENCE, b"a sealed capture"),),
    )
    await graph.add_relationship(
        Relationship(
            edge_id=new_id(IdPrefix.EDGE),
            source_id=actor.entity_id,
            target_id=site.entity_id,
            source_type=EntityType.THREAT_ACTOR,
            target_type=EntityType.DOMAIN,
            relation=RelationType.CONTROLS,
            extent=extent,
            confidence=Opinion(belief=0.8, disbelief=0.05, uncertainty=0.15),
            pivot_method=PivotMethod.DIRECT_OBSERVATION,
            supporting_claims=(backing.claim_id,),
            is_synthetic=True,
        )
    )

    roles = await reassess_standing(graph, [site.entity_id], claims=(backing,), assessed_at=now)
    assert roles[site.entity_id] is InfrastructureRole.ACTOR_CONTROLLED

    approved_state = await graph.get_entity(site.entity_id)
    assert approved_state is not None
    gw = gateway()
    target = TargetFingerprint.create(
        entity_id=site.entity_id,
        entity_type="domain",
        natural_key=site.natural_key,
        bound_attributes=dict(approved_state.attributes),
    )
    capability = issued(gw, target, OperationClass.TAKEDOWN_REQUEST_DRAFT)

    # An analyst establishes who actually owns the host.
    ownership = Claim.create(
        kind=ClaimKind.FACT,
        statement=Statement(
            subject="domain:initech-blog.example",
            predicate=OWNERSHIP_PREDICATE,
            obj="organization:Initech",
            natural_language="The domain is registered to Initech, a payroll company.",
        ),
        derivation=DerivationKind.AUTHORITATIVE_RECORD,
        asserted_by=new_id(IdPrefix.ACTOR),
        asserted_at=now,
        valid_extent=extent,
        supported_by_evidence=(content_id(IdPrefix.EVIDENCE, b"a sealed corporate registry"),),
    )
    roles = await reassess_standing(
        graph, [site.entity_id], claims=(backing, ownership), assessed_at=now
    )
    assert roles[site.entity_id] is InfrastructureRole.COMPROMISED_LEGITIMATE

    now_state = await graph.get_entity(site.entity_id)
    assert now_state is not None
    assert now_state.attributes[ROLE_ATTRIBUTE] == "compromised_legitimate"
    assert now_state.attributes["infrastructure_role@prior1"] == "actor_controlled"

    result = await registry(gw).execute(
        request_against(target, OperationClass.TAKEDOWN_REQUEST_DRAFT, dict(now_state.attributes)),
        capability,
    )
    assert result.outcome is EffectOutcome.REFUSED_TARGET_CHANGED
    assert result.external_contact_made is False
