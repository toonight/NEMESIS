"""Founder decision D1: organizational attribution ships, persona linkage does not.

The wall is a data-flow constraint, so these tests follow data rather than inspecting
labels. Each one asks the same question at a different boundary: can persona-linkage or
human-identity material reach something that leaves the platform?

The three layers are tested separately because they fail differently, and because a wall
that rests on one of them is a wall with a gap nobody has looked at yet.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nemesis.attribute.dimensions import AttributionDimension
from nemesis.attribute.disclosure import (
    DELIVERABLE_DIMENSIONS,
    DIMENSION_DISCLOSURE,
    ExternalAttributionProduct,
    ExternalDimension,
    redact_for_disclosure,
)
from nemesis.attribute.engine import AttributionResult
from nemesis.authz.gateway import AuthorizationGateway
from nemesis.core.authorization import AuthorizationCapability
from nemesis.core.disclosure import (
    DisclosureClass,
    DisclosureViolationError,
    disclosure_of_entity,
    most_restrictive,
    scan_for_internal_material,
)
from nemesis.core.entities import EntityType
from nemesis.core.identity import Role
from nemesis.ports.effects import EffectRequest
from tests.support.identity import elevated, hardware_backed_issuer, verifier_over

pytestmark = pytest.mark.invariant

NOW = datetime(2026, 8, 15, tzinfo=UTC)


# --- Layer 1: the external type cannot represent internal material -----------


@pytest.mark.parametrize(
    "dimension", [AttributionDimension.PERSONA, AttributionDimension.HUMAN_IDENTITY]
)
def test_an_internal_dimension_cannot_be_constructed_as_external(
    dimension: AttributionDimension,
) -> None:
    """The strongest layer: a field that does not exist cannot be filled in a hurry."""
    from nemesis.attribute.dimensions import SourceDiversity
    from nemesis.core.confidence import ConfidenceBand, Opinion

    with pytest.raises(DisclosureViolationError, match="internal leads, not deliverables"):
        ExternalDimension(
            dimension=dimension,
            hypothesis="two personas are one operator",
            opinion=Opinion.from_evidence(supporting=9, contradicting=0),
            band=ConfidenceBand.VERY_LIKELY,
            supporting_claims=(),
            contradicting_claims=(),
            alternatives=(),
            missing_evidence=(),
            source_diversity=SourceDiversity(
                independent_source_count=3,
                total_signals=3,
                adversary_influenceable_sources=0,
            ),
            reasoning="",
        )


def test_the_deliverable_set_is_exactly_the_three_above_the_line() -> None:
    """A tripwire on the placement of the wall.

    If this fails, somebody moved the line between ORGANIZATION and PERSONA. That is
    founder decision D1 and it is not an engineering call.
    """
    assert set(DELIVERABLE_DIMENSIONS) == {
        AttributionDimension.INFRASTRUCTURE,
        AttributionDimension.CAMPAIGN,
        AttributionDimension.ORGANIZATION,
    }
    assert DIMENSION_DISCLOSURE[AttributionDimension.PERSONA] is DisclosureClass.INTERNAL_LEAD
    assert DIMENSION_DISCLOSURE[AttributionDimension.HUMAN_IDENTITY] is DisclosureClass.RESTRICTED


def test_an_external_product_has_no_route_to_naming_a_person() -> None:
    product = ExternalAttributionProduct(
        attribution_id="attr_" + "0" * 32,
        subject="Operation GLASS ANVIL",
        assessed_by="actor_" + "0" * 32,
        assessed_at=NOW,
        dimensions=(),
        withheld=(),
    )
    assert not product.names_a_person
    assert "human_identity" not in product.model_dump_json()


# --- Layer 2: redaction is recorded, not silent ------------------------------


def test_redaction_withholds_the_internal_dimensions_and_says_so() -> None:
    result = _attribution_over_all_five()
    product = redact_for_disclosure(result)

    shipped = {item.dimension for item in product.dimensions}
    withheld = {item.dimension for item in product.withheld}

    assert shipped == set(DELIVERABLE_DIMENSIONS)
    assert withheld == {AttributionDimension.PERSONA, AttributionDimension.HUMAN_IDENTITY}


def test_a_recipient_is_told_that_something_was_withheld() -> None:
    """Silence would be read as "nothing was found", which is a different claim entirely."""
    product = redact_for_disclosure(_attribution_over_all_five())
    rendered = product.render()

    assert "WITHHELD" in rendered
    assert "internal investigative lead" in rendered
    assert "not evidence that a person was or was not identified" in rendered


def test_the_withholding_notice_does_not_leak_what_it_withholds() -> None:
    """A notice that explained the finding would defeat the point of withholding it."""
    result = _attribution_over_all_five()
    product = redact_for_disclosure(result)
    payload = product.model_dump_json()

    assert "GlassAnvil" not in payload
    assert "AnvilWorks" not in payload
    assert "same operator" not in payload


def test_the_product_states_that_it_supplies_no_identity_findings() -> None:
    product = redact_for_disclosure(_attribution_over_all_five())
    assert any("does not supply findings about the identity" in c for c in product.caveats)


# --- Layer 3: the free-text boundary guard -----------------------------------


def test_internal_material_in_effect_parameters_is_detected() -> None:
    leaked = scan_for_internal_material(
        {
            "recipient": "abuse@example",
            "summary": "See the persona_linkage assessment: they are the same_operator_as.",
        }
    )
    assert len(leaked) == 2
    assert all("summary" in item for item in leaked)


def test_clean_parameters_pass_the_guard() -> None:
    assert (
        scan_for_internal_material(
            {"recipient": "abuse@example", "summary": "Four domains on one host."}
        )
        == ()
    )


@pytest.mark.anyio
async def test_an_effect_carrying_internal_material_is_refused() -> None:
    """End to end at the boundary: an otherwise fully authorized operation is refused.

    The check runs before the capability verdict is acted on, so being authorized is not a
    defence. An authorized operation carrying persona prose into a document is the case
    worth refusing loudest, not the one worth waving through.
    """
    from nemesis.effects.registry import default_registry
    from nemesis.ports.effects import EffectOutcome

    gateway, capability, request = _authorized_draft_request(
        parameters={
            "purpose": "Abuse report",
            "background": "Our persona_linkage assessment ties these to one operator.",
        }
    )
    result = await default_registry(
        verifying_key=gateway.verifying_key, revocations=gateway.revocations
    ).execute(request, capability)

    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert "internal-classified material" in result.detail
    assert not result.external_contact_made


@pytest.mark.anyio
async def test_the_same_request_without_internal_material_is_drafted() -> None:
    """The counterpart: the guard must not make the plane useless."""
    from nemesis.effects.registry import default_registry
    from nemesis.ports.effects import EffectOutcome

    gateway, capability, request = _authorized_draft_request(
        parameters={
            "purpose": "Abuse report",
            "background": "Four domains resolved to one host inside a 24-hour window.",
        }
    )
    result = await default_registry(
        verifying_key=gateway.verifying_key, revocations=gateway.revocations
    ).execute(request, capability)
    assert result.outcome is EffectOutcome.DRAFTED


# --- Entity-level classification ---------------------------------------------


def test_an_organization_is_deliverable_and_a_persona_is_not() -> None:
    """The one line that is founder decision D1."""
    assert disclosure_of_entity(EntityType.ORGANIZATION) is DisclosureClass.DELIVERABLE
    assert disclosure_of_entity(EntityType.THREAT_ACTOR) is DisclosureClass.DELIVERABLE
    assert disclosure_of_entity(EntityType.PERSONA) is DisclosureClass.INTERNAL_LEAD
    assert disclosure_of_entity(EntityType.ALIAS) is DisclosureClass.INTERNAL_LEAD
    assert disclosure_of_entity(EntityType.HUMAN_IDENTITY_LEAD) is DisclosureClass.RESTRICTED


def test_victims_are_restricted_too() -> None:
    """Not because naming them accuses anyone, but because their exposure is not ours to
    trade. A takedown request naming the victims is a breach notification nobody asked for.
    """
    assert disclosure_of_entity(EntityType.VICTIM) is DisclosureClass.RESTRICTED


def test_a_mixed_product_takes_its_most_restricted_part() -> None:
    """Otherwise a deliverable wrapper launders an internal finding by containing it."""
    assert (
        most_restrictive(DisclosureClass.DELIVERABLE, DisclosureClass.RESTRICTED)
        is DisclosureClass.RESTRICTED
    )
    assert (
        most_restrictive(DisclosureClass.DELIVERABLE, DisclosureClass.INTERNAL_LEAD)
        is DisclosureClass.INTERNAL_LEAD
    )
    assert most_restrictive() is DisclosureClass.DELIVERABLE


# --- helpers ------------------------------------------------------------------


def _attribution_over_all_five() -> AttributionResult:
    from nemesis.attribute.engine import (
        AttributionEngine,
        AttributionRequest,
        DimensionInput,
    )
    from nemesis.core.ids import IdPrefix, new_id

    return AttributionEngine(assessed_by=new_id(IdPrefix.ACTOR)).assess(
        AttributionRequest(
            subject="Operation GLASS ANVIL",
            dimensions=(
                DimensionInput(
                    dimension=AttributionDimension.PERSONA,
                    hypothesis="GlassAnvil and AnvilWorks are the same operator.",
                ),
            ),
        ),
        assessed_at=NOW,
    )


def _authorized_draft_request(
    *, parameters: dict[str, str]
) -> tuple[AuthorizationGateway, AuthorizationCapability, EffectRequest]:
    from datetime import timedelta

    from nemesis.authz.keys import CapabilitySigningKey
    from nemesis.core.authorization import LegalBasis, OperationClass, TargetFingerprint
    from nemesis.core.ids import IdPrefix, new_id
    from nemesis.core.temporal import utcnow

    target = TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="acme-invoice-portal.example",
        bound_attributes={"resolves_to": "198.51.100.23"},
    )
    identities, _ = hardware_backed_issuer()
    actors = verifier_over(identities)
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=actors)
    requester = elevated(identities, "Requester", Role.ANALYST)
    # Established above the development floor: this test drafts a notification, and a
    # development identity is entitled to a rehearsal and nothing more.
    approver = elevated(identities, "Approver", Role.INVESTIGATION_LEAD)
    approval_request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=requester,
        justification="Draft an abuse notification.",
        targets=(target,),
        operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ToS abuse channel; drafted, not sent",
        max_effect_description="One unsent draft.",
        lifetime=timedelta(hours=2),
    )
    gateway.approve(
        approval_request.capability_id,
        approver=approver,
        rationale="Reversible and internal.",
    )
    capability = gateway.issue(approval_request.capability_id)

    return (
        gateway,
        capability,
        EffectRequest(
            operation_id=new_id(IdPrefix.OPERATION),
            operation=OperationClass.PROVIDER_NOTIFICATION,
            target_fingerprint=target.fingerprint,
            target_natural_key=target.natural_key,
            current_target_attributes=dict(target.bound_attributes),
            parameters=parameters,
            requested_by=actors.verify(requester).actor_id,
            requested_at=utcnow(),
        ),
    )
