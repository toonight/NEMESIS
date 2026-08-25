"""The role gate, reached the way a deployment reaches it.

``test_infrastructure_gate.py`` proves the gate refuses correctly. It does so by building a
capability and calling ``registry.execute`` directly, which is the right shape for testing a
control and says nothing about whether anything ever *arrives* there. These tests cover the
other half: a role the producer derived, projected onto an entity, bound into a signature, and
read back at the enforcement point after a pilot asked for an effect through the mediator.

The distinction is not academic. Until this demonstration existed the reference run permitted
exactly one operation class, ``SIMULATION``, which every role is eligible for — so the whole
wiring between the producer and the gate was unexercised end to end, and would have kept passing
its unit tests if it had been disconnected.
"""

from __future__ import annotations

import asyncio

import pytest

from nemesis.core.authorization import OperationClass
from nemesis.core.disclosure import DisclosureClass, disclosure_of_entity
from nemesis.core.entities import EntityType
from nemesis.core.infrastructure import (
    OBSERVE_AND_PRESERVE_OPERATIONS,
    ROLE_ATTRIBUTE,
    InfrastructureRole,
)
from nemesis.pilot.moves import RulingStatus
from nemesis.slice.standing_session import (
    ACTOR_CONTROLLED_DOMAIN,
    CASES,
    COMPROMISED_DOMAIN,
    OPERATIONS,
    SHARED_REGISTRAR,
    SYNTHETIC_AUTHORITY_REFERENCE,
    UNBOUND_DOMAIN,
    UNCLASSIFIED_DOMAIN,
    GateOutcome,
    StandingDemonstration,
    run_standing_demonstration,
)

pytestmark = pytest.mark.invariant


@pytest.fixture(scope="module")
def demonstration() -> StandingDemonstration:
    """One run, shared by the module.

    Driven synchronously rather than through an async fixture: nothing below needs to be a
    coroutine — every assertion inspects a finished result — and a module-scoped async fixture
    would drag in a backend fixture at the same scope for no gain.
    """
    return asyncio.run(run_standing_demonstration())


def outcome(result: StandingDemonstration, key: str, operation: OperationClass) -> GateOutcome:
    found = next(
        (o for o in result.outcomes if o.natural_key == key and o.operation is operation), None
    )
    assert found is not None, f"the demonstration never requested {operation.value} against {key}"
    return found


# -- the point of the whole module -----------------------------------------------------


def test_the_demonstration_actually_reaches_the_role_gate(
    demonstration: StandingDemonstration,
) -> None:
    """Asserted first, because every other assertion here is worthless without it.

    A demonstration whose refusals all came from the capability, the budget or an unmatched
    fingerprint would look identical in a summary and would prove the gate nothing. The
    ``refused_by_the_role_gate`` predicate reads the gate's own wording rather than the status,
    so this is a claim about which control spoke.
    """
    assert demonstration.gate_refusals, "no refusal in this run came from the role gate"


def test_the_run_shows_the_gate_discriminating_rather_than_blocking(
    demonstration: StandingDemonstration,
) -> None:
    """A gate that refused everything would satisfy the test above and be broken.

    This is the control on that control: something must also get through, or "the gate refused
    it" is indistinguishable from "the path is broken and nothing works".
    """
    assert demonstration.accepted, "nothing was drafted; the gate may simply be refusing all"
    assert len(demonstration.accepted) < len(demonstration.outcomes)


def test_every_operation_the_demonstration_requests_is_one_the_gate_governs() -> None:
    """An observe-and-preserve operation would leave the gate silent and the run meaningless."""
    for operation in OPERATIONS:
        assert operation not in OBSERVE_AND_PRESERVE_OPERATIONS


# -- the matrix ------------------------------------------------------------------------


def test_a_target_the_adversary_controls_may_be_drafted_against(
    demonstration: StandingDemonstration,
) -> None:
    assert demonstration.roles[ACTOR_CONTROLLED_DOMAIN] is InfrastructureRole.ACTOR_CONTROLLED
    for operation in OPERATIONS:
        assert outcome(demonstration, ACTOR_CONTROLLED_DOMAIN, operation).accepted


def test_a_compromised_legitimate_host_is_refused_the_takedown_and_allowed_the_notice(
    demonstration: StandingDemonstration,
) -> None:
    """The case the mission is about, end to end.

    A legitimate company's server that the adversary is using: malicious use alone would mark it
    as the adversary's, and the whole point of the facet model is that it does not. The provider
    may still be told — that is how the owner finds out — and the takedown may not run, because
    the harm would land on the victim.
    """
    assert demonstration.roles[COMPROMISED_DOMAIN] is InfrastructureRole.COMPROMISED_LEGITIMATE
    refused = outcome(demonstration, COMPROMISED_DOMAIN, OperationClass.TAKEDOWN_REQUEST_DRAFT)
    assert refused.refused_by_the_role_gate
    assert "compromised_legitimate" in refused.detail
    assert outcome(demonstration, COMPROMISED_DOMAIN, OperationClass.PROVIDER_NOTIFICATION).accepted


def test_shared_infrastructure_is_refused_the_takedown_and_allowed_the_notice(
    demonstration: StandingDemonstration,
) -> None:
    """Adversary traffic through a registrar is not a reason to act against the registrar."""
    assert demonstration.roles[SHARED_REGISTRAR] is InfrastructureRole.SHARED_INFRASTRUCTURE
    assert outcome(
        demonstration, SHARED_REGISTRAR, OperationClass.TAKEDOWN_REQUEST_DRAFT
    ).refused_by_the_role_gate
    assert outcome(demonstration, SHARED_REGISTRAR, OperationClass.PROVIDER_NOTIFICATION).accepted


def test_an_unclassified_target_is_refused_both_tiers(
    demonstration: StandingDemonstration,
) -> None:
    """``unknown`` is the only role that fails the third-party tier as well.

    Which is the correct asymmetry: notifying a provider about a node nobody has classified means
    naming a party we cannot say is involved.
    """
    assert demonstration.roles[UNCLASSIFIED_DOMAIN] is InfrastructureRole.UNKNOWN
    for operation in OPERATIONS:
        assert outcome(demonstration, UNCLASSIFIED_DOMAIN, operation).refused_by_the_role_gate


def test_an_unbound_classification_is_refused_although_the_standing_would_have_allowed_it(
    demonstration: StandingDemonstration,
) -> None:
    """The sharpest cell in the matrix, and the reason the fixture gives this target a control
    edge identical to the one that drafts.

    Both nodes come out of the producer as ``actor_controlled``. One drafts and one does not, and
    the only difference between them is that the approver did not bind the classification into
    the fingerprint. If a future change made the gate fall back to reading the *entity* rather
    than the signed capability, this test is the one that fails — and that change would mean an
    approval no longer had to say what the target was found to be.
    """
    assert demonstration.roles[UNBOUND_DOMAIN] is InfrastructureRole.ACTOR_CONTROLLED
    assert demonstration.roles[ACTOR_CONTROLLED_DOMAIN] is demonstration.roles[UNBOUND_DOMAIN]
    for operation in OPERATIONS:
        refused = outcome(demonstration, UNBOUND_DOMAIN, operation)
        assert refused.refused_by_the_role_gate
        assert f"no {ROLE_ATTRIBUTE} is bound into this capability" in refused.detail


# -- what must not be true -------------------------------------------------------------


def test_nothing_left_the_platform(demonstration: StandingDemonstration) -> None:
    """Invariant 15, measured rather than asserted.

    This is the demonstration where a containment claim stops being obvious: unlike the
    reference run, it permits two operations whose documents name an external recipient, and
    one of them is in the disruptive tier. What is checked is what the Effects plane itself
    reported, and it is fail-closed — an accepted effect that came back without saying counts
    as having left.
    """
    accepted = [item for item in demonstration.outcomes if item.accepted]
    assert accepted, "nothing was accepted, so this proves nothing about containment"
    for item in accepted:
        assert item.external_contact_made is False, (
            f"{item.natural_key}/{item.operation.value} reported "
            f"external_contact_made={item.external_contact_made!r}"
        )
    assert not [item for item in demonstration.outcomes if item.left_the_platform]


def test_the_report_states_the_external_contact_count(
    demonstration: StandingDemonstration,
) -> None:
    """A containment figure a reader has to take on faith is not a figure.

    Pinned as text because the rendered report is what a human sees; a demonstration that
    measured containment and did not print it would leave the reader with the matrix alone.
    """
    assert "External contact reported by the Effects plane on 0 of them." in demonstration.render()


def test_no_refusal_here_is_a_budget_or_authority_refusal(
    demonstration: StandingDemonstration,
) -> None:
    """Every refusal must be the gate's, or the demonstration is measuring something else.

    A budget that ran out mid-run would silently convert the tail of the matrix into refusals
    that look like standing refusals in a summary table.
    """
    for item in demonstration.outcomes:
        assert item.status is not RulingStatus.REFUSED_BUDGET, f"{item.natural_key} hit the budget"
        assert item.status is not RulingStatus.REFUSED_UNKNOWN_ENTITY
        if not item.accepted:
            assert item.refused_by_the_role_gate, (
                f"{item.natural_key}/{item.operation.value} was refused by something other than "
                f"the role gate: {item.detail[:200]}"
            )


def test_the_capability_does_not_claim_an_authority_it_does_not_have(
    demonstration: StandingDemonstration,
) -> None:
    """A capability permitting more than simulation must cite an authority.

    Which means a synthetic exercise has to put *something* in that field, and the something
    travels into every drafted document. It says there is no authority.
    """
    capability = demonstration.envelope.capability
    assert capability.legal_authority_reference == SYNTHETIC_AUTHORITY_REFERENCE
    assert "NO-REAL-AUTHORITY" in (capability.legal_authority_reference or "")
    assert "SIMULATED" in (capability.legal_authority_reference or "")


def test_a_victim_typed_entity_is_stopped_before_this_gate_and_the_module_says_so(
    demonstration: StandingDemonstration,
) -> None:
    """Why the fixture uses a compromised host rather than a victim entity.

    ``VICTIM`` is ``RESTRICTED``, so the mediator's disclosure wall refuses an effect against one
    before the effects plane runs at all. That is a second, earlier control protecting a
    different kind of third party — and a reader of the demonstration would otherwise wonder why
    the obvious case is missing, so the rendered report names it.
    """
    assert disclosure_of_entity(EntityType.VICTIM) is DisclosureClass.RESTRICTED
    assert EntityType.VICTIM not in {case.entity_type for case in CASES}
    assert "disclosure wall" in demonstration.render()


def test_the_report_distinguishes_a_gate_refusal_from_any_other(
    demonstration: StandingDemonstration,
) -> None:
    """A reader must not have to trust the summary line to know which control refused."""
    rendered = demonstration.render()
    assert "REFUSED by the gate" in rendered
    assert "drafted" in rendered
    for case in CASES:
        assert case.natural_key in rendered
