"""A tamper-evident record of the wrong thing is worse than no record.

Invariant 11 says meaningful actions are auditable — "replayable, not just logged". A review
found three places where a refusal was recorded as something other than what happened, and
all three wrote into the append-only, hash-chained trail. The chain verified. It was
faithfully preserving a false statement.

The root cause is the same in each: the record was built by calling ``authorizes()`` on the
capability under suspicion.

- A capability the oracle had **revoked** was refused, and recorded ``permitted: true`` with
  no denial reasons. This one was a regression: the reconstruction deliberately carries no
  revocation state, so once decisions moved onto the reconstruction, the record lost the
  only field that said why.
- A **forged** capability was refused, and recorded a decision the attacker had authored,
  including a ``capability_id`` pointing an investigator at an unrelated real grant.
- The handler whose stated purpose is to guarantee a record for a **crashing adapter**
  called ``authorizes()`` on the same untrusted object that had just crashed, so a
  capability whose ``authorizes`` raised produced no record at all.

Every refusal record is now built from what this plane knows: the operation the adapter
implements, the target in the request, the clock, and the reason for refusing.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.core.authorization import (
    NO_CAPABILITY,
    AuthorizationCapability,
    AuthorizationDecision,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import default_registry
from nemesis.ports.effects import EffectOutcome, EffectRequest

pytestmark = pytest.mark.invariant

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())


def _target() -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="glass-anvil.example",
        bound_attributes={"resolves_to": "198.51.100.23"},
    )


def _grant() -> tuple[AuthorizationGateway, AuthorizationCapability, TargetFingerprint]:
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)
    target = _target()
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=DEV.enrol("Grace", Role.ANALYST),
        justification="Rehearse the takedown.",
        targets=(target,),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="A rehearsal that performs nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(
        request.capability_id,
        approver=DEV.enrol("Ada", Role.INVESTIGATION_LEAD),
        rationale="Performs nothing.",
    )
    return gateway, gateway.issue(request.capability_id), target


def _request(target: TargetFingerprint) -> EffectRequest:
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=OperationClass.SIMULATION,
        target_fingerprint=target.fingerprint,
        target_natural_key=target.natural_key,
        current_target_attributes=dict(target.bound_attributes),
        parameters={},
        requested_by=new_id(IdPrefix.ACTOR),
        requested_at=utcnow(),
    )


def _execute(gateway: AuthorizationGateway, request: EffectRequest, capability: object) -> object:
    return asyncio.run(
        default_registry(
            verifying_key=gateway.verifying_key, revocations=gateway.revocations
        ).execute(request, capability)  # type: ignore[arg-type]
    )


def test_a_revoked_capability_is_recorded_as_refused_not_as_permitted() -> None:
    """The regression. It survived a full green suite because nothing asserted the record."""
    gateway, capability, target = _grant()
    gateway.revoke(
        capability.capability_id, "target ownership disputed", revoked_by=new_id(IdPrefix.ACTOR)
    )

    result = _execute(gateway, _request(target), capability)

    assert result.outcome is EffectOutcome.REFUSED_REVOKED  # type: ignore[attr-defined]
    decision: AuthorizationDecision = result.authorization  # type: ignore[attr-defined]
    assert not decision.permitted
    assert decision.denial_reasons == ("the issuing authority has withdrawn this capability",)
    assert decision.capability_id == capability.capability_id


def test_the_record_of_a_forgery_is_not_written_by_the_forger() -> None:
    """Including the capability id: a false one sends an investigator to the wrong grant."""

    class Liar(AuthorizationCapability):
        def authorizes(self, **kwargs: object) -> AuthorizationDecision:
            return AuthorizationDecision(
                permitted=True,
                capability_id="cap_" + "a" * 32,
                operation=OperationClass.SIMULATION,
                target_fingerprint=str(kwargs["target_fingerprint"]),
                evaluated_at=utcnow(),
            )

    gateway, capability, target = _grant()
    forged = Liar(
        **{**capability.model_dump(), "capability_id": "cap_" + "b" * 32, "signature": None}
    )

    result = _execute(gateway, _request(target), forged)

    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY  # type: ignore[attr-defined]
    decision: AuthorizationDecision = result.authorization  # type: ignore[attr-defined]
    assert not decision.permitted
    assert decision.capability_id == NO_CAPABILITY
    assert "a" * 32 not in decision.capability_id

    # The claim is preserved as an observation, in free text, labelled as a claim.
    assert "claimed the id" in result.detail  # type: ignore[attr-defined]
    assert "b" * 32 in result.detail  # type: ignore[attr-defined]


def test_an_adapter_crash_still_produces_a_record_even_when_the_capability_crashes_too() -> None:
    """The handler that exists to guarantee a record must not consult the suspect object.

    It called ``authorizes()`` on the capability that had just caused the failure, so a
    capability whose ``authorizes`` raised defeated the one guarantee this path is for and
    the exception escaped ``EffectsRegistry.execute`` entirely.
    """

    class Exploding(AuthorizationCapability):
        def authorizes(self, **kwargs: object) -> AuthorizationDecision:
            raise RuntimeError("boom")

        def signing_payload(self) -> bytes:
            raise RuntimeError("boom")

    gateway, capability, target = _grant()
    bomb = Exploding(**capability.model_dump())

    result = _execute(gateway, _request(target), bomb)

    assert result.outcome is EffectOutcome.FAILED  # type: ignore[attr-defined]
    assert not result.authorization.permitted  # type: ignore[attr-defined]
    assert result.authorization.capability_id == NO_CAPABILITY  # type: ignore[attr-defined]
    assert not result.external_contact_made  # type: ignore[attr-defined]


def test_an_unimplemented_class_records_that_nothing_was_verified() -> None:
    """No adapter means no preflight, so there is no authenticated grant to report on."""
    gateway, capability, target = _grant()
    request = _request(target).model_copy(update={"operation": OperationClass.REGISTRAR_SUSPENSION})

    result = _execute(gateway, request, capability)

    assert result.outcome is EffectOutcome.REFUSED_NO_ADAPTER  # type: ignore[attr-defined]
    assert result.authorization.capability_id == NO_CAPABILITY  # type: ignore[attr-defined]
    assert not result.authorization.permitted  # type: ignore[attr-defined]
    # The distinction an analyst needs is still carried, in the outcome and the detail.
    assert "REQUIRES_LEGAL_AUTHORITY" in result.detail  # type: ignore[attr-defined]


def test_a_permitted_operation_still_records_a_faithful_decision() -> None:
    """The counterpart: a record that always says "refused" is as useless as one that lies."""
    gateway, capability, target = _grant()
    result = _execute(gateway, _request(target), capability)

    assert result.outcome is EffectOutcome.SIMULATED  # type: ignore[attr-defined]
    decision: AuthorizationDecision = result.authorization  # type: ignore[attr-defined]
    assert decision.permitted
    assert decision.capability_id == capability.capability_id
    assert decision.denial_reasons == ()


@pytest.mark.anyio
async def test_a_pilot_driven_effect_records_the_authorization_decision() -> None:
    """Found in a real Codex-driven run, where the field was null.

    ``AuditEvent.authorization_decision`` says of itself that it is "present for any action that
    consulted a capability, permitted or denied" and that "denials are recorded with equal
    weight — a pattern of denied attempts is a security signal". An effect requested by a pilot
    is exactly such an action, and the mediator had the decision in hand from the effects plane
    and dropped it.

    So the one actor the whole platform exists to contain was the one whose capability checks
    left no record. `record_effect`, which does carry the decision, is called only from the
    demonstration scenario and never from the pilot path.
    """
    from nemesis.core.authorization import OperationClass
    from nemesis.pilot.moves import Conclude, RequestEffect
    from tests.invariants.test_pilot_containment import ScriptedPilot, _build, _hostile

    h = await _build()
    pilot = ScriptedPilot(
        "gpt-5-cyber",
        [
            RequestEffect(
                entity_id=h.approved.entity_id,
                operation=OperationClass.SIMULATION,
                rationale="rehearse",
            ),
            Conclude(summary=""),
        ],
    )
    await h.mediator.drive(_hostile(pilot), h.seed)

    effects = [
        event
        for event in h.audit.events
        if event.action == "pilot.move" and event.inputs.get("move_kind") == "request_effect"
    ]
    assert effects, "the pilot requested no effect"
    recorded = effects[0]
    assert recorded.authorization_decision is not None, (
        "an effect consulted a capability and the trail records no decision"
    )
    assert recorded.inputs.get("target_natural_key"), (
        "without the target's natural key the record cannot be joined to anything"
    )
