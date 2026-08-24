"""Invariant 7 at the boundary that matters: nothing acts on an unauthenticated grant.

Every test here reproduces something that **worked** before this boundary was hardened. An
external audit found three of them and all three were confirmed by execution rather than by
reading:

- a capability with ``signature=None``, whose only approval the attacker had granted
  themselves, produced a drafted document;
- a capability revoked in the gateway still executed from a copy handed out earlier,
  because the plane read the object's own field instead of asking the issuing authority;
- every stop condition could be stripped from a signed capability while its signature
  continued to verify over identical bytes.

The impact at the time was bounded to local drafts, because no adapter can make external
contact. That is a property of the current adapter set, not of the authorization chain, and
it would have evaporated the day a real adapter arrived.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.infrastructure import ROLE_ATTRIBUTE, InfrastructureRole
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import EffectsRegistry, default_registry
from nemesis.ports.effects import EffectOutcome, EffectRequest
from tests.support.identity import elevated, hardware_backed_issuer, verifier_over

pytestmark = pytest.mark.invariant

IDENTITIES, _ = hardware_backed_issuer()
ACTORS = verifier_over(IDENTITIES)
REQUESTER = elevated(IDENTITIES, "Requester", Role.ANALYST, Role.INVESTIGATION_LEAD)
APPROVER = elevated(IDENTITIES, "Approver", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER)
"""Established above the development floor, because these tests exercise a drafting class
and a development identity is entitled to a rehearsal and nothing more.

The elevation is a registration — the suite tells the verifier what this issuer's word is
worth — and not an edit to an assurance field. Editing the field is the bypass under test.
"""

REQUESTER_ID = ACTORS.verify(REQUESTER).actor_id
APPROVER_ID = ACTORS.verify(APPROVER).actor_id


TARGET = TargetFingerprint.create(
    entity_id=new_id(IdPrefix.ENTITY),
    entity_type="domain",
    natural_key="victim.example",
    bound_attributes={
        "resolves_to": "203.0.113.7",
        # These tests are about forgery, not about standing; the target is bound as the
        # adversary's so the standing gate passes and the signature checks stay the subject.
        ROLE_ATTRIBUTE: InfrastructureRole.ACTOR_CONTROLLED.value,
    },
)


def _request(operation: OperationClass = OperationClass.PROVIDER_NOTIFICATION) -> EffectRequest:
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=operation,
        target_fingerprint=TARGET.fingerprint,
        target_natural_key=TARGET.natural_key,
        current_target_attributes=dict(TARGET.bound_attributes),
        parameters={"purpose": "abuse report"},
        requested_by=REQUESTER_ID,
        requested_at=utcnow(),
    )


def _self_minted(**overrides: object) -> AuthorizationCapability:
    """What an attacker inside the process can build: a well-formed, unsigned capability."""
    defaults: dict[str, object] = {
        "capability_id": new_id(IdPrefix.CAPABILITY),
        "case_id": new_id(IdPrefix.CASE),
        "audit_id": new_id(IdPrefix.AUDIT),
        "issued_at": utcnow(),
        "not_before": utcnow(),
        "expires_at": utcnow() + timedelta(hours=1),
        "targets": (TARGET,),
        "permitted_operations": frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        "jurisdictions": ("XX",),
        "legal_basis": LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        "legal_authority_reference": "none — minted by the caller",
        "max_targets": 1,
        "max_effect_description": "whatever the attacker wrote here",
        "required_approvals": 1,
        "approvals": (
            Approval(
                approver=new_id(IdPrefix.ACTOR),
                approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
                decided_at=utcnow(),
                decision=True,
                rationale="I approved my own request.",
            ),
        ),
    }
    return AuthorizationCapability(**(defaults | overrides))


def _issued(
    gateway: AuthorizationGateway, *, stop_conditions: tuple[StopCondition, ...] = ()
) -> AuthorizationCapability:
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=REQUESTER,
        justification="Draft an abuse notification.",
        targets=(TARGET,),
        operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ToS abuse channel",
        max_effect_description="One unsent draft.",
        lifetime=timedelta(hours=2),
        stop_conditions=stop_conditions,
    )
    gateway.approve(
        request.capability_id,
        approver=APPROVER,
        rationale="Reversible, internal, synthetic targets.",
    )
    return gateway.issue(request.capability_id)


def _gateway() -> AuthorizationGateway:
    return AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)


def _registry(gateway: AuthorizationGateway) -> EffectsRegistry:
    return default_registry(verifying_key=gateway.verifying_key, revocations=gateway.revocations)


# --- Forgery -----------------------------------------------------------------


@pytest.mark.anyio
async def test_a_self_minted_unsigned_capability_acts_on_nothing() -> None:
    """Reproduced before the fix: this drafted a document."""
    gateway = _gateway()
    result = await _registry(gateway).execute(_request(), _self_minted())

    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY
    assert not result.produced_artifacts
    assert "no signature" in result.detail or "not signed" in result.detail


@pytest.mark.anyio
async def test_a_capability_signed_by_a_different_key_is_refused() -> None:
    """An attacker with their own keypair is still an attacker."""
    theirs, ours = _gateway(), _gateway()
    capability = _issued(theirs)

    result = await _registry(ours).execute(_request(), capability)
    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY


@pytest.mark.anyio
async def test_widening_a_signed_capability_invalidates_it() -> None:
    """The signature covers the permission set, so adding an operation breaks it."""
    gateway = _gateway()
    widened = _issued(gateway).model_copy(
        update={
            "permitted_operations": frozenset(
                {OperationClass.PROVIDER_NOTIFICATION, OperationClass.DOMAIN_SEIZURE}
            )
        }
    )
    result = await _registry(gateway).execute(_request(), widened)
    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY


@pytest.mark.anyio
async def test_stripping_a_stop_condition_invalidates_the_signature() -> None:
    """The third audit finding. Stop conditions are a safety control and are now signed.

    Before, ``signing_payload()`` omitted them entirely: an attacker could remove every
    abort criterion from an approved capability and the signature still verified over
    identical bytes.
    """
    gateway = _gateway()
    capability = _issued(
        gateway,
        stop_conditions=(
            StopCondition(
                condition="ownership_disputed",
                description="Abort if the registrant contests ownership.",
            ),
        ),
    )
    stripped = capability.model_copy(update={"stop_conditions": ()})

    assert capability.signing_payload() != stripped.signing_payload()
    result = await _registry(gateway).execute(_request(), stripped)
    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY


def test_the_signature_covers_who_approved_and_why() -> None:
    """An approver's role, rationale and declared reviewed evidence are all signed.

    Otherwise an attacker rewrites "reviewed by an intern, rubber stamp" into "reviewed by
    the investigation lead, evidence bundle examined" without breaking anything.
    """
    gateway = _gateway()
    capability = _issued(gateway)
    original = capability.approvals[0]

    for mutation in (
        {"approver_roles": frozenset({Role.ANALYST})},
        {"rationale": "did not read it"},
        {"reviewed_evidence": ("evd_sha256-" + "0" * 64,)},
    ):
        altered = capability.model_copy(
            update={"approvals": (original.model_copy(update=mutation),)}
        )
        assert capability.signing_payload() != altered.signing_payload(), mutation


# --- Revocation ---------------------------------------------------------------


@pytest.mark.anyio
async def test_a_revoked_capability_is_refused_from_a_copy_handed_out_earlier() -> None:
    """The second audit finding, and the reason an oracle exists at all.

    The copy presented here is byte-identical to the one issued before the withdrawal — its
    own ``revoked_at`` is still None and its signature still verifies. Only the issuing
    authority knows, so only the issuing authority can be asked.
    """
    gateway = _gateway()
    capability = _issued(gateway)
    registry = _registry(gateway)

    before = await registry.execute(_request(), capability)
    assert before.outcome is EffectOutcome.DRAFTED

    gateway.revoke(capability.capability_id, "target ownership disputed", revoked_by=APPROVER_ID)

    assert capability.revoked_at is None, "the distributed copy cannot know"
    after = await registry.execute(_request(), capability)
    assert after.outcome is EffectOutcome.REFUSED_REVOKED


@pytest.mark.anyio
async def test_an_unreachable_revocation_oracle_fails_closed() -> None:
    """An oracle that cannot answer is not an oracle reporting no revocation."""

    class Unreachable:
        def is_revoked(self, capability_id: str) -> bool:
            raise ConnectionError("revocation store unavailable")

    gateway = _gateway()
    capability = _issued(gateway)
    registry = default_registry(verifying_key=gateway.verifying_key, revocations=Unreachable())

    result = await registry.execute(_request(), capability)
    assert result.outcome is EffectOutcome.REFUSED_REVOKED
    assert "could not be consulted" in result.detail


# --- The plane cannot be built without the means to refuse -------------------


def test_a_registry_cannot_be_built_without_a_key_and_an_oracle() -> None:
    """The version that could is the version that drafted from an unsigned grant."""
    with pytest.raises(TypeError, match=r"verifying_key|revocations"):
        default_registry()  # type: ignore[call-arg]


@pytest.mark.anyio
async def test_a_properly_issued_capability_still_works() -> None:
    """The counterpart. A boundary that refuses everything is not a boundary, it is an outage."""
    gateway = _gateway()
    result = await _registry(gateway).execute(_request(), _issued(gateway))

    assert result.outcome is EffectOutcome.DRAFTED
    assert not result.external_contact_made


def test_revocation_still_does_not_invalidate_the_signature() -> None:
    """Kept from the original design and worth re-asserting here.

    A revoked capability must stay cryptographically distinguishable from a forged one, so
    revocation is deliberately outside the signed payload — which is precisely why the
    oracle, not the object, is what the boundary asks.
    """
    gateway = _gateway()
    capability = _issued(gateway)
    revoked = capability.model_copy(
        update={"revoked_at": utcnow(), "revocation_reason": "withdrawn"}
    )
    assert capability.signing_payload() == revoked.signing_payload()


@pytest.mark.anyio
async def test_an_unsigned_capability_is_refused_before_anything_else_is_considered() -> None:
    """Authenticity is checked first, on purpose.

    Everything downstream reasons about the capability's contents, and reasoning about the
    contents of a document nobody signed is how a forgery becomes a policy question. Here
    the capability is also expired and permits the wrong operation; the refusal names the
    signature, because that is the finding that matters.
    """
    gateway = _gateway()
    expired_and_wrong = _self_minted(
        issued_at=utcnow() - timedelta(hours=5),
        not_before=utcnow() - timedelta(hours=5),
        expires_at=utcnow() - timedelta(hours=1),
        permitted_operations=frozenset({OperationClass.SIMULATION}),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        legal_authority_reference=None,
    )
    result = await _registry(gateway).execute(_request(), expired_and_wrong)
    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY


# --- The adapter's trust anchor is its own ------------------------------------


@pytest.mark.anyio
async def test_an_adapter_cannot_be_pointed_at_the_attackers_own_authorizer() -> None:
    """Reproduced before the fix: this drafted a document.

    ``registry.adapters`` is public, and ``execute`` used to take the verifying key and the
    revocation oracle as call arguments. So an attacker took a wired adapter, handed it a
    capability signed by their own key together with that key, and the adapter dutifully
    verified the forgery against the forger's key and acted. The port's docstring said the
    adapter "re-verifies rather than trusting the caller" the whole time.
    """
    ours, theirs = _gateway(), _gateway()
    adapter = _registry(ours).adapters[0]
    forged = _issued(theirs)

    result = await adapter.execute(_request(adapter.operation), forged)

    assert result.outcome is EffectOutcome.REFUSED_UNVERIFIED_CAPABILITY
    assert not result.produced_artifacts


def test_an_adapter_wired_to_another_authorizer_cannot_be_registered() -> None:
    """A wiring mistake that would otherwise only surface as an accepted forgery."""
    from nemesis.effects.registry import EffectsRegistry, TrustAnchor
    from nemesis.effects.simulation import SimulationEffectsAdapter

    ours, theirs = _gateway(), _gateway()
    stranger = SimulationEffectsAdapter(
        TrustAnchor(verifying_key=theirs.verifying_key, revocations=theirs.revocations)
    )
    registry = EffectsRegistry(verifying_key=ours.verifying_key, revocations=ours.revocations)

    with pytest.raises(ValueError, match="verifies against key"):
        registry.register(stranger)


def test_an_adapter_that_names_no_authorizer_cannot_be_registered() -> None:
    """Fails closed and says why, rather than raising AttributeError at registration."""
    from nemesis.effects.registry import EffectsRegistry

    class _Anchorless:
        name = "anchorless-adapter"
        operation = OperationClass.SIMULATION
        makes_external_contact = False

        async def execute(self, request: object, capability: object) -> object:
            raise AssertionError("must never be reached")  # pragma: no cover

    gateway = _gateway()
    registry = EffectsRegistry(verifying_key=gateway.verifying_key, revocations=gateway.revocations)
    with pytest.raises(ValueError, match="declares no trust anchor"):
        registry.register(_Anchorless())  # type: ignore[arg-type]
