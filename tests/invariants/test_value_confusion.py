"""Signing a rendering of a grant is not signing the grant.

An adversarial review broke the authorization chain four ways, all through one mistake. The
signing payload was a hand-written projection of the model — ``op.value`` for an operation,
``role.value`` for a role, ``dt.isoformat()`` for a timestamp — while every decision
downstream compared the *objects*. Anything that rendered as the approved value and compared
as something else passed between the two, with the signature intact.

The class of attack is called value confusion, and Python makes it easy: an ``enum`` member
is its value, a ``StrEnum`` hashes as its string, and a subclass may override ``__eq__``,
``__hash__`` or ``isoformat`` while remaining, to a serializer, the thing it inherits from.

Two independent defences now exist and each is tested here on its own:

1. **The payload is the whole object.** ``model_dump(mode="json")`` renders what the field
   actually holds, so a masked value usually changes the bytes and breaks the signature.
2. **Verification reconstructs.** The signed bytes are parsed back through the model's
   validators, and only that reconstruction is acted on. This is what survives when an
   attacker manages to keep the bytes identical — a parsed enum is a real member.

The second layer is the one that matters, because the first depends on a serializer noticing
something odd. ``test_a_byte_identical_forgery_still_cannot_act`` is the important test in
this file: it defeats layer one on purpose, to prove layer two stands alone.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from nemesis.authz.attestation import AttestationError, PrincipalVerifier
from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.authz.verification import verify_capability
from nemesis.core.authorization import (
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.identity import AssuranceLevel, Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import default_registry
from nemesis.ports.effects import EffectOutcome, EffectRequest

pytestmark = [
    pytest.mark.invariant,
    # Pydantic emits a serializer warning when a field holds something that is not the
    # declared type, and this whole file does exactly that on purpose. The suite turns
    # warnings into errors, so it must be silenced here — and it is worth being explicit
    # that the warning is NOT one of the defences. It fires at serialization time, in a
    # process the attacker controls, and can be silenced by the attacker just as easily as
    # by this line. The defences are the two below it: sign the object, verify by rebuilding.
    pytest.mark.filterwarnings("ignore:Pydantic serializer warnings:UserWarning"),
]

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())


class RendersAs(str):
    """A string that serializes as one value and compares as another.

    The heart of the attack. ``str`` carries its own content, so a serializer writes
    ``simulation``; ``__hash__`` and ``__eq__`` are overridden, so ``in`` finds
    ``provider_notification``. Nothing here is exotic — it is ten lines any caller can write.
    """

    __slots__ = ("_compares_as",)
    _compares_as: str

    def __new__(cls, renders_as: str, compares_as: str) -> RendersAs:
        item = super().__new__(cls, renders_as)
        item._compares_as = compares_as
        return item

    def __hash__(self) -> int:
        return hash(self._compares_as)

    def __eq__(self, other: object) -> bool:
        return other == self._compares_as or str.__eq__(self, other) is True


class Immortal(datetime):
    """A timestamp that reports an old expiry and compares as the far future."""

    __slots__ = ("_claimed",)
    _claimed: datetime

    @classmethod
    def masking(cls, claimed: datetime) -> Immortal:
        item = cls(2099, 1, 1, tzinfo=UTC)
        item._claimed = claimed
        return item

    def isoformat(self, *args: object, **kwargs: object) -> str:
        return self._claimed.isoformat()


# --- fixtures -----------------------------------------------------------------


def _target() -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="glass-anvil.example",
        bound_attributes={"resolves_to": "198.51.100.23"},
    )


def _rehearsal_grant() -> tuple[AuthorizationGateway, AuthorizationCapability, TargetFingerprint]:
    """A capability permitting SIMULATION and nothing else, honestly issued.

    Its legal basis would cover a notification, so nothing but the permitted set stands
    between this grant and a document leaving the platform. That is the point: the test
    must not pass for an unrelated reason.
    """
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
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ToS abuse channel",
        max_effect_description="A rehearsal that performs nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(
        request.capability_id,
        approver=DEV.enrol("Ada", Role.INVESTIGATION_LEAD),
        rationale="Performs nothing.",
    )
    return gateway, gateway.issue(request.capability_id), target


def _notification(target: TargetFingerprint) -> EffectRequest:
    return EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=OperationClass.PROVIDER_NOTIFICATION,
        target_fingerprint=target.fingerprint,
        target_natural_key=target.natural_key,
        current_target_attributes=dict(target.bound_attributes),
        parameters={"purpose": "abuse report"},
        requested_by=new_id(IdPrefix.ACTOR),
        requested_at=utcnow(),
    )


# --- Layer one: the payload is the object -------------------------------------


def test_a_masked_operation_no_longer_renders_as_the_approved_one() -> None:
    """The original break, at the byte level."""
    _, capability, _ = _rehearsal_grant()
    widened = capability.model_copy(
        update={
            "permitted_operations": frozenset(
                {RendersAs("provider_notification", "provider_notification")}
            )
        }
    )
    assert widened.signing_payload() != capability.signing_payload()


def test_a_masked_expiry_no_longer_renders_as_the_approved_one() -> None:
    """``MAX_CAPABILITY_LIFETIME`` was advisory while ``isoformat()`` was what got signed."""
    _, capability, _ = _rehearsal_grant()
    immortal = capability.model_copy(update={"expires_at": Immortal.masking(capability.expires_at)})
    assert immortal.signing_payload() != capability.signing_payload()


# --- Layer two: verification reconstructs -------------------------------------


def test_a_byte_identical_forgery_still_cannot_act() -> None:
    """The load-bearing test. Layer one is defeated here on purpose.

    ``RendersAs("simulation", "provider_notification")`` serializes as ``simulation`` — the
    bytes are genuinely identical and the genuine signature genuinely verifies. A naive
    membership test permits a provider notification. Only reconstructing the grant from the
    signed bytes refuses it.
    """
    gateway, capability, target = _rehearsal_grant()
    forged = capability.model_copy(
        update={
            "permitted_operations": frozenset({RendersAs("simulation", "provider_notification")})
        }
    )

    assert forged.signing_payload() == capability.signing_payload(), "layer one is bypassed"
    assert OperationClass.PROVIDER_NOTIFICATION in forged.permitted_operations, (
        "a naive membership check permits the escalation"
    )

    verification = verify_capability(forged, gateway.verifying_key, now=utcnow())
    assert verification.signature_valid, "the signature is genuine; that was never the defence"
    assert verification.authenticated is not None
    assert verification.authenticated.permitted_operations == frozenset({OperationClass.SIMULATION})

    result = asyncio.run(
        default_registry(
            verifying_key=gateway.verifying_key, revocations=gateway.revocations
        ).execute(_notification(target), forged)
    )
    assert result.outcome is EffectOutcome.REFUSED_UNAUTHORIZED
    assert not result.produced_artifacts


def test_the_reconstruction_is_what_the_effects_plane_acts_on() -> None:
    """Stated as its own assertion, because it is the whole design and it is one line of
    code away from being undone by a well-meaning refactor that reuses ``capability``."""
    gateway, capability, _ = _rehearsal_grant()
    verification = verify_capability(capability, gateway.verifying_key, now=utcnow())

    assert verification.authenticated is not None
    assert verification.authenticated is not capability
    assert verification.authenticated.permitted_operations == capability.permitted_operations


def test_nothing_unverified_is_handed_on_as_a_grant() -> None:
    """``authenticated`` must be None whenever the capability failed any check.

    Otherwise a caller reaching for the reconstruction gets a usable object out of a failed
    verification, which is worse than the bug this replaced.
    """
    gateway, capability, _ = _rehearsal_grant()
    stranger = CapabilitySigningKey.generate()

    assert verify_capability(capability, stranger.verifying_key, now=utcnow()).authenticated is None
    unsigned = capability.model_copy(update={"signature": None})
    assert verify_capability(unsigned, gateway.verifying_key, now=utcnow()).authenticated is None


# --- The same attack on identity ----------------------------------------------


def test_a_masked_role_cannot_establish_a_principal_that_was_not_asserted() -> None:
    """An assertion serializing as ``analyst`` established a ``legal_reviewer``.

    That is worse than an escalation: the audit record showed a legal review, indexed by a
    real actor id, that no issuer ever vouched for.
    """
    honest = DEV.enrol("Mallory", Role.ANALYST)
    masked = honest.model_copy(
        update={"roles": frozenset({RendersAs("analyst", "legal_reviewer")})}
    )

    assert masked.signing_payload() == honest.signing_payload(), "layer one is bypassed"
    assert Role.LEGAL_REVIEWER in masked.roles, "a naive check sees a legal reviewer"

    established = ACTORS.verify(masked)
    assert established.roles == frozenset({Role.ANALYST})
    assert not established.has(Role.LEGAL_REVIEWER)


def test_a_masked_expiry_cannot_revive_an_expired_assertion() -> None:
    """An identity established long enough ago is a session, not a login."""
    honest = DEV.enrol("Mallory", Role.ANALYST)
    immortal = honest.model_copy(update={"expires_at": Immortal.masking(honest.expires_at)})

    with pytest.raises(AttestationError):
        ACTORS.verify(immortal, now=honest.expires_at + timedelta(seconds=1))


def test_a_masked_assurance_cannot_exceed_what_was_asserted() -> None:
    """``AssuranceLevel`` is an ``IntEnum``, so the same trick applies to integers."""

    class Overstated(int):
        __slots__ = ()

        def __eq__(self, other: object) -> bool:
            return other == AssuranceLevel.HARDWARE_BACKED or int.__eq__(self, other) is True

        def __hash__(self) -> int:
            return hash(int(AssuranceLevel.HARDWARE_BACKED))

    honest = DEV.enrol("Mallory", Role.INVESTIGATION_LEAD)
    masked = honest.model_copy(update={"assurance": Overstated(int(AssuranceLevel.DEVELOPMENT))})

    established = ACTORS.verify(masked)
    assert established.assurance is AssuranceLevel.DEVELOPMENT
    assert established.is_development_identity


# --- The canonical encoding is stable and lossless ----------------------------


def test_the_payload_round_trips_to_an_equal_grant() -> None:
    """If reconstruction lost a field, the reconstruction would silently be a weaker grant."""
    _, capability, _ = _rehearsal_grant()
    rebuilt = AuthorizationCapability.from_signed_payload(capability.signing_payload())

    expected = capability.model_dump(exclude={"signature", "revoked_at", "revocation_reason"})
    actual = rebuilt.model_dump(exclude={"signature", "revoked_at", "revocation_reason"})
    assert actual == expected


def test_reordering_a_sequence_does_not_change_the_bytes() -> None:
    """The encoding sorts, so an approval list arriving in a different order still verifies.

    This is safe only because nothing signed here carries meaning in its ordering. If a
    future signed field ever does, sorting becomes the wrong encoding — hence the test.
    """
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)
    first, second = (
        _target(),
        TargetFingerprint.create(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type="domain",
            natural_key="second.example",
            bound_attributes={"resolves_to": "198.51.100.24"},
        ),
    )
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=DEV.enrol("Grace", Role.ANALYST),
        justification="Rehearse.",
        targets=(first, second),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR", "NL"),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="Nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(
        request.capability_id,
        approver=DEV.enrol("Ada", Role.INVESTIGATION_LEAD),
        rationale="Performs nothing.",
    )
    capability = gateway.issue(request.capability_id)

    reordered = capability.model_copy(
        update={"targets": (second, first), "jurisdictions": ("NL", "FR")}
    )
    assert reordered.signing_payload() == capability.signing_payload()
    assert verify_capability(reordered, gateway.verifying_key, now=utcnow()).is_usable_now


# --- The document must quote the grant, not the caller's copy of it -----------


class Lying(str):
    """Content matches the signed value; ``__str__`` does not.

    Defeats the encoding layer completely — the bytes are genuinely identical, because the
    string's *content* is honest. Only what a formatter prints is a lie, which is exactly
    what ends up in a document addressed to somebody outside.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return "TGI Paris ord. 2026/9999 - seizure authorised"

    def __format__(self, spec: str) -> str:
        return str(self)


def test_a_drafted_document_cannot_cite_an_authority_that_was_never_signed() -> None:
    """A provider notification cited a fabricated court order, under a genuine signature.

    The header is composed from the capability because, in the drafting adapter's own
    words, "a document that cited the caller's idea of its own legal basis would be citing
    the attacker". It was composing from the object passed to ``execute`` rather than from
    the reconstruction, so it was citing the attacker.

    This one leaves the platform in the only sense that matters: a human reads the draft and
    sends it. A document is not an internal record.
    """
    from tests.support.identity import elevated, hardware_backed_issuer, verifier_over

    provider, _ = hardware_backed_issuer()
    actors = verifier_over(provider)
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=actors)
    target = _target()
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=elevated(provider, "Grace", Role.ANALYST),
        justification="Notify the transit provider.",
        targets=(target,),
        operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ToS abuse channel",
        max_effect_description="One unsent draft.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(
        request.capability_id,
        approver=elevated(provider, "Ada", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER),
        rationale="Reversible; the draft is not sent by us.",
    )
    capability = gateway.issue(request.capability_id)

    lying = capability.model_copy(update={"legal_authority_reference": Lying("ToS abuse channel")})
    assert lying.signing_payload() == capability.signing_payload(), "layer one is bypassed"

    result = asyncio.run(
        default_registry(
            verifying_key=gateway.verifying_key, revocations=gateway.revocations
        ).execute(
            EffectRequest(
                operation_id=new_id(IdPrefix.OPERATION),
                operation=OperationClass.PROVIDER_NOTIFICATION,
                target_fingerprint=target.fingerprint,
                target_natural_key=target.natural_key,
                current_target_attributes=dict(target.bound_attributes),
                parameters={"purpose": "abuse report"},
                requested_by=new_id(IdPrefix.ACTOR),
                requested_at=utcnow(),
            ),
            lying,
        )
    )

    assert result.outcome is EffectOutcome.DRAFTED, "the grant is genuine; it must still work"
    assert "Authority reference: ToS abuse channel" in result.detail
    assert "2026/9999" not in result.detail
    assert "seizure authorised" not in result.detail
