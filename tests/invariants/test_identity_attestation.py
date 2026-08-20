"""An identity must be established by a verifier, not asserted by whoever is calling.

An audit found the hole this closes. Roles and assurance reached the policy from a
:class:`~nemesis.core.identity.Principal` the caller constructed, so the whole identity
layer could be walked past in four lines::

    forged = Principal(actor_id=..., display_name="Ada", roles={INVESTIGATION_LEAD},
                       assurance=AssuranceLevel.HARDWARE_BACKED,
                       authenticated_by="corporate-sso", authenticated_at=utcnow())
    gateway.approve(request_id, approver=forged, rationale="...")

The gateway issued a genuine Ed25519 capability. The signature was authentic and the
identity behind it had never been checked by anything, which is the failure mode worth
naming: a signature proves that bytes were not edited after signing, and says nothing about
whether they were true when signed.

The tests below cover the four things a self-declared object could not do — prove its
issuer is one we accept, prove it was minted for us, prove it has not expired, and be
capped at what this deployment is willing to believe from that issuer.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from nemesis.authz.attestation import (
    AUDIENCE,
    AttestationError,
    PrincipalVerifier,
    RegisteredIssuer,
)
from nemesis.authz.gateway import AuthorizationGateway
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.providers import PROVIDER_NAME, LocalDevelopmentIdentityProvider
from nemesis.core.authorization import LegalBasis, OperationClass, TargetFingerprint
from nemesis.core.identity import AssuranceLevel, IdentityAssertion, Principal, Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import utcnow

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


# --- The bypass the audit used --------------------------------------------------


def test_a_hand_built_principal_cannot_be_handed_to_the_gateway() -> None:
    """The exploit, verbatim, and it now stops at the door.

    A ``Principal`` is still constructible — it is a value object and there is no way to
    make one unforgeable in-process. What changed is that the gateway does not take one.
    It takes an assertion and asks a verifier, so constructing a principal buys an attacker
    an object nothing will accept.
    """
    forged = Principal(
        actor_id=new_id(IdPrefix.ACTOR),
        display_name="Ada",
        roles=frozenset({Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER}),
        assurance=AssuranceLevel.HARDWARE_BACKED,
        authenticated_by="corporate-sso",
        authenticated_at=utcnow(),
    )
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)

    with pytest.raises((AttributeError, AttestationError, TypeError)):
        gateway.request(
            case_id=new_id(IdPrefix.CASE),
            audit_id=new_id(IdPrefix.AUDIT),
            requested_by=forged,  # type: ignore[arg-type]
            justification="Seize the cluster.",
            targets=(_target(),),
            operations=frozenset({OperationClass.DOMAIN_SEIZURE}),
            jurisdictions=("FR",),
            legal_basis=LegalBasis.COURT_ORDER,
            legal_authority_reference="none held",
            max_effect_description="Four domains seized.",
            lifetime=timedelta(hours=1),
        )


def test_a_gateway_cannot_be_built_without_a_verifier() -> None:
    """The version that could is the version an audit walked through."""
    with pytest.raises(TypeError, match="identity"):
        AuthorizationGateway(CapabilitySigningKey.generate())  # type: ignore[call-arg]


def test_a_verifier_with_no_registered_issuer_is_refused_at_construction() -> None:
    """A verifier that accepts nobody is almost certainly a wiring mistake, and it would
    fail closed in a way that looks like an outage rather than like a misconfiguration."""
    with pytest.raises(ValueError, match="no registered issuer"):
        PrincipalVerifier()


# --- Issuer, audience, expiry, signature ---------------------------------------


def test_an_unknown_issuer_is_refused() -> None:
    """Naming a provider does not make it one."""
    stranger = LocalDevelopmentIdentityProvider(name="corporate-sso")
    assertion = stranger.enrol("Ada", Role.INVESTIGATION_LEAD)

    with pytest.raises(AttestationError, match="not an issuer this deployment accepts"):
        ACTORS.verify(assertion)


def test_an_assertion_minted_for_another_audience_is_refused() -> None:
    """A token obtained from a provider we share with somebody else is not a login here.

    Genuinely minted for the other audience, not edited: editing it now breaks the
    signature, which would test the wrong control.
    """
    elsewhere = DEV.enrol("Ada", Role.INVESTIGATION_LEAD, audience="some-other-relying-party")
    with pytest.raises(AttestationError, match="minted for"):
        ACTORS.verify(elsewhere)


def test_an_edited_audience_breaks_the_signature_before_the_audience_check() -> None:
    """The other half: the audience is inside the signed bytes."""
    edited = DEV.enrol("Ada", Role.INVESTIGATION_LEAD).model_copy(
        update={"audience": "some-other-relying-party"}
    )
    with pytest.raises(AttestationError, match="signature does not verify"):
        ACTORS.verify(edited)


def test_an_expired_assertion_is_refused() -> None:
    assertion = DEV.enrol("Ada", Role.INVESTIGATION_LEAD)
    with pytest.raises(AttestationError, match="expired"):
        ACTORS.verify(assertion, now=assertion.expires_at + timedelta(seconds=1))


def test_an_unsigned_assertion_is_refused() -> None:
    assertion = DEV.enrol("Ada", Role.INVESTIGATION_LEAD)
    with pytest.raises(AttestationError, match="signature does not verify"):
        ACTORS.verify(assertion.model_copy(update={"signature": None}))


def test_an_assertion_signed_by_another_key_is_refused() -> None:
    """Impersonating a registered issuer needs that issuer's key, which is the whole point."""
    impostor = LocalDevelopmentIdentityProvider(name=PROVIDER_NAME)
    with pytest.raises(AttestationError, match="signature does not verify"):
        ACTORS.verify(impostor.enrol("Ada", Role.INVESTIGATION_LEAD))


@pytest.mark.parametrize(
    "mutation",
    [
        {"display_name": "Somebody Else"},
        {"roles": frozenset({Role.LEGAL_REVIEWER})},
        {"assurance": AssuranceLevel.HARDWARE_BACKED},
        {"subject": "actor_" + "f" * 32},
        {"issuer": "corporate-sso"},
        {"audience": "elsewhere"},
        {"expires_at": utcnow() + timedelta(days=3650)},
        {"assertion_id": "actor_" + "e" * 32},
        {"authenticated_at": utcnow() - timedelta(days=1)},
    ],
    ids=lambda m: next(iter(m)),
)
def test_every_field_of_an_assertion_is_covered_by_its_signature(
    mutation: dict[str, object],
) -> None:
    """Generic, so that adding a field without signing it fails here rather than in an audit.

    A field outside the payload is a field an attacker edits for free — which is exactly how
    stop conditions could be stripped from a signed capability before that was found.
    """
    assertion = DEV.enrol("Ada", Role.INVESTIGATION_LEAD)
    altered = assertion.model_copy(update=mutation)

    assert altered.signing_payload() != assertion.signing_payload(), mutation
    with pytest.raises(AttestationError):
        ACTORS.verify(altered)


def test_the_signed_field_list_is_exhaustive() -> None:
    """A tripwire on the model rather than on one instance.

    If somebody adds a field to :class:`IdentityAssertion` and forgets the payload, this
    fails and names the field. Only the signature itself is legitimately excluded.
    """
    import json

    signed = set(json.loads(DEV.enrol("Ada", Role.ANALYST).signing_payload()))
    declared = set(IdentityAssertion.model_fields) - {"signature"}
    assert declared - signed == set(), f"unsigned field(s): {sorted(declared - signed)}"


# --- The ceiling, which is the control that matters today ------------------------


def test_the_development_issuer_is_capped_whatever_it_claims() -> None:
    """The fixture can write ``HARDWARE_BACKED`` into an assertion and sign it honestly.

    What it cannot do is make this deployment believe it. The ceiling belongs to the
    registration, so an issuer cannot promote itself by asserting more.
    """
    overstated = DEV.enrol("Ada", Role.INVESTIGATION_LEAD, claimed=AssuranceLevel.HARDWARE_BACKED)
    assert overstated.assurance is AssuranceLevel.HARDWARE_BACKED

    established = ACTORS.verify(overstated)
    assert established.assurance is AssuranceLevel.DEVELOPMENT
    assert established.is_development_identity


def test_the_ceiling_does_not_promote_a_weaker_assertion() -> None:
    """A ceiling caps; it never raises. An issuer trusted up to hardware-backed still
    establishes only what it actually asserts."""
    provider = LocalDevelopmentIdentityProvider(name="strong-issuer")
    verifier = PrincipalVerifier(
        RegisteredIssuer(
            name=provider.name,
            verifier=provider.verifying_key,
            assurance_ceiling=AssuranceLevel.HARDWARE_BACKED,
        )
    )
    assertion = provider.enrol("Ada", Role.INVESTIGATION_LEAD, claimed=AssuranceLevel.SINGLE_FACTOR)
    assert verifier.verify(assertion).assurance is AssuranceLevel.SINGLE_FACTOR


def test_the_capped_assurance_is_what_the_policy_sees() -> None:
    """End to end: the cap has to reach the decision, not merely the returned object.

    An assertion claiming hardware-backed assurance is capped to DEVELOPMENT, and the
    development floor then refuses a class whose product leaves the platform.
    """
    from nemesis.authz.rbac import AuthorizationPolicyError

    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)
    requester = DEV.enrol("Grace", Role.ANALYST)
    approver = DEV.enrol("Ada", Role.INVESTIGATION_LEAD, claimed=AssuranceLevel.HARDWARE_BACKED)
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=requester,
        justification="Draft an abuse notification.",
        targets=(_target(),),
        operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ToS abuse channel",
        max_effect_description="One unsent draft.",
        lifetime=timedelta(hours=1),
    )

    with pytest.raises(AuthorizationPolicyError, match="not established well enough"):
        gateway.approve(request.capability_id, approver=approver, rationale="Reversible.")


# --- What the audit record says ---------------------------------------------------


def test_the_audit_record_shows_the_established_identity_not_the_asserted_one() -> None:
    """Six months later, a reader must see that a grant rests on a development fixture."""
    gateway = AuthorizationGateway(CapabilitySigningKey.generate(), identity=ACTORS)
    requester = DEV.enrol("Grace", Role.ANALYST)
    approver = DEV.enrol("Ada", Role.INVESTIGATION_LEAD, claimed=AssuranceLevel.HARDWARE_BACKED)
    request = gateway.request(
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=requester,
        justification="Rehearse the takedown.",
        targets=(_target(),),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="A rehearsal that performs nothing.",
        lifetime=timedelta(hours=1),
    )
    approval = gateway.approve(
        request.capability_id, approver=approver, rationale="Performs nothing."
    )

    assert approval.approver_assurance is AssuranceLevel.DEVELOPMENT
    assert approval.authenticated_by == PROVIDER_NAME
    assert approval.approver_roles == frozenset({Role.INVESTIGATION_LEAD})


def test_the_audience_constant_is_what_the_provider_mints_for() -> None:
    """A mismatch here would refuse every login, which is a failure worth catching once."""
    assert DEV.enrol("Ada", Role.ANALYST).audience == AUDIENCE
