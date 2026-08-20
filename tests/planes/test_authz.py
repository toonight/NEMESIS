"""The Authorization Gateway: what stands between an agent and a real-world effect.

Every test here assumes the caller is hostile or broken. The question is never "does the
happy path work" but "what does an attacker get if this control is absent". Three failures
are modelled specifically:

- **Forgery.** Something that was never approved is presented as if it had been. Caught by
  the signature, whose private half no plane that acts ever holds.
- **Alteration after approval.** A real capability is widened, or re-aimed at a different
  target, between the human decision and execution. Caught because the signature covers the
  grant, and because verification re-derives structural validity instead of trusting the
  object it was handed.
- **Confusion between revoked and forged.** A revoked capability must keep verifying. If
  revocation changed the signed bytes, the operator investigating a refused operation could
  no longer tell "we withdrew this" from "someone made this up".

Keys are generated per test and never written anywhere. A private key committed to the
repository would make every reader of the repository an authorizer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nemesis.authz.gateway import (
    MAX_CAPABILITY_LIFETIME,
    AlreadyDecidedError,
    AuthorizationError,
    AuthorizationGateway,
    DuplicateApproverError,
    InsufficientApprovalsError,
    RequestState,
    RevocationRegistry,
    SelfApprovalError,
    UnknownRequestError,
    required_approvals_for,
)
from nemesis.authz.keys import SIGNATURE_SCHEME, CapabilitySigningKey, CapabilityVerifyingKey
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.authz.rbac import AuthorizationPolicyError
from nemesis.authz.verification import verify_capability
from nemesis.core.authorization import (
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.identity import AssuranceLevel, IdentityAssertion, Role
from nemesis.core.ids import IdPrefix, new_id
from tests.support.identity import elevated, hardware_backed_issuer, verifier_over

NOW = datetime(2026, 3, 10, 9, 0, tzinfo=UTC)

DEV = LocalDevelopmentIdentityProvider()
STRONG, _ = hardware_backed_issuer()
ACTORS = verifier_over(DEV, STRONG)
"""Two issuers, and the suite states what each one's word is worth. Everything below that
needs an identity stronger than a development fixture obtains it from ``STRONG`` — not by
overwriting an assurance field, which is the bypass these tests exist to catch."""

PLANNER = DEV.enrol("Planner", Role.ANALYST, Role.INVESTIGATION_LEAD)
ALICE = DEV.enrol("Alice", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER)
BOB = DEV.enrol("Bob", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER)
"""Development identities. They can approve a rehearsal and nothing else, which is what a
platform with no identity provider is entitled to."""

PLANNER_ID = ACTORS.verify(PLANNER).actor_id
ALICE_ID = ACTORS.verify(ALICE).actor_id
BOB_ID = ACTORS.verify(BOB).actor_id


def _at(assertion: IdentityAssertion, assurance: AssuranceLevel) -> IdentityAssertion:
    """The same person, established by an issuer this deployment trusts that far.

    Used where a test exercises an operation class whose floor a development identity cannot
    clear. The elevation goes through the verifier's per-issuer ceiling like any other
    identity, so a test cannot reach an assurance the deployment has not granted.
    """
    if assurance is AssuranceLevel.DEVELOPMENT:
        return assertion
    return elevated(STRONG, assertion.display_name, *assertion.roles, subject=assertion.subject)


CASE = new_id(IdPrefix.CASE)
AUDIT = new_id(IdPrefix.AUDIT)

# The four domains of the GLASS ANVIL cluster (DEMO_SCENARIO.md §2.2).
CLUSTER = (
    "acme-invoice-portal.example",
    "acme-billing-secure.example",
    "globex-invoice-portal.example",
    "initech-payments-secure.example",
)


def _target(domain: str, *, resolves_to: str = "198.51.100.23") -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key=domain,
        bound_attributes={"resolves_to": resolves_to, "registrar": "bulletproofreg"},
    )


def _gateway(
    signer: CapabilitySigningKey,
    *,
    clock: datetime = NOW,
) -> AuthorizationGateway:
    return AuthorizationGateway(signer, identity=ACTORS, clock=lambda: clock)


def _issued(
    signer: CapabilitySigningKey,
    *,
    operations: frozenset[OperationClass] = frozenset({OperationClass.SIMULATION}),
    legal_basis: LegalBasis = LegalBasis.NONE_SIMULATION_ONLY,
    legal_authority_reference: str | None = None,
    targets: tuple[TargetFingerprint, ...] = (),
    lifetime: timedelta = timedelta(hours=4),
) -> tuple[AuthorizationGateway, AuthorizationCapability]:
    """Drive one request all the way through the gateway and return the signed grant."""
    gateway = _gateway(signer)
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Simulated takedown of the GLASS ANVIL cluster.",
        targets=targets or (_target(CLUSTER[0]),),
        operations=operations,
        jurisdictions=("FR",),
        legal_basis=legal_basis,
        legal_authority_reference=legal_authority_reference,
        max_effect_description="One simulated suspension. No external contact.",
        lifetime=lifetime,
    )
    gateway.approve(
        request.capability_id,
        approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
        rationale="Evidence bundle reviewed; the cluster is the adversary's.",
    )
    return gateway, gateway.issue(request.capability_id)


# --- Forgery: an agent cannot mint bytes that verify --------------------------


def test_a_capability_signed_by_another_key_is_refused_and_the_key_is_named() -> None:
    """The forgery case: someone with the whole approval record but not the signing key.

    The refusal must name the key that produced the envelope. "Rejected" alone would lose
    the only lead about whose key is minting capabilities for this platform.
    """
    authorizer = CapabilitySigningKey.generate()
    attacker = CapabilitySigningKey.generate()
    _, genuine = _issued(authorizer)

    forged = genuine.model_copy(
        update={"signature": attacker.sign(genuine.signing_payload())},
    )
    verification = verify_capability(forged, authorizer.verifying_key, now=NOW)

    assert not verification.signature_valid
    assert not verification.is_authentic
    assert verification.signed_by == attacker.key_id
    assert verification.signature_failure is not None
    assert "not signed by this authorizer" in verification.signature_failure


def test_a_stolen_signature_relabelled_with_the_authorizer_key_id_still_fails() -> None:
    """Relabelling the envelope is the obvious next move once the key-id check is known.

    The key id only selects which key to check against; the signature is what decides. If
    this test fails, the identifier has become the credential.
    """
    authorizer = CapabilitySigningKey.generate()
    attacker = CapabilitySigningKey.generate()
    _, genuine = _issued(authorizer)

    stolen = attacker.sign(genuine.signing_payload())
    _, _, encoded = stolen.split(":")
    relabelled = f"{SIGNATURE_SCHEME}:{authorizer.key_id}:{encoded}"

    verification = verify_capability(
        genuine.model_copy(update={"signature": relabelled}),
        authorizer.verifying_key,
        now=NOW,
    )
    assert not verification.signature_valid
    assert verification.signature_failure is not None
    assert "does not match the signed bytes" in verification.signature_failure


def test_an_unsigned_capability_is_not_authentic() -> None:
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer)

    verification = verify_capability(
        capability.model_copy(update={"signature": None}), signer.verifying_key, now=NOW
    )
    assert not verification.is_authentic
    assert verification.signature_failure == "capability carries no signature"


def test_a_malformed_envelope_is_reported_as_malformed_not_as_a_bad_signature() -> None:
    """Different incidents: a parser mismatch is an integration bug, a bad signature is an
    attack. Collapsing them sends an operator hunting the wrong problem."""
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer)

    verification = verify_capability(
        capability.model_copy(update={"signature": "ed25519:deadbeef"}),
        signer.verifying_key,
        now=NOW,
    )
    assert verification.signature_failure is not None
    assert "malformed signature envelope" in verification.signature_failure


# --- Alteration after approval ------------------------------------------------


def test_a_tampered_capability_fails_verification() -> None:
    """The approved worst-case outcome is part of what was signed."""
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer)

    tampered = capability.model_copy(
        update={"max_effect_description": "Suspension of every domain in the cluster."}
    )
    verification = verify_capability(tampered, signer.verifying_key, now=NOW)

    assert not verification.signature_valid
    assert verification.structural_failures == ()  # only the signature caught this


def test_widening_permitted_operations_after_signing_fails_verification() -> None:
    """The escalation an attacker actually wants: keep a genuine grant, add an operation.

    The widened capability stays structurally valid — it is a well-formed object — so the
    signature is the only thing standing between the addition and execution.
    """
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(
        signer,
        operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ACME-2026-0847",
    )

    widened = capability.model_copy(
        update={
            "permitted_operations": frozenset(
                {OperationClass.PROVIDER_NOTIFICATION, OperationClass.TAKEDOWN_REQUEST_DRAFT}
            )
        }
    )
    verification = verify_capability(widened, signer.verifying_key, now=NOW)

    assert not verification.signature_valid
    assert verification.structural_failures == ()
    assert not verification.is_authentic
    assert not verification.is_usable_now


def test_swapping_a_target_after_signing_fails_verification() -> None:
    """Re-aiming an approved operation at infrastructure nobody approved."""
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer)

    swapped = capability.model_copy(update={"targets": (_target("innocent-bystander.example"),)})
    verification = verify_capability(swapped, signer.verifying_key, now=NOW)

    assert not verification.signature_valid


def test_editing_a_target_beneath_its_fingerprint_is_caught_twice_over() -> None:
    """Renaming a target under a kept fingerprint used to be a signature-valid attack.

    The fingerprint is a hash of the target's state, so the old payload signed only the
    hashes and left ``natural_key`` outside the signature: an approval for evil.example
    could be relabelled initech-payments-secure.example and still verify, and only the
    structural re-derivation caught it.

    The payload now covers the whole capability, so the signature catches it first. The
    structural check remains as the second layer — it is what would catch this if the
    attacker held the signing key, which is the case it was written for.
    """
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer)

    relabelled_target = capability.targets[0].model_copy(
        update={"natural_key": "initech-payments-secure.example"}
    )
    altered = capability.model_copy(update={"targets": (relabelled_target,)})

    # Layer one: the rename is inside the signed bytes.
    verification = verify_capability(altered, signer.verifying_key, now=NOW)
    assert not verification.signature_valid
    assert not verification.is_authentic
    assert verification.authenticated is None

    # Layer two: even re-signed by the authorizer's own key, it does not survive.
    resigned = altered.model_copy(update={"signature": signer.sign(altered.signing_payload())})
    reverified = verify_capability(resigned, signer.verifying_key, now=NOW)
    assert reverified.signature_valid
    assert not reverified.is_authentic
    assert "does not match the bound attributes" in " ".join(reverified.structural_failures)
    assert reverified.authenticated is None, "nothing incoherent may be handed on as a grant"


# --- Revocation is not forgery ------------------------------------------------


def test_a_revoked_capability_stays_distinguishable_from_a_forged_one() -> None:
    """Both are refused. They must not be refused for the same reason.

    A revoked capability keeps verifying — the withdrawal lives in state, not in the bytes.
    A forged one never verified. If revocation rewrote the signed payload, these two would
    become the same event to everyone downstream.
    """
    authorizer = CapabilitySigningKey.generate()
    attacker = CapabilitySigningKey.generate()
    gateway, capability = _issued(authorizer)

    gateway.revoke(
        capability.capability_id,
        "target ownership disputed by the registrant",
        revoked_by=ALICE_ID,
    )
    revoked = gateway.capability(capability.capability_id)
    assert revoked is not None

    forged = capability.model_copy(
        update={"signature": attacker.sign(capability.signing_payload())}
    )

    revoked_check = verify_capability(revoked, authorizer.verifying_key, now=NOW)
    forged_check = verify_capability(forged, authorizer.verifying_key, now=NOW)

    assert revoked_check.is_authentic
    assert revoked_check.signature_valid
    assert not forged_check.is_authentic

    # The withdrawal is real, and it is only visible to something holding the registry.
    assert gateway.is_revoked(capability.capability_id)
    withdrawn = revoked.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=revoked.targets[0].fingerprint,
        now=NOW,
    )
    assert not withdrawn.permitted
    assert any("revoked" in reason for reason in withdrawn.denial_reasons)

    # The bytes handed out before the revocation keep verifying, by design.
    assert verify_capability(capability, authorizer.verifying_key, now=NOW).is_authentic


def test_re_revoking_cannot_move_the_effective_time_later() -> None:
    """Otherwise a second revocation could narrow the window in which the first applied,
    and an operation performed in between would retroactively look authorized."""
    signer = CapabilitySigningKey.generate()
    gateway, capability = _issued(signer)

    gateway.revoke(capability.capability_id, "first", revoked_by=ALICE_ID, revoked_at=NOW)
    gateway.revoke(
        capability.capability_id,
        "second",
        revoked_by=BOB_ID,
        revoked_at=NOW + timedelta(hours=1),
    )

    # Read through the concrete registry, not through the gateway's `RevocationLedger` view:
    # that port promises `is_revoked` and not `revocation_of`, and reaching past a narrowed
    # port in a test is how a test comes to depend on something the design does not offer.
    ledger = gateway.revocations
    assert isinstance(ledger, RevocationRegistry)
    revocation = ledger.revocation_of(capability.capability_id)
    assert revocation is not None
    assert revocation.revoked_at == NOW
    assert revocation.reason == "first"


# --- Expiry -------------------------------------------------------------------


def test_an_expired_capability_verifies_structurally_but_authorizes_nothing() -> None:
    """Expiry is not tampering. The object stays authentic and stays unusable, and the two
    answers are reported separately so an operator is not sent hunting a forgery."""
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer, lifetime=timedelta(hours=4))
    later = NOW + timedelta(hours=5)

    verification = verify_capability(capability, signer.verifying_key, now=later)
    assert verification.is_authentic
    assert verification.signature_valid
    assert verification.time_status == "expired"
    assert not verification.is_usable_now

    decision = capability.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=capability.targets[0].fingerprint,
        now=later,
    )
    assert not decision.permitted
    assert any("expired" in reason for reason in decision.denial_reasons)


def test_a_lifetime_beyond_the_ceiling_is_refused_at_request_time() -> None:
    """A capability outliving the situation that justified it is a standing permission."""
    gateway = _gateway(CapabilitySigningKey.generate())
    with pytest.raises(AuthorizationError, match="exceeds the ceiling"):
        gateway.request(
            case_id=CASE,
            audit_id=AUDIT,
            requested_by=PLANNER,
            justification="Keep this handy in case we need it again.",
            targets=(_target(CLUSTER[0]),),
            operations=frozenset({OperationClass.SIMULATION}),
            jurisdictions=("FR",),
            legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
            max_effect_description="One simulated suspension.",
            lifetime=MAX_CAPABILITY_LIFETIME + timedelta(minutes=1),
        )


# --- The Effects plane verifies with the public half and nothing else ---------


def test_the_effects_plane_verifies_with_the_public_key_alone() -> None:
    """Invariant 8: the plane that acts holds no signing key, no gateway and no store.

    The key is reloaded from its distributable PEM to prove nothing else travelled with it.
    """
    signer = CapabilitySigningKey.generate()
    _, capability = _issued(signer)

    distributed = CapabilityVerifyingKey.from_pem(signer.verifying_key.public_pem())
    verification = verify_capability(capability, distributed, now=NOW)

    assert verification.is_usable_now
    assert verification.signed_by == signer.key_id


def test_a_verifying_key_cannot_produce_a_signature() -> None:
    """Structural, not conventional: the public half exposes no way to sign at all, so a
    plane handed one cannot end up minting the authority it was meant only to check.

    The two types are unrelated by inheritance, which is what makes handing a signing key
    where a verifying key is expected a type error rather than a convention someone can
    quietly drop during a refactor.
    """
    verifying = CapabilitySigningKey.generate().verifying_key
    assert not hasattr(verifying, "sign")
    assert not issubclass(CapabilitySigningKey, CapabilityVerifyingKey)
    assert not issubclass(CapabilityVerifyingKey, CapabilitySigningKey)


def test_verification_cannot_see_revocation() -> None:
    """The documented cost of keeping revocation out of the signed bytes: a holder with the
    public key alone will keep verifying a withdrawn capability forever. Asserted so the
    asymmetry stays a known property rather than a surprise in production."""
    signer = CapabilitySigningKey.generate()
    gateway, capability = _issued(signer)
    gateway.revoke(capability.capability_id, "withdrawn", revoked_by=ALICE_ID)

    assert verify_capability(capability, signer.verifying_key, now=NOW).is_usable_now
    assert gateway.is_revoked(capability.capability_id)


def test_a_gateway_refuses_a_verifying_key_that_does_not_match_its_signer() -> None:
    """Otherwise it would issue capabilities that nobody downstream can verify."""
    with pytest.raises(ValueError, match="does not match signer"):
        AuthorizationGateway(
            CapabilitySigningKey.generate(),
            identity=ACTORS,
            verifying_key=CapabilitySigningKey.generate().verifying_key,
        )


def test_a_signing_key_refuses_to_export_itself_unencrypted() -> None:
    """A readable private key makes its reader an authorizer."""
    signer = CapabilitySigningKey.generate()
    with pytest.raises(ValueError, match="refusing to export an unencrypted signing key"):
        signer.export_private_pem(passphrase=b"")

    exported = signer.export_private_pem(passphrase=b"correct horse battery staple")
    assert b"ENCRYPTED PRIVATE KEY" in exported


# --- Dual control -------------------------------------------------------------


def test_dual_control_requires_distinct_approvers() -> None:
    """One person supplying both halves is one person deciding, wearing two signatures."""
    gateway = _gateway(CapabilitySigningKey.generate())
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Seize the four domains.",
        targets=(_target(CLUSTER[0]),),
        operations=frozenset({OperationClass.DOMAIN_SEIZURE}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.COURT_ORDER,
        legal_authority_reference="TGI Paris, ord. 2026/1234",
        max_effect_description="Seizure of one domain.",
        lifetime=timedelta(hours=2),
    )
    assert request.required_approvals == 2

    gateway.approve(
        request.capability_id,
        approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
        rationale="Ownership corroborated by registrar record and certificate reuse.",
    )
    with pytest.raises(DuplicateApproverError, match="cannot supply two"):
        gateway.approve(
            request.capability_id,
            approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
            rationale="Still fine by me.",
        )

    with pytest.raises(InsufficientApprovalsError, match="needs 2 approval"):
        gateway.issue(request.capability_id)

    gateway.approve(
        request.capability_id,
        approver=_at(BOB, AssuranceLevel.HARDWARE_BACKED),
        rationale="Court order on file.",
    )
    capability = gateway.issue(request.capability_id)
    assert len({approval.approver for approval in capability.approvals if approval.decision}) == 2


def test_a_requester_cannot_approve_their_own_request() -> None:
    """A requester who can approve is a requester who can issue."""
    gateway = _gateway(CapabilitySigningKey.generate())
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Simulated takedown.",
        targets=(_target(CLUSTER[0]),),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="One simulated suspension.",
        lifetime=timedelta(hours=1),
    )
    with pytest.raises(SelfApprovalError, match="cannot also decide it"):
        gateway.approve(
            request.capability_id,
            approver=PLANNER,
            rationale="I proposed it, so it must be right.",
        )


def test_only_irreversible_operations_demand_two_approvers() -> None:
    assert required_approvals_for({OperationClass.SIMULATION}) == 1
    assert required_approvals_for({OperationClass.PROVIDER_NOTIFICATION}) == 1
    assert required_approvals_for({OperationClass.DOMAIN_SEIZURE}) == 2
    assert (
        required_approvals_for({OperationClass.SIMULATION, OperationClass.REGISTRAR_SUSPENSION})
        == 2
    )


# --- The record of what was refused -------------------------------------------


def test_a_rejection_closes_the_request_and_stays_readable() -> None:
    """DEMO_SCENARIO.md phase 7: the analyst rejects the registrar suspension. The refusal
    and its rationale are as operationally important as the grants, and a later approver
    must not be able to outvote it — otherwise dual control degrades into a search for the
    most permissive reviewer."""
    gateway = _gateway(CapabilitySigningKey.generate())
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Suspend all four domains at the registrar.",
        targets=tuple(_target(domain) for domain in CLUSTER),
        operations=frozenset({OperationClass.REGISTRAR_SUSPENSION}),
        jurisdictions=("FR", "US"),
        legal_basis=LegalBasis.STATUTORY_NOTICE_AND_ACTION,
        legal_authority_reference="DSA Art. 16 notice 2026-0031",
        max_effect_description="Four domains suspended at the registrar.",
        lifetime=timedelta(hours=4),
    )
    gateway.reject(
        request.capability_id,
        approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
        rationale="initech-payments-secure.example may belong to an uninvolved business.",
    )

    with pytest.raises(AlreadyDecidedError, match="was rejected"):
        gateway.approve(
            request.capability_id,
            approver=_at(BOB, AssuranceLevel.HARDWARE_BACKED),
            rationale="Looks fine to me.",
        )
    with pytest.raises(AlreadyDecidedError, match="was rejected"):
        gateway.issue(request.capability_id)

    status = gateway.status(request.capability_id)
    assert status.state is RequestState.REJECTED
    assert status.capability is None
    assert len(status.refused) == 1
    assert "uninvolved business" in status.refused[0].rationale
    assert request not in gateway.pending()


def test_a_capability_cannot_be_issued_twice() -> None:
    """Two live capabilities from one human decision is one decision being spent twice."""
    signer = CapabilitySigningKey.generate()
    gateway, capability = _issued(signer)
    with pytest.raises(AlreadyDecidedError, match="already been issued"):
        gateway.issue(capability.capability_id)


def test_an_unknown_request_id_cannot_be_decided_issued_or_revoked() -> None:
    """A decision trail against an id the gateway never saw is a fabricated one."""
    gateway = _gateway(CapabilitySigningKey.generate())
    unknown = new_id(IdPrefix.CAPABILITY)

    with pytest.raises(UnknownRequestError):
        gateway.approve(
            unknown,
            approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
            rationale="fine",
        )
    with pytest.raises(UnknownRequestError):
        gateway.issue(unknown)
    with pytest.raises(UnknownRequestError):
        gateway.revoke(unknown, "never existed", revoked_by=ALICE_ID)


# --- The scenario's capability, end to end ------------------------------------


def test_the_glass_anvil_capability_is_narrow_and_expiring() -> None:
    """DEMO_SCENARIO.md phase 7: four target fingerprints, permitted operations
    {SIMULATION, PROVIDER_NOTIFICATION}, a four-hour expiry, one approver for these
    reversible classes."""
    signer = CapabilitySigningKey.generate()
    gateway = _gateway(signer)
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification=(
            "Simulated takedown plus a factual notification to the upstream transit "
            "provider for the four domains of the GLASS ANVIL cluster."
        ),
        targets=tuple(_target(domain) for domain in CLUSTER),
        operations=frozenset({OperationClass.SIMULATION, OperationClass.PROVIDER_NOTIFICATION}),
        jurisdictions=("FR", "NL"),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference="ACME-2026-0847",
        max_effect_description=(
            "One drafted abuse notification and one simulated suspension. No external contact."
        ),
        lifetime=timedelta(hours=4),
    )
    gateway.approve(
        request.capability_id,
        approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
        rationale="Infrastructure and campaign attribution reviewed; both classes reversible.",
        reviewed_evidence=("evd_cluster_bundle",),
    )
    capability = gateway.issue(request.capability_id)

    assert len(capability.targets) == 4
    assert capability.remaining(NOW) == timedelta(hours=4)
    assert capability.time_status(NOW) == "valid"
    assert gateway.status(request.capability_id).state is RequestState.ISSUED

    permitted = capability.authorizes(
        operation=OperationClass.PROVIDER_NOTIFICATION,
        target_fingerprint=capability.targets[0].fingerprint,
        now=NOW,
    )
    assert permitted.permitted

    # The grant is narrow: an operation nobody approved is refused even on an approved
    # target, and an approved operation is refused against a target nobody approved.
    refused_operation = capability.authorizes(
        operation=OperationClass.REGISTRAR_SUSPENSION,
        target_fingerprint=capability.targets[0].fingerprint,
        now=NOW,
    )
    assert not refused_operation.permitted

    refused_target = capability.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=_target("unrelated.example").fingerprint,
        now=NOW,
    )
    assert not refused_target.permitted
    assert "does not match any approved target" in refused_target.render()


# --- The legal reviewer, who has to be in the room ------------------------------


def _under_court_order(gateway: AuthorizationGateway) -> str:
    """A notification sent under a court order.

    Deliberately an operation class an investigation lead may approve on their own. The role
    table already routes seizures to a legal reviewer, so a seizure would prove nothing here;
    the gap is a modest operation resting on a legal instrument nobody qualified has read.
    """
    return gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Notify the transit provider, as the order directs.",
        targets=(_target(CLUSTER[0]),),
        operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.COURT_ORDER,
        legal_authority_reference="TGI Paris, ord. 2026/1234",
        max_effect_description="One notification, as directed by the order.",
        lifetime=timedelta(hours=2),
    ).capability_id


def test_a_capability_resting_on_a_court_order_needs_somebody_who_read_it() -> None:
    """``check_legal_basis_reviewed`` existed and was never called until an audit noticed.

    An investigation lead confirming that they want the outcome is not the same as somebody
    confirming that we are entitled to it. A court order is a document with conditions in
    it, and whoever signs off on acting under it should be able to read them.
    """
    gateway = _gateway(CapabilitySigningKey.generate())
    request_id = _under_court_order(gateway)
    gateway.approve(
        request_id,
        approver=_at(
            DEV.enrol("Lead One", Role.INVESTIGATION_LEAD), AssuranceLevel.HARDWARE_BACKED
        ),
        rationale="The order names these domains.",
    )

    with pytest.raises(AuthorizationPolicyError, match="requires a legal reviewer"):
        gateway.issue(request_id)


def test_the_same_request_issues_once_a_legal_reviewer_has_approved() -> None:
    """The counterpart: the check gates on who reviewed, not on the operation being unpopular."""
    gateway = _gateway(CapabilitySigningKey.generate())
    request_id = _under_court_order(gateway)
    gateway.approve(
        request_id,
        approver=_at(ALICE, AssuranceLevel.HARDWARE_BACKED),
        rationale="Order read; its scope matches these four domains and no others.",
    )

    capability = gateway.issue(request_id)
    assert Role.LEGAL_REVIEWER in set().union(
        *(approval.approver_roles for approval in capability.approvals)
    )


def test_a_capability_cannot_be_placed_far_in_the_future() -> None:
    """``not_before`` was unbounded, so the lifetime ceiling was a window, not a limit.

    A grant that becomes valid a month after the decision authorizing it is a standing
    permission with a delay: the situation the approver reviewed is not the situation it
    acts in, and the capability outlives every fact it rested on.
    """
    gateway = _gateway(CapabilitySigningKey.generate())
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Rehearse.",
        targets=(_target(CLUSTER[0]),),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="Nothing.",
        lifetime=timedelta(hours=2),
    )
    gateway.approve(request.capability_id, approver=ALICE, rationale="Performs nothing.")

    with pytest.raises(AuthorizationError, match="beyond the"):
        gateway.issue(request.capability_id, not_before=NOW + timedelta(days=30))

    # The ordinary case still works: a short delay is a legitimate scheduling need.
    capability = gateway.issue(request.capability_id, not_before=NOW + timedelta(minutes=30))
    assert capability.not_before == NOW + timedelta(minutes=30)


# --- The gateway's records are its own ----------------------------------------


def test_editing_the_returned_request_after_approval_does_not_change_what_is_issued() -> None:
    """Time-of-check to time-of-use on the approval itself, and it needed no key.

    ``request()`` used to return the very object it retained. So a requester could have a
    rehearsal approved, edit the retained record, and have ``issue()`` sign the edited
    version: an adversarial review turned an approved ``SIMULATION`` into a working
    ``PROVIDER_NOTIFICATION`` capability that drafted a document. Frozen models are no
    defence — ``__dict__`` is still there, and the attacker is inside the process by
    assumption.
    """
    gateway = _gateway(CapabilitySigningKey.generate())
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Rehearse, and nothing more.",
        targets=(_target(CLUSTER[0]),),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="A rehearsal that performs nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(request.capability_id, approver=ALICE, rationale="Performs nothing.")

    request.__dict__["requested_operations"] = frozenset({OperationClass.PROVIDER_NOTIFICATION})
    request.__dict__["legal_basis"] = LegalBasis.PROVIDER_TERMS_OF_SERVICE
    request.__dict__["legal_authority_reference"] = "Provider ToS"

    capability = gateway.issue(request.capability_id)
    assert capability.permitted_operations == frozenset({OperationClass.SIMULATION})
    assert capability.legal_basis is LegalBasis.NONE_SIMULATION_ONLY


def test_editing_a_returned_approval_cannot_add_a_reviewer_who_never_reviewed() -> None:
    """The same defect on the other record, and it defeated the legal-basis check.

    Adding ``legal_reviewer`` to the returned ``Approval`` used to change what ``issue()``
    saw, producing an authentic court-order capability that no qualified reviewer had ever
    approved — and an audit trail that said one had.
    """
    gateway = _gateway(CapabilitySigningKey.generate())
    request_id = _under_court_order(gateway)
    approval = gateway.approve(
        request_id,
        approver=_at(
            DEV.enrol("Lead Two", Role.INVESTIGATION_LEAD), AssuranceLevel.HARDWARE_BACKED
        ),
        rationale="The order names these domains.",
    )
    approval.__dict__["approver_roles"] = approval.approver_roles | {Role.LEGAL_REVIEWER}

    with pytest.raises(AuthorizationPolicyError, match="requires a legal reviewer"):
        gateway.issue(request_id)


def test_no_reader_hands_out_a_reference_to_a_retained_record() -> None:
    """Copying on write is not enough if a read method leaks the record instead."""
    gateway = _gateway(CapabilitySigningKey.generate())
    request = gateway.request(
        case_id=CASE,
        audit_id=AUDIT,
        requested_by=PLANNER,
        justification="Rehearse.",
        targets=(_target(CLUSTER[0]),),
        operations=frozenset({OperationClass.SIMULATION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_effect_description="Nothing.",
        lifetime=timedelta(hours=1),
    )
    gateway.approve(request.capability_id, approver=ALICE, rationale="Performs nothing.")

    status = gateway.status(request.capability_id)
    status.request.__dict__["requested_operations"] = frozenset({OperationClass.DOMAIN_SEIZURE})
    status.decisions[0].__dict__["approver_roles"] = frozenset({Role.LEGAL_REVIEWER})
    for queued in gateway.pending():
        queued.__dict__["max_targets"] = 9999

    capability = gateway.issue(request.capability_id)
    assert capability.permitted_operations == frozenset({OperationClass.SIMULATION})
    assert capability.approvals[0].approver_roles == frozenset(
        {Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER}
    )
    assert capability.max_targets == 1
