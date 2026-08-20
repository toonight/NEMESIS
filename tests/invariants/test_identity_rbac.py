"""Approval must mean two authenticated people, not two distinct strings.

An audit found that the gateway accepted caller-supplied actor ids and role names with
nothing behind either, and checked only that two ids differed and that the requester had not
approved themselves. Dual control therefore meant *two distinct strings*, and the audit
record named whoever the caller typed.

The tests below cover the two gates that replaced that, and one that matters more than
either: a development identity — the only kind this platform can currently issue — is
entitled to authorize a rehearsal and nothing meant to leave the system. That is how "we
have not built authentication yet" stops being a paragraph and becomes a refusal.
"""

from __future__ import annotations

import pytest

from nemesis.authz.providers import PROVIDER_NAME, LocalDevelopmentIdentityProvider
from nemesis.authz.rbac import (
    DEFAULT_MINIMUM_ASSURANCE,
    AuthorizationPolicyError,
    check_may_approve,
    check_may_reject,
    check_may_request,
    minimum_assurance_for,
)
from nemesis.core.authorization import OperationClass
from nemesis.core.identity import AssuranceLevel, Principal, Role
from nemesis.ports.identity import AuthenticationError, IdentityProvider
from tests.support.identity import elevated, hardware_backed_issuer, verifier_over

pytestmark = pytest.mark.invariant


DEV = LocalDevelopmentIdentityProvider()
STRONG, _ = hardware_backed_issuer()
ACTORS = verifier_over(DEV, STRONG)


def _dev(display_name: str, *roles: Role) -> Principal:
    """A development identity, established through the verifier like any other."""
    return ACTORS.verify(DEV.enrol(display_name, *roles))


def _at(principal: Principal, assurance: AssuranceLevel) -> Principal:
    """The same person, established by an issuer this deployment trusts that far.

    The elevation is a registration, not an edit: it goes through the verifier's per-issuer
    ceiling like everything else. The version of this helper that wrote the assurance field
    directly was a working forgery kept in the test suite.
    """
    if assurance is AssuranceLevel.DEVELOPMENT:
        return principal
    return ACTORS.verify(
        elevated(STRONG, principal.display_name, *principal.roles, subject=principal.actor_id)
    )


# --- The assurance floor, which is the control that matters today -------------


def test_a_development_identity_may_authorize_a_rehearsal() -> None:
    """The demonstration has to remain runnable, and a rehearsal touches nothing."""
    lead = _dev("Ada", Role.INVESTIGATION_LEAD)
    check_may_approve(lead, frozenset({OperationClass.SIMULATION}))


@pytest.mark.parametrize(
    "operation",
    [
        OperationClass.PROVIDER_NOTIFICATION,
        OperationClass.TAKEDOWN_REQUEST_DRAFT,
        OperationClass.EVIDENCE_EXPORT,
        OperationClass.DOMAIN_SEIZURE,
    ],
)
def test_a_development_identity_may_authorize_nothing_that_leaves_the_platform(
    operation: OperationClass,
) -> None:
    """Including a draft. A draft exists so that a human can send it."""
    person = _dev("Ada", Role.INVESTIGATION_LEAD, Role.LEGAL_REVIEWER)
    with pytest.raises(AuthorizationPolicyError, match="not established well enough"):
        check_may_approve(person, frozenset({operation}))


def test_the_refusal_says_the_gap_is_the_control() -> None:
    """An operator hitting this must not read it as a configuration problem to work around."""
    lead = _dev("Ada", Role.INVESTIGATION_LEAD)
    with pytest.raises(AuthorizationPolicyError) as raised:
        check_may_approve(lead, frozenset({OperationClass.PROVIDER_NOTIFICATION}))
    assert "no real identity provider" in str(raised.value)
    assert "is the control" in str(raised.value)


def test_an_unlisted_operation_class_inherits_the_strictest_floor() -> None:
    """Forgetting to add an entry must fail closed.

    The classes not listed today are seizures, sinkholes and asset freezes. If somebody
    implements one and forgets the table, the failure should be that nobody can authorize it.
    """
    assert DEFAULT_MINIMUM_ASSURANCE is AssuranceLevel.HARDWARE_BACKED
    assert minimum_assurance_for(OperationClass.SINKHOLE) is AssuranceLevel.HARDWARE_BACKED
    assert minimum_assurance_for(OperationClass.ASSET_FREEZE_REQUEST) is (
        AssuranceLevel.HARDWARE_BACKED
    )


# --- Roles are checked, not accepted ------------------------------------------


def test_an_analyst_requests_and_does_not_approve() -> None:
    analyst = _dev("Grace", Role.ANALYST)
    check_may_request(analyst)
    with pytest.raises(AuthorizationPolicyError, match="may not approve"):
        check_may_approve(analyst, frozenset({OperationClass.SIMULATION}))


def test_a_lead_alone_cannot_approve_a_class_that_needs_a_legal_basis() -> None:
    """Wanting the outcome and being entitled to it are different judgements."""
    lead = _at(_dev("Ada", Role.INVESTIGATION_LEAD), AssuranceLevel.HARDWARE_BACKED)
    with pytest.raises(AuthorizationPolicyError, match="requires one of \\['legal_reviewer'\\]"):
        check_may_approve(lead, frozenset({OperationClass.DOMAIN_SEIZURE}))


def test_an_auditor_approves_nothing() -> None:
    """Oversight must not require the ability to act."""
    auditor = _at(_dev("Ida", Role.AUDITOR), AssuranceLevel.HARDWARE_BACKED)
    with pytest.raises(AuthorizationPolicyError):
        check_may_approve(auditor, frozenset({OperationClass.SIMULATION}))
    with pytest.raises(AuthorizationPolicyError):
        check_may_request(auditor)


def test_a_mixed_grant_needs_entitlement_to_all_of_it() -> None:
    """Approving the reversible half of a grant that also carries a seizure is an approval."""
    lead = _at(_dev("Ada", Role.INVESTIGATION_LEAD), AssuranceLevel.HARDWARE_BACKED)
    with pytest.raises(AuthorizationPolicyError):
        check_may_approve(
            lead, frozenset({OperationClass.SIMULATION, OperationClass.DOMAIN_SEIZURE})
        )


# --- Refusal is deliberately easier than approval ------------------------------


def test_anyone_entitled_to_review_may_refuse() -> None:
    """Asymmetric on purpose: refusal is the safe direction.

    Requiring the approval role to reject would leave a request nobody qualified can review
    sitting open, and would stop a lead from killing something they can see is wrong merely
    because permitting it needs a lawyer.
    """
    for principal in (
        _dev("Grace", Role.ANALYST),
        _dev("Ada", Role.INVESTIGATION_LEAD),
        _dev("Ida", Role.AUDITOR),
    ):
        check_may_reject(principal)


def test_a_development_identity_may_still_refuse_a_seizure() -> None:
    """The assurance floor gates approval, not refusal."""
    check_may_reject(_dev("Ada", Role.INVESTIGATION_LEAD))


# --- The provider cannot pretend to be more than it is ------------------------


def test_every_development_principal_is_stamped_as_one() -> None:
    """A convincing fake authenticator is worse than none: it produces audit records that
    look like logins. This one is impossible to mistake for real, and says so in every
    principal it issues."""
    principal = _dev("Ada", Role.INVESTIGATION_LEAD)

    assert principal.assurance is AssuranceLevel.DEVELOPMENT
    assert principal.is_development_identity
    assert principal.authenticated_by == PROVIDER_NAME
    assert "development" in principal.describe()


def test_the_local_provider_satisfies_the_port() -> None:
    assert isinstance(DEV, IdentityProvider)


def test_authentication_failure_does_not_say_why() -> None:
    """Distinguishing "no such account" from "wrong secret" is an enumeration oracle, and
    the gateway has no use for the difference."""
    with pytest.raises(AuthenticationError) as raised:
        DEV.authenticate("nobody")
    assert "no identity established" in str(raised.value)
    assert "nobody" not in str(raised.value)


def test_assurance_levels_are_ordered_and_development_is_the_floor() -> None:
    """Every floor above zero excludes a development identity, which is the whole design."""
    assert AssuranceLevel.DEVELOPMENT.value == 0
    assert (
        AssuranceLevel.DEVELOPMENT
        < AssuranceLevel.SINGLE_FACTOR
        < AssuranceLevel.MULTI_FACTOR
        < AssuranceLevel.HARDWARE_BACKED
    )
