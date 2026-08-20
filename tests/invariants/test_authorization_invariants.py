"""Invariants 7, 8, 9: authorization is external, narrow, expiring and fails closed.

The scenario every test here defends against is the same one: an agent, or a compromised
component, or an honest bug, produces a request to act on real infrastructure. Nothing in
this file trusts the caller's intent. Each test asserts that a specific structural control
refuses, and says what would go wrong if it did not.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nemesis.core.authorization import (
    IRREVERSIBLE_OPERATIONS,
    MVP_IMPLEMENTED_OPERATIONS,
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id

pytestmark = pytest.mark.invariant

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
ALICE = new_id(IdPrefix.ACTOR)
BOB = new_id(IdPrefix.ACTOR)


def _target(**bound: str) -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="evil.example",
        bound_attributes=bound or {"resolves_to": "203.0.113.7", "registrar": "example-registrar"},
    )


def _approval(approver: str, *, decision: bool = True) -> Approval:
    return Approval(
        approver=approver,
        approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
        decided_at=NOW,
        decision=decision,
        rationale="Evidence bundle reviewed; target ownership established.",
    )


def _capability(**overrides: object) -> AuthorizationCapability:
    defaults: dict[str, object] = {
        "capability_id": new_id(IdPrefix.CAPABILITY),
        "case_id": new_id(IdPrefix.CASE),
        "audit_id": new_id(IdPrefix.AUDIT),
        "issued_at": NOW,
        "not_before": NOW,
        "expires_at": NOW + timedelta(hours=4),
        "targets": (_target(),),
        "permitted_operations": frozenset({OperationClass.SIMULATION}),
        "jurisdictions": ("FR",),
        "legal_basis": LegalBasis.NONE_SIMULATION_ONLY,
        "max_targets": 5,
        "max_effect_description": "Simulated takedown of one domain. No external contact.",
        "approvals": (_approval(ALICE),),
        "required_approvals": 1,
    }
    return AuthorizationCapability(**(defaults | overrides))


# --- Invariant 9: authority is narrow and expires ----------------------------


def test_a_capability_must_expire() -> None:
    with pytest.raises(ValueError, match="must expire after"):
        _capability(expires_at=NOW)


def test_an_expired_capability_authorizes_nothing() -> None:
    cap = _capability()
    decision = cap.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=cap.targets[0].fingerprint,
        now=NOW + timedelta(hours=5),
    )
    assert not decision.permitted
    assert any("expired" in reason for reason in decision.denial_reasons)


def test_a_capability_is_not_valid_before_its_start() -> None:
    cap = _capability(not_before=NOW + timedelta(hours=1))
    decision = cap.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=cap.targets[0].fingerprint,
        now=NOW,
    )
    assert not decision.permitted
    assert any("not valid until" in reason for reason in decision.denial_reasons)


def test_a_revoked_capability_authorizes_nothing() -> None:
    cap = _capability(revoked_at=NOW, revocation_reason="target ownership disputed")
    decision = cap.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=cap.targets[0].fingerprint,
        now=NOW + timedelta(minutes=1),
    )
    assert not decision.permitted
    assert any("revoked" in reason for reason in decision.denial_reasons)


def test_an_operation_outside_the_grant_is_denied() -> None:
    cap = _capability()
    decision = cap.authorizes(
        operation=OperationClass.DOMAIN_SEIZURE,
        target_fingerprint=cap.targets[0].fingerprint,
        now=NOW,
    )
    assert not decision.permitted
    assert any("not among the permitted operations" in r for r in decision.denial_reasons)


def test_explicit_denial_beats_permission() -> None:
    """A forbidden operation stays forbidden even if it is also granted.

    Guards against a future widening of a permission set silently re-enabling something
    an approver specifically refused.
    """
    with pytest.raises(ValueError, match="both permitted and forbidden"):
        _capability(
            permitted_operations=frozenset({OperationClass.SIMULATION}),
            forbidden_operations=frozenset({OperationClass.SIMULATION}),
        )


def test_a_capability_permitting_nothing_is_rejected() -> None:
    with pytest.raises(ValueError, match="permits nothing"):
        _capability(permitted_operations=frozenset())


# --- Target binding: approval is bound to the state that was approved --------


def test_an_operation_against_an_unapproved_target_is_denied() -> None:
    cap = _capability()
    other = _target(resolves_to="198.51.100.9", registrar="other-registrar")
    decision = cap.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=other.fingerprint,
        now=NOW,
    )
    assert not decision.permitted
    assert any("does not match any approved target" in r for r in decision.denial_reasons)


def test_a_target_whose_bound_state_changed_no_longer_matches() -> None:
    """The scenario: approval is granted, then the domain is transferred to a legitimate
    owner before execution. The capability must stop matching rather than acting on a
    stale decision about a target that no longer exists in that form.
    """
    target = _target(resolves_to="203.0.113.7", registrar="example-registrar")
    assert target.matches_current_state(
        {"resolves_to": "203.0.113.7", "registrar": "example-registrar"}
    )
    assert not target.matches_current_state(
        {"resolves_to": "198.51.100.9", "registrar": "example-registrar"}
    )


def test_unbound_attributes_may_change_freely() -> None:
    """Binding everything would expire every capability on the first unrelated observation,
    which trains operators to re-approve without reading.
    """
    target = _target(registrar="example-registrar")
    assert target.matches_current_state(
        {"registrar": "example-registrar", "http_title": "changed since approval"}
    )


def test_a_forged_target_fingerprint_is_rejected() -> None:
    with pytest.raises(ValueError, match="does not match the bound attributes"):
        TargetFingerprint(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type="domain",
            natural_key="innocent.example",
            bound_attributes={"resolves_to": "203.0.113.7"},
            fingerprint="sha256:" + "0" * 64,
        )


def test_more_targets_than_the_ceiling_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_targets"):
        _capability(targets=tuple(_target(n=str(i)) for i in range(4)), max_targets=3)


# --- Dual control ------------------------------------------------------------


def test_irreversible_operations_require_two_approvers() -> None:
    with pytest.raises(ValueError, match="cannot be undone and require"):
        _capability(
            permitted_operations=frozenset({OperationClass.DOMAIN_SEIZURE}),
            legal_basis=LegalBasis.COURT_ORDER,
            legal_authority_reference="TGI Paris, ord. 2026/1234",
            required_approvals=1,
            approvals=(_approval(ALICE),),
        )


def test_one_person_cannot_supply_both_halves_of_dual_control() -> None:
    with pytest.raises(ValueError, match="distinct approvers"):
        _capability(
            permitted_operations=frozenset({OperationClass.DOMAIN_SEIZURE}),
            legal_basis=LegalBasis.COURT_ORDER,
            legal_authority_reference="TGI Paris, ord. 2026/1234",
            required_approvals=2,
            approvals=(_approval(ALICE), _approval(ALICE)),
        )


def test_a_rejection_does_not_count_towards_the_approval_threshold() -> None:
    with pytest.raises(ValueError, match="approval\\(s\\) required"):
        _capability(
            required_approvals=2,
            approvals=(_approval(ALICE), _approval(BOB, decision=False)),
        )


def test_dual_control_with_two_distinct_approvers_is_accepted() -> None:
    cap = _capability(
        permitted_operations=frozenset({OperationClass.DOMAIN_SEIZURE}),
        legal_basis=LegalBasis.COURT_ORDER,
        legal_authority_reference="TGI Paris, ord. 2026/1234",
        required_approvals=2,
        approvals=(_approval(ALICE), _approval(BOB)),
    )
    decision = cap.authorizes(
        operation=OperationClass.DOMAIN_SEIZURE,
        target_fingerprint=cap.targets[0].fingerprint,
        now=NOW,
    )
    assert decision.permitted


# --- Legal basis -------------------------------------------------------------


def test_anything_beyond_simulation_needs_a_legal_basis() -> None:
    with pytest.raises(ValueError, match="require a legal basis"):
        _capability(
            permitted_operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
            legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        )


def test_anything_beyond_simulation_needs_an_authority_reference() -> None:
    with pytest.raises(ValueError, match="legal_authority_reference is required"):
        _capability(
            permitted_operations=frozenset({OperationClass.PROVIDER_NOTIFICATION}),
            legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
            legal_authority_reference=None,
        )


# --- Invariant 15: the MVP implements nothing that touches real infrastructure


def test_the_mvp_implements_no_irreversible_operation() -> None:
    """If this ever fails, NEMESIS has grown the ability to act on real infrastructure.

    That is a product and legal decision, not an engineering one — it must be made
    deliberately by a human, and this test is the tripwire.
    """
    assert not (MVP_IMPLEMENTED_OPERATIONS & IRREVERSIBLE_OPERATIONS)


def test_the_mvp_operation_set_has_not_grown() -> None:
    expected = {
        OperationClass.SIMULATION,
        OperationClass.PROVIDER_NOTIFICATION,
        OperationClass.TAKEDOWN_REQUEST_DRAFT,
        OperationClass.EVIDENCE_EXPORT,
    }
    assert expected == MVP_IMPLEMENTED_OPERATIONS


# --- The signature covers what matters ---------------------------------------


def test_revocation_does_not_change_the_signing_payload() -> None:
    """Revocation happens after issuance. If it changed the payload, a revoked capability
    would be cryptographically indistinguishable from a forged one.
    """
    cap = _capability()
    revoked = cap.model_copy(update={"revoked_at": NOW, "revocation_reason": "disputed"})
    assert cap.signing_payload() == revoked.signing_payload()


def test_changing_a_target_changes_the_signing_payload() -> None:
    cap = _capability()
    tampered = cap.model_copy(
        update={"targets": (_target(resolves_to="198.51.100.9", registrar="other"),)}
    )
    assert cap.signing_payload() != tampered.signing_payload()


def test_widening_permissions_changes_the_signing_payload() -> None:
    cap = _capability()
    widened = cap.model_copy(
        update={
            "permitted_operations": frozenset(
                {OperationClass.SIMULATION, OperationClass.DOMAIN_SEIZURE}
            )
        }
    )
    assert cap.signing_payload() != widened.signing_payload()


def test_a_permitted_decision_carries_its_stop_conditions() -> None:
    cap = _capability(
        stop_conditions=(
            StopCondition(
                condition="target_ownership_disputed",
                description="Abort if the registrant contests ownership.",
            ),
        )
    )
    decision = cap.authorizes(
        operation=OperationClass.SIMULATION,
        target_fingerprint=cap.targets[0].fingerprint,
        now=NOW,
    )
    assert decision.permitted
    assert "target_ownership_disputed" in decision.stop_conditions_to_check


def test_a_denial_states_every_reason_not_just_the_first() -> None:
    """An operator fixing one problem must not discover a second only on the next attempt."""
    cap = _capability(revoked_at=NOW, revocation_reason="disputed")
    decision = cap.authorizes(
        operation=OperationClass.DOMAIN_SEIZURE,
        target_fingerprint="sha256:" + "0" * 64,
        now=NOW + timedelta(days=1),
    )
    assert not decision.permitted
    assert len(decision.denial_reasons) >= 3


# --- Everything a signature is supposed to cover -------------------------------


UNSIGNED_BY_DESIGN = frozenset({"signature", "revoked_at", "revocation_reason"})
"""The only fields legitimately outside the payload.

The signature cannot cover itself. Revocation is deliberately excluded: it happens after
issuance, and if withdrawing an authority changed the signed bytes, a revoked capability
would become cryptographically indistinguishable from a forged one — so the Effects plane
asks the issuing authority instead of asking the object.
"""

SIGNED_FIELD_MUTATIONS: dict[str, object] = {
    "capability_id": new_id(IdPrefix.CAPABILITY),
    "case_id": new_id(IdPrefix.CASE),
    "audit_id": new_id(IdPrefix.AUDIT),
    "issued_at": NOW - timedelta(hours=3),
    "not_before": NOW - timedelta(hours=3),
    "expires_at": NOW + timedelta(days=365),
    "targets": (_target(resolves_to="203.0.113.99", registrar="other-registrar"),),
    "permitted_operations": frozenset({OperationClass.SIMULATION, OperationClass.DOMAIN_SEIZURE}),
    "forbidden_operations": frozenset(),
    "jurisdictions": ("XX",),
    "legal_basis": LegalBasis.COURT_ORDER,
    "legal_authority_reference": "a court order we do not hold",
    "max_targets": 400,
    "max_effect_description": "Anything at all, on anyone.",
    "stop_conditions": (
        StopCondition(condition="never", description="A criterion nobody agreed to."),
    ),
    "approvals": (_approval(new_id(IdPrefix.ACTOR)),),
    "required_approvals": 2,
}


def test_the_mutation_table_covers_every_signed_field() -> None:
    """Keeps the test below honest as the model grows.

    A field added to the capability and forgotten in ``signing_payload`` is a constraint an
    attacker removes for free. That is not hypothetical here: stop conditions were exactly
    that until an audit found it, and every abort criterion could be stripped from an
    approved capability while its signature kept verifying over identical bytes.
    """
    declared = set(AuthorizationCapability.model_fields) - UNSIGNED_BY_DESIGN
    assert declared == set(SIGNED_FIELD_MUTATIONS), (
        f"unlisted: {sorted(declared - set(SIGNED_FIELD_MUTATIONS))}; "
        f"stale: {sorted(set(SIGNED_FIELD_MUTATIONS) - declared)}"
    )


@pytest.mark.parametrize("field", sorted(SIGNED_FIELD_MUTATIONS))
def test_mutating_any_signed_field_changes_the_bytes(field: str) -> None:
    """One assertion, applied to every field, rather than to the three somebody thought of."""
    capability = _capability(
        permitted_operations=frozenset({OperationClass.SIMULATION}),
        forbidden_operations=frozenset({OperationClass.DOMAIN_SEIZURE}),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        legal_authority_reference=None,
        stop_conditions=(
            StopCondition(
                condition="ownership_disputed",
                description="Abort if the registrant contests ownership.",
            ),
        ),
        approvals=(_approval(ALICE),),
        required_approvals=1,
    )
    altered = capability.model_copy(update={field: SIGNED_FIELD_MUTATIONS[field]})

    assert altered.model_dump() != capability.model_dump(), (
        f"the mutation for {field} does not actually change the model"
    )
    assert altered.signing_payload() != capability.signing_payload()


@pytest.mark.parametrize("field", sorted(UNSIGNED_BY_DESIGN - {"signature"}))
def test_revocation_fields_stay_outside_the_payload(field: str) -> None:
    """The counterpart, and the reason a revocation oracle exists at all."""
    capability = _capability(approvals=(_approval(ALICE),), required_approvals=1)
    revoked = capability.model_copy(update={field: NOW if field == "revoked_at" else "withdrawn"})
    assert revoked.signing_payload() == capability.signing_payload()
