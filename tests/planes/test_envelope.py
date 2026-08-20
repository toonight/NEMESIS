"""The pre-signed autonomy envelope: authority delegated in advance, and counted.

A capability bounds *what* may be done. Approved per-action, that is enough — a human is the
rate limit. Hand the same capability to something autonomous running at machine speed and "four
approved targets" becomes an unbounded number of operations against four approved targets. These
tests are about the bound that closes that gap, and about the ways a budget is normally defeated:
by deleting a spend, by failing on purpose, by wrapping a grant nobody signed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nemesis.authz.envelope import (
    DEFAULT_AUTONOMOUS_EFFECT_BUDGET,
    AutonomyEnvelope,
    EnvelopeError,
    InMemorySpendLedger,
)
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.identity import Role
from nemesis.core.ids import IdPrefix, new_id

SIGNING_KEY = CapabilitySigningKey.generate()
ACTOR = new_id(IdPrefix.ACTOR)


def _target() -> TargetFingerprint:
    return TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type="domain",
        natural_key="acme-invoice-portal.example",
        bound_attributes={"resolves_to": "198.51.100.23"},
    )


def _capability(*, signed: bool = True) -> AuthorizationCapability:
    now = datetime.now(UTC)
    unsigned = AuthorizationCapability(
        capability_id=new_id(IdPrefix.CAPABILITY),
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        issued_at=now - timedelta(minutes=1),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=4),
        targets=(_target(),),
        permitted_operations=frozenset({OperationClass.SIMULATION}),
        forbidden_operations=frozenset({OperationClass.REGISTRAR_SUSPENSION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        max_targets=4,
        max_effect_description="Rehearsals that suspend nothing.",
        approvals=(
            Approval(
                approver=ACTOR,
                approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
                decided_at=now,
                decision=True,
                rationale="Reversible class, synthetic targets.",
            ),
        ),
        required_approvals=1,
    )
    if not signed:
        return unsigned
    return unsigned.model_copy(update={"signature": SIGNING_KEY.sign(unsigned.signing_payload())})


def _debit(envelope: AutonomyEnvelope) -> object:
    return envelope.debit(
        operation=OperationClass.SIMULATION,
        target_fingerprint=envelope.capability.targets[0].fingerprint,
        requested_by=ACTOR,
    )


# --- The bound a capability does not carry -----------------------------------


def test_an_envelope_bounds_how_often_not_only_what() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    The capability permits SIMULATION against this target with no stated limit on repetition.
    The envelope is what makes autonomy finite.
    """
    envelope = AutonomyEnvelope(_capability(), max_autonomous_effects=3)

    assert [_debit(envelope) is not None for _ in range(3)] == [True, True, True]
    assert envelope.exhausted
    assert _debit(envelope) is None, "a fourth effect was spent from a budget of three"


def test_an_exhausted_envelope_refuses_rather_than_raising() -> None:
    """An exhausted envelope is an expected outcome the pilot must be told about and the
    mediator must record — not an error that unwinds a session."""
    envelope = AutonomyEnvelope(_capability(), max_autonomous_effects=1)
    assert _debit(envelope) is not None
    assert _debit(envelope) is None  # no exception


def test_a_zero_budget_envelope_authorizes_no_autonomous_effect() -> None:
    """The degenerate case is meaningful: a grant a human must spend by hand."""
    envelope = AutonomyEnvelope(_capability(), max_autonomous_effects=0)
    assert envelope.exhausted
    assert _debit(envelope) is None


def test_the_default_budget_is_small_and_stated() -> None:
    """A default nobody chose is a default nobody argued with."""
    envelope = AutonomyEnvelope(_capability())
    assert envelope.budget == DEFAULT_AUTONOMOUS_EFFECT_BUDGET
    assert envelope.remaining == DEFAULT_AUTONOMOUS_EFFECT_BUDGET


# --- The envelope can only narrow -------------------------------------------


def test_an_envelope_cannot_wrap_an_unsigned_capability() -> None:
    """Delegating autonomous action under a grant nobody signed is not a narrower authority,
    it is none."""
    with pytest.raises(EnvelopeError, match="signed capability"):
        AutonomyEnvelope(_capability(signed=False))


def test_a_negative_budget_is_refused() -> None:
    with pytest.raises(EnvelopeError):
        AutonomyEnvelope(_capability(), max_autonomous_effects=-1)


def test_the_envelope_exposes_the_capability_unchanged() -> None:
    """The Effects plane must verify against exactly what the authority signed. If the envelope
    could alter the grant, the signature would stop verifying — or worse, would not."""
    capability = _capability()
    envelope = AutonomyEnvelope(capability, max_autonomous_effects=2)
    _debit(envelope)

    assert envelope.capability is capability
    assert envelope.capability.signature == capability.signature


def test_the_envelope_holds_no_way_to_widen_itself() -> None:
    """A structural check: there is no public method that raises the budget or edits the grant.

    An envelope that could raise its own ceiling would be the standing permission invariant 9
    exists to prevent, so the absence is the control.
    """
    public = {name for name in dir(AutonomyEnvelope) if not name.startswith("_")}
    assert public == {
        "budget",
        "capability",
        "debit",
        "exhausted",
        "ledger",
        "remaining",
        "spent",
        "status",
        "verify_chain",
    }


# --- Deleting a spend to buy another effect ----------------------------------


def test_the_ledger_chains_so_a_deleted_spend_is_detectable() -> None:
    """The obvious attack on a budget, and one a signature would not catch: remove a debit and
    the envelope has room again. A gap breaks every link after it.

    Mounted against the *ledger*, which is where the rows live and therefore what an operator
    with store access actually edits — not against the envelope, which only reads them.
    """
    ledger = InMemorySpendLedger()
    capability = _capability()
    envelope = AutonomyEnvelope(capability, max_autonomous_effects=5, ledger=ledger)
    for _ in range(4):
        _debit(envelope)
    assert envelope.verify_chain()

    ledger._spends[capability.capability_id].pop(1)
    assert not envelope.verify_chain(), "a deleted spend left the ledger verifying"


def test_reordering_the_ledger_is_detectable() -> None:
    ledger = InMemorySpendLedger()
    capability = _capability()
    envelope = AutonomyEnvelope(capability, max_autonomous_effects=5, ledger=ledger)
    for _ in range(3):
        _debit(envelope)

    rows = ledger._spends[capability.capability_id]
    rows[0], rows[2] = rows[2], rows[0]
    assert not envelope.verify_chain()


def test_an_intact_ledger_verifies_and_records_every_spend_in_order() -> None:
    envelope = AutonomyEnvelope(_capability(), max_autonomous_effects=4)
    for _ in range(4):
        _debit(envelope)

    ledger = envelope.ledger()
    assert envelope.verify_chain()
    assert [record.sequence for record in ledger] == [0, 1, 2, 3]
    assert all(record.capability_id == envelope.capability.capability_id for record in ledger)
    assert all(record.requested_by == ACTOR for record in ledger)


def test_the_ledger_is_a_copy_so_a_caller_cannot_edit_history() -> None:
    """`ledger()` returns a tuple, so the record a caller reads is not the record the envelope
    counts."""
    envelope = AutonomyEnvelope(_capability(), max_autonomous_effects=2)
    _debit(envelope)
    snapshot = envelope.ledger()

    _debit(envelope)
    assert len(snapshot) == 1 and len(envelope.ledger()) == 2


# --- Status reads honestly ---------------------------------------------------


def test_status_reports_what_is_left_and_says_when_exhausted() -> None:
    envelope = AutonomyEnvelope(_capability(), max_autonomous_effects=2)
    _debit(envelope)

    status = envelope.status()
    assert (status.budget, status.spent, status.remaining) == (2, 1, 1)
    assert status.exhausted is False
    assert "1/2 autonomous effects remaining" in status.render()

    _debit(envelope)
    assert envelope.status().exhausted is True
    assert "EXHAUSTED" in envelope.status().render()


def test_status_names_the_operations_the_envelope_permits_and_forbids() -> None:
    """An operator reading a status should see the edges without opening the capability."""
    status = AutonomyEnvelope(_capability()).status()
    assert status.permitted_operations == ("simulation",)
    assert status.forbidden_operations == ("registrar_suspension",)
