"""A platform must not be able to mark its own legal duty complete.

`ContentSafety.MANDATORY_REPORT` says escalation "is a human decision, immediately". The
quarantine enforces the first half — no automated exit. This is the other half, and every test
here is about one of the two ways a reporting obligation is normally lost:

- **It is closed by the system.** A compliance record that a platform can write about itself
  is a record of its own convenience.
- **It is closed by nobody, quietly.** The dangerous obligation is not the one somebody
  refuses; it is the one that lands in a queue nobody reads. So an open obligation must get
  louder with age, not quieter.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.core.identity import Principal, Role
from nemesis.evidence.escalation import (
    MAY_DISCHARGE,
    EscalationError,
    ObligationState,
    Register,
)

pytestmark = pytest.mark.invariant

DEV = LocalDevelopmentIdentityProvider()
ACTORS = PrincipalVerifier(DEV.registered_issuer())
NOW = datetime(2026, 8, 17, tzinfo=UTC)


def _who(*roles: Role) -> Principal:
    return ACTORS.verify(DEV.enrol("Ada", *roles))


def _register(now: datetime = NOW) -> tuple[Register, dict[str, datetime]]:
    clock = {"now": now}
    return Register(clock=lambda: clock["now"]), clock


def _incur(register: Register) -> str:
    return register.incur(
        artifact_id="qtn_abc",
        authority="the competent national authority",
        reason="material classified mandatory_report",
    ).obligation_id


# --- The platform cannot close its own obligation ----------------------------


def test_nothing_discharges_an_obligation_on_its_own() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    There is no worker, no timer and no cleanup path that closes one. The absence of an
    automated consumer is the control rather than a missing feature.
    """
    register, clock = _register()
    _incur(register)

    clock["now"] = NOW + timedelta(days=30)

    assert register.open_obligations()[0].state is ObligationState.OPEN
    assert len(register.overdue()) == 1
    # No public method takes an obligation from open to discharged without a principal.
    assert set(dir(register)) & {"close", "complete", "resolve", "drain", "expire"} == set()


def test_only_a_legal_reviewer_may_discharge() -> None:
    """Letting whoever found the material also close the duty removes the only second pair of
    eyes in the process."""
    register, _ = _register()
    obligation_id = _incur(register)

    with pytest.raises(EscalationError, match="legal reviewer"):
        register.discharge(obligation_id, _who(Role.INVESTIGATION_LEAD), channel_reference="X-1")

    discharged = register.discharge(
        obligation_id, _who(Role.LEGAL_REVIEWER), channel_reference="NCA-2026-114"
    )
    assert discharged.state is ObligationState.DISCHARGED


def test_the_discharging_role_set_is_exactly_one_role() -> None:
    """A tripwire. Widening who may close a legal duty is a compliance decision."""
    assert {Role.LEGAL_REVIEWER} == MAY_DISCHARGE


def test_a_discharge_needs_something_an_auditor_could_follow() -> None:
    """ "We handled it" with no reference is not a record."""
    register, _ = _register()
    obligation_id = _incur(register)

    for blank in ("", "   "):
        with pytest.raises(EscalationError, match="channel reference"):
            register.discharge(obligation_id, _who(Role.LEGAL_REVIEWER), channel_reference=blank)


def test_a_discharged_obligation_cannot_be_closed_again() -> None:
    """Re-closing would overwrite the record of who actually did it, which is the only thing
    the register holds that matters."""
    register, _ = _register()
    obligation_id = _incur(register)
    register.discharge(obligation_id, _who(Role.LEGAL_REVIEWER), channel_reference="NCA-1")

    with pytest.raises(EscalationError, match="already discharged"):
        register.discharge(obligation_id, _who(Role.LEGAL_REVIEWER), channel_reference="NCA-2")


def test_discharged_does_not_claim_the_report_was_filed() -> None:
    """The platform cannot see whether a report was accepted or acted on, and a status that
    implied otherwise would be worse than none."""
    register, _ = _register()
    obligation_id = _incur(register)
    discharged = register.discharge(
        obligation_id, _who(Role.LEGAL_REVIEWER), channel_reference="NCA-2026-114"
    )

    assert "not verified as filed" in discharged.render(NOW)


# --- Silence is the failure mode ---------------------------------------------


def test_an_open_obligation_gets_louder_with_age() -> None:
    """The dangerous one is not the obligation somebody refuses — it is the one nobody reads."""
    register, clock = _register()
    _incur(register)

    assert "OVERDUE" not in register.render()

    clock["now"] = NOW + timedelta(days=5)
    rendered = register.render()
    assert rendered.startswith("!!")
    assert "OVERDUE" in rendered
    assert "NEMESIS cannot discharge these" in rendered


def test_re_examining_the_material_does_not_restart_the_clock() -> None:
    """An obligation whose deadline moves every time the artifact is re-examined is an
    obligation that never becomes overdue."""
    register, clock = _register()
    first = _incur(register)

    clock["now"] = NOW + timedelta(days=5)
    again = _incur(register)

    assert again == first
    assert len(register.open_obligations()) == 1
    assert len(register.overdue()) == 1, "re-incurring reset the deadline"


def test_open_obligations_come_back_oldest_first() -> None:
    """Because the one that has been waiting longest is the one at risk."""
    register, clock = _register()
    register.incur(artifact_id="qtn_old", authority="authority", reason="first")
    clock["now"] = NOW + timedelta(hours=1)
    register.incur(artifact_id="qtn_new", authority="authority", reason="second")

    assert [o.artifact_id for o in register.open_obligations()] == ["qtn_old", "qtn_new"]


def test_an_empty_register_says_so_rather_than_rendering_nothing() -> None:
    """A blank compliance report and a clean one look identical, which is how a broken
    register goes unnoticed."""
    register, _ = _register()
    assert "No reporting obligation has been incurred." in register.render()
