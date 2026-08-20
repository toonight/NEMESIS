"""The Disruption Planner: proposals a human can weigh, including the ones against acting.

The failures modelled here are the ones that make a disruption programme cause harm rather
than prevent it:

- **A gesture proposed as a lever.** A termination request to a host that ignores abuse
  reports is filed and forgotten. The plan must say so before anyone spends a week on it.
- **Someone else's business taken down.** ``initech-payments-secure.example`` reads like a
  real company. Acting on the wrong target is the one disruption error that cannot be
  undone, so ownership evidence gates the ranking ahead of impact.
- **An investigation narrowed to what happens to be built.** Options with no adapter must
  still be proposed at full reasoning. A planner that only proposes what it can execute
  quietly deletes every lever that needs a court.

The scenario anchors are DEMO_SCENARIO.md §2.6 and phase 7.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from nemesis.core.authorization import LegalBasis, OperationClass
from nemesis.core.confidence import ConfidenceBand, Opinion
from nemesis.core.entities import EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.disrupt.options import (
    AdversaryRecovery,
    CollateralRisk,
    DisruptionOption,
    DisruptionTarget,
    ExpectedImpact,
    ImpactLevel,
    ImplementationStatus,
    OwnershipEvidence,
    ProviderDisposition,
    RecoveryDifficulty,
)
from nemesis.disrupt.planner import DisruptionLever, DisruptionPlanner

NOW = datetime(2026, 3, 12, 10, 0, tzinfo=UTC)

CLUSTER = (
    "acme-invoice-portal.example",
    "acme-billing-secure.example",
    "globex-invoice-portal.example",
    "initech-payments-secure.example",
)

# Ownership resting on several independent origins: the registrar record, the shared
# certificate and the kit's exfiltration address all point the same way.
CORROBORATED = OwnershipEvidence(
    opinion=Opinion.from_evidence(supporting=8.0, contradicting=0.0, base_rate=0.1),
    independent_source_count=3,
    basis="Registrar record, shared TLS certificate and kit exfiltration address agree.",
)

# The same numeric confidence, from one origin. Identical projected probability, and not
# safe to act on: that difference is the whole reason the source count is a separate field.
SINGLE_SOURCED = OwnershipEvidence(
    opinion=Opinion.from_evidence(supporting=8.0, contradicting=0.0, base_rate=0.1),
    independent_source_count=1,
    basis="One dark-web post naming the operator's infrastructure.",
)


def _target(natural_key: str, *, legitimate_looking: bool = False) -> DisruptionTarget:
    return DisruptionTarget(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN,
        natural_key=natural_key,
        resembles_legitimate_business=legitimate_looking,
    )


def _lever(
    key: str,
    *,
    operation: OperationClass = OperationClass.PROVIDER_NOTIFICATION,
    targets: tuple[DisruptionTarget, ...] = (),
    unconstrained_impact: ImpactLevel = ImpactLevel.MODERATE,
    disposition: ProviderDisposition = ProviderDisposition.COOPERATIVE,
    provider_name: str | None = None,
    recovery_difficulty: RecoveryDifficulty = RecoveryDifficulty.HARD,
    ownership: OwnershipEvidence = CORROBORATED,
    collateral: tuple[CollateralRisk, ...] = (),
    legal_basis: LegalBasis = LegalBasis.PROVIDER_TERMS_OF_SERVICE,
    impact_note: str = "",
) -> DisruptionLever:
    return DisruptionLever(
        key=key,
        operation=operation,
        title=f"Lever {key}",
        description=f"Candidate action {key} against the GLASS ANVIL infrastructure.",
        targets=targets or (_target(CLUSTER[0]),),
        unconstrained_impact=unconstrained_impact,
        impact_note=impact_note,
        provider_disposition=disposition,
        provider_name=provider_name,
        recovery=AdversaryRecovery(
            path="re-register elsewhere and rebuild the kit",
            difficulty=recovery_difficulty,
            estimated_time="under an hour",
        ),
        ownership=ownership,
        collateral=collateral,
        legal_basis=legal_basis,
        jurisdictions=("FR", "NL"),
    )


def _plan(*levers: DisruptionLever) -> tuple[DisruptionOption, ...]:
    return DisruptionPlanner().plan(levers, now=NOW).options


def _option(plan: tuple[DisruptionOption, ...], key: str) -> DisruptionOption:
    return next(option for option in plan if option.key == key)


# --- A bulletproof host is not a lever ----------------------------------------


def test_a_bulletproof_host_yields_low_impact_with_the_reason_stated() -> None:
    """DEMO_SCENARIO.md phase 7, option 2. The target is central — terminating it would
    hurt — and the host ignores abuse reports as a selling point, so the real expected
    impact is LOW. Proposing the termination at its unconstrained reach would promise an
    effect the plan cannot deliver, and impact that ignores the provider is worse than no
    estimate because it looks like one."""
    plan = _plan(
        _lever(
            "hosting",
            operation=OperationClass.HOSTING_TERMINATION,
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.BULLETPROOF,
            provider_name="ShadowHost LLC (AS64512)",
            legal_basis=LegalBasis.COURT_ORDER,
        )
    )
    option = _option(plan, "hosting")

    assert option.expected_impact.level is ImpactLevel.LOW
    assert option.expected_impact.unconstrained_level is ImpactLevel.HIGH
    assert option.expected_impact.was_capped
    assert "ignores abuse reports" in option.expected_impact.basis
    assert "ShadowHost LLC" in option.expected_impact.basis
    assert any("capped at low" in flag for flag in option.flags)
    assert not option.degrades_capability


def test_an_unknown_disposition_is_never_read_as_cooperation() -> None:
    """Assuming a provider will act because nobody checked is how a plan promises impact it
    cannot deliver. The estimate is capped, and the confidence in the estimate is vacuous —
    "we cannot tell how well this would work" said as ignorance rather than as a middling
    probability."""
    plan = _plan(
        _lever(
            "unknown-provider",
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.UNKNOWN,
        )
    )
    option = _option(plan, "unknown-provider")

    assert option.expected_impact.level is ImpactLevel.MODERATE
    assert option.expected_impact.was_capped
    assert option.impact_confidence.is_vacuous
    assert "cannot be assumed cooperative" in option.expected_impact.basis


def test_a_known_disposition_leaves_a_cooperative_lever_at_full_reach() -> None:
    """The control case for the cap: without it, every option would look capped and the
    bulletproof finding would carry no information."""
    plan = _plan(
        _lever(
            "cooperative",
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.COOPERATIVE,
        )
    )
    option = _option(plan, "cooperative")

    assert option.expected_impact.level is ImpactLevel.HIGH
    assert not option.expected_impact.was_capped
    assert option.expected_impact.unconstrained_level is None
    assert not option.impact_confidence.is_vacuous


# --- Someone else's business --------------------------------------------------


def test_a_legitimate_looking_target_forces_ownership_confirmation() -> None:
    """DEMO_SCENARIO.md phase 7: option 1 must flag that initech-payments-secure.example
    resembles a legitimate name and warrants ownership confirmation before suspension.

    The caller supplies no collateral risk at all here. The planner raises it, because the
    entire point of the flag is that it fires when nobody was looking."""
    plan = _plan(
        _lever(
            "registrar-suspension",
            operation=OperationClass.REGISTRAR_SUSPENSION,
            targets=tuple(
                _target(domain, legitimate_looking=domain.startswith("initech"))
                for domain in CLUSTER
            ),
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.SLOW,
            provider_name="BulletproofReg",
            legal_basis=LegalBasis.STATUTORY_NOTICE_AND_ACTION,
        )
    )
    option = _option(plan, "registrar-suspension")

    blocking = option.blocking_collateral
    assert len(blocking) == 1
    assert blocking[0].affected_party == "initech-payments-secure.example"
    assert blocking[0].severity is ImpactLevel.HIGH
    assert "resembles a legitimate business name" in blocking[0].description
    assert option.requires_ownership_confirmation
    assert not option.is_ownership_sound
    assert any("initech-payments-secure.example" in flag for flag in option.flags)
    assert "CONFIRM OWNERSHIP FIRST" in option.render()

    # The three sibling domains do not look like businesses and raise no such risk.
    assert len(option.collateral_risks) == 1


def test_the_planner_does_not_duplicate_a_risk_the_caller_already_raised() -> None:
    """A duplicated warning is a warning an operator learns to skim."""
    already = CollateralRisk(
        affected_party="initech-payments-secure.example",
        description="Ownership contested by a party claiming to run an invoicing business.",
        severity=ImpactLevel.HIGH,
        requires_ownership_confirmation=True,
    )
    plan = _plan(
        _lever(
            "registrar-suspension",
            operation=OperationClass.REGISTRAR_SUSPENSION,
            targets=(_target(CLUSTER[3], legitimate_looking=True),),
            collateral=(already,),
        )
    )
    option = _option(plan, "registrar-suspension")

    assert len(option.blocking_collateral) == 1
    assert option.collateral_risks[0] is already


# --- Ownership evidence gates the ranking -------------------------------------


def test_weak_ownership_is_outranked_by_sound_ownership_however_attractive() -> None:
    """The single-sourced option here is strictly more attractive on every other axis: HIGH
    impact against a cooperative provider with severe recovery, against a MODERATE option
    the adversary recovers from more easily. It still ranks below, because acting on the
    wrong target is the failure that ends the company and no amount of impact buys it out."""
    plan = _plan(
        _lever(
            "attractive-but-thin",
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.COOPERATIVE,
            recovery_difficulty=RecoveryDifficulty.SEVERE,
            ownership=SINGLE_SOURCED,
        ),
        _lever(
            "modest-but-sound",
            unconstrained_impact=ImpactLevel.MODERATE,
            disposition=ProviderDisposition.COOPERATIVE,
            recovery_difficulty=RecoveryDifficulty.MODERATE,
            ownership=CORROBORATED,
        ),
    )

    assert [option.key for option in plan] == ["modest-but-sound", "attractive-but-thin"]

    thin = _option(plan, "attractive-but-thin")
    assert thin.requires_ownership_confirmation
    assert any("weak target ownership" in flag for flag in thin.flags)
    assert any("single-sourced" in flag for flag in thin.flags)
    # The downranking does not hide the impact: it is still HIGH, and still stated.
    assert thin.expected_impact.level is ImpactLevel.HIGH


def test_single_sourced_ownership_is_weak_however_confident_that_source_sounds() -> None:
    """A single confident source and three corroborating ones project the same probability.
    Only the second is safe to act on."""
    assert (
        SINGLE_SOURCED.opinion.projected_probability == CORROBORATED.opinion.projected_probability
    )
    assert SINGLE_SOURCED.band is ConfidenceBand.VERY_LIKELY
    assert SINGLE_SOURCED.is_single_sourced
    assert SINGLE_SOURCED.is_weak
    assert not CORROBORATED.is_weak
    assert "single-sourced" in SINGLE_SOURCED.describe()


def test_ownership_with_no_basis_at_all_is_weak_and_says_so() -> None:
    """Vacuous evidence must not be read as a middling estimate. Nobody looked."""
    nothing = OwnershipEvidence(
        opinion=Opinion.vacuous(base_rate=0.1),
        independent_source_count=4,
        basis="Assumed from the cluster, never checked against a registrant record.",
    )
    assert nothing.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert nothing.is_weak
    assert "insufficient basis" in nothing.describe()


def test_ownership_below_the_floor_is_weak_even_when_corroborated() -> None:
    """A band of "likely" is not good enough when the error is unrecoverable."""
    thin = OwnershipEvidence(
        opinion=Opinion.from_evidence(supporting=2.0, contradicting=1.0, base_rate=0.1),
        independent_source_count=3,
        basis="Two sightings agree, one registrant record disagrees.",
    )
    assert not thin.is_single_sourced
    assert thin.band is not ConfidenceBand.INSUFFICIENT_BASIS
    assert thin.opinion.projected_probability < 0.55
    assert thin.is_weak
    assert "below the ownership floor" in thin.describe()


# --- Durability beats impact --------------------------------------------------


def test_an_action_the_adversary_undoes_within_the_hour_degrades_nothing() -> None:
    """A HIGH-impact suspension the adversary re-registers by lunchtime is theatre, and it
    must rank below a MODERATE action that costs them something they cannot cheaply rebuild.
    Both are soundly owned, so the ownership gate is not what decides this."""
    plan = _plan(
        _lever(
            "whack-a-mole",
            unconstrained_impact=ImpactLevel.HIGH,
            recovery_difficulty=RecoveryDifficulty.TRIVIAL,
        ),
        _lever(
            "durable",
            unconstrained_impact=ImpactLevel.MODERATE,
            recovery_difficulty=RecoveryDifficulty.HARD,
        ),
    )

    assert [option.key for option in plan] == ["durable", "whack-a-mole"]
    theatre = _option(plan, "whack-a-mole")
    assert theatre.is_whack_a_mole
    assert not theatre.degrades_capability
    assert any("whack-a-mole" in flag for flag in theatre.flags)
    assert _option(plan, "durable").degrades_capability


# --- Options NEMESIS cannot execute are still proposed ------------------------


def test_an_operation_with_no_adapter_cannot_be_marked_implemented() -> None:
    """Claiming IMPLEMENTED for a class with no adapter advertises an executability NEMESIS
    does not have — the precise lie the boundary labels exist to prevent."""
    with pytest.raises(ValidationError, match="has no adapter and cannot be marked IMPLEMENTED"):
        DisruptionOption(
            key="seizure",
            operation=OperationClass.DOMAIN_SEIZURE,
            title="Seize the cluster",
            description="Judicial seizure of four domains.",
            targets=(_target(CLUSTER[0]),),
            expected_impact=ExpectedImpact(level=ImpactLevel.HIGH, basis="Removes the cluster."),
            impact_confidence=Opinion.from_evidence(supporting=3.0, contradicting=0.0),
            recovery=AdversaryRecovery(
                path="register elsewhere", difficulty=RecoveryDifficulty.MODERATE
            ),
            ownership_evidence=CORROBORATED,
            legal_basis=LegalBasis.COURT_ORDER,
            jurisdictions=("FR",),
            implementation_status=ImplementationStatus.IMPLEMENTED,
        )


def test_the_glass_anvil_plan_carries_every_option_including_the_unexecutable_ones() -> None:
    """DEMO_SCENARIO.md phase 7's table, as a plan. Nothing is dropped for being blocked on
    authority we do not hold: a planner limited to what is implemented silently narrows
    every investigation to whatever happens to be built, and the narrowing is invisible."""
    plan = _plan(
        _lever(
            "registrar-suspension",
            operation=OperationClass.REGISTRAR_SUSPENSION,
            targets=tuple(
                _target(domain, legitimate_looking=domain.startswith("initech"))
                for domain in CLUSTER
            ),
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.SLOW,
            provider_name="BulletproofReg",
            legal_basis=LegalBasis.STATUTORY_NOTICE_AND_ACTION,
        ),
        _lever(
            "hosting-termination",
            operation=OperationClass.HOSTING_TERMINATION,
            unconstrained_impact=ImpactLevel.HIGH,
            disposition=ProviderDisposition.BULLETPROOF,
            provider_name="ShadowHost LLC",
            legal_basis=LegalBasis.COURT_ORDER,
        ),
        _lever(
            "transit-notification",
            operation=OperationClass.PROVIDER_NOTIFICATION,
            unconstrained_impact=ImpactLevel.MODERATE,
            disposition=ProviderDisposition.COOPERATIVE,
            provider_name="upstream transit provider",
            recovery_difficulty=RecoveryDifficulty.MODERATE,
        ),
        _lever(
            "exchange-notification",
            operation=OperationClass.EXCHANGE_NOTIFICATION,
            unconstrained_impact=ImpactLevel.MODERATE,
            disposition=ProviderDisposition.SLOW,
            provider_name="SynthEx",
            legal_basis=LegalBasis.LAW_ENFORCEMENT_REQUEST,
        ),
        # The referral *package* is an evidence export, which NEMESIS can produce. The
        # referral itself is somebody else's authority and is not modelled as executable.
        _lever(
            "referral-package",
            operation=OperationClass.EVIDENCE_EXPORT,
            unconstrained_impact=ImpactLevel.LOW,
            disposition=ProviderDisposition.COOPERATIVE,
            recovery_difficulty=RecoveryDifficulty.MODERATE,
            legal_basis=LegalBasis.LAW_ENFORCEMENT_REQUEST,
        ),
        _lever(
            "simulated-takedown",
            operation=OperationClass.SIMULATION,
            unconstrained_impact=ImpactLevel.NONE,
            disposition=ProviderDisposition.COOPERATIVE,
            recovery_difficulty=RecoveryDifficulty.MODERATE,
            legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        ),
    )

    by_key = {option.key: option for option in plan}
    assert set(by_key) == {
        "registrar-suspension",
        "hosting-termination",
        "transit-notification",
        "exchange-notification",
        "referral-package",
        "simulated-takedown",
    }

    assert by_key["registrar-suspension"].implementation_status is (
        ImplementationStatus.REQUIRES_LEGAL_AUTHORITY
    )
    assert by_key["hosting-termination"].implementation_status is (
        ImplementationStatus.REQUIRES_LEGAL_AUTHORITY
    )
    assert by_key["exchange-notification"].implementation_status is (
        ImplementationStatus.REQUIRES_LEGAL_AUTHORITY
    )
    assert by_key["transit-notification"].is_executable_now
    assert by_key["referral-package"].is_executable_now
    assert by_key["simulated-takedown"].is_executable_now

    # Blocked options are carried at full reasoning, not as stubs.
    for key in ("registrar-suspension", "hosting-termination", "exchange-notification"):
        option = by_key[key]
        assert option.expected_impact.basis
        assert option.ownership_evidence.basis
        assert option.recovery.path
        assert any("requires legal authority" in flag for flag in option.flags)

    assert by_key["hosting-termination"].expected_impact.level is ImpactLevel.LOW
    assert by_key["transit-notification"].expected_impact.level is ImpactLevel.MODERATE

    # The registrar suspension is the highest-impact lever in the scenario and still ranks
    # last: nothing may be acted on before the initech domain's ownership is confirmed.
    assert plan[-1].key == "registrar-suspension"
    assert by_key["registrar-suspension"].expected_impact.level is ImpactLevel.MODERATE

    rendered = DisruptionPlanner().plan([_lever("x")], now=NOW).render()
    assert "Disruption plan (1 option(s))" in rendered
