"""The Disruption Planner: reason over the whole network, propose levers, rank honestly.

The planner is handed the network as a set of :class:`DisruptionLever` inputs — candidate
actions with the facts needed to judge them — and returns fully-argued options plus a
ranking. It reasons over the *whole criminal network* rather than one server: the same four
domains behind one registrar are one coordinated action, and the value of terminating a host
depends on that host's disposition, not on the domain sitting in front of it.

The planner adds the judgement, not the facts. Given a lever's reach and the target's
disposition, it decides the real expected impact and says when it was capped. Given a target
that resembles a legitimate business, it raises the collateral flag the caller did not have
to remember. Given ownership evidence that rests on one source, it downranks the option
below every soundly-owned one, however attractive the impact — because acting on the wrong
target is the failure that is not recoverable.

The ranking makes one distinction explicit above all others: which options degrade capability
and which are whack-a-mole. An option the adversary undoes within the hour is separated from
one that costs them something they cannot cheaply rebuild, so a reader is never left to infer
it from an impact number that does not carry it.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.authorization import LegalBasis, OperationClass
from nemesis.core.confidence import Opinion
from nemesis.core.temporal import utcnow
from nemesis.disrupt.options import (
    IMPACT_RANK,
    AdversaryRecovery,
    CollateralRisk,
    DisruptionOption,
    DisruptionTarget,
    ExpectedImpact,
    ImpactLevel,
    ImplementationStatus,
    OwnershipEvidence,
    ProviderDisposition,
    weaker_impact,
)

# How far a provider's disposition lets a takedown actually reach. A bulletproof or absent
# provider caps the effect at LOW no matter how central the target is — the request is filed
# and ignored. An unknown disposition is capped at MODERATE, never treated as cooperation:
# assuming a provider will act because nobody checked is how a plan promises impact it cannot
# deliver. These are a stated calibration choice, monotone in the right direction, to be
# re-set against observed provider behaviour rather than derived from it.
_DISPOSITION_CEILING: dict[ProviderDisposition, ImpactLevel] = {
    ProviderDisposition.COOPERATIVE: ImpactLevel.HIGH,
    ProviderDisposition.SLOW: ImpactLevel.MODERATE,
    ProviderDisposition.UNRESPONSIVE: ImpactLevel.LOW,
    ProviderDisposition.BULLETPROOF: ImpactLevel.LOW,
    ProviderDisposition.UNKNOWN: ImpactLevel.MODERATE,
}

_DISPOSITION_REASON: dict[ProviderDisposition, str] = {
    ProviderDisposition.COOPERATIVE: "the provider acts on well-founded abuse reports",
    ProviderDisposition.SLOW: (
        "the provider acts only on its own timeline, long enough for the adversary to move"
    ),
    ProviderDisposition.UNRESPONSIVE: "the provider does not answer abuse reports",
    ProviderDisposition.BULLETPROOF: (
        "the provider ignores abuse reports by design and may warn the client"
    ),
    ProviderDisposition.UNKNOWN: (
        "the provider's disposition is unestablished and cannot be assumed cooperative"
    ),
}


class DisruptionLever(BaseModel):
    """A candidate action, with the network facts the planner needs to judge it.

    This is the input side: it names *what* could be done and the facts that bear on it, and
    leaves the judgement — real impact, collateral flags, ranking — to the planner. The
    separation is deliberate: a lever that arrived pre-judged would let the caller smuggle in
    the conclusion the planner exists to reach.
    """

    model_config = ConfigDict(frozen=True)

    key: Annotated[str, Field(min_length=1)]
    operation: OperationClass
    title: Annotated[str, Field(min_length=1)]
    description: Annotated[str, Field(min_length=1)]

    targets: Annotated[tuple[DisruptionTarget, ...], Field(min_length=1)]

    unconstrained_impact: ImpactLevel
    """What this lever would achieve if the provider fully cooperated — the target's
    centrality to the operation, before disposition is taken into account."""

    impact_note: str = ""
    """Optional detail folded into the impact basis, e.g. what the target does for the
    operation."""

    provider_disposition: ProviderDisposition = ProviderDisposition.UNKNOWN
    provider_name: str | None = None

    recovery: AdversaryRecovery
    ownership: OwnershipEvidence
    collateral: tuple[CollateralRisk, ...] = ()

    legal_basis: LegalBasis = LegalBasis.NONE_SIMULATION_ONLY
    jurisdictions: Annotated[tuple[str, ...], Field(min_length=1)] = ("XX",)
    depends_on: tuple[str, ...] = ()


class DisruptionPlan(BaseModel):
    """A ranked set of options, with the network-level distinctions surfaced.

    The options are ordered most-actionable first, but the ordering alone is not the
    product: the plan also names which options degrade capability, which are whack-a-mole,
    which cannot be executed without legal authority, and which must not be acted on until
    ownership is confirmed. A ranking that hid those behind a single position would be the
    list this plane exists to avoid.
    """

    model_config = ConfigDict(frozen=True)

    generated_at: datetime
    options: tuple[DisruptionOption, ...]

    @property
    def capability_degrading(self) -> tuple[DisruptionOption, ...]:
        return tuple(o for o in self.options if o.degrades_capability)

    @property
    def whack_a_mole(self) -> tuple[DisruptionOption, ...]:
        return tuple(o for o in self.options if o.is_whack_a_mole)

    @property
    def requires_legal_authority(self) -> tuple[DisruptionOption, ...]:
        """Options proposed at full reasoning that NEMESIS cannot itself execute."""
        return tuple(
            o
            for o in self.options
            if o.implementation_status is ImplementationStatus.REQUIRES_LEGAL_AUTHORITY
        )

    @property
    def needs_ownership_confirmation(self) -> tuple[DisruptionOption, ...]:
        """Options that must not be acted on before the target's ownership is confirmed."""
        return tuple(o for o in self.options if o.requires_ownership_confirmation)

    @property
    def executable_now(self) -> tuple[DisruptionOption, ...]:
        return tuple(o for o in self.options if o.is_executable_now)

    def render(self) -> str:
        lines = [f"Disruption plan ({len(self.options)} option(s)):", ""]
        for position, option in enumerate(self.options, start=1):
            lines.append(f"{position}. {option.render()}")
            lines.append("")
        degrading = self.capability_degrading
        whack = self.whack_a_mole
        lines.append(
            f"Capability-degrading: {len(degrading)}; whack-a-mole: {len(whack)}; "
            f"blocked on legal authority: {len(self.requires_legal_authority)}; "
            f"awaiting ownership confirmation: {len(self.needs_ownership_confirmation)}."
        )
        return "\n".join(lines)


class DisruptionPlanner:
    """Turns levers into ranked, fully-argued disruption options.

    Stateless. It holds no graph handle and no effects capability, and imports neither the
    authorization gateway nor the effects plane: proposing is all it can do, structurally.
    """

    def plan(
        self,
        levers: Sequence[DisruptionLever],
        *,
        now: datetime | None = None,
    ) -> DisruptionPlan:
        """Reason over every lever and return them ranked."""
        moment = now or utcnow()
        options = [self._build_option(lever) for lever in levers]
        options.sort(key=_rank_key, reverse=True)
        return DisruptionPlan(generated_at=moment, options=tuple(options))

    # -- per-lever reasoning --------------------------------------------------

    def _build_option(self, lever: DisruptionLever) -> DisruptionOption:
        impact = self._expected_impact(lever)
        collateral = self._collateral(lever)
        status = ImplementationStatus.for_operation(lever.operation)
        flags = self._flags(lever, impact, collateral, status)

        return DisruptionOption(
            key=lever.key,
            operation=lever.operation,
            title=lever.title,
            description=lever.description,
            targets=lever.targets,
            expected_impact=impact,
            impact_confidence=_impact_confidence(lever.provider_disposition),
            collateral_risks=collateral,
            recovery=lever.recovery,
            ownership_evidence=lever.ownership,
            legal_basis=lever.legal_basis,
            jurisdictions=lever.jurisdictions,
            depends_on=lever.depends_on,
            implementation_status=status,
            flags=flags,
        )

    def _expected_impact(self, lever: DisruptionLever) -> ExpectedImpact:
        """Cap the lever's reach by the target's disposition and record why.

        The cap is where the bulletproof-host case is handled: a HIGH-centrality target
        behind a host that ignores abuse reports yields LOW expected impact, and the basis
        says so, rather than the plan proposing the termination as though it would work.
        """
        ceiling = _DISPOSITION_CEILING[lever.provider_disposition]
        level = weaker_impact(lever.unconstrained_impact, ceiling)

        detail = f" {lever.impact_note}" if lever.impact_note else ""
        capped = IMPACT_RANK[level] < IMPACT_RANK[lever.unconstrained_impact]
        if capped:
            provider = lever.provider_name or "the provider"
            basis = (
                f"Reach would be {lever.unconstrained_impact.value}, but capped at "
                f"{level.value}: {_DISPOSITION_REASON[lever.provider_disposition]} "
                f"({provider}).{detail}"
            )
            return ExpectedImpact(
                level=level, basis=basis, unconstrained_level=lever.unconstrained_impact
            )
        basis = (
            f"Assessed {level.value}: {_DISPOSITION_REASON[lever.provider_disposition]}.{detail}"
        )
        return ExpectedImpact(level=level, basis=basis)

    def _collateral(self, lever: DisruptionLever) -> tuple[CollateralRisk, ...]:
        """Carry the lever's stated risks and add ownership-confirmation flags.

        A target that resembles a legitimate business raises a collateral risk that whoever
        owns it may be uninvolved. The planner adds this so the caller does not have to
        remember to — the whole point of the flag is that it fires when nobody was looking.
        """
        risks = list(lever.collateral)
        already = {r.affected_party for r in risks if r.requires_ownership_confirmation}
        for target in lever.targets:
            if not target.resembles_legitimate_business:
                continue
            party = target.display or target.natural_key
            if party in already:
                continue
            risks.append(
                CollateralRisk(
                    affected_party=party,
                    description=(
                        f"{party} resembles a legitimate business name; suspending it could "
                        "take down an uninvolved third party if ownership is not the "
                        "adversary's. Confirm ownership before any action."
                    ),
                    severity=ImpactLevel.HIGH,
                    requires_ownership_confirmation=True,
                )
            )
            already.add(party)
        return tuple(risks)

    def _flags(
        self,
        lever: DisruptionLever,
        impact: ExpectedImpact,
        collateral: tuple[CollateralRisk, ...],
        status: ImplementationStatus,
    ) -> tuple[str, ...]:
        flags: list[str] = []
        if impact.was_capped:
            flags.append(
                f"expected impact capped at {impact.level.value}: "
                f"{_DISPOSITION_REASON[lever.provider_disposition]}"
            )
        if lever.recovery.is_whack_a_mole:
            when = f" ({lever.recovery.estimated_time})" if lever.recovery.estimated_time else ""
            flags.append(
                f"whack-a-mole: the adversary recovers by {lever.recovery.path}{when}; "
                "disruption is temporary"
            )
        if lever.ownership.is_weak:
            flags.append(
                f"weak target ownership — {lever.ownership.describe()}; downranked, and "
                "must be corroborated before acting"
            )
        for risk in collateral:
            if risk.requires_ownership_confirmation:
                flags.append(
                    f"confirm ownership of {risk.affected_party} before acting — "
                    "it may be an uninvolved third party"
                )
        if status is ImplementationStatus.REQUIRES_LEGAL_AUTHORITY:
            flags.append(
                "NEMESIS cannot execute this: it requires legal authority the platform does "
                "not hold. Proposed for a human to pursue through the proper channel."
            )
        return tuple(flags)


def _impact_confidence(disposition: ProviderDisposition) -> Opinion:
    """How confident we are in the *impact estimate*, driven by disposition certainty.

    When the disposition is known — cooperative, unresponsive, bulletproof — we can estimate
    the effect with real confidence, even (especially) when that estimate is "this will do
    little". When it is unknown, the honest opinion is vacuous: we cannot say how well the
    lever would work. This is confidence in the estimate, not in ownership, and the two are
    kept as separate fields precisely so one cannot borrow the other's strength.
    """
    if disposition is ProviderDisposition.UNKNOWN:
        return Opinion.vacuous()
    # Beta mapping with three concordant observations and the default prior weight: belief
    # 0.6, uncertainty 0.4 — enough to clear the vacuity threshold, never dogmatic.
    return Opinion.from_evidence(supporting=3.0, contradicting=0.0)


def _rank_key(option: DisruptionOption) -> tuple[int, int, int, int]:
    """Sort key, applied with ``reverse=True`` so a larger tuple ranks higher.

    Ownership soundness dominates every other consideration: an option that might be aimed
    at an innocent party ranks below every soundly-owned option, no matter how attractive
    its impact (the failure that ends the company). Below that gate, capability-degrading
    options beat whack-a-mole ones, then higher impact wins, then lower collateral. Impact
    sits beneath durability on purpose: a HIGH-impact action undone within the hour is worth
    less than a MODERATE one the adversary cannot cheaply reverse.
    """
    return (
        0 if option.requires_ownership_confirmation else 1,
        1 if option.degrades_capability else 0,
        IMPACT_RANK[option.expected_impact.level],
        -_collateral_penalty(option),
    )


def _collateral_penalty(option: DisruptionOption) -> int:
    """Total collateral weight, so a heavier-collateral option loses the tie-break."""
    return sum(IMPACT_RANK[risk.severity] for risk in option.collateral_risks)
