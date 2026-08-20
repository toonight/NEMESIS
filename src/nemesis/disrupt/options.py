"""Disruption options: what could be done to an adversary, and at what cost to whom.

A disruption option is a *proposal*, never an action. This plane has no path to execution;
that runs through the Authorization Gateway (:mod:`nemesis.authz`) and the Effects plane,
and this module deliberately imports neither. An option is a fully-reasoned argument for a
lever, assembled so a human can weigh it — including the arguments against pulling it.

Four properties of the model carry the weight, because each guards against a specific way a
disruption programme causes harm rather than preventing it:

- **Expected impact carries its basis and accounts for the target's disposition.** "Suspend
  the host" is not a plan; "suspend the host, which will do nothing because the host ignores
  abuse reports" is. Impact that ignores whether the lever actually moves is worse than no
  estimate, because it looks like one.

- **Collateral risk is a required, first-class field.** An option that cannot state who else
  it might harm is an option that will eventually take down someone innocent. A name that
  resembles a legitimate business is the archetype: it must be flagged as needing ownership
  confirmation *before* anyone acts, not after.

- **Target-ownership evidence is required, not optional.** Acting on the wrong target is the
  failure that ends the company. An option whose ownership rests on a single, weak or
  uncorroborated source is marked as such and ranked accordingly, however attractive its
  impact.

- **An option may be proposed that NEMESIS cannot execute.** Options whose operation class
  has no adapter are carried at full reasoning with status ``REQUIRES_LEGAL_AUTHORITY``. A
  planner limited to what is implemented silently narrows every investigation to whatever
  happens to be built.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.authorization import (
    MVP_IMPLEMENTED_OPERATIONS,
    LegalBasis,
    OperationClass,
)
from nemesis.core.confidence import ConfidenceBand, Opinion, band_of, describe
from nemesis.core.entities import EntityType
from nemesis.core.ids import ClaimId, EntityId


class ImpactLevel(StrEnum):
    """How much an option would degrade the adversary's operational capability."""

    NONE = "none"
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


IMPACT_RANK: dict[ImpactLevel, int] = {
    ImpactLevel.NONE: 0,
    ImpactLevel.NEGLIGIBLE: 1,
    ImpactLevel.LOW: 2,
    ImpactLevel.MODERATE: 3,
    ImpactLevel.HIGH: 4,
}


def weaker_impact(left: ImpactLevel, right: ImpactLevel) -> ImpactLevel:
    """The lesser of two impact levels. Used to cap a lever by what the world allows."""
    return left if IMPACT_RANK[left] <= IMPACT_RANK[right] else right


class ProviderDisposition(StrEnum):
    """How a provider responds when asked to act against a client.

    This is the input that turns a takedown from a lever into a gesture. A termination
    request to a cooperative registrar removes the domain; the same request to a
    bulletproof host is filed and ignored. Modelling the disposition is what lets the
    planner say the second one is LOW impact instead of proposing it as though it worked.
    """

    COOPERATIVE = "cooperative"
    """Acts on well-founded abuse reports, promptly and predictably."""

    SLOW = "slow"
    """Eventually acts, but on its own timeline — long enough for the adversary to move."""

    UNRESPONSIVE = "unresponsive"
    """Does not answer abuse reports. Not adversarial by design, merely absent."""

    BULLETPROOF = "bulletproof"
    """Ignores abuse reports as a selling point, and may tip off the client. A request here
    is not merely futile; it can warn the adversary that they have been found."""

    UNKNOWN = "unknown"
    """Disposition not established. Treated as a ceiling on confidence, never as cooperation."""


class RecoveryDifficulty(StrEnum):
    """How hard it is for the adversary to undo the disruption and resume operating.

    This axis is what separates whack-a-mole from capability degradation. Suspending a
    domain the adversary re-registers within the hour is theatre; seizing the one private
    key their whole persona rests on is not.
    """

    TRIVIAL = "trivial"
    """Restored in minutes to hours, at near-zero cost. Whack-a-mole."""

    EASY = "easy"
    """Restored within a day using interchangeable resources."""

    MODERATE = "moderate"
    """Costs the adversary real time or money to rebuild."""

    HARD = "hard"
    """Requires rebuilding something they cannot cheaply replace."""

    SEVERE = "severe"
    """Degrades a capability the adversary cannot reconstitute without starting over."""


_WHACK_A_MOLE = {RecoveryDifficulty.TRIVIAL, RecoveryDifficulty.EASY}


class ImplementationStatus(StrEnum):
    """Whether NEMESIS can actually carry out this option, using CLAUDE.md's labels.

    Only two values are reachable here: an option is either backed by an implemented
    adapter, or it is a proposal blocked on authority we do not and may not have. The
    planner must be able to emit the second kind at full reasoning, or it silently narrows
    every investigation to whatever happens to be built.
    """

    IMPLEMENTED = "IMPLEMENTED"
    REQUIRES_LEGAL_AUTHORITY = "REQUIRES_LEGAL_AUTHORITY"

    @classmethod
    def for_operation(cls, operation: OperationClass) -> ImplementationStatus:
        """The only honest status for an operation: implemented iff it has an adapter."""
        if operation in MVP_IMPLEMENTED_OPERATIONS:
            return cls.IMPLEMENTED
        return cls.REQUIRES_LEGAL_AUTHORITY


class DisruptionTarget(BaseModel):
    """One entity an option would act against.

    Carries ``resembles_legitimate_business`` because that fact travels with the target,
    not with any one option: whichever lever touches this node inherits the obligation to
    confirm ownership before acting. A name a court clerk would mistake for a real company
    is the case the collateral machinery exists for.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: EntityId
    entity_type: EntityType
    natural_key: Annotated[str, Field(min_length=1)]
    display: str | None = None

    resembles_legitimate_business: bool = False
    """True when the identifier looks like a genuine business and could belong to an
    uninvolved third party. Forces an ownership-confirmation collateral flag."""


class ExpectedImpact(BaseModel):
    """An impact estimate that must show its work.

    ``basis`` is not optional prose. A level with no stated basis is a guess wearing the
    costume of an estimate, and it is exactly what lets "terminate the hosting" be proposed
    against a host that will ignore it.
    """

    model_config = ConfigDict(frozen=True)

    level: ImpactLevel
    basis: Annotated[str, Field(min_length=1)]
    """Why this level: what the lever moves, and — where relevant — what stops it moving."""

    unconstrained_level: ImpactLevel | None = None
    """What the impact would be if the provider fully cooperated. Present when the target's
    disposition capped the estimate, so a reader can see the gap between the lever's reach
    and its actual effect."""

    @property
    def was_capped(self) -> bool:
        """Whether the target's disposition held the estimate below the lever's reach."""
        return (
            self.unconstrained_level is not None
            and IMPACT_RANK[self.level] < IMPACT_RANK[self.unconstrained_level]
        )


class AdversaryRecovery(BaseModel):
    """How the adversary comes back, and how hard that is."""

    model_config = ConfigDict(frozen=True)

    path: Annotated[str, Field(min_length=1)]
    """The concrete route back to operating: re-register at another registrar, spin up a
    new host, mint a new persona. Named, not scored."""

    difficulty: RecoveryDifficulty
    estimated_time: str | None = None
    """Rough time-to-recover in plain language, e.g. 'under an hour', 'weeks'."""

    @property
    def is_whack_a_mole(self) -> bool:
        """Whether disrupting this achieves nothing the adversary cannot cheaply undo."""
        return self.difficulty in _WHACK_A_MOLE


class CollateralRisk(BaseModel):
    """Who else an option could harm, and how badly.

    A first-class output rather than a footnote. The point of the field is to make the
    sentence "you might be about to take down someone innocent" sayable by the system
    before anyone acts, instead of discoverable afterwards from the wreckage.
    """

    model_config = ConfigDict(frozen=True)

    affected_party: Annotated[str, Field(min_length=1)]
    description: Annotated[str, Field(min_length=1)]
    severity: ImpactLevel
    requires_ownership_confirmation: bool = False
    """True when the risk is that the target may not be the adversary's at all. Such an
    option must not be executed before ownership is independently confirmed."""


# Below this projected probability, or with only a single source, target ownership is too
# thin to act on. Acting on a target that is not the adversary's is the one disruption error
# that is not recoverable, so the floor is deliberately high: "likely" is not good enough.
OWNERSHIP_CONFIDENCE_FLOOR = 0.55


class OwnershipEvidence(BaseModel):
    """The basis for believing the target belongs to the adversary — a required field.

    Ownership is scored as an :class:`Opinion`, not a float, and paired with the number of
    *independent* sources behind it, because those are two different questions. A single
    confident source and three corroborating ones can project the same probability; only the
    second is safe to act on, and ``independent_source_count`` is what tells them apart.
    """

    model_config = ConfigDict(frozen=True)

    opinion: Opinion
    independent_source_count: Annotated[int, Field(ge=0)]
    """Distinct origins after resolving resellers and mirrors — the fusion sense of the
    word, not the feed count. One is single-sourced, and single-sourced ownership is weak
    however confident that one source sounds."""

    basis: Annotated[str, Field(min_length=1)]
    """What establishes ownership: a shared unique key, a registrant record, a confession
    in a controlled channel. Named so a reviewer can attack it."""

    supporting_claims: tuple[ClaimId, ...] = ()

    @property
    def is_single_sourced(self) -> bool:
        return self.independent_source_count <= 1

    @property
    def band(self) -> ConfidenceBand:
        return band_of(self.opinion)

    @property
    def is_weak(self) -> bool:
        """Whether this ownership basis is too thin to act on.

        Weak if it rests on a single source, if the evidence is too vacuous to support any
        band at all, or if it does not clear the confidence floor. Any one of these is
        enough: acting on the wrong target is unrecoverable, so the test is conjunction of
        safeguards, not a single averaged score.
        """
        return (
            self.is_single_sourced
            or self.band is ConfidenceBand.INSUFFICIENT_BASIS
            or self.opinion.projected_probability < OWNERSHIP_CONFIDENCE_FLOOR
        )

    def describe(self) -> str:
        reasons: list[str] = []
        if self.is_single_sourced:
            reasons.append(f"single-sourced ({self.independent_source_count} independent origin)")
        if self.band is ConfidenceBand.INSUFFICIENT_BASIS:
            reasons.append("insufficient basis to estimate")
        elif self.opinion.projected_probability < OWNERSHIP_CONFIDENCE_FLOOR:
            reasons.append(
                f"below the ownership floor ({self.opinion.projected_probability:.0%} < "
                f"{OWNERSHIP_CONFIDENCE_FLOOR:.0%})"
            )
        detail = "; ".join(reasons) if reasons else describe(self.opinion)
        return f"target ownership: {self.basis} — {detail}"


class DisruptionOption(BaseModel):
    """A single, fully-argued proposal to damage the adversary's capability.

    Frozen: an option is a record of a judgement made at a point in time, not a mutable
    worksheet. Re-planning produces new options rather than editing old ones, so a plan can
    be shown to have said what it said.
    """

    model_config = ConfigDict(frozen=True)

    key: Annotated[str, Field(min_length=1)]
    """Stable handle for this option within a plan, so dependencies can reference it."""

    operation: OperationClass
    title: Annotated[str, Field(min_length=1)]
    description: Annotated[str, Field(min_length=1)]

    targets: Annotated[tuple[DisruptionTarget, ...], Field(min_length=1)]

    expected_impact: ExpectedImpact
    impact_confidence: Opinion
    """Confidence in the *impact estimate itself*, distinct from confidence in ownership.
    An Opinion, so "we cannot tell how well this would work" is expressible as uncertainty
    rather than misreported as a middling probability."""

    collateral_risks: tuple[CollateralRisk, ...] = ()
    recovery: AdversaryRecovery
    ownership_evidence: OwnershipEvidence

    legal_basis: LegalBasis
    jurisdictions: Annotated[tuple[str, ...], Field(min_length=1)]
    """ISO 3166-1 alpha-2 codes of every jurisdiction the option touches. An option that
    spans jurisdictions needs authority in each; listing them is what makes that visible."""

    depends_on: tuple[str, ...] = ()
    """Keys of other options this one presupposes."""

    implementation_status: ImplementationStatus
    flags: tuple[str, ...] = ()
    """Planner-surfaced warnings: capped impact, whack-a-mole recovery, weak ownership,
    ownership confirmation required, execution blocked on legal authority. Kept structured
    so an export cannot drop them into prose and lose them."""

    @model_validator(mode="after")
    def _check_status_matches_capability(self) -> Self:
        # IMPLEMENTED must not be claimed for an operation class that has no adapter: that
        # would advertise an executability NEMESIS does not have, which is the precise lie
        # the boundary labels exist to prevent.
        if (
            self.implementation_status is ImplementationStatus.IMPLEMENTED
            and self.operation not in MVP_IMPLEMENTED_OPERATIONS
        ):
            raise ValueError(
                f"{self.operation.value} has no adapter and cannot be marked IMPLEMENTED; "
                "it is REQUIRES_LEGAL_AUTHORITY"
            )
        if self.key in self.depends_on:
            raise ValueError("an option cannot depend on itself")
        return self

    # -- derived judgements ---------------------------------------------------

    @property
    def is_whack_a_mole(self) -> bool:
        return self.recovery.is_whack_a_mole

    @property
    def degrades_capability(self) -> bool:
        """Whether this actually reduces capability rather than inviting re-registration.

        Requires both durability (not whack-a-mole) and non-trivial impact. A durable
        action with negligible impact degrades nothing; a high-impact action the adversary
        undoes in an hour degrades nothing either.
        """
        return (
            not self.is_whack_a_mole
            and IMPACT_RANK[self.expected_impact.level] >= IMPACT_RANK[ImpactLevel.MODERATE]
        )

    @property
    def blocking_collateral(self) -> tuple[CollateralRisk, ...]:
        """Collateral risks that demand ownership confirmation before any action."""
        return tuple(r for r in self.collateral_risks if r.requires_ownership_confirmation)

    @property
    def requires_ownership_confirmation(self) -> bool:
        return bool(self.blocking_collateral) or self.ownership_evidence.is_weak

    @property
    def is_ownership_sound(self) -> bool:
        """Whether this option is safe to act on without first confirming the target.

        Sound means both that the ownership evidence is not weak and that no collateral
        risk turns on the target possibly not being the adversary's. Either failure blocks
        action, so this is the gate the planner ranks on before any question of impact.
        """
        return not self.requires_ownership_confirmation

    @property
    def is_executable_now(self) -> bool:
        """Whether NEMESIS could carry this out today (still only via the authz gateway)."""
        return self.implementation_status is ImplementationStatus.IMPLEMENTED

    def render(self) -> str:
        """Plain text an analyst can read without the model behind it."""
        lines = [
            f"[{self.implementation_status.value}] {self.title}",
            f"  operation: {self.operation.value}",
            f"  impact: {self.expected_impact.level.value} — {self.expected_impact.basis}",
            f"  impact confidence: {describe(self.impact_confidence)}",
            f"  recovery: {self.recovery.difficulty.value} — {self.recovery.path}",
            f"  {self.ownership_evidence.describe()}",
        ]
        for risk in self.collateral_risks:
            mark = " (CONFIRM OWNERSHIP FIRST)" if risk.requires_ownership_confirmation else ""
            lines.append(
                f"  collateral [{risk.severity.value}]: {risk.affected_party} — "
                f"{risk.description}{mark}"
            )
        for flag in self.flags:
            lines.append(f"  ! {flag}")
        return "\n".join(lines)
