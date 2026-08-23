"""Is the trajectory still productive? Answered in code, on purpose.

AVO escapes plateaus with self-supervision. NEMESIS needs the same escape and must not pay for it
the same way: asking a model after every move whether the investigation is stuck would put a
nondeterministic judgement on the hot path of a loop whose whole value is that it is
reconstructable, and would spend a provider call to learn something the numbers already say.

So detection is deterministic and cheap, and a model — if one is used at all — is consulted only
*after* the deterministic detector says there is something to consult about. That ordering is the
design: :class:`~nemesis.evolution.supervisor.TrajectorySupervisor` is the expensive, fallible,
optional half, and it never runs on a healthy trajectory.

Every threshold lives in :class:`StagnationPolicy` with a documented default and a stated reason.
None of them is measured — like every constant in this repository they are choices, frozen so they
can be argued with, and they will be wrong in ways only a real corpus can reveal. What they are
*not* is hidden: there is no magic number inside a comparison anywhere in this module.

Status: `IMPLEMENTED`. The thresholds are `PROPOSED` as calibration — nothing has validated them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from nemesis.evolution.models import MAX_NOTE_LENGTH, CandidateStatus, EvaluationResult


class StagnationSignal(StrEnum):
    """Why the detector thinks the trajectory has stalled. Several may fire at once.

    Reported as a set rather than reduced to a verdict, because the supervisor's directive depends
    on *which* stall this is: a run repeating one pivot family needs diversification, a run whose
    candidates all fail wants a different question, and a run burning budget for nothing may simply
    need to stop.
    """

    NO_PROMOTION = "no_promotion"
    """No candidate has been promoted for the whole window."""

    NO_EPISTEMIC_GAIN = "no_epistemic_gain"
    """Candidates were promoted and none of them moved a tier-1 term. Progress by utility alone is
    a run collecting entities rather than learning anything."""

    REPEATED_PIVOT_FAMILY = "repeated_pivot_family"
    ALL_CANDIDATES_REJECTED = "all_candidates_rejected"
    REPEATED_STATE = "repeated_state"
    """Two checkpoints in the window measured structurally identical. The strongest signal here,
    because it is the one that cannot be explained by an unlucky pivot."""

    BUDGET_WITHOUT_PROGRESS = "budget_without_progress"
    CONTRADICTIONS_UNCHANGED = "contradictions_unchanged"
    REDUNDANT_WORK = "redundant_work"
    """The run is re-proposing directions its own memory records as spent."""


@dataclass(frozen=True)
class StagnationPolicy:
    """Thresholds, with the reason each one is where it is.

    A frozen dataclass rather than a model because it is configuration a deployment sets once, and
    because :class:`~nemesis.pilot.challenger.ChallengePolicy` — the closest existing analogue —
    is one.
    """

    window: Annotated[int, Field(ge=2)] = 4
    """How many recent steps count as "recently".

    Four, because two is one unlucky pivot and eight is a quarter of a default run spent before
    anything notices. A window is a trade between reacting to noise and reacting too late, and
    this one is set to react early: the cost of an unnecessary redirect is one directive, and the
    cost of a late one is every step in between."""

    min_epistemic_gain: int = 1
    """How much tier-1 movement counts as progress. One independent origin, one contradiction
    resolved, one hypothesis settled. Deliberately an integer over structural counts and not a
    float over a score, so "progress" cannot be manufactured by a rounding."""

    max_same_family: int = 3
    """How many times one pivot family may be proposed inside the window before the repetition is
    itself the finding."""

    max_budget_share_without_progress: float = 0.25
    """Fraction of the pursuit budget a window may consume with no tier-1 gain. A quarter of the
    budget for nothing is a direction that has stopped paying."""

    min_signals: int = 1
    """How many signals make a plateau. One, because every signal here is already conservative and
    requiring agreement between two would mean the detector fires only once the run is thoroughly
    stuck — which is the case where a redirect is worth least."""


class StagnationAssessment(BaseModel):
    """What the detector found, with the numbers it found it from.

    Carries the metrics as well as the verdict, because a redirect an operator cannot audit is a
    strategy change nobody can second-guess — and because the supervisor is handed this rather than
    the trajectory itself.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    stagnant: bool
    window: Annotated[int, Field(ge=0)]
    signals: tuple[StagnationSignal, ...] = ()
    reasons: tuple[Annotated[str, Field(max_length=MAX_NOTE_LENGTH)], ...] = ()
    metrics: dict[str, str] = Field(default_factory=dict)

    @property
    def describes_a_plateau(self) -> bool:
        return self.stagnant and bool(self.signals)


@dataclass(frozen=True)
class StepRecord:
    """One step's outcome, as the detector needs to see it.

    Deliberately not the checkpoint: a detector that read checkpoints would have to know how they
    are built, and this way the same detector works over a branch's steps, a run's steps, or a
    replayed trajectory.
    """

    evaluation: EvaluationResult
    promoted: bool
    pivot_families: tuple[str, ...]
    state_digest: str


class StagnationDetector:
    """Deterministic plateau detection over a window of recent steps."""

    def __init__(self, policy: StagnationPolicy | None = None) -> None:
        self._policy = policy or StagnationPolicy()

    @property
    def policy(self) -> StagnationPolicy:
        return self._policy

    def assess(
        self, steps: Sequence[StepRecord], *, pursuit_budget: float = 0.0
    ) -> StagnationAssessment:
        """Look at the last ``window`` steps and say whether they went anywhere.

        Returns ``stagnant=False`` with an empty signal set when the window is not yet full. A
        detector that fired on the first two steps of every run would make its own verdict
        meaningless, and a run has to be given room to open.
        """
        policy = self._policy
        recent = tuple(steps[-policy.window :])
        if len(recent) < policy.window:
            return StagnationAssessment(
                stagnant=False,
                window=len(recent),
                metrics={"reason": "the window is not full yet"},
            )

        signals: list[StagnationSignal] = []
        reasons: list[str] = []

        promotions = sum(1 for step in recent if step.promoted)
        epistemic = sum(
            max(0, step.evaluation.score.epistemic_key[0])
            + max(0, step.evaluation.score.epistemic_key[1])
            + step.evaluation.score.contradictions_resolved
            + max(0, step.evaluation.score.hypotheses_settled)
            for step in recent
        )
        rejected = sum(
            1 for step in recent if step.evaluation.status is not CandidateStatus.PROMOTED
        )
        spent = sum(step.evaluation.score.budget_spent for step in recent)
        redundant = sum(step.evaluation.score.redundant_pivots for step in recent)
        contradictions = {step.evaluation.measurement.open_contradictions for step in recent}
        digests = [step.state_digest for step in recent if step.state_digest]
        family_counts: dict[str, int] = {}
        for step in recent:
            for family in step.pivot_families:
                family_counts[family] = family_counts.get(family, 0) + 1

        if promotions == 0:
            signals.append(StagnationSignal.NO_PROMOTION)
            reasons.append(f"no candidate was promoted in the last {policy.window} steps")
        if epistemic < policy.min_epistemic_gain:
            signals.append(StagnationSignal.NO_EPISTEMIC_GAIN)
            reasons.append(
                f"tier-1 movement over the window was {epistemic}, below the "
                f"{policy.min_epistemic_gain} that counts as progress"
            )
        if rejected == len(recent):
            signals.append(StagnationSignal.ALL_CANDIDATES_REJECTED)
            reasons.append("every candidate in the window was rejected or invalid")
        for family, count in sorted(family_counts.items()):
            if count > policy.max_same_family:
                signals.append(StagnationSignal.REPEATED_PIVOT_FAMILY)
                reasons.append(
                    f"the {family!r} pivot family was proposed {count} times in "
                    f"{policy.window} steps"
                )
                break
        if len(digests) >= 2 and len(set(digests)) < len(digests):
            signals.append(StagnationSignal.REPEATED_STATE)
            reasons.append(
                "two checkpoints in the window measured structurally identical; the "
                "investigation returned to a state it had already reached"
            )
        if (
            pursuit_budget > 0
            and spent / pursuit_budget > policy.max_budget_share_without_progress
            and epistemic < policy.min_epistemic_gain
        ):
            signals.append(StagnationSignal.BUDGET_WITHOUT_PROGRESS)
            reasons.append(
                f"the window spent {spent:.1f} of a {pursuit_budget:.1f} budget without moving a "
                "tier-1 term"
            )
        if len(contradictions) == 1 and next(iter(contradictions)) > 0:
            signals.append(StagnationSignal.CONTRADICTIONS_UNCHANGED)
            reasons.append(
                f"{next(iter(contradictions))} contradiction(s) stood unchanged across the window"
            )
        if redundant > 0:
            signals.append(StagnationSignal.REDUNDANT_WORK)
            reasons.append(
                f"{redundant} pivot(s) in the window repeated a direction the memory records as "
                "spent"
            )

        unique = tuple(dict.fromkeys(signals))
        return StagnationAssessment(
            stagnant=len(unique) >= policy.min_signals,
            window=policy.window,
            signals=unique,
            reasons=tuple(reasons),
            metrics={
                "promotions": str(promotions),
                "epistemic_gain": str(epistemic),
                "rejected": str(rejected),
                "budget_spent": f"{spent:.2f}",
                "redundant_pivots": str(redundant),
                "distinct_states": str(len(set(digests))),
                "most_repeated_family": max(
                    family_counts, key=lambda k: family_counts[k], default=""
                ),
            },
        )


__all__ = [
    "StagnationAssessment",
    "StagnationDetector",
    "StagnationPolicy",
    "StagnationSignal",
    "StepRecord",
]
