"""A second opinion on the *trajectory*, given no way to act on it.

Two review roles exist in NEMESIS now and they answer different questions. The existing
:class:`~nemesis.pilot.challenger.MoveChallenger` asks *is this one move problematic* — a
contradiction, thin evidence, a provenance problem, an injection — and it sees one briefing and one
move. The :class:`TrajectorySupervisor` asks *is this line of enquiry still worth pursuing*, and it
sees many checkpoints and no move at all. Merging them would produce a reviewer that is wrong about
both: move-level review needs the move, and trajectory-level review needs everything except it.

**What the supervisor may say is a closed enumeration, and there is deliberately no member that
does anything.** :class:`DirectiveType` has no ``APPROVE``, no ``ESCALATE``, no ``RUN_PIVOT``, no
``AUTHORIZE`` — the same absence argument the pilot's four verbs and the challenger's five verdicts
rest on. A supervisor cannot emit a :class:`~nemesis.pilot.moves.PilotMove` because a
:class:`ResearchDirective` is a different type with no member that is one, and
:func:`validate_directive` re-validates whatever it returned through this vocabulary before the
controller reads a field of it. The worst a hijacked, hallucinating or hostile supervisor achieves
is an investigation that changes strategy when it should not have: wasted budget, never an
unauthorized action.

**What a directive actually does.** It changes what goes into the *next briefing* — one word in a
:class:`~nemesis.pilot.moves.ResearchContext`, plus a focus and a rationale the pilot reads as
context. It runs nothing, authorizes nothing, creates no evidence, modifies no graph truth and
widens no envelope, because the controller that applies it holds none of those handles either.

**The shipped supervisor is deterministic and holds no model.** :class:`DeterministicSupervisor`
maps a :class:`~nemesis.evolution.stagnation.StagnationAssessment` onto a directive by a fixed
table. That is not a placeholder for a model — it is the right answer for most plateaus, which have
an obvious response ("you have run the same pivot family four times"), and it keeps a
nondeterministic call off a loop that must reconstruct.

A model-backed supervisor is `PROPOSED` and the seam for one exists: any object satisfying
:class:`TrajectorySupervisor` may be passed, and its output is re-validated identically. It is not
shipped because :class:`~nemesis.pilot.providers.contract.PilotContext` carries a briefing and a
proposed move, and a trajectory dossier is neither — reusing
:class:`~nemesis.pilot.providers.seat.ProviderSeat` would mean widening the least-trusted plane in
the tree to carry a third kind of content, which is not a change to make speculatively. See
ADR-0011.

Status: `IMPLEMENTED` (deterministic supervisor, directive vocabulary, validation seam).
`PROPOSED` (model-backed supervisor).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Final, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from nemesis.core.ids import DirectiveId, IdPrefix, new_id
from nemesis.core.temporal import require_utc
from nemesis.evolution.memory import reads_as_an_instruction, sanitize
from nemesis.evolution.models import MAX_NOTE_LENGTH
from nemesis.evolution.stagnation import StagnationAssessment, StagnationSignal


class DirectiveType(StrEnum):
    """The whole of what a supervisor may recommend.

    Every member changes what the next briefing emphasises and nothing else. There is no member
    that runs a pivot, requests an effect, approves anything, widens scope or summons a human —
    each of those would be authority, and a reviewer that holds authority is a second pilot.
    """

    CONTINUE = "continue"
    """No change. The honest answer when a plateau signal fired and the trajectory is fine."""

    DIVERSIFY = "diversify"
    """Try a pivot family this branch has not used. The response to repetition."""

    REVISIT_PRIOR_BRANCH = "revisit_prior_branch"
    """Go back to a direction set aside earlier. Possible only because the trajectory kept the
    rejected candidates."""

    CHALLENGE_ASSUMPTION = "challenge_assumption"
    """Attack a premise the run has been treating as settled — co-hosting implying common control
    is the standing example, and it is the assumption that produces most false clusters."""

    SEEK_INDEPENDENT_ORIGIN = "seek_independent_origin"
    """Look for corroboration from a channel unrelated to the ones already used. The response to a
    trajectory resting on one provenance cluster."""

    RESOLVE_CONTRADICTION = "resolve_contradiction"
    REDUCE_SCOPE = "reduce_scope"
    """Narrow what the run is chasing. Note the direction: a directive can ask for *less*, and
    there is deliberately no ``EXPAND_SCOPE`` counterpart — scope comes from the seed and the
    envelope, and neither is reachable from here."""

    STOP_LOW_YIELD = "stop_low_yield"
    """Recommend the run end. A recommendation the *controller* acts on by checking a deterministic
    stop condition; the supervisor stops nothing itself."""


class FocusDimension(StrEnum):
    """Where a directive points. Vocabulary shared with the investigation's own language."""

    INFRASTRUCTURE = "infrastructure"
    TEMPORAL = "temporal"
    MALWARE = "malware"
    FINANCIAL = "financial"
    PROVENANCE = "provenance"
    CRYPTOGRAPHIC = "cryptographic"
    HOSTING = "hosting"
    CERTIFICATE = "certificate"
    DOMAIN = "domain"
    REGISTRATION = "registration"
    NONE = "none"


class ResearchDirective(BaseModel):
    """One recommendation about strategy. The only thing a supervisor returns.

    Frozen and ``extra="forbid"``. A field the vocabulary does not define is a field nobody
    validated — the lesson the move models learned when an adapter's error marker validated into a
    clean conclusion because the model ignored an unknown key.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    directive: DirectiveType
    focus: FocusDimension = FocusDimension.NONE
    rationale: Annotated[str, Field(max_length=MAX_NOTE_LENGTH)] = ""
    """Supervisor-authored text, capped here rather than wherever it lands. It reaches the lineage,
    the next briefing and — for a hosted pilot — a vendor, so it is bounded at the seam like every
    other string a model writes."""

    @model_validator(mode="after")
    def _sanitize_rationale(self) -> Self:
        # Sanitized rather than trusted, because it is model-authored text on its way into a
        # briefing. Assignment through `object.__setattr__` because the model is frozen and this
        # is the constructor's own normalisation rather than a mutation of a built object.
        object.__setattr__(self, "rationale", sanitize(self.rationale, limit=MAX_NOTE_LENGTH))
        return self


RESEARCH_DIRECTIVE_ADAPTER: TypeAdapter[ResearchDirective] = TypeAdapter(ResearchDirective)
"""Validates a supervisor's raw output. The same discipline as ``PILOT_MOVE_ADAPTER`` and
``CHALLENGER_RULING_ADAPTER``: whatever an implementation emits, only a well-formed directive in
the closed vocabulary gets past here."""


class IssuedDirective(BaseModel):
    """A directive with who issued it and when. What the trajectory records."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    directive_id: DirectiveId
    directive: ResearchDirective
    issued_by: Annotated[str, Field(max_length=200)]
    issued_at: datetime
    answered: bool = True
    """``False`` when the supervisor raised, stalled or returned something outside the vocabulary
    and the controller substituted :data:`CONTINUE`.

    Its own field rather than a directive value, for the reason
    :class:`~nemesis.pilot.challenger.ChallengeOutcome` gives: routing a *failure* back through the
    verdict vocabulary once made a configured control silently do nothing while the record said it
    had acted."""

    @model_validator(mode="after")
    def _require_utc(self) -> Self:
        require_utc(self.issued_at, "issued_at")
        return self


class TrajectoryDossier(BaseModel):
    """Everything a supervisor is shown. No handle, no move, no capability, no evidence.

    Deliberately built from the :class:`~nemesis.evolution.stagnation.StagnationAssessment` and a
    bounded summary of the recent trajectory rather than from the checkpoints themselves. A
    supervisor that received checkpoints would receive their evidence references and their
    research memory, which is more than the question needs — and minimum necessary applies to a
    reviewer exactly as it applies to a pilot.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: Annotated[str, Field(max_length=128)]
    step_index: Annotated[int, Field(ge=0)]
    assessment: StagnationAssessment
    recent_pivot_families: tuple[Annotated[str, Field(max_length=120)], ...] = ()
    open_questions: tuple[Annotated[str, Field(max_length=MAX_NOTE_LENGTH)], ...] = ()
    standing_assumptions: tuple[Annotated[str, Field(max_length=MAX_NOTE_LENGTH)], ...] = ()
    independent_origins: Annotated[int, Field(ge=0)] = 0
    origin_floor: Annotated[int, Field(ge=0)] = 0
    open_contradictions: Annotated[int, Field(ge=0)] = 0
    steps_remaining: Annotated[int, Field(ge=0)] = 0

    last_directive: Annotated[str, Field(max_length=64)] = ""
    """The directive currently in force, if any.

    Present because a supervisor that could not see it repeated itself, and the reference
    demonstration made that visible in one run: the trajectory rested on a single provenance
    cluster, the origin rule fired, and it fired again on every subsequent plateau with the same
    answer while nothing changed. A redirect that has already been tried and has already failed to
    move a tier-1 term is not a redirect — it is the plateau, restated. So the standing directive
    is part of what a supervisor is shown, and the shipped one will not re-issue it."""

    directive_steps_without_gain: Annotated[int, Field(ge=0)] = 0
    """How many steps the standing directive has been in force without moving a tier-1 term."""


@runtime_checkable
class TrajectorySupervisor(Protocol):
    """Whatever reviews a trajectory: a rule, a second model, or an attacker's puppet.

    Returns a directive or a raw mapping; either is validated at the seam by
    :func:`validate_directive`, so an implementation cannot smuggle an unvalidated object past by
    constructing one itself. The same defence the mediator applies to a pilot's move, for the same
    reason — a ``BaseModel`` subclass with an overridden method is the value-confusion shape this
    codebase has been bitten by.
    """

    @property
    def name(self) -> str: ...

    async def review(self, dossier: TrajectoryDossier) -> ResearchDirective | Mapping[str, Any]: ...


def validate_directive(raw: object) -> ResearchDirective:
    """Turn whatever a supervisor returned into a directive, or raise.

    A model instance is dumped to plain data and re-validated, never trusted as-is. In particular:
    a :class:`~nemesis.pilot.moves.PilotMove` handed back here does not validate, because no move
    carries a ``directive`` field and ``extra="forbid"`` refuses its ``kind``. That is the
    structural half of "a supervisor cannot emit a pilot move" — the other half being that nothing
    downstream would route one anywhere if it did.
    """
    data = raw.model_dump() if isinstance(raw, BaseModel) else raw
    return RESEARCH_DIRECTIVE_ADAPTER.validate_python(data)


def validation_detail(exc: ValidationError) -> str:
    """The first validation failure, in the one sentence a lineage detail has room for."""
    errors = exc.errors()
    if not errors:
        return "invalid directive"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "directive"
    return f"{location}: {first.get('msg', 'invalid')}"


def without_imperative_rationale(directive: ResearchDirective) -> ResearchDirective:
    """Drop a rationale that reads as an instruction, keeping the directive itself.

    A directive's ``rationale`` reaches the next briefing, which makes it a free-text channel from a
    supervisor into a pilot — and an adversarial review pointed out that the *same* payload arriving
    as a research hint is quarantined by
    :func:`~nemesis.evolution.memory.reads_as_an_instruction` while this one travelled verbatim. Two
    doors, one guard, is not a guard.

    So the same classifier runs here. The directive stands, because a directive is a member of a
    closed enumeration and nothing about it is text; only the prose is dropped, and it is replaced
    with a line naming which instruction shapes fired, so the trajectory records the attempt rather
    than hiding it.
    """
    shapes = reads_as_an_instruction(directive.rationale)
    if not shapes:
        return directive
    return directive.model_copy(
        update={
            "rationale": (
                "the supervisor's rationale read as an instruction "
                f"({', '.join(shapes)}) and was withheld from the briefing"
            )
        }
    )


CONTINUE_ON_FAILURE: Final = ResearchDirective(
    directive=DirectiveType.CONTINUE,
    rationale="the supervisor did not answer; the trajectory was NOT redirected",
)
"""What is recorded when a supervisor produces nothing.

``CONTINUE`` with a reason that says why, and ``answered=False`` on the
:class:`IssuedDirective` beside it. The word for "nothing needed changing" and the word for
"nothing was asked" must not be the same word in the record — the challenger's own lesson, applied
here before it can be relearned.
"""


_SIGNAL_DIRECTIVE: Final[Mapping[StagnationSignal, tuple[DirectiveType, FocusDimension]]] = {
    StagnationSignal.REPEATED_STATE: (DirectiveType.DIVERSIFY, FocusDimension.INFRASTRUCTURE),
    StagnationSignal.REPEATED_PIVOT_FAMILY: (DirectiveType.DIVERSIFY, FocusDimension.TEMPORAL),
    StagnationSignal.REDUNDANT_WORK: (DirectiveType.DIVERSIFY, FocusDimension.NONE),
    StagnationSignal.CONTRADICTIONS_UNCHANGED: (
        DirectiveType.RESOLVE_CONTRADICTION,
        FocusDimension.PROVENANCE,
    ),
    StagnationSignal.ALL_CANDIDATES_REJECTED: (
        DirectiveType.CHALLENGE_ASSUMPTION,
        FocusDimension.HOSTING,
    ),
    StagnationSignal.NO_EPISTEMIC_GAIN: (
        DirectiveType.SEEK_INDEPENDENT_ORIGIN,
        FocusDimension.CERTIFICATE,
    ),
    StagnationSignal.NO_PROMOTION: (DirectiveType.REVISIT_PRIOR_BRANCH, FocusDimension.NONE),
    StagnationSignal.BUDGET_WITHOUT_PROGRESS: (DirectiveType.STOP_LOW_YIELD, FocusDimension.NONE),
}
"""Which signal calls for which posture.

Ordered by *specificity of the remedy* rather than by severity, and the table is read in this
order: a repeated state has one obvious answer, a budget burning with nothing to show has one
obvious answer, and the vaguer signals get the vaguer responses. Every pair is a choice, stated as
data so it can be argued with, and frozen with the rest of the calibration.
"""


@dataclass(frozen=True)
class DeterministicSupervisor:
    """The shipped supervisor. A table, a clock, and no model.

    Sufficient for the plateau shapes the detector can name, and preferable to a model call for
    exactly those: the response to "you ran passive DNS four times" is not a judgement call, and
    spending a provider turn on it would add latency, cost and nondeterminism to buy nothing.
    """

    name: str = "deterministic-trajectory-supervisor"

    async def review(self, dossier: TrajectoryDossier) -> ResearchDirective:
        assessment = dossier.assessment
        if not assessment.describes_a_plateau:
            return ResearchDirective(
                directive=DirectiveType.CONTINUE,
                rationale="no plateau signal fired; the trajectory is still moving",
            )

        # A trajectory resting on a single origin is redirected toward corroboration whatever else
        # fired. Independence is the property attribution actually turns on, and a run that keeps
        # adding depth on one origin is getting more confident without getting more right.
        #
        # Once, though. If that directive is already in force and has bought nothing, repeating it
        # is the plateau restated rather than a response to it — and the honest next move is a
        # different posture, or a stop. Learned from the reference run, where this rule fired on
        # every plateau of an eight-step trajectory and said the same thing each time.
        exhausted_redirect = (
            dossier.last_directive == DirectiveType.SEEK_INDEPENDENT_ORIGIN.value
            and dossier.directive_steps_without_gain >= 2
        )
        if (
            dossier.origin_floor == 0
            and dossier.independent_origins <= 1
            and not exhausted_redirect
        ):
            return ResearchDirective(
                directive=DirectiveType.SEEK_INDEPENDENT_ORIGIN,
                focus=FocusDimension.PROVENANCE,
                rationale=(
                    "the trajectory rests on at most one independent origin and nothing survives "
                    "removing a plantable artifact; depth on one origin is not corroboration"
                ),
            )
        if dossier.steps_remaining == 0:
            return ResearchDirective(
                directive=DirectiveType.STOP_LOW_YIELD,
                rationale="no steps remain in this run's allowance",
            )

        for signal in assessment.signals:
            mapped = _SIGNAL_DIRECTIVE.get(signal)
            if mapped is None:
                continue
            directive, focus = mapped
            if (
                directive.value == dossier.last_directive
                and dossier.directive_steps_without_gain >= 2
            ):
                # Same reasoning as above, applied to the table: a posture that has been in force
                # for two steps without moving anything does not get re-issued as though it were
                # news.
                continue
            return ResearchDirective(
                directive=directive,
                focus=focus,
                rationale=f"plateau signal {signal.value!r}: " + "; ".join(assessment.reasons[:2]),
            )
        if dossier.directive_steps_without_gain >= 2:
            return ResearchDirective(
                directive=DirectiveType.STOP_LOW_YIELD,
                rationale=(
                    "every posture this supervisor can recommend is already in force and has not "
                    "moved a tier-1 term; continuing would spend budget to restate the plateau"
                ),
            )
        return ResearchDirective(
            directive=DirectiveType.CONTINUE,
            rationale="a plateau was detected and no signal maps to a redirection",
        )


def new_directive_id() -> str:
    return new_id(IdPrefix.DIRECTIVE)


__all__ = [
    "CONTINUE_ON_FAILURE",
    "RESEARCH_DIRECTIVE_ADAPTER",
    "DeterministicSupervisor",
    "DirectiveType",
    "FocusDimension",
    "IssuedDirective",
    "ResearchDirective",
    "TrajectoryDossier",
    "TrajectorySupervisor",
    "new_directive_id",
    "validate_directive",
    "validation_detail",
    "without_imperative_rationale",
]
