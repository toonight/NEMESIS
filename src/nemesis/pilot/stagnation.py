"""Is this session still going anywhere? Answered deterministically, inside one session.

:mod:`nemesis.evolution.stagnation` already answers a version of this question, and this module
is not a second copy of it. They look at different things on different clocks:

- The Evolution detector reads a *trajectory* — many bounded sessions over one investigation,
  scored by an evaluator, measured in promotions and tier-1 epistemic movement. It fires after
  four checkpoints, and its answer is a change of research posture.
- This detector reads *one session's transcript* — the moves a pilot proposed and the rulings it
  got — and its answer is that the session should end. It cannot import the Evolution plane
  (`pilot-does-not-know-about-evolution`, and rightly: a limiter with a branch for "when the
  research loop is driving" is a limiter with an off switch), and it must work in the ordinary
  case where no research loop exists at all.

**Why a session needs its own.** The move ceiling already bounds a runaway pilot, and bounding is
not the same as stopping well. A pilot that spends its last thirty moves re-proposing a refused
effect burns the ceiling, produces a transcript that says "halted", and tells nobody *why* — while
the interesting fact, that it stopped learning at move nine, is sitting in plain sight in the
rulings. The OpenAI Hugging Face incident is the general case: an agent given an impossible task
keeps looking for another route, and the routes it finds late are the ones nobody modelled.

**The response is always to stop, never to widen.** There is no signal here whose handling is
"try somewhere else", because the vocabulary the mediator would need for that does not exist and
must not: scope comes from the seed and the envelope, and a stuck pilot is precisely the party
that must not be able to change either (SAFEFAIL-02). Every signal maps to a
:class:`~nemesis.pilot.moves.ConclusionOutcome` in the safe-failure set, and the mediator ends the
session with it.

**Deterministic, and cheap enough to run every turn.** No model is consulted, nothing is scored,
and the whole assessment is a fold over a list of small frozen records. A nondeterministic
judgement on the hot path of a loop whose value is that it reconstructs exactly would be the
wrong trade twice over.

Every threshold is a named field on :class:`SessionStagnationPolicy` with the reason it is where
it is. None of them is measured; like every constant here they are choices, frozen so they can be
argued with.

Status: `IMPLEMENTED`. Thresholds `PROPOSED` as calibration — nothing has validated them.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from nemesis.pilot.moves import ConclusionOutcome, RulingStatus


@dataclass(frozen=True)
class SessionStep:
    """One turn, reduced to what the detector needs.

    Deliberately not the :class:`~nemesis.pilot.mediator.TurnRecord`: a detector that read those
    would import the mediator that imports it, and would also have to know how a transcript is
    built. The mediator projects into this instead, which keeps the dependency one-way and makes
    the detector testable from a list of literals.

    ``move_digest`` is a stable rendering of the move's arguments — the mediator builds it from
    the validated model, never from the pilot's raw output, so two moves that *are* the same
    compare equal however the vendor spelled them.
    """

    move_kind: str
    move_digest: str
    status: RulingStatus
    entities_discovered: int = 0
    evidence_sealed: int = 0

    @property
    def was_productive(self) -> bool:
        """Whether this turn added anything to the investigation.

        A pivot that ran and returned nothing is *accepted* — the pilot asked a fair question and
        the world had no answer — and it is not productive. Keeping those two apart is the whole
        point: an accepted-but-barren pivot is the exact shape of a session going nowhere, and a
        detector that counted acceptances would call it healthy.
        """
        return self.entities_discovered > 0 or self.evidence_sealed > 0


class SessionStagnationSignal(StrEnum):
    """Why this session looks stuck. Several may fire at once, and all are reported."""

    BARREN_PIVOTS = "barren_pivots"
    """Consecutive pivots that ran and surfaced neither an entity nor a piece of evidence."""

    REPEATED_MOVE = "repeated_move"
    """The identical move, arguments and all, proposed again and again. The clearest signal
    here, because it cannot be explained by an unlucky question."""

    REPEATED_REFUSAL = "repeated_refusal"
    """The same refusal, over and over. A pilot arguing with a control that will not move."""

    EFFECT_REFUSALS_REPEATED = "effect_refusals_repeated"
    """Repeated effect requests the envelope will not authorize. Called out separately from
    ``REPEATED_REFUSAL`` because its honest ending is different: this run needs a human to
    decide something, not a different pivot."""

    NO_PRODUCTIVE_TURN = "no_productive_turn"
    """A full window in which nothing at all was added to the investigation."""


_OUTCOME_BY_SIGNAL: Final[dict[SessionStagnationSignal, ConclusionOutcome]] = {
    # Ordered by how specific the ending is, and read in this order by `assess`. A run that is
    # both barren and blocked on authorization should end saying it needs a decision, because
    # that is the actionable half.
    SessionStagnationSignal.EFFECT_REFUSALS_REPEATED: ConclusionOutcome.AUTHORIZATION_REQUIRED,
    SessionStagnationSignal.REPEATED_MOVE: ConclusionOutcome.NO_SAFE_NEXT_PIVOT,
    SessionStagnationSignal.REPEATED_REFUSAL: ConclusionOutcome.NO_SAFE_NEXT_PIVOT,
    SessionStagnationSignal.BARREN_PIVOTS: ConclusionOutcome.INSUFFICIENT_EVIDENCE,
    SessionStagnationSignal.NO_PRODUCTIVE_TURN: ConclusionOutcome.INSUFFICIENT_EVIDENCE,
}
"""Which honest ending each signal implies.

A fixed table rather than a judgement, for the reason
:data:`~nemesis.evolution.supervisor._SIGNAL_DIRECTIVE` gives: the mapping from a measurement to a
response is the part an operator most needs to be able to read and disagree with, and burying it
in branching code is how it stops being reviewable. Every value is in
:data:`~nemesis.pilot.moves.SAFE_FAILURE_OUTCOMES`, and a test asserts that rather than trusting
it — a table that could map a stall to ``ATTRIBUTION_REACHED`` would turn giving up into a
finding.
"""


@dataclass(frozen=True)
class SessionStagnationPolicy:
    """Thresholds, each with the reason it is where it is.

    A frozen dataclass, matching :class:`~nemesis.pilot.challenger.ChallengePolicy` and
    :class:`~nemesis.evolution.stagnation.StagnationPolicy`, because it is configuration a
    deployment sets once.
    """

    window: int = 6
    """How many recent turns count as "recently".

    Six, against the Evolution detector's four, because a turn here is one *move* and a step
    there is a whole bounded session. Six moves is long enough that an ordinary sequence —
    pivot, pivot, record a belief, pivot — is not mistaken for a stall, and short enough to fire
    well inside the default forty-move ceiling rather than beside it.
    """

    max_barren_pivots: int = 4
    """Consecutive pivots returning nothing before that is itself the finding. Four, because
    three empty answers is an ordinary run of bad luck on a thin investigation and the fourth is
    a pattern."""

    max_repeated_move: int = 3
    """How many times one identical move may be proposed. Three: twice is a retry, and this
    platform already treats a third identical malformed answer as the end of a session."""

    max_repeated_refusal: int = 4
    """How many consecutive refusals with the same status before the session is arguing rather
    than investigating. One higher than the identical-move threshold on purpose — refusals of the
    same *class* for different reasons are a pilot exploring the edges, which is legitimate for
    slightly longer than a pilot repeating itself."""

    max_refused_effects: int = 3
    """How many refused effect requests make "this needs a human" the honest ending. Not
    consecutive: an envelope that has refused three separate requests has said what it is going
    to say, however the pilot spaced them."""

    min_signals: int = 1
    """How many signals make a stall. One, because every signal above is already conservative and
    requiring two would mean firing only once a run is thoroughly stuck — which is where a safe
    ending is worth least."""

    halt_on_stall: bool = True
    """Whether a detected stall ends the session, as opposed to merely being recorded.

    **Detection is never configurable; only stopping is.** A flag that switched the detector off
    would be a control with an off switch, and this repository's own history says what those are
    worth. So a deployment or a harness that sets this to ``False`` still gets every assessment,
    on the session object and in the audit close, and still cannot suppress the finding — it only
    declines to act on it.

    The case for ``False`` is narrow and real: a *measurement* harness deliberately drives a
    pathological pilot to characterise the limiter. `standing_session` requests every operation
    against every target to demonstrate the role gate; `loopbench` walks a conjuring pilot for
    forty-eight moves to measure what refusals cost. Both look exactly like a stall, because in
    production they would be one — and stopping them at move six would measure the detector
    instead of the thing under test. Each sets this explicitly, in source, with its reason.

    Production leaves it ``True``. A test asserts the default, so making the production path inert
    requires editing that assertion rather than a constructor call nobody reads.
    """

    def __post_init__(self) -> None:
        if self.window < 2:
            raise ValueError("a stagnation window shorter than two turns measures nothing")
        for name in (
            "max_barren_pivots",
            "max_repeated_move",
            "max_repeated_refusal",
            "max_refused_effects",
            "min_signals",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1; a threshold of 0 fires on turn one")


@dataclass(frozen=True)
class SessionStagnation:
    """What the detector found, with the numbers it found it from and the ending it implies."""

    stagnant: bool
    turns_examined: int
    signals: tuple[SessionStagnationSignal, ...] = ()
    reasons: tuple[str, ...] = ()
    outcome: ConclusionOutcome = ConclusionOutcome.UNSPECIFIED
    """The safe ending this stall implies, or ``UNSPECIFIED`` when nothing stalled.

    Always a member of :data:`~nemesis.pilot.moves.SAFE_FAILURE_OUTCOMES` when ``stagnant`` is
    true. A stall never produces ``ATTRIBUTION_REACHED``, and never produces anything that asks
    for more room.
    """

    def describe(self) -> str:
        if not self.stagnant:
            return f"no stall over {self.turns_examined} turn(s)"
        return (
            f"stalled after {self.turns_examined} turn(s): "
            + "; ".join(self.reasons)
            + f" — ending as {self.outcome.value}"
        )


class SessionStagnationDetector:
    """Deterministic stall detection over one session's transcript."""

    def __init__(self, policy: SessionStagnationPolicy | None = None) -> None:
        self._policy = policy or SessionStagnationPolicy()

    @property
    def policy(self) -> SessionStagnationPolicy:
        return self._policy

    def assess(self, steps: Sequence[SessionStep]) -> SessionStagnation:
        """Look at the session so far and say whether it is going anywhere.

        Returns ``stagnant=False`` before the window is full, for the reason the Evolution
        detector does: a detector that fired on turn two of every run would make its own verdict
        worthless, and a session has to be allowed to open.

        Note which counters are over the *window* and which are over the *whole session*.
        Barren pivots, repeated moves and repeated refusals are runs — they mean something only
        when consecutive, and a window is how "consecutive" is bounded. Refused effects are
        cumulative, because an envelope's refusal does not become less final by being spaced out.
        """
        policy = self._policy
        if len(steps) < policy.window:
            return SessionStagnation(stagnant=False, turns_examined=len(steps))

        recent = tuple(steps[-policy.window :])
        signals: list[SessionStagnationSignal] = []
        reasons: list[str] = []

        barren = _trailing_run(
            recent, lambda step: step.move_kind == "run_pivot" and not step.was_productive
        )
        if barren >= policy.max_barren_pivots:
            signals.append(SessionStagnationSignal.BARREN_PIVOTS)
            reasons.append(f"{barren} consecutive pivots surfaced no entity and sealed no evidence")

        repeated = _trailing_identical(recent)
        if repeated >= policy.max_repeated_move:
            signals.append(SessionStagnationSignal.REPEATED_MOVE)
            reasons.append(f"the same move was proposed {repeated} times in a row")

        refusal_run, refusal_status = _trailing_same_refusal(recent)
        if refusal_run >= policy.max_repeated_refusal and refusal_status is not None:
            signals.append(SessionStagnationSignal.REPEATED_REFUSAL)
            reasons.append(
                f"{refusal_run} consecutive moves were refused as {refusal_status.value}"
            )

        refused_effects = sum(
            1
            for step in steps
            if step.move_kind == "request_effect" and step.status is not RulingStatus.ACCEPTED
        )
        if refused_effects >= policy.max_refused_effects:
            signals.append(SessionStagnationSignal.EFFECT_REFUSALS_REPEATED)
            reasons.append(
                f"{refused_effects} effect request(s) were refused; the envelope has said what "
                "it is going to say and the next step belongs to a human"
            )

        if not any(step.was_productive for step in recent):
            signals.append(SessionStagnationSignal.NO_PRODUCTIVE_TURN)
            reasons.append(
                f"nothing was added to the investigation in the last {policy.window} turns"
            )

        unique = tuple(dict.fromkeys(signals))
        stagnant = len(unique) >= policy.min_signals
        return SessionStagnation(
            stagnant=stagnant,
            turns_examined=len(steps),
            signals=unique,
            reasons=tuple(reasons),
            outcome=_outcome_for(unique) if stagnant else ConclusionOutcome.UNSPECIFIED,
        )


def _outcome_for(signals: Sequence[SessionStagnationSignal]) -> ConclusionOutcome:
    """The most specific honest ending among the signals that fired.

    Iterates :data:`_OUTCOME_BY_SIGNAL` in declaration order rather than the signals in theirs,
    so the answer does not depend on which check happened to run first — an ordering dependence
    in a security-adjacent decision being the defect the anchor registry was rewritten to remove.
    """
    fired = set(signals)
    for signal, outcome in _OUTCOME_BY_SIGNAL.items():
        if signal in fired:
            return outcome
    return ConclusionOutcome.NO_SAFE_NEXT_PIVOT


def _trailing_run(steps: Sequence[SessionStep], predicate: Callable[[SessionStep], bool]) -> int:
    """How many steps at the end of the sequence satisfy ``predicate``, counting backwards."""
    count = 0
    for step in reversed(steps):
        if not predicate(step):
            break
        count += 1
    return count


def _trailing_identical(steps: Sequence[SessionStep]) -> int:
    """How many identical moves sit at the end of the sequence."""
    if not steps:
        return 0
    last = (steps[-1].move_kind, steps[-1].move_digest)
    return _trailing_run(steps, lambda step: (step.move_kind, step.move_digest) == last)


def _trailing_same_refusal(
    steps: Sequence[SessionStep],
) -> tuple[int, RulingStatus | None]:
    """How many consecutive refusals of one status sit at the end, and which status."""
    if not steps or steps[-1].status is RulingStatus.ACCEPTED:
        return 0, None
    status = steps[-1].status
    return _trailing_run(steps, lambda step: step.status is status), status


__all__ = [
    "SessionStagnation",
    "SessionStagnationDetector",
    "SessionStagnationPolicy",
    "SessionStagnationSignal",
    "SessionStep",
]
