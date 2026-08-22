"""A second, independent model asked one question — and given no way to act on the answer.

The pilot proposes; the mediator disposes. This adds a third party that may only *object*.

**Why a second model at all.** Attribution is the domain where correlated reasoning failure is
most expensive: a model that talks itself into a shared-hosting coincidence being common control
produces a confident, well-written, wrong answer, and a second instance of the same weights
asked the same question produces the same wrong answer with the same confidence. This
repository's own rule is that model consensus is *one correlated opinion*, not independent
confirmation. So a challenger is worth having only when it comes from a different family, which
is why it is configured as its own provider and model rather than as a temperature setting.

**Why it holds no authority, structurally.** A challenger returns one of five verdicts and
nothing else. It cannot propose a move, cannot amend one, cannot substitute a different target,
and cannot decide that an effect is fine — a :data:`ChallengerVerdict.CONSISTENT` is not an
approval, it is the absence of an objection, and every control that would have refused the move
still refuses it. The worst a hijacked, hallucinating or hostile challenger achieves is a
session that refuses moves it should have allowed: an availability failure, never an
unauthorized action. That asymmetry is the whole design, and it is the reason the challenger's
vocabulary is closed for exactly the reason the pilot's is.

**Why a broken challenger does not stop the platform.** If it raises, times out or returns
something outside the vocabulary, the default is to let the move through *and record loudly that
nothing challenged it* (:data:`ChallengerFailureMode.PROCEED_AND_RECORD`). The reasoning is worth
stating because the opposite reads as the safer default: without a challenger the platform is at
its baseline posture, which is the posture every containment test in this repository is written
against and the one the security argument actually rests on. Failing closed would instead make an
advisory control a single point of failure — and hand anyone who can degrade the challenger's
provider a way to stop an investigation. A deployment that would rather stop than proceed
unchallenged sets :data:`ChallengerFailureMode.REFUSE`, and that is a choice it makes knowingly.

The challenger is optional everywhere. Constructed without one, the mediator behaves exactly as
it did before this module existed, which is what every existing containment test asserts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from nemesis.pilot.moves import Briefing, PilotMove


class ChallengerVerdict(StrEnum):
    """The whole of what a challenger may say.

    Five values, and deliberately no ``APPROVED``, no ``ESCALATE_TO_HUMAN``, no
    ``PROCEED_ANYWAY``. Each of those would be authority: the first turns silence into
    endorsement, the second lets a model summon a human, the third lets it overrule a control.
    A challenger objects or it does not.
    """

    CONSISTENT = "consistent"
    """No objection. Not an endorsement and not an approval — every control that would have
    refused this move still refuses it."""

    CONTRADICTED = "contradicted"
    """Something the investigation surfaced contradicts what the move asserts or assumes."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    """The move may be right and nothing seen so far supports it. The commonest honest verdict
    in attribution work, and the one a confident model is least likely to reach on its own."""

    PROVENANCE_PROBLEM = "provenance_problem"
    """The move rests on something whose derivation does not hold up: a belief cited as though
    it were evidence, a claim whose support is a single origin wearing several hats."""

    POSSIBLE_INJECTION = "possible_injection"
    """The move looks like the pilot following an instruction found in collected content rather
    than a conclusion drawn from it.

    A verdict rather than a control. What actually stops an injection is the envelope, the
    target binding and the closed vocabulary; a challenger noticing is a cheap extra look, and
    a challenger *not* noticing changes nothing about what the platform permits."""


BLOCKING_VERDICTS: Final[frozenset[ChallengerVerdict]] = frozenset(
    {
        ChallengerVerdict.CONTRADICTED,
        ChallengerVerdict.PROVENANCE_PROBLEM,
        ChallengerVerdict.POSSIBLE_INJECTION,
    }
)
"""Verdicts that refuse the move by default.

``INSUFFICIENT_EVIDENCE`` is deliberately not among them. It is the correct verdict on most
honest investigative moves — a pivot exists precisely because the evidence is insufficient — and
blocking on it would produce a challenger that refuses the investigation rather than the
overreach. It is recorded, and a deployment that wants it blocking says so.
"""


class ChallengerFailureMode(StrEnum):
    """What to do when the challenger itself does not answer."""

    PROCEED_AND_RECORD = "proceed_and_record"
    """Let the move through, and record that nothing challenged it. Returns the session to the
    baseline posture the containment tests are written against."""

    REFUSE = "refuse"
    """Refuse the move. A deployment that would rather stop than proceed unchallenged."""


class ChallengerRuling(BaseModel):
    """A verdict with its reason. The only thing a challenger returns."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: ChallengerVerdict
    reason: str = Field(default="", max_length=1000)
    """Challenger-authored text, capped here rather than wherever it lands. It reaches the
    ruling and therefore the audit trail, and — for a hosted pilot — the next briefing, so it is
    bounded at the seam like every other string a model writes."""


CHALLENGER_RULING_ADAPTER: TypeAdapter[ChallengerRuling] = TypeAdapter(ChallengerRuling)
"""Validates a challenger's raw output. The same discipline as ``PILOT_MOVE_ADAPTER``: whatever
a model emits, only a well-formed verdict in the closed vocabulary gets past here."""


@runtime_checkable
class MoveChallenger(Protocol):
    """Whatever reviews a proposed move: a second model, a rule, or an attacker's puppet.

    Receives the same briefing the pilot received and the move the pilot proposed — no graph
    handle, no capability, no key, and nothing the pilot did not already have. Returns a ruling
    or a raw mapping; either is validated at the seam, so a challenger cannot smuggle an
    unvalidated object past by constructing one itself.
    """

    @property
    def name(self) -> str: ...

    async def review(
        self, briefing: Briefing, move: PilotMove
    ) -> ChallengerRuling | Mapping[str, Any]: ...


@dataclass(frozen=True)
class ChallengePolicy:
    """Which moves a verdict may block, and what a silent challenger means."""

    gated_kinds: frozenset[str] = frozenset({"request_effect", "record_belief"})
    """Effects are the consequential move; beliefs are where a false attribution enters the
    graph. Pivots and conclusions are reviewed and never blocked — a challenger that can stop an
    investigation from *looking* is a denial-of-service surface with no matching safety gain."""

    blocking: frozenset[ChallengerVerdict] = BLOCKING_VERDICTS
    on_failure: ChallengerFailureMode = ChallengerFailureMode.PROCEED_AND_RECORD
    timeout_seconds: float = 60.0

    def blocks(self, move_kind: str, verdict: ChallengerVerdict) -> bool:
        return move_kind in self.gated_kinds and verdict in self.blocking


def validate_ruling(raw: object) -> ChallengerRuling:
    """Turn whatever the challenger returned into a ruling, or raise.

    A model instance is dumped to plain data and re-validated, never trusted as-is — the same
    value-confusion defence the mediator applies to a pilot's move, for the same reason.
    """
    data = raw.model_dump() if isinstance(raw, BaseModel) else raw
    return CHALLENGER_RULING_ADAPTER.validate_python(data)


def failure_ruling(detail: str) -> ChallengerRuling:
    """What is recorded when the challenger did not answer.

    ``CONSISTENT`` with a reason that says why, so a transcript never shows an unchallenged move
    as a challenged one. The word for "nothing objected" and the word for "nothing was asked"
    must not be the same word in the record.
    """
    return ChallengerRuling(verdict=ChallengerVerdict.CONSISTENT, reason=detail[:1000])


class ChallengerError(RuntimeError):
    """The challenger did not produce a verdict. Contained by the policy, never raised past it."""


def validation_detail(exc: ValidationError) -> str:
    """The first validation failure, in the one sentence a ruling reason has room for."""
    errors = exc.errors()
    if not errors:
        return "invalid verdict"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "verdict"
    return f"{location}: {first.get('msg', 'invalid')}"


__all__ = [
    "BLOCKING_VERDICTS",
    "CHALLENGER_RULING_ADAPTER",
    "ChallengePolicy",
    "ChallengerError",
    "ChallengerFailureMode",
    "ChallengerRuling",
    "ChallengerVerdict",
    "MoveChallenger",
    "failure_ruling",
    "validate_ruling",
    "validation_detail",
]
