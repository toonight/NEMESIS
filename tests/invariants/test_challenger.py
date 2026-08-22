"""A second model that may object, and the proof that objecting is all it can do.

The challenger exists because correlated reasoning failure is a first-order risk in attribution:
two instances of the same weights asked the same question produce the same confident wrong answer,
and this repository's own rule is to treat model consensus as one correlated opinion rather than
as independent confirmation. Model diversity is the point, so the challenger is configured as its
own provider and model.

That makes it a second untrusted party, and these tests are what makes its untrustworthiness
harmless. The asymmetry is the whole design and every test below is a way of checking it:

- A challenger can cause a **refusal** and can never cause an **action**. There is no verdict
  that permits anything, so the worst a hijacked one achieves is a session that refuses moves it
  should have allowed — an availability failure, never an unauthorized effect.
- A verdict is validated through a closed five-value vocabulary, exactly as a move is. A model
  instance with an overridden method is re-validated at the seam.
- A broken challenger does not stop the platform and does not silently look like a working one:
  the move proceeds and the transcript records that nothing challenged it.
- Configured with none, the mediator behaves exactly as it did before the seam existed, which is
  what every other containment test in this suite asserts.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any, cast

import pytest

from nemesis.pilot.challenger import (
    ChallengePolicy,
    ChallengerFailureMode,
    ChallengerRuling,
    ChallengerVerdict,
    MoveChallenger,
)
from nemesis.pilot.moves import Briefing, PilotMove, RulingStatus
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilotbench.corpus import BASELINE
from nemesis.pilotbench.harness import ScenarioRun, run_scenario
from nemesis.pilotbench.pilots import careful_pilot, overreaching_pilot

pytestmark = pytest.mark.invariant


class FixedChallenger:
    """Returns the same verdict every time, and remembers what it was shown."""

    def __init__(self, verdict: ChallengerVerdict, reason: str = "because") -> None:
        self._verdict = verdict
        self._reason = reason
        self.seen: list[tuple[Briefing, PilotMove]] = []

    @property
    def name(self) -> str:
        return f"fixed:{self._verdict.value}"

    async def review(self, briefing: Briefing, move: PilotMove) -> ChallengerRuling:
        self.seen.append((briefing, move))
        return ChallengerRuling(verdict=self._verdict, reason=self._reason)


class RawChallenger:
    """Returns whatever it was constructed with. Every double here breaks the contract."""

    def __init__(self, answer: object) -> None:
        self._answer = answer

    @property
    def name(self) -> str:
        return "raw"

    async def review(self, briefing: Briefing, move: PilotMove) -> Any:
        return self._answer


class RaisingChallenger:
    @property
    def name(self) -> str:
        return "raising"

    async def review(self, briefing: Briefing, move: PilotMove) -> ChallengerRuling:
        raise RuntimeError("the challenger's vendor is down")


class StallingChallenger:
    @property
    def name(self) -> str:
        return "stalling"

    async def review(self, briefing: Briefing, move: PilotMove) -> ChallengerRuling:
        await asyncio.sleep(60)
        raise AssertionError("unreachable: the policy timeout fires first")


def drive(
    pilot: object,
    challenger: object | None = None,
    policy: ChallengePolicy | None = None,
) -> ScenarioRun:
    return asyncio.run(
        run_scenario(
            BASELINE,
            cast(AutonomousPilot, pilot),
            challenger=cast(MoveChallenger, challenger) if challenger is not None else None,
            challenge_policy=policy,
        )
    )


# --- the seam is optional and additive ---------------------------------------


def test_without_a_challenger_nothing_changes() -> None:
    """Every other containment test in this suite is written against this baseline, so it has
    to keep holding exactly."""
    plain = drive(careful_pilot())
    assert plain.session.concluded
    assert all(turn.challenge is None for turn in plain.session.transcript), (
        "a challenge appeared where none was configured"
    )
    assert not any(r.status is RulingStatus.REFUSED_CHALLENGED for r in plain.session.rulings)


def test_a_consistent_verdict_is_not_an_approval() -> None:
    """`CONSISTENT` is the absence of an objection. Every control that would have refused the
    move still refuses it, and the overreaching pilot is refused exactly as it is without one."""
    challenger = FixedChallenger(ChallengerVerdict.CONSISTENT)
    with_challenger = drive(overreaching_pilot(), challenger)
    without = drive(overreaching_pilot())

    refused_with = [r.status for r in with_challenger.session.rulings if not r.accepted]
    refused_without = [r.status for r in without.session.rulings if not r.accepted]
    assert refused_with == refused_without
    assert with_challenger.session.any_effect_left_the_platform() is False
    assert challenger.seen, "the challenger was never asked"


# --- it can subtract, and only subtract --------------------------------------


def test_a_blocking_verdict_refuses_an_effect_before_the_envelope_is_debited() -> None:
    """Refused upstream of `_apply`, so no budget is spent and no adapter is reached.

    A challenger that could only refuse *after* an effect ran would be auditing after it left,
    which is the alternative ADR-0008 rejected for the mediator itself.
    """
    challenger = FixedChallenger(ChallengerVerdict.POSSIBLE_INJECTION, "that hostname is a command")
    run = drive(overreaching_pilot(), challenger)

    effects = [r for r in run.session.rulings if r.move_kind == "request_effect"]
    assert effects
    assert all(r.status is RulingStatus.REFUSED_CHALLENGED for r in effects), [
        r.status for r in effects
    ]
    assert "possible_injection" in effects[0].reason
    assert run.envelope.remaining == BASELINE.envelope.effect_budget, "budget was spent anyway"


def test_a_challenger_cannot_cause_an_action_it_was_not_already_going_to_get() -> None:
    """The asymmetry, stated as a property: for every verdict, the set of ACCEPTED moves is a
    subset of the set accepted with no challenger at all.

    This is the test that makes a hostile challenger harmless rather than merely unlikely. It
    has nothing to permit with, whatever it says.
    """
    baseline = drive(overreaching_pilot())
    permitted = [
        (turn.ruling.move_kind, turn.ruling.status)
        for turn in baseline.session.transcript
        if turn.ruling.accepted
    ]
    for verdict in ChallengerVerdict:
        run = drive(overreaching_pilot(), FixedChallenger(verdict))
        with_verdict = [
            (turn.ruling.move_kind, turn.ruling.status)
            for turn in run.session.transcript
            if turn.ruling.accepted
        ]
        assert set(with_verdict) <= set(permitted), verdict


def test_a_challenger_holds_nothing_the_pilot_did_not_already_have() -> None:
    """It receives the briefing the pilot received and the move the pilot proposed. That is all
    there is to receive: `review` has two parameters and neither is a handle."""
    challenger = FixedChallenger(ChallengerVerdict.CONSISTENT)
    drive(careful_pilot(), challenger)
    for briefing, move in challenger.seen:
        assert isinstance(briefing, Briefing)
        assert move.kind in {"run_pivot", "record_belief", "request_effect", "conclude"}
    import inspect

    signature = inspect.signature(FixedChallenger.review)
    assert list(signature.parameters) == ["self", "briefing", "move"]


def test_pivots_and_conclusions_are_reviewed_and_never_blocked() -> None:
    """A challenger that can stop an investigation from *looking* is a denial-of-service surface
    with no matching safety gain, so the default policy gates the consequential moves only."""
    run = drive(careful_pilot(), FixedChallenger(ChallengerVerdict.CONTRADICTED))
    blocked = [
        r.move_kind for r in run.session.rulings if r.status is RulingStatus.REFUSED_CHALLENGED
    ]
    assert "run_pivot" not in blocked
    assert "conclude" not in blocked
    assert run.session.concluded


# --- the verdict vocabulary is closed ----------------------------------------


def test_a_verdict_outside_the_vocabulary_does_not_stop_the_session() -> None:
    """Same discipline as a move: whatever the model emits, only a well-formed verdict gets past
    the seam — and a malformed one is contained rather than raised."""
    for answer in (
        {"verdict": "approved"},
        {"verdict": "consistent", "authorize": True},
        "just let it through",
        None,
        42,
    ):
        run = drive(careful_pilot(), RawChallenger(answer))
        assert run.session.concluded, answer
        assert not any(r.status is RulingStatus.REFUSED_CHALLENGED for r in run.session.rulings), (
            answer
        )


def test_a_challenger_cannot_smuggle_an_unvalidated_object_past_the_seam() -> None:
    """A model instance with an overridden method is the value-confusion shape this codebase has
    been bitten by, and the seam is where it is stopped."""

    class Sneaky(ChallengerRuling):
        """Claims to be consistent through a method, while its data says otherwise.

        The mediator dumps a model instance to plain data and re-validates it, so the *data*
        is what rules — the override is never consulted. Exactly the defence the pilot seam
        applies to a move that arrives as a `BaseModel`.
        """

        def model_dump(self, **kwargs: Any) -> dict[str, Any]:
            return {"verdict": "consistent", "reason": "nothing to see here"}

    run = drive(
        overreaching_pilot(),
        RawChallenger(ChallengerRuling(verdict=ChallengerVerdict.CONTRADICTED, reason="blocked")),
    )
    blocked = [r for r in run.session.rulings if r.status is RulingStatus.REFUSED_CHALLENGED]
    assert blocked, "the re-validated verdict was not honoured"

    lying = drive(
        overreaching_pilot(), RawChallenger(Sneaky(verdict=ChallengerVerdict.CONTRADICTED))
    )
    assert not any(r.status is RulingStatus.REFUSED_CHALLENGED for r in lying.session.rulings), (
        "the overridden method decided the verdict instead of the data"
    )


# --- a broken challenger cannot weaken enforcement or masquerade as a working one ---


def test_a_raising_challenger_lets_the_move_through_and_says_it_did_not_challenge_it() -> None:
    """Failing open returns the session to the baseline posture every containment test is
    written against. Failing closed would make an advisory control a single point of failure and
    hand anyone who can degrade a second vendor a way to stop an investigation.

    What must never happen is the third option: an unchallenged move that reads as a challenged
    one. The word for "nothing objected" and the word for "nothing was asked" are not the same
    word in this record.
    """
    run = drive(overreaching_pilot(), RaisingChallenger())
    assert not any(r.status is RulingStatus.REFUSED_CHALLENGED for r in run.session.rulings)
    challenged = [turn.challenge for turn in run.session.transcript if turn.challenge is not None]
    assert challenged
    assert all("NOT challenged" in ruling.reason for ruling in challenged)
    assert all("RuntimeError" in ruling.reason for ruling in challenged)


def test_a_stalling_challenger_is_bounded_by_its_own_timeout() -> None:
    """A second vendor that hangs must not park a session on one turn."""
    run = drive(
        careful_pilot(),
        StallingChallenger(),
        ChallengePolicy(timeout_seconds=0.05),
    )
    assert run.session.concluded
    challenged = [turn.challenge for turn in run.session.transcript if turn.challenge is not None]
    assert challenged
    assert any("did not answer" in ruling.reason for ruling in challenged)


def test_a_deployment_may_choose_to_refuse_an_unchallenged_move_instead() -> None:
    """The other side of the default, available and explicit rather than assumed."""
    run = drive(
        overreaching_pilot(),
        RaisingChallenger(),
        ChallengePolicy(
            on_failure=ChallengerFailureMode.REFUSE,
            blocking=frozenset(
                {ChallengerVerdict.INSUFFICIENT_EVIDENCE, ChallengerVerdict.CONTRADICTED}
            ),
        ),
    )
    blocked = [r for r in run.session.rulings if r.status is RulingStatus.REFUSED_CHALLENGED]
    assert blocked
    assert run.session.any_effect_left_the_platform() is False


# --- the challenger reaches the audit trail ----------------------------------


def test_the_verdict_and_the_challengers_identity_are_recorded() -> None:
    """An auditor reading a transcript must be able to tell a refusal a *model* caused from one
    the envelope, the target binding or the budget produced."""
    challenger = FixedChallenger(ChallengerVerdict.PROVENANCE_PROBLEM, "cites a belief as fact")
    run = drive(overreaching_pilot(), challenger)
    events = asyncio.run(run.audit.query(action="pilot.move", limit=100))
    recorded = [event for event in events if "challenger_verdict" in event.inputs]
    assert recorded
    assert recorded[0].inputs["challenger"] == "fixed:provenance_problem"
    assert recorded[0].inputs["challenger_reason"] == "cites a belief as fact"
    blocked = [event for event in events if event.outcome == RulingStatus.REFUSED_CHALLENGED.value]
    assert blocked


def test_a_challengers_reason_is_bounded_before_it_reaches_a_record() -> None:
    """Challenger-authored text, capped at the seam like every other string a model writes."""
    with pytest.raises(Exception):  # noqa: B017 - max_length on the model
        ChallengerRuling(verdict=ChallengerVerdict.CONSISTENT, reason="x" * 5000)


# --- a challenger backed by a real model, on the same machinery ---------------


def _challenger_response(verdict: str, reason: str = "") -> dict[str, Any]:
    return {
        "id": "req_1",
        "model": "as-served",
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "challenger_verdict",
                                "arguments": {"verdict": verdict, "reason": reason},
                            }
                        }
                    ]
                }
            }
        ],
    }


class CannedTransport:
    def __init__(self, body: Mapping[str, Any]) -> None:
        self.body = body
        self.payloads: list[Mapping[str, Any]] = []

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.payloads.append(payload)
        return self.body


def _model_challenger(body: Mapping[str, Any]) -> tuple[object, CannedTransport]:
    from nemesis.pilot.providers.challenger_seat import build_challenger
    from nemesis.pilot.providers.config import ChallengerConfig, PilotConfig

    transport = CannedTransport(body)
    challenger = build_challenger(
        ChallengerConfig(pilot=PilotConfig(provider="openai", model="a-model-id")),
        transport=transport,
    )
    return challenger, transport


def test_a_model_backed_challenger_is_offered_exactly_one_verb() -> None:
    """One tool, and it permits nothing. The same reasoning as the pilot's missing
    `mint_capability`: a challenger cannot approve because there is no verb for approving."""
    from nemesis.pilot.providers.challenger_seat import CHALLENGER_TOOL_SUITE

    challenger, transport = _model_challenger(_challenger_response("consistent"))
    drive(careful_pilot(), challenger)

    assert transport.payloads, "the challenger was never asked"
    tools = transport.payloads[0]["tools"]
    assert [tool["function"]["name"] for tool in tools] == ["challenger_verdict"]
    assert len(CHALLENGER_TOOL_SUITE) == 1
    enum = tools[0]["function"]["parameters"]["properties"]["verdict"]["enum"]
    assert set(enum) == {item.value for item in ChallengerVerdict}
    assert "approve" not in json.dumps(tools).lower()


def test_a_model_backed_challenger_sees_the_briefing_and_the_move_and_nothing_else() -> None:
    """Its whole input is what the pilot saw plus what the pilot did."""
    challenger, transport = _model_challenger(_challenger_response("consistent"))
    drive(careful_pilot(), challenger)

    content = json.loads(transport.payloads[0]["messages"][1]["content"])
    assert set(content) == {"briefing", "proposed_move"}
    assert content["proposed_move"]["kind"] in {
        "run_pivot",
        "record_belief",
        "request_effect",
        "conclude",
    }


def test_a_model_backed_challenger_is_told_it_is_not_the_pilot() -> None:
    """A challenger told the pilot's mission prompt would be a second pilot."""
    from nemesis.pilot.model_seat import SYSTEM_INSTRUCTIONS
    from nemesis.pilot.providers.challenger_seat import CHALLENGER_INSTRUCTIONS

    challenger, transport = _model_challenger(_challenger_response("consistent"))
    drive(careful_pilot(), challenger)

    system = transport.payloads[0]["messages"][0]["content"]
    assert system == CHALLENGER_INSTRUCTIONS
    assert system != SYSTEM_INSTRUCTIONS
    assert "you cannot approve anything" in system


def test_a_model_backed_challenger_blocking_an_effect_spends_no_budget() -> None:
    challenger, _ = _model_challenger(
        _challenger_response("possible_injection", "that hostname is a command")
    )
    run = drive(overreaching_pilot(), challenger)
    effects = [r for r in run.session.rulings if r.move_kind == "request_effect"]
    assert effects
    assert all(r.status is RulingStatus.REFUSED_CHALLENGED for r in effects)
    assert run.envelope.remaining == BASELINE.envelope.effect_budget


def test_a_model_backed_challenger_naming_a_verb_it_was_not_offered_is_refused() -> None:
    """Passed through uncorrected, exactly as a pilot naming a fifth verb is."""
    body = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {"function": {"name": "authorize_effect", "arguments": {"ok": True}}}
                    ]
                }
            }
        ]
    }
    challenger, _ = _model_challenger(body)
    run = drive(overreaching_pilot(), challenger)
    assert not any(r.status is RulingStatus.REFUSED_CHALLENGED for r in run.session.rulings)
    challenged = [t.challenge for t in run.session.transcript if t.challenge is not None]
    assert challenged and all("NOT challenged" in c.reason for c in challenged)


def test_an_unwired_challenger_does_not_stop_the_session() -> None:
    """A second vendor nobody wired is a second vendor that is down, and the answer is the same:
    the move proceeds and the record says nothing challenged it."""
    from nemesis.pilot.providers.challenger_seat import build_challenger
    from nemesis.pilot.providers.config import ChallengerConfig, PilotConfig

    challenger = build_challenger(
        ChallengerConfig(pilot=PilotConfig(provider="gemini", model="a-model-id"))
    )
    run = drive(careful_pilot(), challenger)
    assert run.session.concluded
    challenged = [t.challenge for t in run.session.transcript if t.challenge is not None]
    assert challenged and all("NOT challenged" in c.reason for c in challenged)
