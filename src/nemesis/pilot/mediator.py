"""The referee. Holds every handle the pilot does not, and rules on every move it makes.

This is the limiter in the metaphor the founder set: the pilot drives flat-out and
autonomously, and the car physically cannot leave the track. Concretely, the
:class:`PilotMediator` is constructed with the pursuit engine, the graph, the pre-signed
capability **envelope**, the effects registry, the claim store and the audit sink — and the
pilot is constructed with none of them. The pilot proposes a move; the mediator validates it,
carries out only the part the guardrail permits, records the move and its ruling, and hands
back a fresh briefing. Nothing the pilot returns is trusted: it is untrusted data, validated
at the seam, exactly as content crossing the collection boundary is (invariant 5).

Where each containment lives, so a reader can find it rather than take it on faith:

- **Authority escalation** is contained by the *vocabulary*, in :mod:`nemesis.pilot.moves`:
  there is no move that mints a capability or widens the envelope, so a hostile pilot has no
  verb to reach for. The mediator never issues authority; it only routes an effect request to
  the envelope and reports what the envelope decided.
- **Acting outside the envelope** — a forbidden operation, an unapproved target, an expired
  grant — is contained by routing every :class:`RequestEffect` through
  ``registry.execute(request, envelope)``. The refusal is the *capability's*, reached by
  asking it, never a judgement the mediator substituted for it.
- **Forging the target's state** to slip past target binding is contained because the mediator
  observes the target's current attributes *from the graph*, never from the pilot. A pilot may
  name a target; it may not tell NEMESIS what that target currently looks like.
- **Turning opinion into evidence** is contained because a :class:`RecordBelief` becomes a
  claim of kind HYPOTHESIS derived from MODEL_ASSERTION, which :class:`~nemesis.core.claims.Claim`
  forbids from ever being an observation or a fact (invariant 1, enforced at construction).
- **Leaking withheld material** into a document is contained at the effects boundary, where
  the D1 disclosure scan refuses a request whose parameters carry persona linkage or a name.
- **Never stopping** is contained by the move ceiling and the investigation budget: runaway
  autonomy costs wall-clock, not correctness, and the halt is recorded as a halt.

And the property that makes all of the above auditable: the session is **replayable though the
pilot is not**. The pilot cannot be re-run to the same output — it is a model — but the
transcript of ``(move, ruling)`` pairs, each written to the hash-chained audit trail,
reconstructs exactly what it was allowed to do and why. Invariant 11 asks for replayable, and
a nondeterministic driver does not get to make an investigation unreplayable.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ValidationError

from nemesis.authz.envelope import AutonomyEnvelope
from nemesis.core.authorization import AuthorizationCapability, TargetFingerprint
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.disclosure import (
    INTERNAL_MARKERS,
    DisclosureClass,
    DisclosureViolationError,
    disclosure_of_entity,
    scan_for_internal_material,
)
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.temporal import TemporalExtent, utcnow
from nemesis.effects.registry import (
    STOP_CONDITION_CLEARED,
    STOP_CONDITION_PARAMETER_PREFIX,
    EffectsRegistry,
)
from nemesis.pilot.challenger import (
    ChallengePolicy,
    ChallengerFailureMode,
    ChallengerRuling,
    ChallengerVerdict,
    MoveChallenger,
    failure_ruling,
    validate_ruling,
    validation_detail,
)
from nemesis.pilot.moves import (
    PILOT_MOVE_ADAPTER,
    Briefing,
    Conclude,
    EntityView,
    EnvelopeView,
    HypothesisView,
    PilotMove,
    RecordBelief,
    RequestEffect,
    Ruling,
    RulingStatus,
    RunPivot,
)
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilot.providers.contract import (
    PilotDecision,
    PilotResponseMetadata,
    ProviderIdentity,
)
from nemesis.ports.effects import EffectRequest
from nemesis.ports.storage import AuditEvent, AuditSink, ClaimStore, GraphStore
from nemesis.pursuit.engine import PursuitEngine
from nemesis.pursuit.investigation import IncidentSeed, Investigation

DEFAULT_MAX_MOVES = 40
DEFAULT_MAX_CONSECUTIVE_MALFORMED = 3
DEFAULT_PROPOSE_TIMEOUT = 120.0
"""Wall-clock ceiling on a single ``pilot.propose`` call, in seconds.

A hosted model's transport can hang — a genuine stall, or a slowloris on the connection that
carries every briefing to the vendor. Without a bound the whole session parks on one turn and
no halt is ever recorded. The move ceiling counts *iterations*, not seconds, so it does not
help here; this does."""

MAX_BRIEFING_ENTITIES = 50

PILOT_ACTOR_KIND = "agent"
"""Per the audit taxonomy (human | agent | rule | system). A pilot is an agent — a
distinctively *untrusted, external* one, which the action names and the actor id carry rather
than a new actor kind."""

_BUDGET_REFUSAL_MARKER = "exceeds the remaining budget"
_DISCLOSURE_MARKER = "internal-classified material"

_MARKER_PATTERN = re.compile("|".join(re.escape(m) for m in INTERNAL_MARKERS), re.IGNORECASE)


def _redact_markers(text: str) -> str:
    """Strip internal-vocabulary markers from text before it enters a briefing.

    A disclosure refusal names the markers it caught, so echoing that refusal back to the pilot
    through ``last_ruling`` would carry them into the next request — and, for a hosted model, to
    the vendor. The markers came from the pilot's own parameters, but they are NEMESIS's internal
    vocabulary and must not travel outward; the rest of the reason is kept so the pilot still
    learns it was refused for disclosure.
    """
    return _MARKER_PATTERN.sub("[redacted-internal-marker]", text)


@dataclass(frozen=True)
class TurnRecord:
    """One proposed move and the mediator's ruling on it. ``move`` is ``None`` when the pilot
    emitted something that was not a valid move at all."""

    move: PilotMove | None
    ruling: Ruling

    metadata: PilotResponseMetadata | None = None
    """What the provider call cost, when the seat reported it. ``None`` for a scripted pilot,
    a pilot that raised, or any seat that does not meter itself.

    Descriptive only. No ruling above reads it — a session driven by a seat that lied in every
    field would produce a misleading audit record and never an action that should not have
    happened, which is what makes it safe to accept from an untrusted seat at all."""

    challenge: ChallengerRuling | None = None
    """The challenger's verdict on this move, when one was configured."""


@dataclass(frozen=True)
class PilotSession:
    """The record of one pilot driving one investigation: where it ended up, and every move
    it made on the way, ruled on."""

    investigation: Investigation
    transcript: tuple[TurnRecord, ...]
    concluded: bool
    halted_reason: str | None
    pilot_actor: str

    identity: ProviderIdentity | None = None
    """Which provider and which model drove, read **once at session open** and used for every
    audit record in the session.

    Read once rather than per turn on purpose. The seat is untrusted code on the audit path, and
    a seat free to report a different provider each turn would be rewriting attribution move by
    move — so it is not given the chance, and a per-turn metadata block cannot override what was
    recorded at open. ``None`` when the pilot does not meter itself, which is the honest answer
    for a scripted pilot and better than inventing a vendor for it."""

    @property
    def rulings(self) -> tuple[Ruling, ...]:
        return tuple(turn.ruling for turn in self.transcript)

    @property
    def refused_effects(self) -> tuple[Ruling, ...]:
        """Every effect request that was refused. The interesting half of a hostile session.

        Keyed on the *move*, not on whether an `effect_outcome` came back. An earlier version
        filtered on `effect_outcome`, which silently excluded every refusal raised before the
        Effects plane was reached — budget exhaustion, an unknown entity, an internal-class
        target — so a hostile session under-reported its own refusals. A summary that
        under-counts what it stopped is the same defect class as an audit record that says
        `permitted: true` for a refusal.
        """
        return tuple(r for r in self.rulings if r.move_kind == "request_effect" and not r.accepted)

    def any_effect_left_the_platform(self) -> bool:
        """Whether any effect this session ran reported contact with the outside world.

        Computed from what the Effects plane actually reported, and **fail-closed**: an
        accepted effect that came back without saying counts as having left. The previous
        version returned the literal ``False``, which made every test asserting it — including
        the live-pilot one — assert a constant. Invariant 15 is genuinely enforced elsewhere,
        by a registry that refuses to register any adapter declaring external contact, so the
        constant happened to be true; that is exactly what makes it dangerous. A containment
        assertion that cannot fail is not evidence of containment, and this file is the last
        place that should carry one.
        """
        for ruling in self.rulings:
            # Gated on having *reached* the Effects plane, not on having been accepted. The
            # first version skipped every non-accepted ruling, and the mediator maps any
            # unsuccessful outcome to a refusal — so an effect that ran, failed, and reported
            # contact was never examined. `effect_outcome` is set exactly when the request
            # reached the plane, which is precisely the set whose contact report matters; a
            # refusal raised before it (budget, unknown entity, disclosure) has none to give.
            if ruling.move_kind != "request_effect" or ruling.effect_outcome is None:
                continue
            if ruling.external_contact_made is not False:
                return True
        return False


OBSERVABLE_STOP_CONDITIONS: Final[frozenset[str]] = frozenset({"target_ownership_contested"})
"""Stop conditions NEMESIS can settle by looking, rather than by being told.

Deliberately tiny, and everything outside it stays uncleared. A condition the platform cannot
check is one no code here may declare satisfied — the honest outcome is a refusal that names
what nobody verified, not a clearance nobody earned.
"""


def _observed_clearances(
    capability: AuthorizationCapability, observed: Mapping[str, str]
) -> dict[str, str]:
    """Clear the blocking stop conditions the platform can verify from what it observed.

    The clearances live in ``EffectRequest.parameters``, which is also where the pilot's own
    parameters used to arrive verbatim — that was the hole: the party a condition constrains
    was the party satisfying it. Stripping the pilot's attestations closed it and left nothing
    behind, which made every blocking condition unsatisfiable and quietly turned the reference
    demonstration's rehearsal into a refusal. A control nobody can satisfy is not a strict
    control; it is a dead one, and it stops protecting anything the day someone removes it to
    make the demo work again.

    So the clearance comes from the same place the target's current state does: the graph, read
    by the mediator, unreachable by the pilot. ``target_ownership_contested`` asks whether
    anyone has contested ownership since approval — a fact about the world, observable as an
    entity attribute, and exactly the kind of thing an untrusted model must not get to assert.

    Fail-closed three times over: a condition outside :data:`OBSERVABLE_STOP_CONDITIONS` is
    never cleared; one inside it is cleared only when the attribute is *present*; and present
    means the platform positively recorded the observation, not that it looked and found
    nothing. A missing attribute is a target nobody checked, and a target nobody checked is
    not a target anybody cleared.
    """
    clearances: dict[str, str] = {}
    for condition in capability.stop_conditions:
        if not condition.is_blocking or condition.condition not in OBSERVABLE_STOP_CONDITIONS:
            continue
        if condition.condition == "target_ownership_contested":
            # Present AND negative. The first version accepted an ABSENT attribute as
            # "not contested", and nothing in this platform ever writes that attribute — so
            # the condition cleared on every entity, always, while its own docstring claimed
            # it cleared "only when the observation positively says so". An adversarial audit
            # caught it within the hour. Absence of a finding is not a finding: it is the
            # quarantine module's own rule — unexamined is not safe — applied here.
            observation = observed.get("ownership_contested")
            if observation is not None and str(observation).lower() in {"false", "no", "0"}:
                clearances[f"{STOP_CONDITION_PARAMETER_PREFIX}{condition.condition}"] = (
                    STOP_CONDITION_CLEARED
                )
    return clearances


def _without_attestations(parameters: Mapping[str, str]) -> dict[str, str]:
    """Strip anything the pilot could use to attest that a stop condition was cleared.

    The effects preflight reads stop-condition clearances out of ``request.parameters``, and
    the mediator used to copy the pilot's dict into that field verbatim. A pilot could
    therefore satisfy the very conditions it is constrained by — one entry,
    ``stop_condition.target_ownership_contested: cleared``, turned a refusal into an
    acceptance. The condition in the reference envelope is *abort if anyone has contested
    ownership of this target since approval*: the innocent-third-party abort, cleared by the
    party it exists to stop.

    Stripping rather than rejecting, and stripping the whole prefix rather than the known
    keys, because the failure must not depend on enumerating what a hostile pilot might send.
    A clearance is an attestation about the world, and an untrusted model attests to nothing:
    whoever actually checked the condition records it outside this seam.
    """
    return {
        key: value
        for key, value in parameters.items()
        if not key.startswith(STOP_CONDITION_PARAMETER_PREFIX)
    }


class PilotMediator:
    """Drives an investigation by asking a pilot for moves and enforcing every one."""

    def __init__(
        self,
        *,
        engine: PursuitEngine,
        graph: GraphStore,
        envelope: AutonomyEnvelope,
        registry: EffectsRegistry,
        claims: ClaimStore,
        audit: AuditSink,
        clock: Callable[[], datetime] = utcnow,
        max_moves: int = DEFAULT_MAX_MOVES,
        max_consecutive_malformed: int = DEFAULT_MAX_CONSECUTIVE_MALFORMED,
        propose_timeout: float = DEFAULT_PROPOSE_TIMEOUT,
        challenger: MoveChallenger | None = None,
        challenge_policy: ChallengePolicy | None = None,
    ) -> None:
        self._engine = engine
        self._graph = graph
        self._envelope = envelope
        self._registry = registry
        self._claims = claims
        self._audit = audit
        self._clock = clock
        self._max_moves = max_moves
        self._max_consecutive_malformed = max_consecutive_malformed
        self._propose_timeout = propose_timeout
        self._challenger = challenger
        self._challenge_policy = challenge_policy or ChallengePolicy()

    async def drive(
        self, pilot: AutonomousPilot, seed: IncidentSeed, *, total_budget: float = 100.0
    ) -> PilotSession:
        """Run one full session: open an investigation, then loop asking the pilot for moves
        until it concludes, exhausts the move ceiling, or misbehaves past tolerance."""
        pilot_actor = new_id(IdPrefix.ACTOR)
        # Read once, here, and used for every record below. A seat is untrusted code sitting on
        # the audit path; one free to report a different provider each turn would be rewriting
        # attribution move by move.
        identity = self._identity_of(pilot)
        investigation = await self._engine.start(seed, total_budget=total_budget)
        await self._record_session(
            pilot,
            pilot_actor,
            investigation,
            identity,
            outcome="opened",
            extra={"budget": f"{total_budget}"},
        )

        transcript: list[TurnRecord] = []
        malformed_streak = 0
        last_ruling: Ruling | None = None
        concluded = False
        halted: str | None = None

        async def refuse(
            move_kind: str, reason: str, metadata: PilotResponseMetadata | None = None
        ) -> bool:
            """Record a refused non-move and report whether the streak has ended the session."""
            nonlocal malformed_streak, last_ruling
            malformed_streak += 1
            ruling = Ruling(
                move_kind=move_kind, status=RulingStatus.REFUSED_MALFORMED, reason=reason[:400]
            )
            transcript.append(TurnRecord(None, ruling, metadata))
            last_ruling = ruling
            await self._record_move(
                pilot, pilot_actor, investigation, identity, None, ruling, metadata
            )
            return malformed_streak >= self._max_consecutive_malformed

        for turn in range(self._max_moves):
            try:
                briefing = await self._brief(
                    investigation, last_ruling, moves_remaining=self._max_moves - turn
                )
            except DisclosureViolationError:
                # Recorded, then re-raised untouched. This is NOT handling it — the wall's
                # contract is that nobody catches it to carry on, and nothing here carries on.
                # But an audit trail holding a `pilot.session` open with no close is a session
                # that cannot be reconstructed, and invariant 11 does not make an exception for
                # the case where the platform stopped itself. So the close is written and the
                # error goes on being loud.
                await self._record_session(
                    pilot,
                    pilot_actor,
                    investigation,
                    identity,
                    outcome="halted",
                    extra={
                        "halted_reason": "the briefing would have carried internal-classified "
                        "material to the pilot",
                        "moves": str(len(transcript)),
                    },
                )
                raise

            raw: object = None
            metadata: PilotResponseMetadata | None = None
            try:
                # Bounded by a wall clock the pilot cannot influence: a hosted model that hangs
                # must not park the whole session on one turn with no halt ever recorded. The
                # bound covers the seat's own retries too, which is why they cannot buy a
                # hanging vendor more wall-clock than a single call would have had.
                decision = await asyncio.wait_for(
                    self._elicit(pilot, briefing), timeout=self._propose_timeout
                )
                raw, metadata = decision.raw, decision.metadata
                move = self._validate(raw)
            except ValidationError as exc:
                if await refuse(
                    self._raw_kind(raw),
                    "not a move in the pilot vocabulary: "
                    f"{self._first_error(exc)}. The vocabulary is closed; a pilot cannot "
                    "act through a verb that does not exist.",
                    metadata,
                ):
                    halted = f"{malformed_streak} malformed moves in a row; session ended"
                    break
                continue
            except TimeoutError:
                # `wait_for` cancels the stalled call. A stall is a refused move, and a run of
                # them ends the session — the same containment as a pilot that raises.
                if await refuse(
                    "unknown",
                    f"the pilot did not return a move within {self._propose_timeout:g}s; "
                    "the stalled call was cancelled",
                    metadata,
                ):
                    halted = "the pilot stalled repeatedly; session ended"
                    break
                continue
            except Exception as exc:
                # An untrusted pilot must not be able to end a session by raising. A model that
                # hangs, a transport that is not wired, an OpenAI call that fails — each is a
                # refused move and eventually a halt, never a crash of the harness and never a
                # silent retry against whatever the pilot was about to contact.
                if await refuse(
                    "unknown",
                    f"the pilot raised {type(exc).__name__} instead of returning a move: {exc}",
                    metadata,
                ):
                    halted = f"the pilot raised {type(exc).__name__} repeatedly; session ended"
                    break
                continue

            malformed_streak = 0
            challenge = await self._challenge(briefing, move)
            if challenge is not None and self._challenge_policy.blocks(
                move.kind, challenge.verdict
            ):
                # Refused BEFORE `_apply`, so the envelope is never debited and no pivot runs.
                # A challenger can only subtract; it never reaches a control that would have
                # permitted something on its own.
                ruling = Ruling(
                    move_kind=move.kind,
                    status=RulingStatus.REFUSED_CHALLENGED,
                    reason=(
                        f"an independent challenger returned {challenge.verdict.value}: "
                        f"{challenge.reason}"
                    )[:400],
                )
            else:
                investigation, ruling = await self._apply(pilot, pilot_actor, investigation, move)
            transcript.append(TurnRecord(move, ruling, metadata, challenge))
            last_ruling = ruling
            await self._record_move(
                pilot, pilot_actor, investigation, identity, move, ruling, metadata, challenge
            )

            if isinstance(move, Conclude) and ruling.accepted:
                concluded = True
                break
        else:
            halted = f"reached the {self._max_moves}-move ceiling without concluding"

        await self._record_session(
            pilot,
            pilot_actor,
            investigation,
            identity,
            outcome="concluded" if concluded else "halted",
            extra={"halted_reason": halted or "", "moves": str(len(transcript))},
        )
        return PilotSession(
            investigation=investigation,
            transcript=tuple(transcript),
            concluded=concluded,
            halted_reason=halted,
            pilot_actor=pilot_actor,
            identity=identity,
        )

    # -- eliciting a move ------------------------------------------------------

    @staticmethod
    def _identity_of(pilot: AutonomousPilot) -> ProviderIdentity | None:
        """Which provider and model the seat says it is, read once at session open.

        Defensive about the value, not merely about the attribute: a seat is untrusted code and
        the strings it hands over land in the hash-chained audit trail. Anything that is not a
        genuine :class:`ProviderIdentity` is treated as no identity at all rather than coerced
        into a plausible-looking one, because an audit record naming a vendor nobody ran is
        worse than one that admits it does not know.
        """
        identity = getattr(pilot, "identity", None)
        return identity if isinstance(identity, ProviderIdentity) else None

    @staticmethod
    async def _elicit(pilot: AutonomousPilot, briefing: Briefing) -> PilotDecision:
        """Ask the pilot for a move, keeping the call metadata when the seat reports it.

        Two protocols, one loop. :class:`~nemesis.pilot.pilot.AutonomousPilot` is unchanged and
        remains the whole contract; :class:`~nemesis.pilot.providers.contract.MeteredPilot` adds
        ``decide``, and a seat that offers it gets its latency, token counts and attempt count
        into the audit trail. A scripted pilot, an adversarial double and a five-line fake are
        all still valid pilots that nobody has to update — which matters because every hostile
        double in the containment suite is cast to the protocol, and a required member added
        there would leave each of them compiling while silently no longer conforming.
        """
        decide = getattr(pilot, "decide", None)
        if callable(decide):
            decision = await decide(briefing)
            if isinstance(decision, PilotDecision):
                return decision
            # A seat that answered `decide` with something else is not trusted to have meant it.
            # The value is passed on as a raw move, which the seam refuses if it is not one.
            return PilotDecision(raw=decision if isinstance(decision, Mapping) else {})
        return PilotDecision(raw=await pilot.propose(briefing))

    # -- the challenger --------------------------------------------------------

    async def _challenge(self, briefing: Briefing, move: PilotMove) -> ChallengerRuling | None:
        """Ask the challenger about a move. Returns ``None`` when none is configured.

        The challenger receives what the pilot received and the move the pilot proposed, and
        nothing else. Its answer is re-validated through the closed verdict vocabulary for the
        same reason a move is: a model instance with an overridden method is the value-confusion
        shape this codebase has been bitten by, and the seam is where it is stopped.

        A challenger that raises, stalls or answers outside the vocabulary does not take the
        session with it. Under the default failure mode the move proceeds and the transcript
        records that nothing challenged it — returning the session to the baseline posture every
        containment test is written against, rather than making an advisory control a single
        point of failure that anyone who can degrade a second vendor could pull.
        """
        if self._challenger is None:
            return None
        try:
            raw = await asyncio.wait_for(
                self._challenger.review(briefing, move),
                timeout=self._challenge_policy.timeout_seconds,
            )
            return validate_ruling(raw)
        except ValidationError as exc:
            return self._unanswered(
                f"the challenger returned no valid verdict ({validation_detail(exc)})"
            )
        except TimeoutError:
            return self._unanswered(
                f"the challenger did not answer within {self._challenge_policy.timeout_seconds:g}s"
            )
        except Exception as exc:
            return self._unanswered(f"the challenger raised {type(exc).__name__}")

    def _unanswered(self, detail: str) -> ChallengerRuling:
        """What is recorded when the challenger did not produce a verdict."""
        if self._challenge_policy.on_failure is ChallengerFailureMode.REFUSE:
            return ChallengerRuling(
                verdict=ChallengerVerdict.INSUFFICIENT_EVIDENCE,
                reason=f"{detail}; this deployment refuses an unchallenged move",
            )
        return failure_ruling(f"{detail}; the move was NOT challenged")

    # -- move validation ------------------------------------------------------

    def _validate(self, raw: object) -> PilotMove:
        """Turn whatever the pilot returned into a move, or raise.

        A model instance is dumped to plain data and re-validated, never trusted as-is: a
        ``BaseModel`` subclass with an overridden method is exactly the value-confusion shape
        that has bitten this codebase before, and the seam is where it is stopped.
        """
        data = raw.model_dump() if isinstance(raw, BaseModel) else raw
        return PILOT_MOVE_ADAPTER.validate_python(data)

    @staticmethod
    def _raw_kind(raw: object) -> str:
        """What the pilot called its move, for the refusal record. Never trusted, always bounded.

        ``Mapping`` and not ``dict``: a parser that returned an immutable mapping — the natural
        shape for untrusted data — would otherwise fall through to ``"unknown"`` and quietly
        degrade every refusal record in the transcript, which is a direct hit on invariant 11.
        The value is stringified and capped because it is pilot-authored text on its way to the
        hash-chained audit trail.
        """
        if isinstance(raw, BaseModel):
            return str(getattr(raw, "kind", "unknown"))[:64]
        if isinstance(raw, Mapping):
            return str(raw.get("kind", "unknown"))[:64]
        return "unknown"

    @staticmethod
    def _first_error(exc: ValidationError) -> str:
        errors = exc.errors()
        if not errors:
            return "invalid move"
        first = errors[0]
        location = ".".join(str(part) for part in first.get("loc", ())) or "move"
        return f"{location}: {first.get('msg', 'invalid')}"

    # -- move application -----------------------------------------------------

    async def _apply(
        self,
        pilot: AutonomousPilot,
        pilot_actor: str,
        investigation: Investigation,
        move: PilotMove,
    ) -> tuple[Investigation, Ruling]:
        if isinstance(move, RunPivot):
            return await self._apply_pivot(investigation, move)
        if isinstance(move, RecordBelief):
            return investigation, await self._apply_belief(pilot, pilot_actor, move)
        if isinstance(move, RequestEffect):
            return investigation, await self._apply_effect(pilot_actor, move)
        # Conclude: nothing to do but rule on it. The loop sees the type and stops.
        return investigation, Ruling(
            move_kind="conclude",
            status=RulingStatus.ACCEPTED,
            reason=move.summary or "pilot concluded the session",
        )

    async def _apply_pivot(
        self, investigation: Investigation, move: RunPivot
    ) -> tuple[Investigation, Ruling]:
        entity = await self._graph.get_entity(move.entity_id)
        if entity is None:
            return investigation, Ruling(
                move_kind="run_pivot",
                status=RulingStatus.REFUSED_UNKNOWN_ENTITY,
                reason=(
                    f"no entity {move.entity_id!r} has been surfaced in this investigation; "
                    "a pivot names a lead the pilot was shown, not one it invents"
                ),
            )
        # The pilot works with deliverable-class material only. It is never briefed on internal
        # leads (persona linkage) or RESTRICTED nodes, and it may not act on one by naming its id
        # either — otherwise a pivot on a persona could surface a human-identity lead into the
        # graph, which the next briefing would then have to redact. Refused at the source.
        if disclosure_of_entity(entity.entity_type) is not DisclosureClass.DELIVERABLE:
            return investigation, Ruling(
                move_kind="run_pivot",
                status=RulingStatus.REFUSED_DISCLOSURE,
                reason=(
                    f"entity {move.entity_id!r} is internal-classified "
                    f"({disclosure_of_entity(entity.entity_type).value}); the pilot works with "
                    "deliverable-class material only and may not pivot on an internal lead"
                ),
            )

        investigation, executed = await self._engine.execute_pivot(
            investigation,
            entity_id=move.entity_id,
            pivot_type=move.pivot_type,
            rationale=move.rationale,
        )
        if executed is None:  # entity vanished between the check and the call; treat as unknown
            return investigation, Ruling(
                move_kind="run_pivot",
                status=RulingStatus.REFUSED_UNKNOWN_ENTITY,
                reason=f"entity {move.entity_id!r} could not be pivoted on",
            )

        if not executed.succeeded and _BUDGET_REFUSAL_MARKER in (executed.error or ""):
            return investigation, Ruling(
                move_kind="run_pivot",
                status=RulingStatus.REFUSED_BUDGET,
                reason=executed.error or "budget exhausted",
            )

        # A pivot that ran but returned nothing is still a permitted move: the pilot asked a
        # fair question and the world had no answer (often REQUIRES_EXTERNAL_DATA). That is
        # ACCEPTED with an honest reason, not a refusal.
        reason = executed.error or (
            f"{len(executed.evidence_produced)} evidence sealed, "
            f"{len(executed.entities_discovered)} entities discovered"
        )
        return investigation, Ruling(
            move_kind="run_pivot",
            status=RulingStatus.ACCEPTED,
            reason=reason,
            evidence_sealed=executed.evidence_produced,
            entities_discovered=executed.entities_discovered,
        )

    async def _apply_belief(
        self, pilot: AutonomousPilot, pilot_actor: str, move: RecordBelief
    ) -> Ruling:
        now = self._clock()
        try:
            statement = Statement(
                subject=move.subject,
                predicate=move.predicate,
                obj=move.obj,
                natural_language=move.natural_language,
            )
            claim = Claim.create(
                kind=ClaimKind.HYPOTHESIS,
                statement=statement,
                derivation=DerivationKind.MODEL_ASSERTION,
                asserted_by=pilot_actor,
                asserted_at=now,
                valid_extent=TemporalExtent.at(now),
                derived_from_claims=move.derived_from_claims,
                model_identifier=pilot.name,
            )
        except ValidationError as exc:
            # A belief the domain model refuses to mint — a malformed statement, a junk claim
            # id in `derived_from_claims`, or (impossible here, but the guard is the point) an
            # attempt to make a model assertion into a fact. Refused, never raised past the
            # seam: a pilot must not be able to end a session by handing the mediator something
            # that throws.
            return Ruling(
                move_kind="record_belief",
                status=RulingStatus.REFUSED_MALFORMED,
                reason=f"the belief could not be recorded as a claim: {self._first_error(exc)}",
            )

        stored = await self._claims.record(claim)
        return Ruling(
            move_kind="record_belief",
            status=RulingStatus.ACCEPTED,
            reason=(
                "recorded as a HYPOTHESIS derived from MODEL_ASSERTION, attributed to the "
                "pilot and naming the model; it is not evidence and cannot outrank what it "
                "cites (invariant 1)"
            ),
            recorded_claim_id=stored.claim_id,
        )

    async def _apply_effect(self, pilot_actor: str, move: RequestEffect) -> Ruling:
        entity = await self._graph.get_entity(move.entity_id)
        if entity is None:
            return Ruling(
                move_kind="request_effect",
                status=RulingStatus.REFUSED_UNKNOWN_ENTITY,
                reason=f"no entity {move.entity_id!r} to act on in this investigation",
            )

        # The mediator observes the target's current state. The pilot does not get to report
        # it: a caller-supplied "this is what the target looks like now" is all it would take
        # to spend a stale approval against a target that has since changed hands.
        observed = dict(entity.attributes)
        capability = self._envelope.capability
        approved = next((t for t in capability.targets if t.entity_id == move.entity_id), None)
        if approved is not None:
            target_fingerprint = approved.fingerprint
            target_natural_key = approved.natural_key
        else:
            # No approval names this entity. The request is routed anyway, with a fingerprint
            # computed from the entity's own current state, so the *envelope* refuses it for
            # the true reason — "no approved target matches" — rather than the mediator
            # refusing on the capability's behalf and possibly disagreeing with it.
            target_fingerprint = TargetFingerprint.compute(
                entity_id=entity.entity_id,
                entity_type=entity.entity_type.value,
                natural_key=entity.natural_key,
                bound_attributes=observed,
            )
            target_natural_key = entity.natural_key

        # Debit the autonomy budget BEFORE anything executes. A capability bounds what may be
        # done; at machine speed something must bound how often, or an autonomous pilot turns
        # "four approved targets" into unbounded operations against four approved targets. The
        # ledger entry is written first and never removed, so a crash mid-effect costs the
        # budget rather than losing the record — a counter that decrements only on success is a
        # counter an adversary empties by failing.
        spend = self._envelope.debit(
            operation=move.operation,
            target_fingerprint=target_fingerprint,
            requested_by=pilot_actor,
        )
        if spend is None:
            return Ruling(
                move_kind="request_effect",
                status=RulingStatus.REFUSED_BUDGET,
                reason=(
                    f"the autonomy envelope is exhausted: all {self._envelope.budget} "
                    "pre-authorized effects have been spent. Autonomy inside an envelope is "
                    "bounded by construction; more requires a human to define a new envelope, "
                    "which is the point rather than a limitation to work around"
                ),
            )

        request = EffectRequest(
            operation_id=new_id(IdPrefix.OPERATION),
            operation=move.operation,
            target_fingerprint=target_fingerprint,
            target_natural_key=target_natural_key,
            current_target_attributes=observed,
            # The pilot's attestations are stripped; the mediator's own observations are
            # added. Order matters and is asserted by a test: a pilot key can never survive
            # into a clearance, because the clearances are applied second and from elsewhere.
            parameters=_without_attestations(move.parameters)
            | _observed_clearances(capability, observed),
            requested_by=pilot_actor,
            requested_at=self._clock(),
        )
        result = await self._registry.execute(request, capability)

        if result.succeeded:
            status = RulingStatus.ACCEPTED
        elif _DISCLOSURE_MARKER in result.detail:
            status = RulingStatus.REFUSED_DISCLOSURE
        else:
            status = RulingStatus.REFUSED_OUT_OF_ENVELOPE
        return Ruling(
            move_kind="request_effect",
            status=status,
            reason=result.detail,
            effect_outcome=result.outcome.value,
            external_contact_made=result.external_contact_made,
        )

    # -- briefing -------------------------------------------------------------

    async def _brief(
        self,
        investigation: Investigation,
        last_ruling: Ruling | None,
        *,
        moves_remaining: int,
    ) -> Briefing:
        entity_ids: list[str] = []
        seen: set[str] = set()
        for branch in investigation.branches:
            surfaced = (
                branch.focus_entity_id,
                *(eid for pivot in branch.executed for eid in pivot.entities_discovered),
            )
            for eid in surfaced:
                if eid not in seen:
                    seen.add(eid)
                    entity_ids.append(eid)

        entities: list[EntityView] = []
        # The cap counts entities the pilot is actually shown, not entities considered. It used
        # to slice `entity_ids` before the disclosure filter below, so internal-class nodes
        # consumed cap slots and were then dropped — an investigation that surfaced fifty
        # personas would have briefed the pilot on nothing at all while reporting a full
        # briefing. Filtering first is also the safe direction: the filter still runs on every
        # candidate, and only the *count* changed.
        for eid in entity_ids:
            if len(entities) >= MAX_BRIEFING_ENTITIES:
                break
            entity = await self._graph.get_entity(eid)
            if entity is None:
                continue
            # Deliverable-class only. The pilot is untrusted and — for a hosted model — a
            # conduit to a third party, so internal leads (persona linkage) and RESTRICTED
            # nodes (human-identity leads, victims) must not enter what it is sent. An
            # adversarial review found a materialized human-identity lead ("john doe")
            # reaching the vendor through this listing, because a pivot the pilot chose had
            # surfaced it into the graph. The redaction wall that governs an export governs
            # this projection too.
            #
            # **What this filter is and is not.** It is a filter on the entity *type*, and it
            # is exactly as strong as the claim that a type's disclosure class describes its
            # content. It does NOT detect a natural person's name embedded in a
            # deliverable-class identifier: `domain:john-doe.example` and an
            # ORGANIZATION whose natural key is a person's name are DELIVERABLE by type and
            # are briefed verbatim. Nothing here can fix that — reliably recognising arbitrary
            # personal names in identifiers is not a thing code does — so the honest position
            # is that this bounds *classified* material, not *personal* material, and a
            # deployment sending briefings to a hosted vendor must not read it as the latter.
            if disclosure_of_entity(entity.entity_type) is not DisclosureClass.DELIVERABLE:
                continue
            entities.append(
                EntityView(
                    entity_id=entity.entity_id,
                    entity_type=entity.entity_type.value,
                    natural_key=entity.natural_key,
                )
            )

        # The seed and the opening hypotheses interpolate the seed key, so if the investigation
        # was seeded on a non-deliverable entity (a persona, a person) they carry it too. Redact
        # both in that case rather than briefing the pilot — and the vendor — on it.
        seed_deliverable = (
            disclosure_of_entity(investigation.seed.entity_type) is DisclosureClass.DELIVERABLE
        )
        seed_line = (
            f"{investigation.seed.entity_type.value} {investigation.seed.entity_key}"
            if seed_deliverable
            # No entity type either: it can itself be an internal marker ('human_identity_lead'),
            # and it tells the vendor an investigation is about a person.
            else "<redacted: an internal-class seed the pilot is not briefed on>"
        )
        hypotheses = tuple(
            HypothesisView(
                hypothesis_id=h.hypothesis_id,
                statement=(
                    h.statement
                    if seed_deliverable
                    else "<redacted: a hypothesis about an internal-class seed>"
                ),
                settled=h.is_settled,
            )
            for h in investigation.hypotheses
        )
        capability = self._envelope.capability
        envelope = EnvelopeView(
            permitted_operations=tuple(sorted(op.value for op in capability.permitted_operations)),
            forbidden_operations=tuple(sorted(op.value for op in capability.forbidden_operations)),
            approved_target_entity_ids=tuple(t.entity_id for t in capability.targets),
            expires_at=capability.expires_at,
            max_effect=capability.max_effect_description,
            autonomous_effects_remaining=self._envelope.remaining,
        )
        # The previous ruling is echoed back so the pilot learns why a move was refused — but a
        # disclosure refusal names the markers it caught, and those must not travel onward.
        safe_last_ruling = last_ruling
        if last_ruling is not None and scan_for_internal_material({"r": last_ruling.reason}):
            safe_last_ruling = last_ruling.model_copy(
                update={"reason": _redact_markers(last_ruling.reason)}
            )

        briefing = Briefing(
            investigation_id=investigation.investigation_id,
            seed=seed_line,
            step_count=investigation.step_count,
            budget_remaining=investigation.budget_remaining,
            moves_remaining=moves_remaining,
            hypotheses=hypotheses,
            entities=tuple(entities),
            envelope=envelope,
            last_ruling=safe_last_ruling,
        )

        # Fail-closed backstop over the assembled projection: nothing NEMESIS classifies as an
        # internal marker may reach the pilot (and thus the vendor). Unreachable after the
        # measures above — a raise here means a new leak path was opened and must be closed at
        # its source, not caught. Loud on purpose, per DisclosureViolationError's contract.
        leaked = scan_for_internal_material({"briefing": briefing.model_dump_json()})
        if leaked:
            raise DisclosureViolationError(
                "the briefing would carry internal-classified material to the pilot: "
                + "; ".join(leaked)
            )
        return briefing

    # -- audit ----------------------------------------------------------------

    async def _record_move(
        self,
        pilot: AutonomousPilot,
        pilot_actor: str,
        investigation: Investigation,
        identity: ProviderIdentity | None,
        move: PilotMove | None,
        ruling: Ruling,
        metadata: PilotResponseMetadata | None = None,
        challenge: ChallengerRuling | None = None,
    ) -> None:
        inputs = {
            "pilot": pilot.name,
            "move_kind": ruling.move_kind,
            "status": ruling.status.value,
            "reason": ruling.reason[:400],
        }
        inputs |= self._attribution(identity, metadata)
        if ruling.effect_outcome:
            inputs["effect_outcome"] = ruling.effect_outcome
        if ruling.recorded_claim_id:
            inputs["claim"] = ruling.recorded_claim_id
        if isinstance(move, RequestEffect):
            inputs["operation"] = move.operation.value
            inputs["target_entity"] = move.entity_id
        if challenge is not None:
            inputs["challenger"] = self._challenger.name[:128] if self._challenger else ""
            inputs["challenger_verdict"] = challenge.verdict.value
            inputs["challenger_reason"] = challenge.reason[:400]
        await self._audit.record(
            AuditEvent(
                audit_id=new_id(IdPrefix.AUDIT),
                occurred_at=self._clock(),
                actor=pilot_actor,
                actor_kind=PILOT_ACTOR_KIND,
                action="pilot.move",
                subject=investigation.investigation_id,
                outcome=ruling.status.value,
                inputs=inputs,
            )
        )

    def _attribution(
        self, identity: ProviderIdentity | None, metadata: PilotResponseMetadata | None
    ) -> dict[str, str]:
        """Who drove and what the call cost, in the shape an audit record can carry.

        Two rules, and the first is the load-bearing one.

        **The identity wins.** ``provider``, ``model`` and ``seat`` come from what was read at
        session open and are written *after* the per-turn fields, so a metadata block claiming a
        different vendor cannot rewrite attribution mid-session. A comparison between providers
        is worth exactly what the field distinguishing them is worth, and that field must not be
        re-assertable per turn by the party being compared.

        **Nothing here decides anything.** Latency, token counts and the attempt count are
        recorded because a session has to be explainable and a benchmark has to be able to say
        what a run cost. No ruling reads them. A seat that lied in every one would produce a
        misleading record and never an action that should not have happened.

        ``attempts`` in particular closes a gap this file's own prose had opened: a seat that
        retries a failing vendor three times inside one ``propose`` used to collapse into one
        audit event that said nothing about it, while the comment above claimed there was
        "never a silent retry". Now the record says how many there were.
        """
        fields: dict[str, str] = {}
        if metadata is not None:
            fields |= metadata.audit_fields()
        if identity is not None:
            fields["provider"] = identity.provider[:64]
            fields["model"] = identity.model[:128]
            fields["seat"] = identity.seat[:64]
        return fields

    async def _record_session(
        self,
        pilot: AutonomousPilot,
        pilot_actor: str,
        investigation: Investigation,
        identity: ProviderIdentity | None,
        *,
        outcome: str,
        extra: dict[str, str],
    ) -> None:
        inputs = {"pilot": pilot.name, **extra} | self._attribution(identity, None)
        if self._challenger is not None:
            inputs["challenger"] = self._challenger.name[:128]
        await self._audit.record(
            AuditEvent(
                audit_id=new_id(IdPrefix.AUDIT),
                occurred_at=self._clock(),
                actor=pilot_actor,
                actor_kind=PILOT_ACTOR_KIND,
                action="pilot.session",
                subject=investigation.investigation_id,
                outcome=outcome,
                inputs=inputs,
            )
        )


__all__ = ["PilotMediator", "PilotSession", "TurnRecord"]
