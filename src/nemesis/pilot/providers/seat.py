"""The seat every provider sits in, so five vendors cannot enforce five different things.

There are five concrete seats in this package and there will be more. They differ in *dialect*
— how a tool schema is shaped, how a request is composed, how a chosen verb comes back — and in
nothing else, because a containment that said different things to five vendors would be a
containment with a seam an adversary could pick which side of. Everything that must be identical
lives here:

- **The untrusted-pilot contract**, composed once in :mod:`nemesis.pilot.model_seat` and carried
  byte-identically into every request.
- **The closed vocabulary**, rendered from one tool suite through a dialect that never
  sees the list — so no adapter can add a verb — and re-checked by ``render_tools``
  anyway.
- **The capability scan.** Every rendered request is searched for the vendor built-ins NEMESIS
  never exposes (shell, code execution, retrieval, browsing). A model that *supports* computer
  use is not a model NEMESIS *permits* computer use to, and the difference is checked in the
  payload rather than remembered by a reviewer.
- **The retry policy**, bounded and deterministic, identical for every vendor, and forbidden
  from changing the request or the model between attempts.
- **The not-wired discipline.** No seat ships a live network client. The default transport
  refuses, so an unwired build contacts nothing and finds out loudly.
- **The metadata contract.** Provider, model, latency, tokens, attempts and the verb chosen are
  recorded on every turn. None of it is consulted for a ruling — see
  :mod:`nemesis.pilot.providers.contract`.

What a concrete seat supplies is a :class:`SeatDialect`: four pure functions and two names. It
holds no handle to NEMESIS — not the engine, the graph, the vault, the capability or the key —
and an ``import-linter`` contract makes that structural rather than a habit: nothing under
``nemesis.pilot.providers`` may import the mediator or any platform plane.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from nemesis.core.temporal import utcnow
from nemesis.pilot.model_seat import (
    PROMPT_VERSION,
    SYSTEM_INSTRUCTIONS,
    PilotNotWiredError,
)
from nemesis.pilot.moves import Briefing, PilotMove
from nemesis.pilot.providers.capabilities import (
    REQUIRED_OF_EVERY_PILOT,
    ModelCapabilities,
    ModelCapability,
    forbidden_tool_types,
)
from nemesis.pilot.providers.contract import (
    DecodingParameters,
    PilotContext,
    PilotDecision,
    PilotRequest,
    PilotResponseMetadata,
    PilotUsage,
    ProviderIdentity,
)
from nemesis.pilot.providers.errors import PilotError, PilotErrorKind
from nemesis.pilot.providers.reliability import RetryPolicy, Sleeper, call_with_retries
from nemesis.pilot.providers.schema import (
    MOVE_TOOL_SCHEMA_VERSION,
    MOVE_TOOL_SUITE,
    PilotToolSuite,
    ToolDialect,
    render_tools,
    suite_version,
)
from nemesis.pilot.providers.transport import PilotTransport, UnwiredPilotTransport

NO_MOVE_SENTINEL = "__no_move__"
"""What a parser returns when the model chose no verb at all.

A mapping that cannot validate, so the mediator records a refused move and the pilot is told
why on its next briefing. Not an exception: a model answering in prose is the most ordinary
thing a weak model does, and it is a *move* the seam refuses, not a fault in the platform.
"""

AMBIGUOUS_MOVE_SENTINEL = "__multiple_moves__"
"""What a parser returns when the model asked for more than one action in one turn.

Refused rather than resolved by taking the first. Taking the first executes one action while
discarding another the model asked for, and writes a transcript claiming it proposed one thing
when it proposed two. An audit record that is wrong about what was requested is worse than a
refusal, and every seat here disables parallel tool calls where the vendor allows it, so this
is the belt behind those braces.
"""


@dataclass(frozen=True)
class ParsedResponse:
    """What a dialect extracted from one vendor response.

    ``move`` is raw, untrusted data on its way to the mediator's seam — an unknown tool name or
    an argument of the wrong shape is passed on as-is rather than corrected here. Correcting it
    would be the harness quietly making the pilot look better behaved than it is, which for a
    containment demonstration is the one thing that must not happen.
    """

    move: Mapping[str, Any]
    request_id: str | None = None
    model_reported: str | None = None
    finish_reason: str | None = None
    usage: PilotUsage = field(default_factory=PilotUsage)


RequestBuilder = Callable[[PilotRequest, list[dict[str, Any]]], dict[str, Any]]
ResponseParser = Callable[[Mapping[str, Any]], ParsedResponse]


@dataclass(frozen=True)
class SeatDialect:
    """Everything one vendor does differently, and nothing else."""

    provider: str
    """The registry key and the audit attribution. ``xai`` is never ``openai``, however
    compatible the transport is."""

    vendor_label: str
    """How the vendor is named in an unwired refusal, in prose a human reads."""

    tools: ToolDialect
    build: RequestBuilder
    parse: ResponseParser

    transmits_offsite: bool = True
    """Whether wiring this seat sends briefings to a third party.

    False for the local seat alone. It changes only the wording of an unwired refusal, and it is
    a field rather than a string because the wording is a statement about the trust boundary and
    got it backwards once already."""


class ProviderSeat:
    """A pilot backed by a hosted or local model, in whichever dialect it speaks.

    Satisfies :class:`~nemesis.pilot.pilot.AutonomousPilot` through ``propose`` and the metered
    contract through ``decide``; the mediator prefers the second when it is there and gets the
    same move either way. Holds a model id, a dialect, a transport and a retry policy — and
    nothing of NEMESIS.
    """

    def __init__(
        self,
        *,
        model: str,
        dialect: SeatDialect,
        capabilities: ModelCapabilities,
        transport: PilotTransport | None = None,
        decoding: DecodingParameters | None = None,
        retries: RetryPolicy | None = None,
        tools: PilotToolSuite = MOVE_TOOL_SUITE,
        name: str | None = None,
        instructions: str = SYSTEM_INSTRUCTIONS,
        instructions_version: str = PROMPT_VERSION,
        clock: Callable[[], datetime] = utcnow,
        sleep: Sleeper | None = None,
    ) -> None:
        missing = capabilities.missing(*REQUIRED_OF_EVERY_PILOT)
        if missing:
            raise ValueError(
                f"{dialect.provider}:{model} does not declare "
                f"{', '.join(item.value for item in missing)}; a seat that cannot be given a "
                "tool schema would have to read a verb out of free text, and a free-text verb "
                "is a vocabulary that is no longer closed"
            )
        self._decoding = decoding or DecodingParameters()
        if self._decoding.seed is not None and not capabilities.supports(ModelCapability.SEEDING):
            raise ValueError(
                f"a seed was configured for {dialect.provider}:{model}, which does not declare "
                "seeding. Dropping it silently would let a deployment believe two runs are "
                "comparable when nothing made them so"
            )
        if self._decoding.reasoning is not None and not capabilities.supports(
            ModelCapability.REASONING_EFFORT
        ):
            raise ValueError(
                f"a reasoning effort was configured for {dialect.provider}:{model}, which does "
                "not accept one. Where a vendor's reasoning mode returns the trace itself, this "
                "platform declines to request it rather than receiving and discarding it"
            )
        self._model = model
        self._dialect = dialect
        self._capabilities = capabilities
        self._transport: PilotTransport = transport or UnwiredPilotTransport(
            dialect.vendor_label, transmits_offsite=dialect.transmits_offsite
        )
        self._retries = retries or RetryPolicy()
        self._tools = tools
        self._instructions = instructions
        self._instructions_version = instructions_version
        self._tool_schema_version = (
            MOVE_TOOL_SCHEMA_VERSION if tools is MOVE_TOOL_SUITE else suite_version(tools)
        )
        self._identity = ProviderIdentity(
            provider=dialect.provider, model=model, seat=type(self).__name__
        )
        self._name = name or self._identity.name
        self._clock = clock
        self._sleep = sleep
        self.calls = 0
        """How many times the transport was asked. A live test that never called the model
        would otherwise assert nothing, which this repository has shipped once already."""

    # -- identity -------------------------------------------------------------

    @property
    def name(self) -> str:
        return self._name

    @property
    def identity(self) -> ProviderIdentity:
        return self._identity

    @property
    def capabilities(self) -> ModelCapabilities:
        return self._capabilities

    @property
    def dialect(self) -> SeatDialect:
        return self._dialect

    @property
    def transport(self) -> PilotTransport:
        return self._transport

    @property
    def decoding(self) -> DecodingParameters:
        return self._decoding

    @property
    def retries(self) -> RetryPolicy:
        return self._retries

    @property
    def tools(self) -> PilotToolSuite:
        return self._tools

    # -- the turn -------------------------------------------------------------

    def build_payload(
        self,
        briefing: Briefing,
        *,
        attempt: int = 1,
        proposed_move: PilotMove | None = None,
    ) -> dict[str, Any]:
        """Compose the vendor request from the briefing, and only the briefing.

        Public because it is worth being able to look at. ``nemesis pilot-preview`` renders
        exactly this so an operator can read what would be transmitted to a third party before
        deciding whether it may be — which is the founder decision a hosted seat waits on, and
        not one any code here makes.
        """
        request = PilotRequest(
            identity=self._identity,
            context=PilotContext(briefing=briefing, attempt=attempt, proposed_move=proposed_move),
            instructions=self._instructions,
            instructions_version=self._instructions_version,
            tools=self._tools,
            tool_schema_version=self._tool_schema_version,
            decoding=self._decoding,
        )
        payload = self._dialect.build(request, render_tools(self._tools, self._dialect.tools))
        exposed = forbidden_tool_types(payload)
        if exposed:
            raise PilotError(
                PilotErrorKind.UNKNOWN,
                f"the {self._dialect.provider} request would expose {', '.join(exposed)}; a "
                "model supporting a capability is not NEMESIS granting it",
                provider=self._dialect.provider,
                model=self._model,
            )
        return payload

    async def decide(
        self, briefing: Briefing, *, proposed_move: PilotMove | None = None
    ) -> PilotDecision:
        """Ask the model for one move, and report what the call cost.

        ``proposed_move`` is keyword-only with a default so the metered-pilot contract is
        unchanged: a caller that knows nothing about challengers calls this exactly as before.
        """
        started_at = self._clock()
        started = time.monotonic()
        parsed, attempts = await call_with_retries(
            lambda attempt: self._attempt(briefing, attempt, proposed_move),
            policy=self._retries,
            **({"sleep": self._sleep} if self._sleep is not None else {}),
        )
        metadata = PilotResponseMetadata(
            identity=self._identity,
            requested_at=started_at,
            latency_seconds=max(0.0, time.monotonic() - started),
            attempts=attempts,
            request_id=parsed.request_id,
            model_reported=parsed.model_reported,
            finish_reason=parsed.finish_reason,
            tool_selected=str(parsed.move.get("kind", "")) or None,
            usage=parsed.usage,
            reasoning_requested=self._decoding.reasoning,
            instructions_version=self._instructions_version,
            tool_schema_version=self._tool_schema_version,
        )
        return PilotDecision(raw=parsed.move, metadata=metadata)

    async def propose(self, briefing: Briefing) -> PilotMove | Mapping[str, Any]:
        """The narrow contract every pilot satisfies. Returns the move and drops the metering."""
        return (await self.decide(briefing)).raw

    async def _attempt(
        self, briefing: Briefing, attempt: int, proposed_move: PilotMove | None = None
    ) -> ParsedResponse:
        payload = self.build_payload(briefing, attempt=attempt, proposed_move=proposed_move)
        self.calls += 1
        try:
            response = await self._transport.request(payload)
        except (PilotError, PilotNotWiredError):
            # A classified failure and a build that was never wired both pass through. The
            # first is already in the taxonomy; the second is a deployment error the mediator
            # contains as a refused move, and wrapping it would hide which of the two happened.
            raise
        except TimeoutError as exc:
            raise PilotError(
                PilotErrorKind.TIMEOUT,
                str(exc)[:200] or "the transport timed out",
                provider=self._dialect.provider,
                model=self._model,
            ) from exc
        except Exception as exc:
            # Deliberately NOT classified as retryable. A transport that raises something this
            # taxonomy does not know about is as likely to be a defect as an outage, and
            # re-sending on a defect is how one bug becomes an unbounded spend.
            raise PilotError(
                PilotErrorKind.UNKNOWN,
                f"{type(exc).__name__}: {str(exc)[:160]}",
                provider=self._dialect.provider,
                model=self._model,
            ) from exc
        if not isinstance(response, Mapping):
            raise PilotError(
                PilotErrorKind.MALFORMED_RESPONSE,
                f"the transport returned {type(response).__name__}, not a response body",
                provider=self._dialect.provider,
                model=self._model,
            )
        return self._dialect.parse(response)


def no_move(detail: str) -> dict[str, Any]:
    """The mapping a parser returns when the model chose no verb."""
    return {"kind": NO_MOVE_SENTINEL, "detail": detail[:200]}


def ambiguous_move(count: int) -> dict[str, Any]:
    """The mapping a parser returns when the model asked for several actions at once."""
    return {
        "kind": AMBIGUOUS_MOVE_SENTINEL,
        "detail": (
            f"the model requested {count} actions in a turn where exactly one is allowed; "
            "none was carried out"
        ),
    }


def move_from(name: object, arguments: object) -> dict[str, Any]:
    """Assemble ``{"kind": <tool name>, **arguments}`` with the tool name authoritative.

    A ``kind`` smuggled into the arguments must never override the tool the model actually
    called: a ``conclude`` call carrying ``kind: request_effect`` would be recorded as a conclude
    while acting as a request_effect, and the audit trail would name the wrong verb. Not an
    escalation — the envelope refuses either way — and a correctness defect in the one record
    that is supposed to reconstruct the session.

    **Arguments that are present and not an object are recorded as unparsable, not discarded.**
    This is where the parametrised contract suite earned its place on the day it was written.
    Three seats returned a bare ``{"kind": name}`` for a non-object input, and ``conclude`` has
    no required fields — so a model whose tool arguments arrived as a string, a number or a list
    ended the session with an ACCEPTED conclusion and a transcript that recorded a clean
    completion. Meanwhile the OpenAI path, which decodes JSON strings, emitted an unparsable
    marker for the same input and was refused. Two vendors accepting what two others refused, on
    the identical malformed response, is the drift this whole layer exists to prevent.

    ``None`` and an empty mapping mean "the model called this tool with no arguments", which is
    a real and valid thing to do with ``conclude``. Anything else non-object means the model
    tried to say something the transport could not carry, and the marker is a key the closed
    vocabulary forbids — so the seam refuses the move and the transcript still says what arrived.
    """
    if not isinstance(name, str):
        return no_move("the model named no tool")
    if arguments is None or arguments == {}:
        return {"kind": name}
    if not isinstance(arguments, Mapping):
        return {"kind": name, "__unparsable_arguments__": str(arguments)[:400]}
    return {"kind": name, **{key: value for key, value in arguments.items() if key != "kind"}}


__all__ = [
    "AMBIGUOUS_MOVE_SENTINEL",
    "NO_MOVE_SENTINEL",
    "ParsedResponse",
    "ProviderSeat",
    "RequestBuilder",
    "ResponseParser",
    "SeatDialect",
    "ambiguous_move",
    "move_from",
    "no_move",
]
