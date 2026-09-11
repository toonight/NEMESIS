"""A pilot that runs on this machine, so the laboratory proof of concept needs nobody's permission.

The hosted seats are the shape a production deployment takes, and every one of them is blocked
on the same founder decision: a hosted model means every briefing is transmitted to a third
party, which is a data-governance question this repository cannot answer for anybody. Four
providers make that question four questions.

This seat sidesteps all of them by not leaving the machine. Ollama listens on localhost, the
weights sit on local disk, and no briefing crosses a network boundary — so a laboratory can put
a **real autonomous model** in the seat today, driving the real harness against synthetic data,
with invariant 15 untouched and no decision pending.

**Why a weak model is the right one for this.** The local model was measured before it was ever
considered for this job: on a deliberately planted contradiction it scored 3/6, then 5/10, and
it collapsed into repetition at the wrong sampling settings. That is not a caveat here — it is
the point. A limiter that only holds against a well-behaved pilot holds nothing, and the
containment tests have always argued that the seat must not depend on who is driving. This is
the seat where something genuinely unpredictable sits.

Expect it to emit malformed moves, name entities that do not exist, and occasionally return
prose instead of a tool call. Every one of those is already a recorded refusal rather than a
crash, and a proof of concept where that never happened would be one that proved less.

Like every other seat it takes an **injected transport whose default refuses**, and holds no
network code. The first version of this module imported ``urllib`` directly on the reasoning
that localhost is harmless; the prohibited-content scan refused it and was right. Only the
collection plane holds network capability, and a rule that yields to "but this destination is
safe" is a habit rather than a control. The concrete Ollama transport lives in the test harness,
which also keeps every seat honestly comparable rather than one being special.

Status: `IMPLEMENTED`, `SIMULATED` data, local inference only.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Final

from nemesis.core.temporal import utcnow
from nemesis.pilot.providers.capabilities import ModelCapabilities, ModelCapability
from nemesis.pilot.providers.contract import DecodingParameters, PilotRequest, PilotUsage
from nemesis.pilot.providers.openai_dialect import arguments_to_move
from nemesis.pilot.providers.reliability import RetryPolicy, Sleeper
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, PilotToolSuite, openai_dialect
from nemesis.pilot.providers.seat import (
    ParsedResponse,
    ProviderSeat,
    SeatDialect,
    ambiguous_move,
    no_move,
)
from nemesis.pilot.providers.transport import PilotTransport

PROVIDER = "ollama"
DEFAULT_ENDPOINT: Final = "http://localhost:11434/api/chat"
"""Where a laboratory transport points. Recorded here so the test harness and the documentation
agree on one address; nothing in this package opens it."""

DEFAULT_MODEL: Final = "qwen3.8:27b-q8_0"
DEFAULT_TIMEOUT_SECONDS: Final = 180.0

THINKING_NUM_PREDICT_FLOOR: Final = 8192
"""Minimum output budget once ``think`` is on, because a reasoning trace spends tokens before
the answer starts. Measured: an xhigh trace plus its answer finished well under this bound
(``done_reason=stop`` at ~2400 eval tokens), while a 1024 ceiling returned empty content —
the whole budget consumed by thinking. The floor never lowers a larger request."""

LAB_NOTICE: Final = (
    "Local inference. No briefing leaves this machine, so the hosted-model data-governance "
    "question does not arise — and does not get answered by omission either."
)

OLLAMA_CAPABILITIES = ModelCapabilities(
    declared=frozenset(
        {
            ModelCapability.STRUCTURED_TOOL_CALLING,
            ModelCapability.SINGLE_TOOL_CALL,
            ModelCapability.NATIVE_JSON,
            ModelCapability.USAGE_REPORTING,
            ModelCapability.SEEDING,
        }
    )
)
"""No ``FORCED_TOOL_CHOICE``: Ollama's chat API offers tools but no way to require one, which is
most of why this seat sees prose where the hosted ones see a tool call. The seam refuses that
prose either way — the vendor-side narrowing is a convenience, never the control."""


def build_request(request: PilotRequest, tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Compose the request from the briefing, and only the briefing.

    ``think`` is on for this local-only seat. This differs materially from Gemini: Gemini gets
    ``thinkingBudget > 0`` with ``includeThoughts`` absent, so its trace never comes back; Ollama
    returns ``message.thinking`` to the injected localhost transport. :func:`parse_chat` ignores
    that field, so the trace exists transiently in local process memory but never enters a
    :class:`~nemesis.pilot.providers.seat.ParsedResponse`, move, metadata record or audit event.
    The honest guarantee is therefore local-only handling with no persistence or exposure, not
    that NEMESIS never receives the trace.

    A blind comparison motivated the change: with the trace on, Qwen was preferred in all four
    sampled persona scenarios against the no-reasoning path, largely on deception-awareness —
    the faculty that layer exists for (invariant 13). That was four scenarios, one trial per
    condition and one judge model evaluated in both presentation orders; it is an integration
    signal, not a general quality estimate.

    ``num_predict`` is therefore floored at :data:`THINKING_NUM_PREDICT_FLOOR`. A reasoning trace
    consumes output budget before the answer begins, and the ceiling that was fine without a
    trace produced empty content with one — all of it spent thinking. The floor only raises a
    ceiling that is too low; a caller asking for more still gets more. The sampling settings are
    the ones measured to avoid repetition collapse; see ``scripts/local-review.sh``.
    """
    options: dict[str, Any] = {
        "temperature": 0.6
        if request.decoding.temperature is None
        else request.decoding.temperature,
        "repeat_penalty": 1.15,
        "num_ctx": 16384,
        "num_predict": max(request.decoding.max_output_tokens, THINKING_NUM_PREDICT_FLOOR),
    }
    if request.decoding.seed is not None:
        options["seed"] = request.decoding.seed
    return {
        "model": request.identity.model,
        "messages": [
            {"role": "system", "content": request.instructions},
            {"role": "user", "content": request.context.user_content()},
        ],
        "tools": tools,
        "stream": False,
        "think": True,
        "options": options,
    }


def parse_chat(response: Mapping[str, Any]) -> ParsedResponse:
    """Extract the chosen move as raw data for the mediator to re-validate.

    Never corrects anything. An unknown verb, a missing call, arguments of the wrong shape: all
    pass through to the seam, which refuses them and records the refusal. Fixing them here would
    be the harness quietly making the pilot look better behaved than it is, which for a
    containment demonstration is the one thing that must not happen.
    """
    usage = PilotUsage(
        input_tokens=_count(response.get("prompt_eval_count")),
        output_tokens=_count(response.get("eval_count")),
    )
    model_reported = _text(response.get("model"))
    message = response.get("message")
    if not isinstance(message, Mapping):
        return ParsedResponse(
            move=no_move("the response carried no message"),
            model_reported=model_reported,
            usage=usage,
        )
    calls = message.get("tool_calls")
    if not isinstance(calls, list) or not calls:
        # The model's own prose is echoed, coerced to `str` and capped: a local model explaining
        # in words why it will not choose a verb is the most useful diagnostic this seat
        # produces, and it is also model-authored text moving toward the audit path, so it is
        # bounded here rather than wherever it lands.
        return ParsedResponse(
            move=no_move(_text(message.get("content")) or "the model returned no tool call"),
            model_reported=model_reported,
            usage=usage,
        )
    if len(calls) > 1:
        return ParsedResponse(
            move=ambiguous_move(len(calls)),
            model_reported=model_reported,
            usage=usage,
        )
    call = calls[0]
    function = call.get("function") if isinstance(call, Mapping) else None
    if not isinstance(function, Mapping):
        return ParsedResponse(
            move=no_move("the tool call carried no function"),
            model_reported=model_reported,
            usage=usage,
        )
    return ParsedResponse(
        move=arguments_to_move(function.get("name"), function.get("arguments", {})),
        model_reported=model_reported,
        usage=usage,
    )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object) -> str | None:
    """Model-authored text, coerced and capped before it goes anywhere near a record."""
    if isinstance(value, str) and value:
        return value[:200]
    if value in (None, "", [], {}):
        return None
    return str(value)[:200]


OLLAMA_DIALECT = SeatDialect(
    provider=PROVIDER,
    vendor_label="the local model",
    tools=openai_dialect,
    build=build_request,
    parse=parse_chat,
    transmits_offsite=False,
)


class LocalPilot(ProviderSeat):
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by a model on this machine.

    Exactly the same contract as the hosted seats, which is the property being demonstrated: the
    mediator cannot tell which one is driving, and does not need to.
    """

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        transport: PilotTransport | None = None,
        name: str | None = None,
        decoding: DecodingParameters | None = None,
        retries: RetryPolicy | None = None,
        capabilities: ModelCapabilities | None = None,
        tools: PilotToolSuite = MOVE_TOOL_SUITE,
        clock: Callable[[], datetime] = utcnow,
        sleep: Sleeper | None = None,
    ) -> None:
        super().__init__(
            model=model,
            dialect=OLLAMA_DIALECT,
            capabilities=capabilities or OLLAMA_CAPABILITIES,
            transport=transport,
            decoding=decoding,
            retries=retries,
            tools=tools,
            name=name or f"local:{model}",
            clock=clock,
            sleep=sleep,
        )


OllamaPilot = LocalPilot
"""The registry name for the same seat.

``LocalPilot`` is what the laboratory called it and what the live-injection test imports;
``OllamaPilot`` is what the provider is called. One class, because two would be two things to
keep in step for no gain."""


__all__ = [
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT_SECONDS",
    "LAB_NOTICE",
    "OLLAMA_CAPABILITIES",
    "OLLAMA_DIALECT",
    "PROVIDER",
    "LocalPilot",
    "OllamaPilot",
    "build_request",
    "parse_chat",
]
