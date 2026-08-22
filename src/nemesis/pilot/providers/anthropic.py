"""The seat for an autonomous frontier cyber model from Anthropic.

The mirror of :mod:`nemesis.pilot.providers.openai`, in Anthropic's dialect and with one
deliberate refusal. What differs, and only this:

- Tools carry their schema under ``input_schema`` rather than ``function.parameters``, and the
  untrusted-pilot contract is a top-level ``system`` field rather than a message.
- ``tool_choice`` is ``{"type": "any", "disable_parallel_tool_use": true}``, which forces one of
  the four tools and asks for exactly one of them. Anthropic's own tool-calling therefore
  refuses a fifth verb before the seam has to, and the seam refuses it anyway.
- A response returns content *blocks*; the move is the first ``tool_use`` block, and a response
  carrying two of them is refused rather than resolved by taking the first.

**Extended thinking is not requested here, and that is a decision rather than an omission.**
Anthropic's reasoning mode returns the reasoning: ``thinking`` blocks come back in the response
body. This platform does not request or persist private reasoning traces — a hidden chain of
thought is not evidence, is not a claim, and has nowhere in the evidence model to live — so the
seat declines the feature rather than receiving a trace and discarding it, and
:data:`ANTHROPIC_CAPABILITIES` does not declare ``REASONING_EFFORT``. Configuring a reasoning
effort against this provider is refused at construction, loudly, instead of being silently
dropped. Where a vendor offers deliberation *without* returning the deliberation — OpenAI's
``reasoning_effort``, Gemini's thinking budget with thoughts excluded — this platform uses it.
The difference is what comes back, not how much the model thinks.

Any ``thinking`` block that arrives regardless is dropped where it lands: :func:`parse_message`
reads ``tool_use`` blocks and nothing else, and there is no field on
:class:`~nemesis.pilot.providers.contract.PilotResponseMetadata` for a trace to occupy.

As with every hosted seat: **no live network in the tree** (the call is an injected transport
whose default refuses), and **a hosted model transmits each briefing to Anthropic** — the same
data-governance decision the founder owns, guarded by the same briefing minimization.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from nemesis.core.temporal import utcnow
from nemesis.pilot.providers.capabilities import ModelCapabilities, ModelCapability
from nemesis.pilot.providers.contract import DecodingParameters, PilotRequest, PilotUsage
from nemesis.pilot.providers.errors import PilotError, PilotErrorKind
from nemesis.pilot.providers.reliability import RetryPolicy, Sleeper
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, PilotToolSuite, anthropic_dialect
from nemesis.pilot.providers.seat import (
    ParsedResponse,
    ProviderSeat,
    SeatDialect,
    ambiguous_move,
    move_from,
    no_move,
)
from nemesis.pilot.providers.transport import PilotTransport

PROVIDER = "anthropic"
API_KEY_ENVIRONMENT_VARIABLE = "ANTHROPIC_API_KEY"

ANTHROPIC_CAPABILITIES = ModelCapabilities(
    declared=frozenset(
        {
            ModelCapability.STRUCTURED_TOOL_CALLING,
            ModelCapability.FORCED_TOOL_CHOICE,
            ModelCapability.SINGLE_TOOL_CALL,
            ModelCapability.USAGE_REPORTING,
            ModelCapability.LARGE_CONTEXT,
            ModelCapability.VISION,
            ModelCapability.STREAMING,
        }
    )
)
"""No ``REASONING_EFFORT`` and no ``SEEDING``, both absent for stated reasons rather than by
oversight: the reasoning mode returns the trace (see the module docstring), and the Messages API
offers no seed, so a deployment asking for reproducibility here is told it cannot have it."""


def build_request(request: PilotRequest, tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Compose the Messages request from the briefing, and only the briefing."""
    payload: dict[str, Any] = {
        "model": request.identity.model,
        "max_tokens": request.decoding.max_output_tokens,
        "system": request.instructions,
        "messages": [{"role": "user", "content": request.context.user_content()}],
        "tools": tools,
        "tool_choice": {"type": "any", "disable_parallel_tool_use": True},
    }
    if request.decoding.temperature is not None:
        payload["temperature"] = request.decoding.temperature
    return payload


def parse_message(response: Mapping[str, Any]) -> ParsedResponse:
    """Extract the move the model chose, as raw data for the mediator to re-validate.

    Reads ``tool_use`` blocks and ignores every other kind — text, and ``thinking`` if a
    deployment ever enables it elsewhere. An unknown tool name or a non-object input passes
    through uncorrected: the seam is what refuses them.
    """
    _raise_for_error_body(response)
    usage = _usage(response.get("usage"))
    request_id = _text(response.get("id"))
    model_reported = _text(response.get("model"))
    stop_reason = _text(response.get("stop_reason"))

    content = response.get("content")
    if not isinstance(content, list):
        return ParsedResponse(
            move=no_move("the response carried no content blocks"),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=stop_reason,
            usage=usage,
        )
    uses = [
        block for block in content if isinstance(block, Mapping) and block.get("type") == "tool_use"
    ]
    if not uses:
        detail = "the model returned no tool use"
        if stop_reason == "max_tokens":
            detail = "the response was cut off before the model chose a verb"
        elif stop_reason == "refusal":
            detail = "the provider's own safety layer declined the request"
        return ParsedResponse(
            move=no_move(detail),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=stop_reason,
            usage=usage,
        )
    if len(uses) > 1:
        return ParsedResponse(
            move=ambiguous_move(len(uses)),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=stop_reason,
            usage=usage,
        )
    block = uses[0]
    return ParsedResponse(
        move=move_from(block.get("name"), block.get("input", {})),
        request_id=request_id,
        model_reported=model_reported,
        finish_reason=stop_reason,
        usage=usage,
    )


def _raise_for_error_body(response: Mapping[str, Any]) -> None:
    if response.get("type") != "error":
        return
    error = response.get("error")
    detail = "the provider returned an error"
    if isinstance(error, Mapping):
        detail = _text(error.get("message")) or detail
    raise PilotError(PilotErrorKind.UNKNOWN, detail[:200], provider=PROVIDER)


def _usage(raw: object) -> PilotUsage:
    if not isinstance(raw, Mapping):
        return PilotUsage()
    return PilotUsage(
        input_tokens=_count(raw.get("input_tokens")),
        output_tokens=_count(raw.get("output_tokens")),
        cached_input_tokens=_count(raw.get("cache_read_input_tokens")),
    )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object) -> str | None:
    return value[:400] if isinstance(value, str) and value else None


ANTHROPIC_DIALECT = SeatDialect(
    provider=PROVIDER,
    vendor_label="Anthropic",
    tools=anthropic_dialect,
    build=build_request,
    parse=parse_message,
)


class AnthropicPilot(ProviderSeat):
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by an Anthropic model."""

    def __init__(
        self,
        *,
        model: str,
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
            dialect=ANTHROPIC_DIALECT,
            capabilities=capabilities or ANTHROPIC_CAPABILITIES,
            transport=transport,
            decoding=decoding,
            retries=retries,
            tools=tools,
            name=name,
            clock=clock,
            sleep=sleep,
        )


__all__ = [
    "ANTHROPIC_CAPABILITIES",
    "ANTHROPIC_DIALECT",
    "API_KEY_ENVIRONMENT_VARIABLE",
    "PROVIDER",
    "AnthropicPilot",
    "build_request",
    "parse_message",
]
