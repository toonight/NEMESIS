"""The seat for an autonomous frontier model from Google, and the two places it is genuinely
different rather than merely differently spelled.

Gemini's ``generateContent`` differs from the other seats in more than field names, and both
differences are handled here rather than smoothed over somewhere shared:

**The schema subset.** ``FunctionDeclaration.parameters`` is an OpenAPI 3.0 subset with no
``$ref``, no ``$defs`` and no ``additionalProperties``. Pydantic emits every enum argument as a
``$ref`` into ``$defs``, so ``run_pivot`` and ``request_effect`` — the two moves whose arguments
are closed enumerations, and therefore the two that matter — arrive in a shape Gemini rejects.
:func:`~nemesis.pilot.providers.schema.to_openapi_subset` inlines the reference and drops the
unsupported keywords, and the thing it must never drop is the ``enum`` that arrives attached to
the reference. Dropping it would leave one vendor's model free to name a pivot type or an
operation class the others cannot — the n-way version of exactly the drift the canonical schema
exists to prevent. A test walks both enum-carrying moves and asserts every value survives.

**The model id is not in the body.** Every other provider routes on ``payload["model"]``; Gemini
routes on the URL. Rather than have the transport reach into a body and mutate it, this dialect
returns an explicit envelope — ``{"model": ..., "request": {...}}`` — so a transport composes
``/v1beta/models/{model}:generateContent`` from the first key and sends the second verbatim. The
consequence is worth stating because it is visible to an operator: ``nemesis pilot-preview
--provider gemini`` shows the envelope, and the bytes that would leave are the value under
``request``.

Reasoning is requested through ``thinkingConfig`` **without** ``includeThoughts``, so the model
may deliberate and the deliberation does not come back. That is the only form of reasoning this
platform asks for anywhere — see :mod:`nemesis.pilot.providers.anthropic` for the vendor where
the same feature returns a trace and is therefore declined. Any ``thought`` part that arrives
anyway is ignored: :func:`parse_generate_content` reads ``functionCall`` parts and nothing else.

As with every hosted seat: no live network in the tree, and a briefing transmitted to Google is
a data-governance decision the founder owns.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Final

from nemesis.core.temporal import utcnow
from nemesis.pilot.providers.capabilities import ModelCapabilities, ModelCapability
from nemesis.pilot.providers.contract import (
    DecodingParameters,
    PilotRequest,
    PilotUsage,
    ReasoningEffort,
)
from nemesis.pilot.providers.errors import PilotError, PilotErrorKind, kind_for_status
from nemesis.pilot.providers.reliability import RetryPolicy, Sleeper
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, PilotToolSuite, gemini_dialect
from nemesis.pilot.providers.seat import (
    ParsedResponse,
    ProviderSeat,
    SeatDialect,
    ambiguous_move,
    move_from,
    no_move,
)
from nemesis.pilot.providers.transport import PilotTransport

PROVIDER = "gemini"
API_KEY_ENVIRONMENT_VARIABLE = "GOOGLE_API_KEY"

THINKING_BUDGET_TOKENS: Final[dict[ReasoningEffort, int]] = {
    ReasoningEffort.LOW: 1024,
    ReasoningEffort.MEDIUM: 8192,
    ReasoningEffort.HIGH: 24576,
}
"""Gemini takes a token budget where the others take a level, so the three levels are mapped to
three budgets. The numbers are a choice and not a measurement: nothing here has been calibrated
against how much thinking a NEMESIS turn actually needs, and a deployment that measures it
should override the mapping rather than trust it."""

GEMINI_CAPABILITIES = ModelCapabilities(
    declared=frozenset(
        {
            ModelCapability.STRUCTURED_TOOL_CALLING,
            ModelCapability.FORCED_TOOL_CHOICE,
            ModelCapability.REASONING_EFFORT,
            ModelCapability.USAGE_REPORTING,
            ModelCapability.NATIVE_JSON,
            ModelCapability.LARGE_CONTEXT,
            ModelCapability.VISION,
            ModelCapability.STREAMING,
        }
    )
)
"""``SINGLE_TOOL_CALL`` is absent: ``functionCallingConfig`` has a mode that *requires* a call
and no switch that forbids a second one, so a Gemini response carrying two function calls is
possible and is refused by the parser rather than prevented by the request. ``SEEDING`` is
absent because ``generateContent`` offers none."""


def build_request(request: PilotRequest, tools: list[dict[str, Any]]) -> dict[str, Any]:
    """Compose the ``generateContent`` envelope from the briefing, and only the briefing."""
    generation: dict[str, Any] = {"maxOutputTokens": request.decoding.max_output_tokens}
    if request.decoding.temperature is not None:
        generation["temperature"] = request.decoding.temperature
    if request.decoding.reasoning is not None:
        # No `includeThoughts`. The model may deliberate; the deliberation does not come back.
        generation["thinkingConfig"] = {
            "thinkingBudget": THINKING_BUDGET_TOKENS[request.decoding.reasoning]
        }
    body: dict[str, Any] = {
        "systemInstruction": {"parts": [{"text": request.instructions}]},
        "contents": [
            {
                "role": "user",
                "parts": [{"text": request.context.user_content()}],
            }
        ],
        "tools": [{"functionDeclarations": tools}],
        "toolConfig": {
            "functionCallingConfig": {
                "mode": "ANY",
                # Named explicitly as well as offered. Two narrowings that mean the same thing,
                # because this is the one vendor whose tool list travels nested two levels deep
                # and a nesting mistake would silently offer nothing at all.
                "allowedFunctionNames": [tool["name"] for tool in tools],
            }
        },
        "generationConfig": generation,
    }
    return {"model": request.identity.model, "request": body}


def parse_generate_content(response: Mapping[str, Any]) -> ParsedResponse:
    """Extract the move the model chose, as raw data for the mediator to re-validate."""
    _raise_for_error_body(response)
    _raise_for_prompt_block(response)
    usage = _usage(response.get("usageMetadata"))
    request_id = _text(response.get("responseId"))
    model_reported = _text(response.get("modelVersion"))

    candidates = response.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return ParsedResponse(
            move=no_move("the response carried no candidates"),
            request_id=request_id,
            model_reported=model_reported,
            usage=usage,
        )
    first = candidates[0]
    if not isinstance(first, Mapping):
        return ParsedResponse(
            move=no_move("the response carried a malformed candidate"),
            request_id=request_id,
            model_reported=model_reported,
            usage=usage,
        )
    finish_reason = _text(first.get("finishReason"))
    content = first.get("content")
    parts = content.get("parts") if isinstance(content, Mapping) else None
    calls = (
        [
            part["functionCall"]
            for part in parts
            if isinstance(part, Mapping) and isinstance(part.get("functionCall"), Mapping)
        ]
        if isinstance(parts, list)
        else []
    )
    if not calls:
        detail = "the model returned no function call"
        if finish_reason == "MAX_TOKENS":
            detail = "the response was cut off before the model chose a verb"
        elif finish_reason in {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST"}:
            detail = f"the provider's own safety layer declined the request ({finish_reason})"
        return ParsedResponse(
            move=no_move(detail),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=finish_reason,
            usage=usage,
        )
    if len(calls) > 1:
        return ParsedResponse(
            move=ambiguous_move(len(calls)),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=finish_reason,
            usage=usage,
        )
    call = calls[0]
    return ParsedResponse(
        move=move_from(call.get("name"), call.get("args", {})),
        request_id=request_id,
        model_reported=model_reported,
        finish_reason=finish_reason,
        usage=usage,
    )


def _raise_for_error_body(response: Mapping[str, Any]) -> None:
    error = response.get("error")
    if not isinstance(error, Mapping):
        return
    message = _text(error.get("message")) or "the provider returned an error"
    code = error.get("code")
    status = code if isinstance(code, int) and not isinstance(code, bool) else None
    raise PilotError(
        kind_for_status(status, message=message) if status else PilotErrorKind.UNKNOWN,
        message[:200],
        provider=PROVIDER,
        status=status,
    )


def _raise_for_prompt_block(response: Mapping[str, Any]) -> None:
    """A blocked *prompt* is not a model declining to move; the turn never happened.

    Distinguished from an empty candidate list because a benchmark that recorded "the model
    chose no verb" for a request the provider never ran would attribute a vendor's policy
    decision to the model's judgement.
    """
    feedback = response.get("promptFeedback")
    if not isinstance(feedback, Mapping):
        return
    reason = feedback.get("blockReason")
    if not isinstance(reason, str) or not reason:
        return
    raise PilotError(
        PilotErrorKind.REFUSED_BY_PROVIDER,
        f"the provider blocked the request before the model saw it ({reason})",
        provider=PROVIDER,
    )


def _usage(raw: object) -> PilotUsage:
    if not isinstance(raw, Mapping):
        return PilotUsage()
    return PilotUsage(
        input_tokens=_count(raw.get("promptTokenCount")),
        output_tokens=_count(raw.get("candidatesTokenCount")),
        reasoning_tokens=_count(raw.get("thoughtsTokenCount")),
        cached_input_tokens=_count(raw.get("cachedContentTokenCount")),
    )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object) -> str | None:
    return value[:400] if isinstance(value, str) and value else None


GEMINI_DIALECT = SeatDialect(
    provider=PROVIDER,
    vendor_label="Google Gemini",
    tools=gemini_dialect,
    build=build_request,
    parse=parse_generate_content,
)


class GeminiPilot(ProviderSeat):
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by a Google Gemini model."""

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
            dialect=GEMINI_DIALECT,
            capabilities=capabilities or GEMINI_CAPABILITIES,
            transport=transport,
            decoding=decoding,
            retries=retries,
            tools=tools,
            name=name,
            clock=clock,
            sleep=sleep,
        )


__all__ = [
    "API_KEY_ENVIRONMENT_VARIABLE",
    "GEMINI_CAPABILITIES",
    "GEMINI_DIALECT",
    "PROVIDER",
    "THINKING_BUDGET_TOKENS",
    "GeminiPilot",
    "build_request",
    "parse_generate_content",
]
