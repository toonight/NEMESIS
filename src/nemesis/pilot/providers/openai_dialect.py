"""The OpenAI chat-completions dialect, shared by four providers who are not the same provider.

OpenAI's request and response shape is the lingua franca of tool calling. xAI serves it, vLLM
serves it, Ollama serves a near-identical variant, and a dozen other endpoints serve it because
their clients already speak it. Writing it four times would guarantee four drifts, so it is
written once here.

**And that is exactly where the tempting mistake is.** A shared transport shape is not a shared
identity. If ``XaiPilot`` were implemented by constructing an ``OpenAIPilot``, then every audit
record, every benchmark row and every ``Claim.model_identifier`` for an xAI run would say
``openai`` — and an audit trail that attributes a decision to the wrong vendor is wrong about
precisely the thing it exists to establish. So the dialect is shared and the *seat* is not:
each provider has its own module, its own registry entry, its own
:class:`~nemesis.pilot.providers.contract.ProviderIdentity`, and its own declared capabilities.
The functions here take what varies as arguments rather than assuming a vendor.

Three details in this dialect are security-relevant rather than cosmetic:

- ``tool_choice: "required"`` makes the vendor's own machinery refuse a fifth verb before the
  seam has to. The seam refuses it anyway.
- ``parallel_tool_calls: false`` asks for exactly one action per turn. Where a compatible
  endpoint ignores the field, :func:`parse_chat_completion` refuses the multi-call response
  rather than silently executing the first of several requested actions.
- Nothing reads a ``reasoning`` or ``reasoning_content`` field off the response. OpenAI's
  ``reasoning_effort`` does not return the trace; some compatible endpoints return one anyway,
  and this platform neither requests nor persists private reasoning. What comes back is dropped
  where it lands, because there is no field on the way out to put it in.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from nemesis.pilot.providers.capabilities import ModelCapabilities, ModelCapability
from nemesis.pilot.providers.contract import PilotRequest, PilotUsage
from nemesis.pilot.providers.errors import PilotError, PilotErrorKind, kind_for_status
from nemesis.pilot.providers.seat import ParsedResponse, ambiguous_move, move_from, no_move

OPENAI_COMPATIBLE_CAPABILITIES = ModelCapabilities(
    declared=frozenset(
        {
            ModelCapability.STRUCTURED_TOOL_CALLING,
            ModelCapability.FORCED_TOOL_CHOICE,
            ModelCapability.SINGLE_TOOL_CALL,
            ModelCapability.NATIVE_JSON,
            ModelCapability.USAGE_REPORTING,
            ModelCapability.SEEDING,
            ModelCapability.STREAMING,
        }
    )
)
"""What a chat-completions endpoint is assumed to offer.

Declared configuration and not a discovery: a self-hosted vLLM may honour none of it. The
consequences of each are narrowing only — a missing capability means a parameter is not sent or
a configuration is refused — so an over-generous declaration costs a rejected request from the
vendor, never a widened authority here.
"""


def build_chat_completion(
    request: PilotRequest,
    tools: list[dict[str, Any]],
    *,
    supports_reasoning: bool = False,
    output_limit_field: str = "max_completion_tokens",
) -> dict[str, Any]:
    """Compose a chat-completions request from the briefing, and only the briefing.

    The system message is the untrusted-pilot contract; the user message is the briefing the
    mediator already minimized to deliverable-class material. This adapter holds no broader
    handle, so what reaches a vendor is bounded by what the mediator chose to expose.

    ``output_limit_field`` exists because the compatible endpoints disagree about one field name:
    OpenAI moved to ``max_completion_tokens`` while xAI, vLLM and Ollama kept ``max_tokens``.
    It is a parameter rather than a per-provider copy of this function, which is the whole
    argument for a shared dialect — the differences are named and small, or they are not
    differences in a dialect at all.
    """
    payload: dict[str, Any] = {
        "model": request.identity.model,
        "messages": [
            {"role": "system", "content": request.instructions},
            {"role": "user", "content": request.context.user_content()},
        ],
        "tools": tools,
        "tool_choice": "required",
        "parallel_tool_calls": False,
        output_limit_field: request.decoding.max_output_tokens,
    }
    if request.decoding.temperature is not None:
        payload["temperature"] = request.decoding.temperature
    if request.decoding.seed is not None:
        payload["seed"] = request.decoding.seed
    if supports_reasoning and request.decoding.reasoning is not None:
        payload["reasoning_effort"] = request.decoding.reasoning.value
    return payload


def parse_chat_completion(response: Mapping[str, Any]) -> ParsedResponse:
    """Extract the move the model chose, as raw data for the mediator to re-validate.

    Never corrects anything. An unknown verb, arguments of the wrong shape, a missing call: all
    pass through to the seam, which refuses them and records the refusal. Fixing them here would
    be the harness quietly making the pilot look better behaved than it is.

    An error body is raised as a classified :class:`~nemesis.pilot.providers.errors.PilotError`,
    because some compatible endpoints answer 200 with ``{"error": ...}`` and a parser that read
    that as "no tool call" would report a model refusing when the request never ran.
    """
    _raise_for_error_body(response)
    usage = _usage(response.get("usage"))
    request_id = _text(response.get("id"))
    model_reported = _text(response.get("model"))

    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        return ParsedResponse(
            move=no_move("the response carried no choices"),
            request_id=request_id,
            model_reported=model_reported,
            usage=usage,
        )
    first = choices[0]
    if not isinstance(first, Mapping):
        return ParsedResponse(
            move=no_move("the response carried a malformed choice"),
            request_id=request_id,
            model_reported=model_reported,
            usage=usage,
        )
    finish_reason = _text(first.get("finish_reason"))
    message = first.get("message")
    # A non-dict message (a bare string, a list) has no `.get`. Guarded rather than allowed to
    # raise: every seat must behave identically on a malformed response, and an adversarial
    # review once found this exact divergence between two of them.
    if not isinstance(message, Mapping):
        return ParsedResponse(
            move=no_move("the model returned no tool call"),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=finish_reason,
            usage=usage,
        )

    tool_calls = message.get("tool_calls")
    if not isinstance(tool_calls, list) or not tool_calls:
        detail = _text(message.get("content")) or "the model returned no tool call"
        if finish_reason == "length":
            detail = "the response was cut off before the model chose a verb"
        return ParsedResponse(
            move=no_move(detail),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=finish_reason,
            usage=usage,
        )
    if len(tool_calls) > 1:
        return ParsedResponse(
            move=ambiguous_move(len(tool_calls)),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=finish_reason,
            usage=usage,
        )

    call = tool_calls[0]
    function = call.get("function") if isinstance(call, Mapping) else None
    if not isinstance(function, Mapping):
        return ParsedResponse(
            move=no_move("the tool call carried no function"),
            request_id=request_id,
            model_reported=model_reported,
            finish_reason=finish_reason,
            usage=usage,
        )
    return ParsedResponse(
        move=arguments_to_move(function.get("name"), function.get("arguments", {})),
        request_id=request_id,
        model_reported=model_reported,
        finish_reason=finish_reason,
        usage=usage,
    )


def arguments_to_move(name: object, arguments: object) -> dict[str, Any]:
    """Turn a function call into a raw move, decoding JSON-string arguments if that is what came.

    Unparsable arguments are returned under a key that cannot validate rather than dropped: the
    mediator refuses the move and the transcript records *what* the model sent, which is the
    difference between "the model asked for something malformed" and "the model asked for
    nothing", two facts a benchmark must not confuse.
    """
    if isinstance(arguments, str):
        try:
            decoded: object = json.loads(arguments)
        except json.JSONDecodeError:
            # Recorded rather than dropped, under a key the closed vocabulary forbids — the same
            # marker `move_from` uses for a non-object input, so the four dialects agree. The
            # mediator refuses the move and the transcript says *what* the model sent, which is
            # the difference between "the model asked for something malformed" and "the model
            # asked for nothing" — two facts a benchmark must not confuse.
            return {
                "kind": name if isinstance(name, str) else "unknown",
                "__unparsable_arguments__": arguments[:400],
            }
        return move_from(name, decoded)
    return move_from(name, arguments)


def _raise_for_error_body(response: Mapping[str, Any]) -> None:
    error = response.get("error")
    if not isinstance(error, Mapping):
        return
    message = _text(error.get("message")) or "the provider returned an error"
    status = error.get("code") if isinstance(error.get("code"), int) else None
    raise PilotError(
        kind_for_status(status, message=message) if status else PilotErrorKind.UNKNOWN,
        message[:200],
        status=status,
    )


def _usage(raw: object) -> PilotUsage:
    if not isinstance(raw, Mapping):
        return PilotUsage()
    details = raw.get("completion_tokens_details")
    reasoning = details.get("reasoning_tokens") if isinstance(details, Mapping) else None
    cached = raw.get("prompt_tokens_details")
    cached_tokens = cached.get("cached_tokens") if isinstance(cached, Mapping) else None
    return PilotUsage(
        input_tokens=_count(raw.get("prompt_tokens")),
        output_tokens=_count(raw.get("completion_tokens")),
        reasoning_tokens=_count(reasoning),
        cached_input_tokens=_count(cached_tokens),
    )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: object) -> str | None:
    return value[:400] if isinstance(value, str) and value else None


__all__ = [
    "OPENAI_COMPATIBLE_CAPABILITIES",
    "arguments_to_move",
    "build_chat_completion",
    "parse_chat_completion",
]
