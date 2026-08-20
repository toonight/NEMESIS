"""The concrete seat for an autonomous, frontier cyber model from Anthropic (a Claude cyber
model). The mirror of :mod:`nemesis.pilot.openai_pilot`, in Anthropic's dialect.

The :class:`~nemesis.pilot.pilot.AutonomousPilot` protocol is vendor-neutral, and that
neutrality is the security argument: the containment in ADR-0008 must not depend on which model
drives, so this adapter changes none of the limits. It changes only how the briefing is
presented (Anthropic's Messages API) and how a move is elicited (a ``tool_use`` block).

What is shared with the OpenAI seat lives in :mod:`nemesis.pilot.model_seat` — the
untrusted-pilot contract, each move's argument schema, and the not-wired discipline — so the two
seats cannot drift into saying different things to two vendors. What differs, and only this:

- Tools carry their schema under ``input_schema`` (not ``function.parameters``), and the system
  prompt is a top-level ``system`` field. ``tool_choice`` is ``{"type": "any"}``, which forces
  the model to use one of the four tools — so Anthropic's own tool-calling refuses a fifth verb,
  and the tool use is still re-validated at the mediator's seam (invariant 5).
- A response returns ``tool_use`` blocks whose ``input`` is already an object, so there is no
  JSON string to parse — but it is still untrusted, and an unknown tool name lands as a refused
  move, not a correction here.

As with the OpenAI seat: **no live network in the tree** (the call is an injected transport, the
default refuses), and **a hosted model transmits each briefing to Anthropic** — the same
data-governance decision the founder owns. It is guarded by the same briefing minimization: the
mediator's ``_brief`` filters the projection to deliverable-class material, so internal leads
and human-identity nodes are not sent here either (an adversarial review found and closed a leak
of a human-identity lead through this path, on both seats identically). This module does not
assert that any particular Anthropic model exists or hardcode its capabilities; ``model`` is
configuration the deployment supplies.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from nemesis.pilot.model_seat import (
    MOVE_MODELS,
    SYSTEM_INSTRUCTIONS,
    argument_schema,
    move_description,
    unwired_error,
)
from nemesis.pilot.moves import Briefing

DEFAULT_MAX_TOKENS = 1024


@runtime_checkable
class AnthropicTransport(Protocol):
    """The one impure boundary: whatever carries a request to Anthropic and back.

    Injected, so this module has no network code and no HTTP dependency. A real transport is an
    HTTP client holding the API key and the endpoint — supplied at deployment, the
    ``REQUIRES_EXTERNAL_DATA`` step.
    """

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnwiredAnthropicTransport:
    """The default transport: it refuses. A build with no Anthropic wiring contacts nothing."""

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise unwired_error("Anthropic")


def anthropic_tool_schemas() -> list[dict[str, Any]]:
    """The four moves, as Anthropic tools. Exactly four — the closed vocabulary, in the shape
    that lets Anthropic's tool-calling refuse a fifth for us."""
    return [
        {
            "name": name,
            "description": move_description(model),
            "input_schema": argument_schema(model),
        }
        for model, name in MOVE_MODELS
    ]


def build_request(
    briefing: Briefing, *, model: str, max_tokens: int = DEFAULT_MAX_TOKENS
) -> dict[str, Any]:
    """Compose the Anthropic request from the briefing, and only the briefing.

    The untrusted-pilot contract is the top-level ``system`` field; the briefing is the single
    user message; the four move tools are offered with ``tool_choice`` forcing one. Built from
    the projection the mediator already minimized, so what reaches Anthropic is bounded by what
    the mediator chose to expose — never a broader handle, because this adapter holds none.
    """
    return {
        "model": model,
        "max_tokens": max_tokens,
        "system": SYSTEM_INSTRUCTIONS,
        "messages": [{"role": "user", "content": briefing.model_dump_json()}],
        "tools": anthropic_tool_schemas(),
        "tool_choice": {"type": "any"},
    }


def parse_tool_use(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the move the model chose, as a raw mapping for the mediator to re-validate.

    Returns ``{"kind": <tool name>, **input}`` from the first ``tool_use`` block. An unknown tool
    name or a non-object input is returned as-is rather than corrected — the mediator's seam is
    what refuses them. A response with no tool use at all returns a mapping that cannot validate.
    """
    try:
        for block in response["content"]:
            if isinstance(block, Mapping) and block.get("type") == "tool_use":
                name = block["name"]
                tool_input = block.get("input", {})
                if isinstance(tool_input, Mapping):
                    # The tool NAME is authoritative for the verb; a "kind" smuggled into the
                    # input must not override it, or the audit trail would name the wrong verb
                    # (a `conclude` tool_use acting as a `request_effect`).
                    fields = {key: value for key, value in tool_input.items() if key != "kind"}
                    return {"kind": name, **fields}
                return {"kind": name}
    except (KeyError, TypeError):
        pass
    return {"kind": "__no_move__", "detail": "the model returned no tool use"}


class AnthropicPilot:
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by an Anthropic cyber model.

    Holds a model id and a transport, and nothing of NEMESIS. ``propose`` builds a request from
    the briefing, sends it through the transport, and returns the tool use as a raw mapping for
    the mediator to validate. It does not trust the response: a hijacked or malfunctioning model
    is contained downstream exactly as a scripted adversary is.
    """

    def __init__(
        self,
        *,
        model: str,
        transport: AnthropicTransport | None = None,
        name: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._model = model
        self._transport: AnthropicTransport = transport or UnwiredAnthropicTransport()
        self._name = name or f"anthropic:{model}"
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return self._name

    async def propose(self, briefing: Briefing) -> Mapping[str, Any]:
        response = await self._transport.request(
            build_request(briefing, model=self._model, max_tokens=self._max_tokens)
        )
        return parse_tool_use(response)


__all__ = [
    "AnthropicPilot",
    "AnthropicTransport",
    "UnwiredAnthropicTransport",
    "anthropic_tool_schemas",
    "build_request",
    "parse_tool_use",
]
