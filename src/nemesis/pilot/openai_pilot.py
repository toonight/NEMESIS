"""The concrete seat for the specific pilot NEMESIS is built for: an autonomous, frontier
cyber model from OpenAI (a GPT-5.6-class "cyber" model, in the founder's words).

The :class:`~nemesis.pilot.pilot.AutonomousPilot` protocol is deliberately vendor-neutral, and
that neutrality is load-bearing: the security argument in ADR-0008 must not depend on *which*
model drives, because a containment that only held for a well-behaved model would be no
containment at all. This module is one concrete implementation of that seat — the one wired to
the model the founder named — and it changes none of the limits. It changes how the briefing is
presented and how a move is elicited.

Three things are specific to this pilot, and only these:

**The closed vocabulary is presented as OpenAI tools.** The four moves become four function
schemas (:func:`move_tool_schemas`), derived from the move models themselves, with
``tool_choice`` forcing the model to emit exactly one. The model is then constrained to the
four verbs by OpenAI's own tool-calling machinery — it cannot *name* a fifth — and what comes
back is still re-validated at the mediator's seam, because a tool call is untrusted data like
any other model output (invariant 5). Belt, and braces.

**No live network lives in this tree.** The call to OpenAI is an injected
:class:`OpenAITransport`, and the default is :class:`UnwiredTransport`, which refuses. Wiring a
real transport — an HTTP client, an API key, an egress path — is the ``REQUIRES_EXTERNAL_DATA``
step a deployment takes, outside a repository whose MVP contacts nothing (invariant 15). An
unwired pilot driven anyway does not reach out and does not crash: it raises
:class:`PilotNotWiredError`, which the mediator now contains as a refused move and, in the end,
a recorded halt.

**A hosted model means the briefing is transmitted to OpenAI.** This is the consequence of
"specifically OpenAI's hosted model" that the abstract seat did not have to reckon with, and it
is stated here rather than discovered in an incident. :func:`build_request` composes the
request *only* from the :class:`~nemesis.pilot.moves.Briefing`, and the mediator filters that
briefing to deliverable-class material — internal leads (persona linkage) and RESTRICTED nodes
(human-identity leads) are dropped in ``_brief``, with a fail-closed backstop scan behind it. An
adversarial review found an earlier version that did *not* filter, leaking a materialized
human-identity lead ("john doe") into this request; the import contract alone did not stop
it, because the material arrived through the graph a pivot had populated, not through an import.
So the minimization that keeps an untrusted pilot from *holding* the withheld band is now also
what keeps it from being *sent to a third party*. Whether CTI data may transit OpenAI at all is
a data-governance decision the founder owns; a real deployment needs an enterprise /
zero-retention arrangement before this is wired. Nothing here makes that decision.

This module does not assert that any particular OpenAI model exists or hardcode its
capabilities. ``model`` is configuration the deployment supplies.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from nemesis.pilot.model_seat import (
    MOVE_MODELS,
    SYSTEM_INSTRUCTIONS,
    PilotNotWiredError,
    argument_schema,
    move_description,
    unwired_error,
)
from nemesis.pilot.moves import Briefing


@runtime_checkable
class OpenAITransport(Protocol):
    """The one impure boundary: whatever actually carries a request to OpenAI and back.

    Injected rather than built here, so this module has no network code and no HTTP dependency,
    and a test drives the whole adapter with a function that returns a canned response. A real
    transport is an HTTP client holding the API key and the endpoint — supplied at deployment,
    the ``REQUIRES_EXTERNAL_DATA`` step.
    """

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnwiredTransport:
    """The default transport: it refuses. A build with no OpenAI wiring contacts nothing."""

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise unwired_error("OpenAI")


def move_tool_schemas() -> list[dict[str, Any]]:
    """The four moves, as OpenAI tools. Exactly four — the closed vocabulary, expressed in the
    one shape that lets OpenAI's tool-calling refuse a fifth for us."""
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": move_description(model),
                "parameters": argument_schema(model),
            },
        }
        for model, name in MOVE_MODELS
    ]


def build_request(briefing: Briefing, *, model: str) -> dict[str, Any]:
    """Compose the OpenAI request from the briefing, and only the briefing.

    The request carries the untrusted-pilot contract as the system message and the briefing as
    the user message, with the four move tools and ``tool_choice`` forcing a move. Built from
    the projection the mediator already minimized, so what reaches OpenAI is bounded by what the
    mediator chose to expose — never a broader handle, because this adapter holds none.

    The chat-completions shape here is the recognizable one; the exact endpoint and request
    dialect are transport concerns a deployment adapts.
    """
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTIONS},
            {"role": "user", "content": briefing.model_dump_json()},
        ],
        "tools": move_tool_schemas(),
        "tool_choice": "required",
    }


def parse_tool_call(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the move the model chose, as a raw mapping for the mediator to re-validate.

    Returns ``{"kind": <tool name>, **arguments}``. An unknown tool name or malformed arguments
    are returned as-is rather than corrected — the mediator's seam is what refuses them, so a
    model that names a verb outside the vocabulary lands as a refused, recorded move, not an
    exception here. A response with no tool call at all returns a mapping that cannot validate.
    """
    try:
        choices = response["choices"]
        message = choices[0]["message"]
        # A non-dict message (a bare string, a list) has no `.get`; guard it the way the
        # Anthropic seat guards its blocks, so a malformed response returns the sentinel here
        # rather than raising — the two seats must behave identically, and the contract of this
        # function is "not an exception here".
        if not isinstance(message, Mapping):
            return {"kind": "__no_move__", "detail": "the model returned no tool call"}
        tool_calls = message.get("tool_calls")
        if not tool_calls:
            return {"kind": "__no_move__", "detail": "the model returned no tool call"}
        call = tool_calls[0]["function"]
        name = call["name"]
        arguments = call.get("arguments", {})
    except (KeyError, IndexError, TypeError, AttributeError):
        return {"kind": "__no_move__", "detail": "the model returned no tool call"}

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            return {"kind": name, "__unparsable_arguments__": arguments}
    if not isinstance(arguments, dict):
        return {"kind": name}
    # The tool NAME is authoritative for the verb. A model that also puts a "kind" inside the
    # arguments must not be able to override it — otherwise a call to the `conclude` tool with
    # a `request_effect` "kind" in its arguments would be recorded as a conclude while acting
    # as a request_effect, and the audit trail would name the wrong verb.
    arguments = {key: value for key, value in arguments.items() if key != "kind"}
    return {"kind": name, **arguments}


class OpenAIPilot:
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by an OpenAI cyber model.

    Holds a model id and a transport, and nothing of NEMESIS — no engine, no graph, no
    capability, no key. ``propose`` builds a request from the briefing, sends it through the
    transport, and returns the tool call as a raw mapping for the mediator to validate. It does
    not trust the response: a hijacked or malfunctioning model is contained downstream exactly
    as a scripted adversary is.
    """

    def __init__(
        self,
        *,
        model: str,
        transport: OpenAITransport | None = None,
        name: str | None = None,
    ) -> None:
        self._model = model
        self._transport: OpenAITransport = transport or UnwiredTransport()
        self._name = name or f"openai:{model}"

    @property
    def name(self) -> str:
        return self._name

    async def propose(self, briefing: Briefing) -> Mapping[str, Any]:
        response = await self._transport.request(build_request(briefing, model=self._model))
        return parse_tool_call(response)


__all__ = [
    "SYSTEM_INSTRUCTIONS",
    "OpenAIPilot",
    "OpenAITransport",
    "PilotNotWiredError",
    "UnwiredTransport",
    "build_request",
    "move_tool_schemas",
    "parse_tool_call",
]
