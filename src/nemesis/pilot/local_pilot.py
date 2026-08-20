"""A pilot that runs on this machine, so the lab POC needs nobody's permission.

The vendor seats (:mod:`nemesis.pilot.openai_pilot`, :mod:`nemesis.pilot.anthropic_pilot`)
are the shape a production deployment takes, and both are blocked on the same founder
decision: a hosted model means every briefing is transmitted to a third party, which is a
data-governance question this repository cannot answer for anybody.

This seat sidesteps that entirely by not leaving the machine. Ollama listens on localhost, the
weights sit on local disk, and no briefing crosses a network boundary — so a laboratory
proof-of-concept can put a **real autonomous model** in the seat today, driving the real
harness against synthetic data, with invariant 15 untouched and no decision pending.

**Why a weak model is the right one for this.** The local model was measured before it was
ever considered for this job: on a deliberately planted contradiction it scored 3/6, then 5/10,
and it collapsed into repetition at the wrong sampling settings. That is not a caveat here —
it is the point. A limiter that only holds against a well-behaved pilot holds nothing, and the
containment tests have always argued that the seat must not depend on who is driving. This is
the first time something genuinely unpredictable sits in it.

Expect it to emit malformed moves, name entities that do not exist, and occasionally return
prose instead of a tool call. Every one of those is already a recorded refusal rather than a
crash, and a POC where that never happened would be a POC that proved less.

Status: `IMPLEMENTED`, `SIMULATED` data, local inference only. This is the laboratory
configuration; a production deployment uses a vendor seat and owes the founder decision first.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final, Protocol, runtime_checkable

from nemesis.pilot.model_seat import (
    MOVE_MODELS,
    SYSTEM_INSTRUCTIONS,
    argument_schema,
    move_description,
    unwired_error,
)
from nemesis.pilot.moves import Briefing

DEFAULT_ENDPOINT: Final = "http://localhost:11434/api/chat"
DEFAULT_MODEL: Final = "qwen3.8:27b-q8_0"
DEFAULT_TIMEOUT_SECONDS: Final = 180.0

LAB_NOTICE: Final = (
    "Local inference. No briefing leaves this machine, so the hosted-model data-governance "
    "question does not arise — and does not get answered by omission either."
)


def local_tool_schemas() -> list[dict[str, Any]]:
    """The four moves in Ollama's tool dialect — OpenAI-shaped, from the shared definitions."""
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
    """Compose the request from the briefing, and only the briefing.

    ``think`` is off: Qwen3 defaults to a long hidden reasoning trace, and a review that
    produced zero bytes for ten minutes was that trace being generated and buffered. The
    sampling settings are the ones measured to avoid repetition collapse — see
    ``scripts/local-review.sh``, where the same lesson was learned the hard way.
    """
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_INSTRUCTIONS},
            {"role": "user", "content": briefing.model_dump_json()},
        ],
        "tools": local_tool_schemas(),
        "stream": False,
        "think": False,
        "options": {"temperature": 0.6, "repeat_penalty": 1.15, "num_ctx": 16384},
    }


def parse_tool_call(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the chosen move as raw data for the mediator to re-validate.

    Never corrects anything. An unknown verb, a missing call, arguments of the wrong shape:
    all pass through to the seam, which refuses them and records the refusal. Fixing them here
    would be the harness quietly making the pilot look better behaved than it is, which for a
    containment demonstration is the one thing that must not happen.
    """
    try:
        message = response["message"]
        calls = message.get("tool_calls") or ()
        if not calls:
            return {
                "kind": "__no_move__",
                "detail": (message.get("content") or "the model returned no tool call")[:200],
            }
        function = calls[0]["function"]
        name = function["name"]
        arguments = function.get("arguments", {})
    except (KeyError, IndexError, TypeError, AttributeError):
        return {"kind": "__no_move__", "detail": "the model returned no tool call"}

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            return {"kind": name, "__unparsable_arguments__": arguments}
    if not isinstance(arguments, Mapping):
        return {"kind": name}
    # The tool NAME is authoritative for the verb; a "kind" smuggled into the arguments must
    # not override it, or the audit trail records the wrong move.
    return {"kind": name, **{k: v for k, v in arguments.items() if k != "kind"}}


@runtime_checkable
class LocalTransport(Protocol):
    """Whatever actually carries a request to the local model and back.

    Injected, exactly as in the vendor seats, and for a reason worth stating because
    "it is only localhost" is the argument that would skip it. The prohibited-content
    scan caught the first version of this file importing ``urllib`` directly, and the
    scan was right: the rule is that **only the collection plane holds network
    capability**, and a rule that yields to "but this destination is safe" is a habit
    rather than a control. The pilot plane is where an untrusted model's output arrives;
    it is the last place that should also own a socket.

    So this module has no network code at all, and a laboratory wires a transport in — the
    same shape a production deployment uses for OpenAI or Anthropic, which also keeps the
    three seats honestly comparable.
    """

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnwiredLocalTransport:
    """The default: it refuses. A build with nothing wired contacts nothing."""

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise unwired_error("the local model")


class LocalPilot:
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by a model on this machine.

    Holds a model name and a transport, and nothing of NEMESIS — no engine, no graph, no
    capability, no key. Exactly the same contract as the vendor seats, which is the property
    being demonstrated: the mediator cannot tell which one is driving, and does not need to.
    """

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        transport: LocalTransport | None = None,
    ) -> None:
        self._model = model
        self._transport: LocalTransport = transport or UnwiredLocalTransport()
        self.calls = 0

    @property
    def name(self) -> str:
        return f"local:{self._model}"

    async def propose(self, briefing: Briefing) -> Mapping[str, Any]:
        self.calls += 1
        body = await self._transport.request(build_request(briefing, model=self._model))
        return parse_tool_call(body)


__all__ = [
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "LAB_NOTICE",
    "LocalPilot",
    "LocalTransport",
    "UnwiredLocalTransport",
    "build_request",
    "local_tool_schemas",
    "parse_tool_call",
]
