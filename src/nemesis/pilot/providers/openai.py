"""The seat for an autonomous frontier cyber model from OpenAI.

The :class:`~nemesis.pilot.pilot.AutonomousPilot` protocol is vendor-neutral, and that
neutrality is load-bearing: the security argument in ADR-0008 must not depend on *which* model
drives, because a containment that only held for a well-behaved model would be no containment at
all. This module is one concrete instance of that seat and it changes none of the limits. It
changes how the briefing is presented and how a move is elicited, and nothing else.

**A hosted model means the briefing is transmitted to OpenAI.** This is the consequence a
vendor-neutral seat did not have to reckon with, and it is stated here rather than discovered in
an incident. The request is composed *only* from the
:class:`~nemesis.pilot.moves.Briefing`, and the mediator filters that briefing to
deliverable-class material — internal leads (persona linkage) and RESTRICTED nodes
(human-identity leads) are dropped, with a fail-closed backstop scan behind it. An adversarial
review found an earlier version that did *not* filter, leaking a materialized human-identity
lead ("john doe") into this request; the import contract alone did not stop it, because the
material arrived through the graph a pivot had populated, not through an import. So the
minimization that keeps an untrusted pilot from *holding* the withheld band is also what keeps
it from being *sent to a third party*.

Whether CTI data may transit OpenAI at all is a data-governance decision the founder owns; a
real deployment needs an enterprise / zero-retention arrangement before this is wired. Nothing
here makes that decision, and ``nemesis pilot-preview --provider openai`` exists so it can be
made by reading exactly what would leave rather than by imagining it.

This module asserts nothing about which OpenAI models exist and hardcodes no capabilities beyond
the chat-completions dialect. ``model`` is configuration the deployment supplies.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from nemesis.core.temporal import utcnow
from nemesis.pilot.providers.capabilities import ModelCapabilities, ModelCapability
from nemesis.pilot.providers.contract import DecodingParameters, PilotRequest
from nemesis.pilot.providers.openai_dialect import (
    OPENAI_COMPATIBLE_CAPABILITIES,
    build_chat_completion,
    parse_chat_completion,
)
from nemesis.pilot.providers.reliability import RetryPolicy, Sleeper
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, PilotToolSuite, openai_dialect
from nemesis.pilot.providers.seat import ProviderSeat, SeatDialect
from nemesis.pilot.providers.transport import PilotTransport

PROVIDER = "openai"
API_KEY_ENVIRONMENT_VARIABLE = "OPENAI_API_KEY"
"""The environment variable a *transport* reads. Nothing in this package reads it.

Recorded so ``nemesis providers`` can tell an operator what a deployment must supply, and so the
answer to "where does the credential live" is a documented boundary rather than a search.
"""

OPENAI_CAPABILITIES = ModelCapabilities(
    declared=OPENAI_COMPATIBLE_CAPABILITIES.declared
    | {ModelCapability.REASONING_EFFORT, ModelCapability.LARGE_CONTEXT, ModelCapability.VISION}
)
"""Reasoning effort is declared here and not on the base dialect for a specific reason: OpenAI's
``reasoning_effort`` changes how much the model deliberates without returning the deliberation.
That is the only form of it this platform will request — see
:mod:`nemesis.pilot.providers.anthropic` for the vendor where the same feature returns a trace
and is therefore declined."""


def build_request(request: PilotRequest, tools: list[dict[str, Any]]) -> dict[str, Any]:
    return build_chat_completion(request, tools, supports_reasoning=True)


OPENAI_DIALECT = SeatDialect(
    provider=PROVIDER,
    vendor_label="OpenAI",
    tools=openai_dialect,
    build=build_request,
    parse=parse_chat_completion,
)


class OpenAIPilot(ProviderSeat):
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by an OpenAI model.

    Holds a model id, a dialect and a transport, and nothing of NEMESIS — no engine, no graph,
    no capability, no key. It does not trust the response: a hijacked or malfunctioning model is
    contained downstream exactly as a scripted adversary is.
    """

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
            dialect=OPENAI_DIALECT,
            capabilities=capabilities or OPENAI_CAPABILITIES,
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
    "OPENAI_CAPABILITIES",
    "OPENAI_DIALECT",
    "PROVIDER",
    "OpenAIPilot",
    "build_request",
]
