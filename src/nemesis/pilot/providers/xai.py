"""The seat for an autonomous frontier model from xAI, which is not an OpenAI seat wearing a hat.

xAI serves an OpenAI-compatible chat-completions API, so the *transport shape* is shared —
:mod:`nemesis.pilot.providers.openai_dialect` is used verbatim and there is no second copy of it
to drift. The identity is not shared, and that distinction is the whole reason this module
exists rather than a line of configuration on ``OpenAIPilot``.

**Why masquerading would be a defect and not a shortcut.** ``pilot.name`` reaches
:attr:`nemesis.core.claims.Claim.model_identifier` on every belief a pilot records, and the
provider reaches the hash-chained audit trail on every move. A run driven by Grok that recorded
``openai`` would produce a claim naming the wrong model as its author and an audit record naming
the wrong vendor as the recipient of the briefing — in a platform whose entire premise is that
provenance is checkable, on the one record that exists to make a session reconstructible. It
would also quietly break the thing model diversity is *for*: a challenger from a different
family is only independent if you can tell which family answered.

So: shared dialect, distinct seat, distinct registry entry, distinct capabilities, distinct
environment variable. What is genuinely different is small and named here — ``max_tokens``
rather than ``max_completion_tokens`` — and everything else is the argument in
:mod:`nemesis.pilot.providers.openai_dialect`.
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

PROVIDER = "xai"
API_KEY_ENVIRONMENT_VARIABLE = "XAI_API_KEY"

XAI_CAPABILITIES = ModelCapabilities(
    declared=OPENAI_COMPATIBLE_CAPABILITIES.declared
    | {ModelCapability.REASONING_EFFORT, ModelCapability.LARGE_CONTEXT}
)
"""Declared configuration, and wrong for some of xAI's own line-up: not every Grok model accepts
``reasoning_effort``, and one that does not will reject the parameter. That rejection is
classified as ``UNSUPPORTED_PARAMETER`` and reported as a configuration error rather than
repaired by dropping the field and trying again — a retry that quietly changed the decision
surface would produce a run whose audit record names a configuration that did not run."""


def build_request(request: PilotRequest, tools: list[dict[str, Any]]) -> dict[str, Any]:
    return build_chat_completion(
        request, tools, supports_reasoning=True, output_limit_field="max_tokens"
    )


XAI_DIALECT = SeatDialect(
    provider=PROVIDER,
    vendor_label="xAI",
    tools=openai_dialect,
    build=build_request,
    parse=parse_chat_completion,
)


class XaiPilot(ProviderSeat):
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by an xAI model.

    Structurally identical to every other seat, which is the property being demonstrated: the
    mediator cannot tell which one is driving, and does not need to.
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
            dialect=XAI_DIALECT,
            capabilities=capabilities or XAI_CAPABILITIES,
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
    "PROVIDER",
    "XAI_CAPABILITIES",
    "XAI_DIALECT",
    "XaiPilot",
    "build_request",
]
