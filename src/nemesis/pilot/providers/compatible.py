"""A seat for any OpenAI-compatible endpoint that is not one of the named vendors.

Self-hosted vLLM, an inference gateway, a Mistral or Together endpoint speaking the
chat-completions dialect, a model served on infrastructure the deployment owns. All of them work
through the same dialect as OpenAI and xAI, and none of them should be *recorded* as OpenAI.

**The identity is supplied, not guessed.** ``provider`` defaults to ``openai_compatible`` and a
deployment is expected to override it with something meaningful — ``vllm``, ``mistral``, the
name of an internal gateway. That string reaches the audit trail on every move and
``Claim.model_identifier`` on every belief, so it is the answer to "which model produced this
conclusion" and it deserves to be true. A generic seat exists so an unnamed endpoint is
*possible*; it does not exist so an endpoint can be anonymous.

**Capabilities are declared and are probably wrong.** A vLLM build may honour ``tool_choice``,
or ignore it; may return usage, or not; may accept a seed, or accept and ignore it. The default
declaration is the conservative one — structured tool calling and nothing else — so a
configuration asking for a seed or a reasoning effort is refused at construction rather than
silently dropped. A deployment that has measured its own endpoint passes a wider set. Nothing
about this can widen NEMESIS's authority: every capability decides only whether a *parameter is
sent*.

This seat is the reason the registry is a mapping of specs rather than a chain of ``elif
provider ==``: adding a sixth vendor that speaks this dialect is one entry and no new module.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from nemesis.core.temporal import utcnow
from nemesis.pilot.providers.capabilities import ModelCapabilities, ModelCapability
from nemesis.pilot.providers.contract import DecodingParameters, PilotRequest
from nemesis.pilot.providers.openai_dialect import build_chat_completion, parse_chat_completion
from nemesis.pilot.providers.reliability import RetryPolicy, Sleeper
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, PilotToolSuite, openai_dialect
from nemesis.pilot.providers.seat import ProviderSeat, SeatDialect
from nemesis.pilot.providers.transport import PilotTransport

PROVIDER = "openai_compatible"
API_KEY_ENVIRONMENT_VARIABLE = "NEMESIS_COMPATIBLE_API_KEY"
"""Deliberately NEMESIS-namespaced rather than borrowed from a vendor. An endpoint that is not
OpenAI must not be reached with ``OPENAI_API_KEY``: a credential sent to the wrong host is the
one mistake in this area that cannot be undone by editing a config file."""

CONSERVATIVE_CAPABILITIES = ModelCapabilities(
    declared=frozenset({ModelCapability.STRUCTURED_TOOL_CALLING})
)
"""The floor, and the honest default for an endpoint nobody here has measured."""


def build_request(request: PilotRequest, tools: list[dict[str, Any]]) -> dict[str, Any]:
    return build_chat_completion(
        request,
        tools,
        supports_reasoning=request.decoding.reasoning is not None,
        output_limit_field="max_tokens",
    )


def dialect_for(provider: str, vendor_label: str) -> SeatDialect:
    """A dialect carrying a caller-supplied identity, so the audit trail names the real endpoint."""
    return SeatDialect(
        provider=provider,
        vendor_label=vendor_label,
        tools=openai_dialect,
        build=build_request,
        parse=parse_chat_completion,
    )


class GenericCompatiblePilot(ProviderSeat):
    """An :class:`~nemesis.pilot.pilot.AutonomousPilot` backed by an OpenAI-compatible endpoint."""

    def __init__(
        self,
        *,
        model: str,
        provider: str = PROVIDER,
        vendor_label: str | None = None,
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
            dialect=dialect_for(provider, vendor_label or provider),
            capabilities=capabilities or CONSERVATIVE_CAPABILITIES,
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
    "CONSERVATIVE_CAPABILITIES",
    "PROVIDER",
    "GenericCompatiblePilot",
    "build_request",
    "dialect_for",
]
