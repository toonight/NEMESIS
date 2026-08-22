"""Where the Anthropic seat used to live, kept working while it lives somewhere better.

The implementation moved to :mod:`nemesis.pilot.providers.anthropic`. See
:mod:`nemesis.pilot.openai_pilot` for why the adapters became a package: an ``import-linter``
contract that names a package covers the adapter nobody has written yet, and one that names
modules covers only the list somebody remembered to extend.

``parse_tool_use`` here returns the raw move alone. The canonical parser also extracts usage,
the request id and the stop reason, all of which now reach the audit trail — new code should
call :func:`nemesis.pilot.providers.anthropic.parse_message` and keep them.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nemesis.pilot.model_seat import PilotNotWiredError
from nemesis.pilot.moves import Briefing
from nemesis.pilot.providers.anthropic import (
    ANTHROPIC_CAPABILITIES,
    AnthropicPilot,
    parse_message,
)
from nemesis.pilot.providers.contract import DecodingParameters
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, anthropic_dialect, render_tools
from nemesis.pilot.providers.transport import PilotTransport, UnwiredPilotTransport

DEFAULT_MAX_TOKENS = 1024

AnthropicTransport = PilotTransport


class UnwiredAnthropicTransport(UnwiredPilotTransport):
    """The default transport at its old name: it refuses."""

    def __init__(self) -> None:
        super().__init__("Anthropic")


def anthropic_tool_schemas() -> list[dict[str, Any]]:
    """The four moves, as Anthropic tools, from the one canonical suite."""
    return render_tools(MOVE_TOOL_SUITE, anthropic_dialect)


def build_request(
    briefing: Briefing, *, model: str, max_tokens: int = DEFAULT_MAX_TOKENS
) -> dict[str, Any]:
    """Compose the Anthropic request from the briefing, and only the briefing."""
    return AnthropicPilot(
        model=model, decoding=DecodingParameters(max_output_tokens=max_tokens)
    ).build_payload(briefing)


def parse_tool_use(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the move the model chose, as a raw mapping for the mediator to re-validate."""
    return parse_message(response).move


__all__ = [
    "ANTHROPIC_CAPABILITIES",
    "DEFAULT_MAX_TOKENS",
    "AnthropicPilot",
    "AnthropicTransport",
    "PilotNotWiredError",
    "UnwiredAnthropicTransport",
    "anthropic_tool_schemas",
    "build_request",
    "parse_tool_use",
]
