"""Where the local (Ollama) seat used to live, kept working while it lives somewhere better.

The implementation moved to :mod:`nemesis.pilot.providers.ollama`. See
:mod:`nemesis.pilot.openai_pilot` for why the adapters became a package.

The laboratory constants are re-exported unchanged, because the live-injection test and the
README both name them and neither should have to care where a class lives.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nemesis.pilot.model_seat import PilotNotWiredError
from nemesis.pilot.moves import Briefing
from nemesis.pilot.providers.ollama import (
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    LAB_NOTICE,
    OLLAMA_CAPABILITIES,
    LocalPilot,
    parse_chat,
)
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, openai_dialect, render_tools
from nemesis.pilot.providers.transport import PilotTransport, UnwiredPilotTransport

LocalTransport = PilotTransport


class UnwiredLocalTransport(UnwiredPilotTransport):
    """The default transport at its old name: it refuses."""

    def __init__(self) -> None:
        super().__init__("the local model", transmits_offsite=False)


def local_tool_schemas() -> list[dict[str, Any]]:
    """The four moves in Ollama's tool dialect — OpenAI-shaped, from the canonical suite."""
    return render_tools(MOVE_TOOL_SUITE, openai_dialect)


def build_request(briefing: Briefing, *, model: str) -> dict[str, Any]:
    """Compose the request from the briefing, and only the briefing."""
    return LocalPilot(model=model).build_payload(briefing)


def parse_tool_call(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the chosen move as raw data for the mediator to re-validate."""
    return parse_chat(response).move


__all__ = [
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT_SECONDS",
    "LAB_NOTICE",
    "OLLAMA_CAPABILITIES",
    "LocalPilot",
    "LocalTransport",
    "PilotNotWiredError",
    "UnwiredLocalTransport",
    "build_request",
    "local_tool_schemas",
    "parse_tool_call",
]
