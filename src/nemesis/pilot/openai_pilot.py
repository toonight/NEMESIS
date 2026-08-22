"""Where the OpenAI seat used to live, kept working while it lives somewhere better.

The implementation moved to :mod:`nemesis.pilot.providers.openai` when the pilot plane grew from
two vendors to five. The move was not tidying. ``.importlinter`` can forbid a *package* from
importing the mediator or any platform plane, and that contract then covers a sixth adapter
added next year; a contract naming individual modules covers only the ones somebody remembered
to list, which is the enumeration failure this repository keeps finding in itself. Adapters
therefore live under one package, and the contract names the package.

This module re-exports the public surface at its old path so nothing that imported it breaks.
Two functions are adapters rather than aliases, because the shapes underneath changed:

- ``build_request(briefing, model=...)`` now composes through the shared seat, which is what
  applies the capability scan and the canonical tool suite.
- ``parse_tool_call(response)`` returns the raw move, discarding the usage and request-id
  metadata the canonical parser also extracts. New code should use
  :func:`nemesis.pilot.providers.openai_dialect.parse_chat_completion` and keep it.

``OpenAITransport`` and ``UnwiredTransport`` are aliases of the provider-neutral
:class:`~nemesis.pilot.providers.transport.PilotTransport` and
:class:`~nemesis.pilot.providers.transport.UnwiredPilotTransport`. They were never different
between vendors, which is exactly why five copies of them would have drifted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from nemesis.pilot.model_seat import SYSTEM_INSTRUCTIONS, PilotNotWiredError
from nemesis.pilot.moves import Briefing
from nemesis.pilot.providers.openai import OPENAI_CAPABILITIES, OpenAIPilot
from nemesis.pilot.providers.openai_dialect import parse_chat_completion
from nemesis.pilot.providers.schema import MOVE_TOOL_SUITE, openai_dialect, render_tools
from nemesis.pilot.providers.transport import PilotTransport, UnwiredPilotTransport

OpenAITransport = PilotTransport


class UnwiredTransport(UnwiredPilotTransport):
    """The default transport at its old name: it refuses."""

    def __init__(self) -> None:
        super().__init__("OpenAI")


def move_tool_schemas() -> list[dict[str, Any]]:
    """The four moves, as OpenAI tools, from the one canonical suite."""
    return render_tools(MOVE_TOOL_SUITE, openai_dialect)


def build_request(briefing: Briefing, *, model: str) -> dict[str, Any]:
    """Compose the OpenAI request from the briefing, and only the briefing."""
    return OpenAIPilot(model=model).build_payload(briefing)


def parse_tool_call(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the move the model chose, as a raw mapping for the mediator to re-validate."""
    return parse_chat_completion(response).move


__all__ = [
    "OPENAI_CAPABILITIES",
    "SYSTEM_INSTRUCTIONS",
    "OpenAIPilot",
    "OpenAITransport",
    "PilotNotWiredError",
    "UnwiredTransport",
    "build_request",
    "move_tool_schemas",
    "parse_tool_call",
]
