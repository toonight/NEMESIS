"""Plane: the pilot seam.

NEMESIS is the harness an autonomous frontier-model pilot drives — the car, the écurie and,
above all, the limiter that keeps the pilot inside the track. This plane is the seat and the
limiter. The pilot (:class:`~nemesis.pilot.pilot.AutonomousPilot`) proposes moves from a
closed vocabulary (:mod:`nemesis.pilot.moves`); the mediator
(:class:`~nemesis.pilot.mediator.PilotMediator`) holds every real handle, validates each move,
enforces the pre-signed capability envelope, and records the lot.

The pilot is untrusted by construction. No production pilot ships here: what ships is the seam
and the proof that whoever drives cannot leave the track. See ADR-0008.
"""

from __future__ import annotations

from nemesis.pilot.anthropic_pilot import (
    AnthropicPilot,
    AnthropicTransport,
    UnwiredAnthropicTransport,
    anthropic_tool_schemas,
)
from nemesis.pilot.mediator import PilotMediator, PilotSession, TurnRecord
from nemesis.pilot.model_seat import PilotNotWiredError
from nemesis.pilot.moves import (
    Briefing,
    Conclude,
    PilotMove,
    RecordBelief,
    RequestEffect,
    Ruling,
    RulingStatus,
    RunPivot,
)
from nemesis.pilot.openai_pilot import (
    OpenAIPilot,
    OpenAITransport,
    UnwiredTransport,
    move_tool_schemas,
)
from nemesis.pilot.pilot import AutonomousPilot

__all__ = [
    "AnthropicPilot",
    "AnthropicTransport",
    "AutonomousPilot",
    "Briefing",
    "Conclude",
    "OpenAIPilot",
    "OpenAITransport",
    "PilotMediator",
    "PilotMove",
    "PilotNotWiredError",
    "PilotSession",
    "RecordBelief",
    "RequestEffect",
    "Ruling",
    "RulingStatus",
    "RunPivot",
    "TurnRecord",
    "UnwiredAnthropicTransport",
    "UnwiredTransport",
    "anthropic_tool_schemas",
    "move_tool_schemas",
]
