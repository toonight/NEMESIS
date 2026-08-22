"""Plane: the pilot seam.

NEMESIS is the harness an autonomous frontier-model pilot drives — the car, the écurie and,
above all, the limiter that keeps the pilot inside the track. This plane is the seat and the
limiter. The pilot (:class:`~nemesis.pilot.pilot.AutonomousPilot`) proposes moves from a closed
vocabulary (:mod:`nemesis.pilot.moves`); the mediator
(:class:`~nemesis.pilot.mediator.PilotMediator`) holds every real handle, validates each move,
enforces the pre-signed capability envelope, and records the lot.

Five vendors can sit in that seat — OpenAI, Anthropic, xAI, Google Gemini and a local model
through Ollama, plus any other OpenAI-compatible endpoint — and the seat is the same one for all
of them. The provider is a configuration key resolved through a frozen registry
(:mod:`nemesis.pilot.providers`), not a branch in investigation logic, and the vocabulary they
are offered comes from a single canonical suite that no adapter can extend. What differs between
them is dialect. What must never differ is enforced above them, by code they cannot import: an
``import-linter`` contract forbids anything under ``nemesis.pilot.providers`` from reaching the
mediator or any platform plane.

The pilot is untrusted by construction, and so is the challenger
(:mod:`nemesis.pilot.challenger`) that may optionally review its moves — a second, independent
model whose whole vocabulary is five verdicts, which can cause a refusal and can never cause an
action. No production pilot ships wired here: what ships is the seam, the proof that whoever
drives cannot leave the track, and a benchmark (:mod:`nemesis.pilotbench`) for asking how well
each of them drives inside it. See ADR-0008 and ADR-0009.
"""

from __future__ import annotations

from nemesis.pilot.challenger import (
    BLOCKING_VERDICTS,
    ChallengePolicy,
    ChallengerFailureMode,
    ChallengerRuling,
    ChallengerVerdict,
    MoveChallenger,
)
from nemesis.pilot.mediator import PilotMediator, PilotSession, TurnRecord
from nemesis.pilot.model_seat import (
    PROMPT_VERSION,
    SYSTEM_INSTRUCTIONS,
    PilotNotWiredError,
    prompt_digest,
)
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
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilot.providers import (
    MOVE_TOOL_SCHEMA_VERSION,
    MOVE_TOOL_SUITE,
    PROVIDER_NAMES,
    PROVIDERS,
    AnthropicPilot,
    ChallengerConfig,
    DecodingParameters,
    GeminiPilot,
    GenericCompatiblePilot,
    LocalPilot,
    ModelCapabilities,
    ModelCapability,
    ModelChallenger,
    OpenAIPilot,
    PilotConfig,
    PilotDecision,
    PilotError,
    PilotErrorKind,
    PilotResponseMetadata,
    PilotToolSpec,
    PilotTransport,
    ProviderIdentity,
    ProviderSeat,
    ProviderSpec,
    ReasoningEffort,
    RetryPolicy,
    UnknownProviderError,
    UnwiredPilotTransport,
    XaiPilot,
    build_challenger,
    build_pilot,
    render_tools,
)

__all__ = [
    "BLOCKING_VERDICTS",
    "MOVE_TOOL_SCHEMA_VERSION",
    "MOVE_TOOL_SUITE",
    "PROMPT_VERSION",
    "PROVIDERS",
    "PROVIDER_NAMES",
    "SYSTEM_INSTRUCTIONS",
    "AnthropicPilot",
    "AutonomousPilot",
    "Briefing",
    "ChallengePolicy",
    "ChallengerConfig",
    "ChallengerFailureMode",
    "ChallengerRuling",
    "ChallengerVerdict",
    "Conclude",
    "DecodingParameters",
    "GeminiPilot",
    "GenericCompatiblePilot",
    "LocalPilot",
    "ModelCapabilities",
    "ModelCapability",
    "ModelChallenger",
    "MoveChallenger",
    "OpenAIPilot",
    "PilotConfig",
    "PilotDecision",
    "PilotError",
    "PilotErrorKind",
    "PilotMediator",
    "PilotMove",
    "PilotNotWiredError",
    "PilotResponseMetadata",
    "PilotSession",
    "PilotToolSpec",
    "PilotTransport",
    "ProviderIdentity",
    "ProviderSeat",
    "ProviderSpec",
    "ReasoningEffort",
    "RecordBelief",
    "RequestEffect",
    "RetryPolicy",
    "Ruling",
    "RulingStatus",
    "RunPivot",
    "TurnRecord",
    "UnknownProviderError",
    "UnwiredPilotTransport",
    "XaiPilot",
    "build_challenger",
    "build_pilot",
    "prompt_digest",
    "render_tools",
]
