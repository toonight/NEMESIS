"""Provider seats: five vendors, one decision surface.

A seat translates between NEMESIS's canonical turn and a vendor's API and holds nothing else.
That is a structural claim, not a description: ``.importlinter`` forbids anything in this package
from importing :mod:`nemesis.pilot.mediator` or any platform plane — pursuit, effects, authz,
graph, evidence, collection, audit — so an adapter cannot acquire a handle, and a sixth adapter
added next year cannot either, because the contract names the package rather than a list of
modules somebody has to remember to extend.

This ``__init__`` is load-bearing for exactly that reason. Without it the directory would be a
PEP 420 namespace package, which ``grimp`` does not discover — every module here would import
and typecheck and lint and be invisible to every ``import-linter`` contract in the repository.
An audit found precisely that state, with ``lint-imports`` cheerfully reporting all contracts
kept over code no contract could see.

What lives here, and what deliberately does not:

- :mod:`~nemesis.pilot.providers.schema` — one canonical tool suite and the dialects that write
  it. Adapters cannot enumerate the tools, so they cannot add one.
- :mod:`~nemesis.pilot.providers.seat` — everything identical across vendors: instructions, the
  capability scan, retries, the not-wired discipline, the metadata contract.
- :mod:`~nemesis.pilot.providers.contract` — the provider-neutral request, response and identity.
- :mod:`~nemesis.pilot.providers.registry` — a frozen table of who exists, and a builder that
  fails closed on a name it does not know.
- The five seats, plus a generic one for any other OpenAI-compatible endpoint.

Not here: the mediator, the closed move vocabulary, and the challenger seam. Those govern what a
pilot may do, and they sit above every vendor rather than inside one.

Trust level: untrusted. Everything a seat returns is data the mediator re-validates.
"""

from __future__ import annotations

from nemesis.pilot.providers.anthropic import ANTHROPIC_CAPABILITIES, AnthropicPilot
from nemesis.pilot.providers.capabilities import (
    NEVER_EXPOSED_TOOL_TYPES,
    ModelCapabilities,
    ModelCapability,
    forbidden_tool_types,
)
from nemesis.pilot.providers.challenger_seat import (
    CHALLENGER_TOOL_SUITE,
    ModelChallenger,
    build_challenger,
)
from nemesis.pilot.providers.compatible import CONSERVATIVE_CAPABILITIES, GenericCompatiblePilot
from nemesis.pilot.providers.config import ChallengerConfig, PilotConfig
from nemesis.pilot.providers.contract import (
    DecodingParameters,
    MeteredPilot,
    PilotContext,
    PilotDecision,
    PilotRequest,
    PilotResponseMetadata,
    PilotUsage,
    ProviderIdentity,
    ReasoningEffort,
)
from nemesis.pilot.providers.errors import PilotError, PilotErrorKind
from nemesis.pilot.providers.gemini import GEMINI_CAPABILITIES, GeminiPilot
from nemesis.pilot.providers.ollama import (
    DEFAULT_ENDPOINT,
    DEFAULT_MODEL,
    OLLAMA_CAPABILITIES,
    LocalPilot,
    OllamaPilot,
)
from nemesis.pilot.providers.openai import OPENAI_CAPABILITIES, OpenAIPilot
from nemesis.pilot.providers.registry import (
    PROVIDER_NAMES,
    PROVIDERS,
    ProviderSpec,
    UnknownProviderError,
    build_pilot,
)
from nemesis.pilot.providers.reliability import RetryPolicy, call_with_retries
from nemesis.pilot.providers.schema import (
    MOVE_TOOL_NAMES,
    MOVE_TOOL_SCHEMA_VERSION,
    MOVE_TOOL_SUITE,
    PilotToolSpec,
    PilotToolSuite,
    ToolSuiteViolationError,
    render_tools,
)
from nemesis.pilot.providers.seat import (
    AMBIGUOUS_MOVE_SENTINEL,
    NO_MOVE_SENTINEL,
    ParsedResponse,
    ProviderSeat,
    SeatDialect,
)
from nemesis.pilot.providers.transport import PilotTransport, UnwiredPilotTransport
from nemesis.pilot.providers.xai import XAI_CAPABILITIES, XaiPilot

__all__ = [
    "AMBIGUOUS_MOVE_SENTINEL",
    "ANTHROPIC_CAPABILITIES",
    "CHALLENGER_TOOL_SUITE",
    "CONSERVATIVE_CAPABILITIES",
    "DEFAULT_ENDPOINT",
    "DEFAULT_MODEL",
    "GEMINI_CAPABILITIES",
    "MOVE_TOOL_NAMES",
    "MOVE_TOOL_SCHEMA_VERSION",
    "MOVE_TOOL_SUITE",
    "NEVER_EXPOSED_TOOL_TYPES",
    "NO_MOVE_SENTINEL",
    "OLLAMA_CAPABILITIES",
    "OPENAI_CAPABILITIES",
    "PROVIDERS",
    "PROVIDER_NAMES",
    "XAI_CAPABILITIES",
    "AnthropicPilot",
    "ChallengerConfig",
    "DecodingParameters",
    "GeminiPilot",
    "GenericCompatiblePilot",
    "LocalPilot",
    "MeteredPilot",
    "ModelCapabilities",
    "ModelCapability",
    "ModelChallenger",
    "OllamaPilot",
    "OpenAIPilot",
    "ParsedResponse",
    "PilotConfig",
    "PilotContext",
    "PilotDecision",
    "PilotError",
    "PilotErrorKind",
    "PilotRequest",
    "PilotResponseMetadata",
    "PilotToolSpec",
    "PilotToolSuite",
    "PilotTransport",
    "PilotUsage",
    "ProviderIdentity",
    "ProviderSeat",
    "ProviderSpec",
    "ReasoningEffort",
    "RetryPolicy",
    "SeatDialect",
    "ToolSuiteViolationError",
    "UnknownProviderError",
    "UnwiredPilotTransport",
    "XaiPilot",
    "build_challenger",
    "build_pilot",
    "call_with_retries",
    "forbidden_tool_types",
    "render_tools",
]
