"""Which providers exist, and why the answer is a frozen table rather than a mutable registry.

A deployment names a provider in configuration and gets a seat. The obvious implementations are
a chain of ``elif provider == "xai"`` — which spreads vendor knowledge through every call site
and grows a subtle asymmetry per branch — and a mutable registry with a ``register_provider``
function, which lets anything that can run code in this process install a pilot.

Neither is what this is. :data:`PROVIDERS` is a :class:`~types.MappingProxyType` built once from
an explicit tuple, and there is no public mutation API. **Adding a provider is a source change
in this file**, reviewed like any other, rather than a runtime call some plugin discovery
mechanism might make on a deployment's behalf. That closes an obvious question before it is
asked: an entry-point or plugin loader would be a way for an installed package to become the
thing driving an investigation, and "the pilot is untrusted but at least we know which pilot it
is" is a claim worth keeping.

The cost is honest and small: a new OpenAI-compatible vendor is one :class:`ProviderSpec`, no
new module. A vendor with its own dialect is one module and one entry — which is what xAI and
Gemini were.

:func:`build_pilot` **fails closed**. An unknown provider is an error naming what is registered;
it never falls back to a default, because a deployment that misspells ``anthropic`` and silently
gets OpenAI has transmitted its briefings to a vendor it did not choose.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from nemesis.pilot.providers import anthropic, compatible, gemini, ollama, openai, xai
from nemesis.pilot.providers.capabilities import ModelCapabilities
from nemesis.pilot.providers.config import PilotConfig
from nemesis.pilot.providers.seat import ProviderSeat
from nemesis.pilot.providers.transport import PilotTransport

SeatFactory = Callable[[PilotConfig, PilotTransport | None], ProviderSeat]


@dataclass(frozen=True)
class ProviderSpec:
    """Everything the platform knows about one provider, and nothing it should not.

    Note what is absent: an endpoint, a credential, a default model. An endpoint and a credential
    belong to the transport a deployment wires; a default model would be this repository
    asserting that a particular frontier model exists, which is the claim that goes stale first.
    """

    provider: str
    vendor_label: str
    build: SeatFactory
    capabilities: ModelCapabilities
    api_key_environment_variable: str
    """The NAME a deployment's transport reads. Nothing in this package reads it, and no value
    of it is ever held here — see :mod:`nemesis.pilot.providers.config`."""

    notes: str = ""
    """One line an operator sees in ``nemesis providers``. Where a provider's treatment differs
    on purpose — Anthropic declining a reasoning mode that returns the trace — this is where the
    difference is stated rather than left to be discovered."""


def _openai(config: PilotConfig, transport: PilotTransport | None) -> ProviderSeat:
    return openai.OpenAIPilot(
        model=config.model,
        transport=transport,
        decoding=config.decoding(),
        retries=config.retries(),
    )


def _anthropic(config: PilotConfig, transport: PilotTransport | None) -> ProviderSeat:
    return anthropic.AnthropicPilot(
        model=config.model,
        transport=transport,
        decoding=config.decoding(),
        retries=config.retries(),
    )


def _xai(config: PilotConfig, transport: PilotTransport | None) -> ProviderSeat:
    return xai.XaiPilot(
        model=config.model,
        transport=transport,
        decoding=config.decoding(),
        retries=config.retries(),
    )


def _gemini(config: PilotConfig, transport: PilotTransport | None) -> ProviderSeat:
    return gemini.GeminiPilot(
        model=config.model,
        transport=transport,
        decoding=config.decoding(),
        retries=config.retries(),
    )


def _ollama(config: PilotConfig, transport: PilotTransport | None) -> ProviderSeat:
    return ollama.LocalPilot(
        model=config.model,
        transport=transport,
        decoding=config.decoding(),
        retries=config.retries(),
    )


def _compatible(config: PilotConfig, transport: PilotTransport | None) -> ProviderSeat:
    return compatible.GenericCompatiblePilot(
        model=config.model,
        provider=config.vendor_label or compatible.PROVIDER,
        vendor_label=config.vendor_label or compatible.PROVIDER,
        transport=transport,
        decoding=config.decoding(),
        retries=config.retries(),
    )


PROVIDERS: Final[Mapping[str, ProviderSpec]] = MappingProxyType(
    {
        spec.provider: spec
        for spec in (
            ProviderSpec(
                provider=openai.PROVIDER,
                vendor_label="OpenAI",
                build=_openai,
                capabilities=openai.OPENAI_CAPABILITIES,
                api_key_environment_variable=openai.API_KEY_ENVIRONMENT_VARIABLE,
                notes="Chat completions. Reasoning effort is requested; the trace is not.",
            ),
            ProviderSpec(
                provider=anthropic.PROVIDER,
                vendor_label="Anthropic",
                build=_anthropic,
                capabilities=anthropic.ANTHROPIC_CAPABILITIES,
                api_key_environment_variable=anthropic.API_KEY_ENVIRONMENT_VARIABLE,
                notes=(
                    "Messages API. Extended thinking is NOT requested: it returns the trace, "
                    "and this platform does not receive or persist private reasoning."
                ),
            ),
            ProviderSpec(
                provider=xai.PROVIDER,
                vendor_label="xAI",
                build=_xai,
                capabilities=xai.XAI_CAPABILITIES,
                api_key_environment_variable=xai.API_KEY_ENVIRONMENT_VARIABLE,
                notes=(
                    "OpenAI-compatible transport, distinct identity. A run driven by xAI is "
                    "recorded as xAI in the audit trail and on every belief."
                ),
            ),
            ProviderSpec(
                provider=gemini.PROVIDER,
                vendor_label="Google Gemini",
                build=_gemini,
                capabilities=gemini.GEMINI_CAPABILITIES,
                api_key_environment_variable=gemini.API_KEY_ENVIRONMENT_VARIABLE,
                notes=(
                    "generateContent. Tool schemas are translated to the OpenAPI subset with "
                    "every enum preserved; the payload is an envelope carrying the model id."
                ),
            ),
            ProviderSpec(
                provider=ollama.PROVIDER,
                vendor_label="the local model",
                build=_ollama,
                capabilities=ollama.OLLAMA_CAPABILITIES,
                api_key_environment_variable="",
                notes=(
                    "Local inference. No briefing leaves the machine, so the hosted-model "
                    "data-governance question does not arise."
                ),
            ),
            ProviderSpec(
                provider=compatible.PROVIDER,
                vendor_label="an OpenAI-compatible endpoint",
                build=_compatible,
                capabilities=compatible.CONSERVATIVE_CAPABILITIES,
                api_key_environment_variable=compatible.API_KEY_ENVIRONMENT_VARIABLE,
                notes=(
                    "vLLM and other compatible endpoints. Set vendor_label so the audit trail "
                    "names the real endpoint rather than 'openai_compatible'."
                ),
            ),
        )
    }
)
"""Every provider this build can seat. Frozen, and extended only by editing this file."""

PROVIDER_NAMES: Final[tuple[str, ...]] = tuple(sorted(PROVIDERS))


class UnknownProviderError(ValueError):
    """A configuration named a provider this build does not have.

    An error rather than a default. A deployment that misspells a provider name and silently
    gets another one has transmitted every briefing to a vendor it did not choose, which is the
    failure this platform's whole data-governance posture exists to prevent.
    """


def build_pilot(
    config: PilotConfig,
    *,
    transport: PilotTransport | None = None,
    providers: Mapping[str, ProviderSpec] = PROVIDERS,
) -> ProviderSeat:
    """Seat the configured provider, or refuse and say what is registered.

    ``transport`` is the deployment's, and ``None`` means the seat gets the refusing default —
    so a build that forgot to wire a model contacts nothing and finds out loudly.

    ``providers`` is a parameter so a test can seat a provider that does not exist, without
    anything being able to mutate the shipped table.
    """
    spec = providers.get(config.provider)
    if spec is None:
        raise UnknownProviderError(
            f"no provider {config.provider!r} is registered; this build seats "
            f"{', '.join(sorted(providers))}. Adding one is a source change in "
            "nemesis.pilot.providers.registry, reviewed like any other"
        )
    return spec.build(config, transport)


__all__ = [
    "PROVIDERS",
    "PROVIDER_NAMES",
    "ProviderSpec",
    "SeatFactory",
    "UnknownProviderError",
    "build_pilot",
]
