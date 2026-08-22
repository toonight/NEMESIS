"""What a deployment chooses about its pilot, and the one thing it must never put here.

A configuration says which provider, which model, how hard to think, how long to wait and how
many times to try. It does **not** say what the pilot may do: that is the four verbs and the
pre-signed envelope, and no value in this module can reach either. The distinction matters
because this is the file a deployment edits, and a config format that *looked* like it could
widen authority would eventually be asked to.

**No credential belongs in a :class:`PilotConfig`.** There is no field for one, and the omission
is structural rather than a convention: a credential lives in whatever transport a deployment
wires, and a config carries at most the *name* of an environment variable
(:attr:`nemesis.pilot.providers.registry.ProviderSpec.api_key_environment_variable`) so an
operator can be told what to supply. Nothing under ``src/nemesis/pilot`` reads that variable.
The reasoning is the effects plane's, applied here: the safest place to keep a secret out of a
log, a trace, a benchmark report and a crash dump is a structure with nowhere to put one.

The shape is Pydantic, so a deployment maps whatever format it already has — YAML, TOML, a
mapping from a secrets manager — onto it with ``PilotConfig.model_validate``. This package adds
no configuration-file dependency and defines no file format, because a platform that invented
one would then own its parsing.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from nemesis.pilot.providers.contract import DecodingParameters, ReasoningEffort
from nemesis.pilot.providers.reliability import (
    DEFAULT_BASE_DELAY_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_DELAY_SECONDS,
    RetryPolicy,
)


class PilotConfig(BaseModel):
    """One pilot's configuration: provider, model, and how the call is made.

    Conceptually the thing a deployment writes as::

        pilot:
          provider: openai
          model: <model-id>
          reasoning: high

    ``model`` is a string this package asserts nothing about. A frontier model's name in
    business logic is a name that is wrong in six months, so the only place a model id appears
    in this repository is configuration, documentation and test fixtures.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str
    model: str
    reasoning: ReasoningEffort | None = None
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_output_tokens: int = Field(default=1024, gt=0, le=32_000)
    seed: int | None = None

    max_attempts: int = Field(default=DEFAULT_MAX_ATTEMPTS, ge=1, le=8)
    retry_base_delay_seconds: float = Field(default=DEFAULT_BASE_DELAY_SECONDS, ge=0.0, le=60.0)
    retry_max_delay_seconds: float = Field(default=DEFAULT_MAX_DELAY_SECONDS, ge=0.0, le=300.0)

    vendor_label: str | None = None
    """A human-readable vendor name for the generic compatible seat. Ignored by named
    providers, which know what they are."""

    def decoding(self) -> DecodingParameters:
        return DecodingParameters(
            max_output_tokens=self.max_output_tokens,
            temperature=self.temperature,
            reasoning=self.reasoning,
            seed=self.seed,
        )

    def retries(self) -> RetryPolicy:
        return RetryPolicy(
            max_attempts=self.max_attempts,
            base_delay_seconds=self.retry_base_delay_seconds,
            max_delay_seconds=self.retry_max_delay_seconds,
        )


class ChallengerConfig(BaseModel):
    """A second, independent model asked whether a proposed move is supported by what was seen.

    Optional everywhere. The challenger holds no authority: its verdicts can cause a refusal and
    can never cause an action, so the worst a hostile or broken one achieves is a session that
    refuses too much — see :mod:`nemesis.pilot.challenger`.

    Model diversity is the reason the pilot and the challenger are configured separately rather
    than as a temperature setting on one model. Correlated reasoning failure is a first-order
    risk in attribution: two instances of the same weights asked the same question are one
    opinion asked twice, and this repository's own rule is to treat model consensus as one
    correlated opinion rather than as independent confirmation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pilot: PilotConfig
    gate_effects: bool = True
    gate_beliefs: bool = True
    """Which moves a verdict may block. Effects are the consequential move; beliefs are where a
    false attribution enters the graph. Pivots and conclusions are recorded but never blocked,
    because a challenger that can stop an investigation from *looking* is a denial-of-service
    surface with no corresponding safety gain."""


__all__ = ["ChallengerConfig", "PilotConfig"]
