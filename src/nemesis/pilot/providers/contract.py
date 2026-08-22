"""The provider-neutral shape of one turn: what goes out, what comes back, what is recorded.

NEMESIS reasons about a pilot turn in these types and never in a vendor's. An adapter's whole
job is the translation at each end —

    PilotRequest  ->  vendor request  ->  vendor response  ->  PilotDecision

— and nothing above the adapter is allowed to care which vendor sat in the middle. That is the
property the containment argument in ADR-0008 rests on: the mediator cannot tell which model is
driving, and does not need to.

Three things about these types are load-bearing rather than convenient.

**The metadata is descriptive and never decides anything.** :class:`PilotResponseMetadata`
carries provider, model, latency, tokens, retries and the tool the model chose. Not one ruling
in :mod:`nemesis.pilot.mediator` reads it. It is written to the audit trail so a session can be
explained; if a seat lied in every field, the worst outcome would be a misleading audit record,
never an action that should not have happened. Keeping it out of the decision path is what lets
the mediator accept it from an untrusted seat at all.

**Provider and model are separate fields.** A run under xAI's OpenAI-compatible endpoint must
record ``provider=xai``, not ``provider=openai`` — a transport similarity is not an identity,
and an audit trail that attributes a decision to the wrong vendor is wrong about the thing it
exists to establish. :class:`ProviderIdentity` also carries what the vendor *said* it ran, so a
provider silently substituting a model is visible (:attr:`PilotResponseMetadata.model_substituted`)
rather than invisible.

**There is nowhere for a credential or a reasoning trace to go.** Every field below is a scalar
or a bounded structure. There is no header map, no raw request, no raw response, and no field
for hidden chain-of-thought — NEMESIS does not request private reasoning traces and has nowhere
to persist one if a vendor sent it anyway. Token *counts* for reasoning are kept, because a
count is a cost and not a thought.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.pilot.moves import Briefing, PilotMove
from nemesis.pilot.providers.schema import PilotToolSuite


class ReasoningEffort(StrEnum):
    """How much deliberation to ask for, where a vendor offers it without returning the trace.

    Three levels rather than a number, because that is what the APIs that have it expose and a
    finer dial would be an invented precision. A provider whose reasoning mode returns thinking
    blocks does not accept this at all — see
    :data:`~nemesis.pilot.providers.capabilities.ModelCapability.REASONING_EFFORT`.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ProviderIdentity(BaseModel):
    """Which vendor, which model, which seat. Recorded on every decision."""

    model_config = ConfigDict(frozen=True)

    provider: str
    """The registry key: ``openai``, ``anthropic``, ``xai``, ``gemini``, ``ollama``,
    ``openai_compatible``. Never inferred from the transport's shape."""

    model: str
    """The model id the deployment configured. This module asserts nothing about which model
    ids exist; a frontier model's name is configuration and a name in business logic is a
    name that is wrong in six months."""

    seat: str
    """The adapter class that built the request, so a defect can be traced to the translation
    rather than only to the vendor."""

    @property
    def name(self) -> str:
        """``provider:model`` — the string that reaches ``Claim.model_identifier`` and names
        the model on every belief a pilot records."""
        return f"{self.provider}:{self.model}"


class DecodingParameters(BaseModel):
    """How the model is asked to sample. Configuration, never a capability."""

    model_config = ConfigDict(frozen=True)

    max_output_tokens: int = Field(default=1024, gt=0, le=32_000)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    reasoning: ReasoningEffort | None = None
    seed: int | None = None
    """Best-effort reproducibility where a vendor offers it. A seed configured against a
    provider that cannot honour it is refused at construction rather than dropped, because a
    deployment that asked for reproducibility and silently did not get it would compare two
    runs that are not comparable."""


class PilotContext(BaseModel):
    """Everything about the investigation that an adapter is allowed to see.

    Exactly one field of substance, and that is the point: the adapter receives the briefing
    the mediator already minimized — deliverable-class material only, with a fail-closed scan
    behind it — and holds nothing else. There is no graph handle here, no capability, no key,
    and no second field through which one could arrive.
    """

    model_config = ConfigDict(frozen=True)

    briefing: Briefing
    attempt: int = Field(default=1, ge=1)
    """Which try this is. Carried so a seat can report it; it changes no content, because a
    retry that altered the request would not be a retry of the same request."""

    proposed_move: PilotMove | None = None
    """The move a pilot has proposed, when this context is being shown to a **challenger**.

    ``None`` for a pilot, which is asked what to do rather than what it thinks of what was
    decided. A challenger sees exactly this and nothing more: the briefing the pilot saw, and the
    move the pilot made from it. There is no third field, and that is the whole of what a
    challenger is given."""

    def user_content(self) -> str:
        """The text a dialect puts in the user turn. Composed here, never by an adapter.

        A vendor adapter decides how to *carry* content, never what the content is. Two reasons,
        and the second is the one that matters: a briefing that five adapters each serialized
        would be five slightly different briefings within a release, and — since an adapter is
        the least-trusted first-party code in this plane — content assembly is not a job to hand
        it. A test asserts the briefing arrives at every vendor byte-identical to this.
        """
        if self.proposed_move is None:
            return self.briefing.model_dump_json()
        return json.dumps(
            {
                "briefing": self.briefing.model_dump(mode="json"),
                "proposed_move": self.proposed_move.model_dump(mode="json"),
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )


class PilotRequest(BaseModel):
    """One turn, provider-neutral. What an adapter translates into a vendor's dialect."""

    model_config = ConfigDict(frozen=True)

    identity: ProviderIdentity
    context: PilotContext
    instructions: str
    """The untrusted-pilot contract, byte-identical for every vendor. A containment that said
    different things to five vendors would be a containment with a seam an adversary could pick
    which side of, so this is composed once in :mod:`nemesis.pilot.model_seat` and a test
    asserts every provider's rendered request carries the same bytes."""

    instructions_version: str
    tools: PilotToolSuite
    tool_schema_version: str
    decoding: DecodingParameters


class PilotUsage(BaseModel):
    """What the turn cost, as the provider reported it. Every field optional: several do not."""

    model_config = ConfigDict(frozen=True)

    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_input_tokens: int | None = None
    reasoning_tokens: int | None = None
    """A count of tokens spent reasoning, never the reasoning. Kept because it is most of the
    bill on a reasoning model and invisible in the output count."""

    @property
    def total_tokens(self) -> int | None:
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return (self.input_tokens or 0) + (self.output_tokens or 0)


class PilotResponseMetadata(BaseModel):
    """The observable facts about one provider call. Audited; never consulted for a ruling."""

    model_config = ConfigDict(frozen=True)

    identity: ProviderIdentity
    requested_at: datetime
    latency_seconds: float = Field(ge=0.0)
    attempts: int = Field(default=1, ge=1)
    request_id: str | None = None
    model_reported: str | None = None
    """What the provider said it ran, when it says. Compared against the configured model so a
    silent substitution is a recorded fact rather than an assumption nobody checked."""

    finish_reason: str | None = None
    tool_selected: str | None = None
    usage: PilotUsage = PilotUsage()
    reasoning_requested: ReasoningEffort | None = None
    instructions_version: str = ""
    tool_schema_version: str = ""

    @property
    def model_substituted(self) -> bool:
        """Whether the provider answered with a model other than the one configured.

        Not an error and not a refusal — vendors alias and re-point model ids, and a deployment
        may be entirely happy about it. It is recorded because a benchmark comparing two runs,
        or an auditor asking which model reached a conclusion, is asking about the model that
        *ran*, and "the one we asked for" is a different answer.
        """
        return self.model_reported is not None and self.model_reported != self.identity.model

    def audit_fields(self) -> dict[str, str]:
        """The bounded view the audit trail carries. Scalars only, every string truncated."""
        fields = {
            "provider": self.identity.provider[:64],
            "model": self.identity.model[:128],
            "seat": self.identity.seat[:64],
            "latency_seconds": f"{self.latency_seconds:.3f}",
            "attempts": str(self.attempts),
        }
        if self.request_id:
            fields["provider_request_id"] = self.request_id[:128]
        if self.model_substituted and self.model_reported:
            fields["model_reported"] = self.model_reported[:128]
        if self.finish_reason:
            fields["finish_reason"] = self.finish_reason[:64]
        if self.usage.input_tokens is not None:
            fields["input_tokens"] = str(self.usage.input_tokens)
        if self.usage.output_tokens is not None:
            fields["output_tokens"] = str(self.usage.output_tokens)
        if self.usage.reasoning_tokens is not None:
            fields["reasoning_tokens"] = str(self.usage.reasoning_tokens)
        if self.reasoning_requested is not None:
            fields["reasoning"] = self.reasoning_requested.value
        return fields


@dataclass(frozen=True)
class PilotDecision:
    """What a metered seat returns: the raw move, and what is known about the call.

    ``raw`` is untrusted in exactly the way ``propose``'s return value is untrusted — a mapping
    the mediator re-validates through the closed vocabulary. Pairing it with metadata changes
    nothing about that; it only means the audit record can say which provider produced the thing
    that was refused.
    """

    raw: PilotMove | Mapping[str, Any]
    metadata: PilotResponseMetadata | None = None


@runtime_checkable
class MeteredPilot(Protocol):
    """A pilot that also reports what its call cost. Strictly optional, strictly additive.

    :class:`~nemesis.pilot.pilot.AutonomousPilot` is deliberately unchanged — one property and
    one method — because every hostile double in the containment suite is cast to it, and a
    required member added there would leave each of them compiling under mypy strict while
    silently no longer conforming. So metering is a *second* protocol the mediator prefers when
    it is present and does without when it is not: a scripted pilot, an adversarial one and a
    five-line fake all remain valid pilots that nobody has to update.

    ``identity`` is read once at session open and used for every audit record in that session. A
    seat that changed its mind about which provider it was, per turn, would be rewriting
    attribution on the audit path — so it is not given the chance.
    """

    @property
    def name(self) -> str: ...

    @property
    def identity(self) -> ProviderIdentity: ...

    async def decide(self, briefing: Briefing) -> PilotDecision: ...


__all__ = [
    "DecodingParameters",
    "MeteredPilot",
    "PilotContext",
    "PilotDecision",
    "PilotRequest",
    "PilotResponseMetadata",
    "PilotUsage",
    "ProviderIdentity",
    "ReasoningEffort",
]
