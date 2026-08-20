"""The collection port: how NEMESIS asks the world a question.

Every intelligence source — a simulated fixture today, a licensed passive-DNS feed
tomorrow — implements :class:`IntelligenceConnector`. Swapping one for the other must not
touch domain or orchestration code; that is the whole point of this file.

Two things here are less obvious than they look.

**A connector returns observations, never conclusions.** It hands back what a source said,
with the evidence, and the platform decides what that means. A connector that returns
"this domain belongs to actor X" has made an attribution inside the collection plane,
where there is no provenance discipline and no contradicting-evidence machinery. The
return type makes that awkward on purpose.

**A connector must declare its cost and its constraints.** The Pursuit Engine chooses which
pivots to spend on; it cannot do that against a set of opaque callables. And a licensed
feed's terms often forbid redistribution of results — that constraint has to travel with
the data, from the moment of collection, or it gets lost exactly when someone assembles an
export for a third party.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.claims import Claim
from nemesis.core.entities import EntityType
from nemesis.core.evidence import EvidenceObject
from nemesis.core.provenance import SourceDescriptor
from nemesis.core.temporal import TemporalExtent


class PivotType(StrEnum):
    """The question being asked of a source.

    Named by the *question*, not by the provider, so the Pursuit Engine can plan over
    capabilities rather than over vendors.
    """

    RESOLUTION_HISTORY = "resolution_history"
    REVERSE_RESOLUTION = "reverse_resolution"
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    REGISTRATION_RECORD = "registration_record"
    CERTIFICATE_HISTORY = "certificate_history"
    CERTIFICATE_REUSE = "certificate_reuse"
    NETWORK_OWNERSHIP = "network_ownership"
    SERVICE_FINGERPRINT = "service_fingerprint"
    HOSTING_NEIGHBOURS = "hosting_neighbours"
    PROXY_CLASSIFICATION = "proxy_classification"
    MALWARE_LOOKUP = "malware_lookup"
    MALWARE_SIMILARITY = "malware_similarity"
    C2_EXTRACTION = "c2_extraction"
    DARK_WEB_SEARCH = "dark_web_search"
    PERSONA_ACTIVITY = "persona_activity"
    MARKETPLACE_LISTING = "marketplace_listing"
    KEY_LOOKUP = "key_lookup"
    WALLET_ACTIVITY = "wallet_activity"
    WALLET_CLUSTERING = "wallet_clustering"
    TRANSACTION_TRACE = "transaction_trace"
    THREAT_INTEL_LOOKUP = "threat_intel_lookup"
    OSINT_SEARCH = "osint_search"


class PivotRequest(BaseModel):
    """One question, aimed at one entity."""

    model_config = ConfigDict(frozen=True)

    pivot_type: PivotType
    entity_type: EntityType
    entity_key: str
    """The entity's normalized natural key."""

    window: TemporalExtent | None = None
    """Restrict to a period. None means whatever history the source holds."""

    max_results: int = Field(default=100, ge=1, le=10_000)
    reason: str = Field(
        min_length=1,
        description="Why this pivot is being run. Recorded in the audit trail — a "
        "collection nobody can justify afterwards is a collection that should not have "
        "happened, and for regulated data this is a legal requirement, not hygiene.",
    )


class PivotResult(BaseModel):
    """What a source said, plus the material to prove it said it.

    Claims and evidence are returned side by side rather than merged, so the caller can
    admit the evidence to the vault and the claims to the intelligence graph without a
    step that could quietly promote one into the other.
    """

    model_config = ConfigDict(frozen=True)

    request: PivotRequest
    connector_name: str
    observations: tuple[Claim, ...]
    evidence: tuple[EvidenceObject, ...]

    artifacts: dict[str, bytes] = Field(
        default_factory=dict,
        description="Raw bytes for the returned evidence, keyed by evidence id.\n\n"
        "Carried here rather than fetched later because the collection plane cannot write "
        "to the Evidence Vault — a collector that could write to the vault would be a "
        "collector that could rewrite it, and hostile content is what collectors handle. "
        "The engine seals these on the vault's side of the boundary.\n\n"
        "Optional: a connector that only reports metadata leaves it empty, and the "
        "resulting evidence is inadmissible for want of a preserved artifact, which is the "
        "correct outcome rather than an error.",
    )

    truncated: bool = Field(
        default=False,
        description="True if the source had more to say than max_results allowed. An "
        "absence in a truncated result is not an absence in the world, and downstream "
        "reasoning that treats it as one produces false negative findings.",
    )

    error: str | None = Field(
        default=None,
        description="Set when the pivot failed. A failed pivot is recorded, not swallowed: "
        "'we looked and found nothing' and 'we could not look' are different, and only "
        "one of them is evidence of absence.",
    )

    @property
    def succeeded(self) -> bool:
        return self.error is None

    @property
    def is_empty(self) -> bool:
        return not self.observations and self.succeeded


class ConnectorCapabilities(BaseModel):
    """What a connector can do, what it costs, and what its terms forbid."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    source: SourceDescriptor

    supported_pivots: frozenset[PivotType]
    supported_entity_types: frozenset[EntityType]

    is_simulated: bool
    """True for fixture-backed connectors. Propagates into every claim and evidence object
    produced, and is never cleared downstream."""

    handles_hostile_content: bool = Field(
        default=False,
        description="True when the connector retrieves adversary-controlled content. Such "
        "connectors must run sandboxed and their output must never reach a model that "
        "holds tool access.",
    )

    isolation_factory: str | None = Field(
        default=None,
        description="An importable ``module:function`` the isolating collector calls in a "
        "child process. Required when `handles_hostile_content` is set: an object cannot "
        "cross a pipe, and pickling one would hand the child a deserialization surface — the "
        "very class of bug the boundary exists to remove. A hostile connector without one "
        "cannot be isolated, and the engine refuses to run it rather than running it in the "
        "main process.",
    )

    cost_per_call: float = Field(
        default=0.0,
        ge=0.0,
        description="Relative cost, used by the Pursuit Engine to budget an investigation. "
        "Unitless; only the ratios between connectors matter.",
    )

    rate_limit_per_minute: int | None = None

    redistribution_permitted: bool = Field(
        default=True,
        description="Whether results may be included in an export to a third party. "
        "Licensed feeds frequently forbid it, and the constraint must travel with the data "
        "from collection, or it is lost precisely when an evidence package is assembled.",
    )

    def can_answer(self, request: PivotRequest) -> bool:
        return (
            request.pivot_type in self.supported_pivots
            and request.entity_type in self.supported_entity_types
        )


@runtime_checkable
class IntelligenceConnector(Protocol):
    """A source of external intelligence.

    Implementations live in :mod:`nemesis.collect`. Nothing else in the platform holds
    network capability, and the prohibited-content scanner enforces that in CI.
    """

    @property
    def capabilities(self) -> ConnectorCapabilities: ...

    async def pivot(self, request: PivotRequest) -> PivotResult:
        """Answer one question.

        Must not raise for an expected failure — a timeout, a rate limit, an empty answer.
        Return a :class:`PivotResult` carrying the error instead, so the investigation
        records that it looked and could not see, rather than losing the attempt.
        """
        ...

    async def health(self) -> bool:
        """Whether the connector is currently usable."""
        ...
