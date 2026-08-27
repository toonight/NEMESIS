"""Provenance: where something came from, who touched it, and what was done to it.

Provenance is the difference between an intelligence product and an assertion. Invariant 3
requires that every material claim resolves to a derivation chain terminating in either a
collected artifact or a named human. This module defines the links of that chain.

Three separable questions, kept separate because they fail differently:

1. **Source** — who or what originated the information, and how much that origin is worth.
2. **Collection** — the mechanism that acquired it, and whether that mechanism is
   reproducible.
3. **Processing** — every transformation between the raw artifact and what an analyst
   sees. Each step is a place where meaning can be lost or injected.

The processing chain is where most silent corruption happens in real intelligence systems:
an artifact is parsed, normalized, deduplicated, translated and summarized, and by the time
it reaches a decision-maker nobody can say which step introduced the error. Recording the
input and output hash of every step makes that answerable.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, ClassVar, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.ids import ActorId, CollectionId
from nemesis.core.temporal import utcnow


class SourceReliability(StrEnum):
    """NATO Admiralty Code source reliability grading (STANAG 2511).

    Grades the SOURCE, independently of any particular piece of information it supplied.
    A completely reliable source can still report something false; that is what the
    credibility axis is for. Conflating the two is the classic analytic error this
    two-axis system exists to prevent.
    """

    COMPLETELY_RELIABLE = "A"
    USUALLY_RELIABLE = "B"
    FAIRLY_RELIABLE = "C"
    NOT_USUALLY_RELIABLE = "D"
    UNRELIABLE = "E"
    CANNOT_BE_JUDGED = "F"


class InformationCredibility(StrEnum):
    """NATO Admiralty Code information credibility grading (STANAG 2511).

    Grades THIS piece of information, chiefly by whether it is corroborated by
    independent sources or consistent with what is otherwise known.
    """

    CONFIRMED = "1"
    PROBABLY_TRUE = "2"
    POSSIBLY_TRUE = "3"
    DOUBTFUL = "4"
    IMPROBABLE = "5"
    CANNOT_BE_JUDGED = "6"


class SourceClass(StrEnum):
    """What kind of thing produced the information.

    Kept coarse deliberately. Its purpose is dependence assessment: two findings from the
    same class are far more likely to be correlated than two from different classes, and
    fusing correlated sources as if independent is the primary mechanism by which
    attribution confidence gets inflated.
    """

    OWN_SENSOR = "own_sensor"
    """Telemetry from infrastructure we operate. Highest control, narrowest view."""

    HONEYPOT = "honeypot"
    """Deception infrastructure we operate."""

    COMMERCIAL_FEED = "commercial_feed"
    """Licensed intelligence provider."""

    OPEN_SOURCE = "open_source"
    """Publicly available. Cheap, and cheap for an adversary to poison."""

    INTERNET_SCAN = "internet_scan"
    """Third-party scan or passive-DNS style observation of the public internet."""

    BLOCKCHAIN = "blockchain"
    """Public ledger. Unusually strong: append-only and independently verifiable."""

    DARK_WEB = "dark_web"
    """Collected from criminal ecosystems. Hostile by construction."""

    PARTNER = "partner"
    """Shared by a trusted peer organization."""

    LAW_ENFORCEMENT = "law_enforcement"
    """Provided under a lawful channel. May carry handling restrictions."""

    HUMAN_ANALYST = "human_analyst"
    """A named person's assertion."""

    MODEL_INFERENCE = "model_inference"
    """Produced by an LLM or ML model. Invariant 1: never evidence."""


UNPLANTABLE_SOURCE_CLASSES: frozenset[SourceClass] = frozenset(
    {SourceClass.OWN_SENSOR, SourceClass.LAW_ENFORCEMENT}
)
"""The only channels an adversary cannot author a record in.

Kept as data so the allowlist can be asserted in a test and argued with in review, rather
than living inside a property nobody re-reads. Adding a class here weakens every control
that depends on plantability, so an addition should be a documented decision.
"""


class SourceDescriptor(BaseModel):
    """Who or what originated a piece of information."""

    model_config = ConfigDict(frozen=True)

    source_class: SourceClass
    identifier: Annotated[str, Field(min_length=1, max_length=512)]
    """Stable name for the source: a feed name, a sensor id, an onion address, a person."""

    reliability: SourceReliability = SourceReliability.CANNOT_BE_JUDGED
    operator: str | None = Field(
        default=None,
        description="Organization operating the source. Two feeds resold from one upstream "
        "share an operator and are therefore not independent, however differently branded.",
    )
    upstream_of_record: str | None = Field(
        default=None,
        description="The true origin when this source is a reseller, aggregator or mirror. "
        "Populating this is what makes independence assessment possible at all.",
    )
    handling_restrictions: tuple[str, ...] = ()
    """e.g. TLP:RED, contractual redistribution limits, law-enforcement caveats.

    **Recorded, not enforced — do not read this as a control.** Two connectors write it and
    nothing in the tree reads it: no export path, no disclosure path, no test. A field whose
    documented purpose is redistribution limits, consulted by nobody, reads as a dissemination
    control in review and is not one, which is the more dangerous of the two states.

    It is also dropped rather than merged when :func:`~nemesis.evidence.lineage.resolve_sources`
    collapses two artifacts naming one source, because that dedup keys on identity alone. See
    the threat model; enforcing it is `PROPOSED` and labelling it honestly is the interim.
    """

    @property
    def is_adversary_influenceable(self) -> bool:
        """Whether an adversary can plausibly plant content into this source.

        An **allowlist**, deliberately: everything is plantable unless it is one of the few
        channels an adversary demonstrably cannot write into. The earlier version was a
        blocklist naming open-source, dark-web and internet-scan, which read every other
        class as unplantable — and laundering one artifact through a commercial feed, a
        partner, a human analyst, a honeypot, a blockchain or a model reached VERY_LIKELY
        as a result. Measured before the inversion: 0.897. After: refused.

        The allowlist is short and each entry earns its place:

        - ``OWN_SENSOR`` — infrastructure we operate, observing traffic sent to us. An
          adversary can cause an observation but cannot author the record.
        - ``LAW_ENFORCEMENT`` — supplied under a lawful channel with its own chain of
          custody.

        Notably absent, and each for a reason worth stating:

        - ``HONEYPOT`` is ours, and an adversary writing into it is the entire point of
          deploying one. Ownership is not unplantability.
        - ``BLOCKCHAIN`` is unforgeable about what was written and says nothing about who
          chose to write it. An adversary can put anything on a public ledger.
        - ``MODEL_INFERENCE`` derives from whatever the model read, so it inherits the
          plantability of its inputs and adds none of its own authority (invariant 1).
        """
        return self.source_class not in UNPLANTABLE_SOURCE_CLASSES

    UNKNOWN_LINEAGE_CLUSTER: ClassVar[str] = "lineage:unknown"

    @property
    def has_known_lineage(self) -> bool:
        """Whether anything is actually known about where this source's data came from."""
        return bool(self.upstream_of_record or self.operator)

    def provenance_cluster(self) -> str:
        """The group within which two sources are known to share an origin.

        Semantics, which are asymmetric and must stay that way:

        - **Same cluster is positive evidence of dependence.** Two feeds resolving to one
          upstream carry one origin's data, and fusing them as independent would count it
          twice.
        - **Different clusters are NOT evidence of independence.** They mean only that we
          have not established a shared origin — which is a statement about our records,
          not about the world.

        Sources with no lineage at all therefore collapse into one shared cluster rather
        than each getting a key of their own. Keying them on their identifier would convert
        *missing provenance* into *asserted independence*, and that is the single most
        dangerous default this system could have: honest sources reporting descendants of
        one adversary-planted artifact would accumulate as independent corroboration.
        Measured on our own cumulative fusion, ten such keys on one planted opinion reach
        a projected probability of 0.97 having learned nothing about the actor at all.

        Grouping them together is conservative in the direction that matters. It understates
        confidence when the sources really were independent, which costs an investigation
        time; the opposite error costs somebody their infrastructure.
        """
        if self.upstream_of_record:
            return f"upstream:{self.upstream_of_record}"
        if self.operator:
            return f"operator:{self.operator}"
        return self.UNKNOWN_LINEAGE_CLUSTER


class CollectionMethod(BaseModel):
    """How an artifact was acquired. Reproducibility is the point."""

    model_config = ConfigDict(frozen=True)

    collector_name: Annotated[str, Field(min_length=1)]
    collector_version: Annotated[str, Field(min_length=1)]
    """Exact version. An artifact collected by a buggy parser is a different artifact."""

    parameters: dict[str, str] = Field(default_factory=dict)
    """Query, endpoint, selectors — whatever would be needed to attempt reproduction."""

    is_simulated: bool = False
    """True when the collector returns synthetic data. Never silently flipped to False."""

    sandbox_profile: str | None = Field(
        default=None,
        description="Isolation profile the collector ran under. Required for any collector "
        "handling hostile content; its absence there is a policy violation.",
    )


class CustodyAction(StrEnum):
    """Chain-of-custody event types, aligned with ISO/IEC 27037 expectations."""

    COLLECTED = "collected"
    SEALED = "sealed"
    TRANSFERRED = "transferred"
    ACCESSED = "accessed"
    ANALYZED = "analyzed"
    COPIED = "copied"
    EXPORTED = "exported"
    QUARANTINED = "quarantined"
    RELEASED_FROM_QUARANTINE = "released_from_quarantine"


class CustodyEvent(BaseModel):
    """One link in the chain of custody.

    Append-only by construction: there is no mutation path. A correction is a new event,
    never an edit, because an edit is indistinguishable from tampering.
    """

    model_config = ConfigDict(frozen=True)

    action: CustodyAction
    actor: ActorId
    occurred_at: datetime = Field(default_factory=utcnow)
    reason: Annotated[str, Field(min_length=1)]
    """Why. An access with no stated purpose is an audit finding."""

    artifact_hash_before: str | None = None
    artifact_hash_after: str | None = None
    """Both present for transforming actions; equal for non-transforming ones."""

    signature: str | None = Field(
        default=None,
        description="Detached signature over the canonical event encoding. Unsigned events "
        "are acceptable in development and are marked as such in export.",
    )

    @model_validator(mode="after")
    def _check_hashes(self) -> Self:
        transforming = self.action in {CustodyAction.ANALYZED, CustodyAction.COPIED}
        if transforming and self.artifact_hash_after is None:
            raise ValueError(f"{self.action} must record artifact_hash_after")
        return self


class ProcessingStep(BaseModel):
    """One transformation between a raw artifact and a derived representation.

    Every step names its tool and version and records the hash on both sides. This makes
    the question "which step introduced this error?" answerable, which it is not in most
    intelligence pipelines.
    """

    model_config = ConfigDict(frozen=True)

    step_name: Annotated[str, Field(min_length=1)]
    tool: Annotated[str, Field(min_length=1)]
    tool_version: Annotated[str, Field(min_length=1)]
    input_hash: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    output_hash: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    performed_at: datetime = Field(default_factory=utcnow)
    parameters: dict[str, str] = Field(default_factory=dict)

    is_lossy: bool = Field(
        default=False,
        description="True when the step discards information (summarization, truncation, "
        "OCR, translation). A lossy step downstream of evidence weakens what can be "
        "defended, and analysts must be able to see where that happened.",
    )

    performed_by_model: str | None = Field(
        default=None,
        description="Model identifier when an LLM performed the step. Its output is a "
        "derived representation, never evidence (invariant 1).",
    )


class ProvenanceChain(BaseModel):
    """The full derivation record attached to an evidence object or claim."""

    model_config = ConfigDict(frozen=True)

    collection_id: CollectionId
    source: SourceDescriptor
    method: CollectionMethod
    collected_at: datetime
    custody: tuple[CustodyEvent, ...] = ()
    processing: tuple[ProcessingStep, ...] = ()

    @model_validator(mode="after")
    def _check_processing_is_a_chain(self) -> Self:
        """Each processing step must consume its predecessor's output.

        A break here means an artifact appeared in the pipeline from somewhere
        unaccounted for — which is exactly what evidence fabrication looks like.
        """
        for earlier, later in zip(self.processing, self.processing[1:], strict=False):
            if earlier.output_hash != later.input_hash:
                raise ValueError(
                    f"processing chain is broken: step {later.step_name!r} consumes "
                    f"{later.input_hash} but {earlier.step_name!r} produced {earlier.output_hash}"
                )
        return self

    @property
    def has_lossy_processing(self) -> bool:
        return any(step.is_lossy for step in self.processing)

    @property
    def touched_by_model(self) -> bool:
        """Whether any LLM sits in this derivation chain."""
        return any(step.performed_by_model is not None for step in self.processing)

    @property
    def is_simulated(self) -> bool:
        return self.method.is_simulated
