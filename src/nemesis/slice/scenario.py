"""The GLASS ANVIL vertical slice: one run, twelve stages, one result object.

`docs/architecture/DEMO_SCENARIO.md` is the contract; this module is the executable form
of it. It wires the nine planes together in the order the scenario prescribes —
DETECT, PURSUE, GRAPH, DARK WEB, BLOCKCHAIN, RESOLVE, ATTRIBUTE, EVIDENCE, DISRUPT,
AUTHORIZE, EFFECT, RESURGENCE — and returns every stage's output in one
:class:`ScenarioResult`, so the CLI and the end-to-end test consume the same run rather
than two orchestrations that can drift apart.

Status: `SIMULATED`. Every connector reads a fixture, every entity and every claim is
flagged synthetic, and the only I/O is a local workspace directory holding the evidence
vault and the audit trail. There is no network code here and none reachable from here.

Three things about the shape of this module are decisions rather than conveniences.

**Autonomous pursuit and analyst-directed collection are separate and separately
recorded.** The Pursuit Engine drives itself from the phishing domain and reaches the
whole infrastructure cluster on its own. It cannot reach the dark-web persona: the only
bridge the scenario gives is the Telegram channel embedded in the kit (§2.7), and no
connector answers "which persona advertises this messaging account". Rather than pretend
the leap was autonomous, the slice performs those pivots through
:func:`_collect`, records each one in the audit trail as ``collection.directed`` with the
analyst's stated reason, and reports them separately from the engine's own work. An
investigation that presents a human's leap as a machine's finding is an investigation
nobody can review.

**Evidence is sealed before the claims that cite it, everywhere.** :func:`_collect`
repeats the Pursuit Engine's ordering rather than inventing its own, because a claim
citing evidence that failed to seal has unresolvable provenance (invariant 3).

**Nothing here computes a confidence figure by hand.** Edge confidence comes from the
relationships materialization built; fusion goes through :func:`nemesis.core.fusion.fuse`;
bands come from :func:`nemesis.core.confidence.band_of`. The one number this module
chooses for itself is :data:`CLUSTER_MIN_CONFIDENCE`, and it is stated with what it
excludes so a reader can disagree with it.
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

from nemesis.attribute.dimensions import (
    AlternativeHypothesis,
    AttributionDimension,
    EvidenceAvailability,
    MissingEvidence,
)
from nemesis.attribute.engine import (
    AttributionEngine,
    AttributionEvidence,
    AttributionRequest,
    AttributionResult,
    DimensionInput,
    EvidenceDirection,
)
from nemesis.audit.trail import ActorKind, AppendOnlyAuditTrail, make_event
from nemesis.authz.attestation import PrincipalVerifier
from nemesis.authz.gateway import (
    AuthorizationGateway,
    RequestState,
)
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.authz.providers import LocalDevelopmentIdentityProvider
from nemesis.authz.rbac import AuthorizationPolicyError
from nemesis.authz.store import SqliteAuthorizationStore
from nemesis.authz.verification import CapabilityVerification
from nemesis.collect.base import (
    CONNECTOR_VERSION,
    QUALIFIER_HOSTILE_CONTENT,
    QUALIFIER_PIVOT_METHOD,
    QUALIFIER_POPULATION_CORPUS,
    QUALIFIER_POPULATION_SIZE,
    QUALIFIER_SHARED_ATTRIBUTE,
    build_observation,
    connector_actor_id,
)
from nemesis.collect.fixtures.glass_anvil import (
    BULLETPROOF_ASN,
    BULLETPROOF_HOST,
    CDN_IP,
    CERT_FINGERPRINT,
    CERTIFICATE_CORPUS_RESURGENCE,
    CERTIFICATE_POPULATION_AFTER_RESURGENCE,
    CLUSTER_DOMAINS,
    CLUSTER_IP,
    CLUSTER_NETBLOCK,
    CLUSTERING_FAILURE_MODE,
    CLUSTERING_HEURISTIC,
    DARK_WEB_CORPUS,
    DETECTED_AT,
    EXCHANGE,
    FORUM_CURRENT,
    FORUM_RESURGENT,
    FRAMED_ORGANIZATION,
    INBOUND_PAYMENT_COUNT,
    KIT_HOST_IP,
    KIT_SHA256,
    MARKETPLACE_HISTORICAL,
    PERSONA_CURRENT,
    PERSONA_HISTORICAL,
    PERSONA_RESURGENT,
    PGP_FINGERPRINT,
    PHISHING_SOURCE_IP,
    REGISTRAR,
    RESURGENCE_AS_OF,
    RESURGENCE_ASN,
    RESURGENCE_DOMAIN,
    RESURGENCE_IP,
    RESURGENCE_REGISTRAR,
    SCENARIO_PRESENT,
    SEED_DOMAIN,
    SENDER_DOMAIN,
    TELEGRAM_CHANNEL,
    WALLET_EXCHANGE_DEPOSIT,
    WALLET_PRIMARY,
    WALLET_SECOND,
    phase_one_detection,
)
from nemesis.collect.isolation import collect_confined
from nemesis.collect.quarantine import (
    ArtifactAnalyser,
    Quarantine,
    StructuralAnalyser,
    seal_when_released,
)
from nemesis.collect.simulated import simulated_connectors
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    AuthorizationDecision,
    LegalBasis,
    OperationClass,
    StopCondition,
    TargetFingerprint,
)
from nemesis.core.claims import (
    Claim,
    ClaimKind,
    DerivationKind,
    Statement,
    check_derivation,
)
from nemesis.core.confidence import BAND_RANGES, ConfidenceBand, Opinion, band_of
from nemesis.core.entities import Entity, EntityCategory, EntityType
from nemesis.core.fusion import FusionResult, SourcedOpinion, fuse
from nemesis.core.identity import AssuranceLevel, Role
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import (
    CollectionMethod,
    InformationCredibility,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
)
from nemesis.core.relationships import (
    Explanation,
    PivotMethod,
    PivotSelectivity,
    Relationship,
    RelationType,
)
from nemesis.core.temporal import TemporalExtent, utcnow
from nemesis.disrupt.options import (
    AdversaryRecovery,
    DisruptionTarget,
    ImpactLevel,
    OwnershipEvidence,
    ProviderDisposition,
    RecoveryDifficulty,
)
from nemesis.disrupt.planner import DisruptionLever, DisruptionPlan, DisruptionPlanner
from nemesis.effects.isolation import IsolatedEffectsExecutor
from nemesis.effects.registry import EffectsRegistry, default_registry
from nemesis.evidence.anchoring import LocalHeadSigner
from nemesis.evidence.lineage import resolve_sources
from nemesis.evidence.vault import (
    AnchorRecord,
    FileSystemEvidenceVault,
    FileSystemVaultIntegrityReport,
)
from nemesis.graph.journal import JournalBackedClaimStore, JournalBackedGraphStore
from nemesis.ports.authorization import TrustAnchor
from nemesis.ports.collection import IntelligenceConnector, PivotRequest, PivotResult, PivotType
from nemesis.ports.effects import EffectRequest, EffectResult
from nemesis.ports.isolation import IsolationReport
from nemesis.ports.storage import AuditEvent, GraphQuery, Subgraph
from nemesis.pursuit.engine import (
    ConnectorRegistry,
    PursuitEngine,
    mark_awaiting_authorization,
    mark_monitoring_resurgence,
)
from nemesis.pursuit.investigation import IncidentSeed, Investigation
from nemesis.pursuit.materialize import MaterializationResult, materialize
from nemesis.pursuit.resurgence import (
    ResurgenceAssessment,
    ResurgenceEngine,
    ResurgenceSignal,
    ResurgenceSignalKind,
)
from nemesis.pursuit.watch import (
    WatchReport,
    assemble_resurgence_signals,
    resume_pursuit,
    watch_for_resurgence,
)
from nemesis.resolve.engine import (
    HumanIdentityRefusal,
    PersonaLinkageAssessment,
    PersonaResolutionEngine,
)
from nemesis.resolve.signals import (
    LinkageSignal,
    alias_similarity,
    shared_cryptographic_identity,
)

# --------------------------------------------------------------------------------------
# Scenario constants
# --------------------------------------------------------------------------------------

SCENARIO_SUBJECT: Final = "the actor behind Operation GLASS ANVIL"

CLUSTER_MIN_CONFIDENCE: Final = 0.5
"""Minimum edge confidence the cluster query will cross.

Chosen against the two pivots the scenario contrasts, not tuned: the 4-domain reverse
resolution lands at a projected 0.74 and the 41,700-domain CDN pivot at 0.32, so any
threshold strictly between them separates them. The value is stated here rather than
buried in a call site so a reader can disagree with it, and the run reports both figures
alongside it.
"""

DARK_BAZAAR_PERSONA_POPULATION: Final = 40_000
"""How many personas the GlassAnvil/AnvilWorks pair was drawn from.

A scenario assumption, not a measurement: the fixture set describes two forums but never
states how many accounts they hold, and
:func:`nemesis.resolve.engine.base_rate_for_population` refuses to answer without one.
Chosen large because the prior it produces is what keeps a moderate resemblance from
reading as a finding; a smaller figure would flatter the engine's own conclusion.
"""

PERSONA_POPULATION_CORPUS: Final = (
    "SIMULATED DarkBazaar account population, GLASS ANVIL fixture set — a scenario "
    "assumption, not a measurement"
)

CAPABILITY_LIFETIME: Final = timedelta(hours=4)
"""Phase 7 of the scenario. Well under the gateway's 24-hour ceiling."""

CASE_AUTHORITY_REFERENCE: Final = "SIMULATED-CASE-GLASS-ANVIL-2026-0042"

RESURGENCE_RULE: Final = "resurgence.shared-artifact-reconnection"

RESUMPTION_BUDGET: Final = 25.0
"""What reopening a case on a recognised return is allowed to cost.

Added to the ceiling, never a reset — a case that reopens with a fresh allowance every time
is a tap an adversary controls, since returning is cheap for them."""

TRACKED_CAMPAIGNS: Final = 40
"""How many campaigns the resurgence assessment compares this cluster against.

A stated assumption rather than a measurement, and the number the prior divides by. Forty is
the order of magnitude a small team tracks; a larger corpus makes every prior smaller and the
same evidence less conclusive, which is the direction honesty runs in."""
RESURGENCE_RULE_VERSION: Final = "0.1.0"

_SENSOR_REPLAY_METHOD: Final = CollectionMethod(
    collector_name="acme-sensor-replay",
    collector_version=CONNECTOR_VERSION,
    parameters={"fixture_set": "glass-anvil", "phase": "1-detect"},
    # Set here and never from an argument: a phase-1 record that lost the flag would make
    # the seed of the whole investigation look like real telemetry.
    is_simulated=True,
)

_DETECTION_PROPOSITION: Final = (
    "the quarantined message and the blocked request are the same attack against ACME"
)


# --------------------------------------------------------------------------------------
# Stage models
#
# Every stage model is frozen and fully serializable, because the end-to-end test walks
# them looking for a natural person's name. A stage that carried a live handle, or bytes,
# would be a hole in that walk.
# --------------------------------------------------------------------------------------


class SensorRecord(BaseModel):
    """One phase-1 sensor, with the key that decides whether it is a second source."""

    model_config = ConfigDict(frozen=True)

    sensor: str
    operator: str
    source_class: SourceClass
    reliability: SourceReliability
    evidence_id: str
    claim_id: str
    independence_key: str


class DetectionStage(BaseModel):
    """Phase 1. One event, two sensors, one origin."""

    model_config = ConfigDict(frozen=True)

    detected_at: datetime
    seed_entity_type: EntityType
    seed_entity_key: str
    detected_by: str
    sensors: tuple[SensorRecord, ...]
    proposition: str
    fusion: FusionResult

    @property
    def sensors_collapsed_to_one_origin(self) -> bool:
        return self.fusion.independent_source_count == 1 and self.fusion.total_sources > 1


class DirectedCollection(BaseModel):
    """One analyst-directed pivot, with why the autonomous policy could not make it.

    ``discovered`` deliberately omits entities in a personal-data category. The listing is
    a convenience for a reader; reproducing a natural person's name in it would publish the
    very lead the platform is about to refuse.
    """

    model_config = ConfigDict(frozen=True)

    pivot_type: PivotType
    entity_type: EntityType
    entity_key: str
    connector: str
    rationale: str
    succeeded: bool
    error: str | None = None
    truncated: bool = False
    claim_count: int = 0
    evidence_count: int = 0
    discovered: tuple[str, ...] = ()
    withheld_personal_data_entities: int = 0
    unmaterialized: tuple[str, ...] = ()


class PursuitStage(BaseModel):
    """Phase 2. What the engine did on its own, and what an analyst had to direct."""

    model_config = ConfigDict(frozen=True)

    investigation: Investigation
    autonomous_pivots: int
    autonomous_failures: tuple[str, ...]
    directed: tuple[DirectedCollection, ...]
    directed_because: str


class EdgeSummary(BaseModel):
    """One edge, reduced to what decides whether it is worth crossing."""

    model_config = ConfigDict(frozen=True)

    source_key: str
    target_key: str
    relation: RelationType
    pivot_method: PivotMethod
    shared_attribute: str | None
    population_size: int | None
    population_measured_against: str | None
    is_informative: bool
    evidential_weight: float
    projected_probability: float
    band: ConfidenceBand
    caveats: tuple[str, ...]


class GraphStage(BaseModel):
    """Phase 2.2 and 2.3. The cluster, and the pivot that must not build one."""

    model_config = ConfigDict(frozen=True)

    entity_count: int
    relationship_count: int
    min_confidence: float
    cluster_entity_keys: tuple[str, ...]
    cluster_domains: tuple[str, ...]
    victim_domains_discovered: tuple[str, ...]
    excluded_shared_infrastructure: tuple[str, ...]
    selective_pivot: EdgeSummary
    worthless_pivot: EdgeSummary
    cdn_tenants_in_cluster: tuple[str, ...]
    cdn_tenants_behind_the_filter: tuple[str, ...]
    cdn_tenants_reachable_unfiltered: tuple[str, ...]


class HumanIdentityLead(BaseModel):
    """A name asserted by a hostile channel, recorded and never promoted.

    This is the only object in the whole result that carries the name, and it carries it
    labelled as a refused lead in a regulated category. Everything downstream — the
    resolution refusal, the attribution refusal, the rendered output — references it by
    claim identifier, because a hash carries no name.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: str
    entity_type: EntityType
    category: EntityCategory
    lead_display: str
    recorded_from_claim: str
    asserted_by_persona: str
    source_class: SourceClass
    source_reliability: SourceReliability
    independent_source_count: int
    adversary_could_plant: bool
    planting_cost: str
    benefits_from_belief: tuple[str, ...]
    promoted_to_attribution: Literal[False] = False
    is_personal_data: Literal[True] = True
    handling: str


class PromptInjectionRecord(BaseModel):
    """Collected text that instructs its reader. Data, never instruction (invariant 5)."""

    model_config = ConfigDict(frozen=True)

    claim_id: str
    posted_by_persona: str
    characters_quoted: int
    quoted_verbatim: bool
    marked_hostile: bool
    acted_on: Literal[False] = False
    note: str


class DarkWebStage(BaseModel):
    """Phase 3 and phase 6. The persona, the key, and both traps."""

    model_config = ConfigDict(frozen=True)

    persona: str
    forum: str
    historical_persona: str
    marketplace: str
    pgp_fingerprint: str
    pgp_key_bits: int
    persona_in_graph: bool
    pgp_key_in_graph: bool
    persona_signs_key_claim: str
    historical_signs_key_claim: str
    telegram_channel: str
    hostile_content_claims: int
    prompt_injection: PromptInjectionRecord
    identity_lead: HumanIdentityLead


class BlockchainStage(BaseModel):
    """Phase 4. A ledger fact, a heuristic inference, and the difference between them."""

    model_config = ConfigDict(frozen=True)

    escrow_address: str
    inbound_payments: int
    clustered_with: str
    clustering_heuristic: str
    known_failure_mode: str
    exchange_deposit_address: str
    exchange: str
    signal_claim_id: str
    signal_opinion: Opinion
    signal_band: ConfidenceBand
    contributes_to: tuple[str, ...]
    withheld_from: tuple[str, ...]


class ResolutionStage(BaseModel):
    """Phase 5. Two personas, one key, and a refusal to go further."""

    model_config = ConfigDict(frozen=True)

    assessment: PersonaLinkageAssessment
    refusal: HumanIdentityRefusal
    signals_used: tuple[str, ...]
    signals_unavailable: tuple[str, ...]


class AttributionStage(BaseModel):
    """Phase 7. Five answers, never one."""

    model_config = ConfigDict(frozen=True)

    result: AttributionResult
    false_flag_claim_id: str
    framed_organization: str
    human_identity_band: ConfidenceBand
    weak_markers_not_scored: tuple[str, ...]
    false_flag_direction: Literal["contradicting"] = "contradicting"
    names_a_natural_person: Literal[False] = False


class EvidenceStage(BaseModel):
    """Phase 8 of the discipline, not of the timeline: what the vault can and cannot say."""

    model_config = ConfigDict(frozen=True)

    report: FileSystemVaultIntegrityReport
    head: str
    anchor: AnchorRecord
    anchor_is_externally_held: bool
    is_intact: bool
    is_defensible_against_insider: Literal[False]
    admissibility_defects: tuple[str, ...]
    cannot_defend: tuple[str, ...]
    export_entries: int
    export_withheld_restricted: int


class DisruptionStage(BaseModel):
    """Phase 7. Levers, including the ones NEMESIS is not permitted to pull."""

    model_config = ConfigDict(frozen=True)

    plan: DisruptionPlan
    executable_now: tuple[str, ...]
    requires_legal_authority: tuple[str, ...]
    needs_ownership_confirmation: tuple[str, ...]
    whack_a_mole: tuple[str, ...]
    capability_degrading: tuple[str, ...]


class ScopeProbe(BaseModel):
    """A question asked of the issued capability, and its answer.

    Carried in the result so the narrowness of the grant is a demonstrated property rather
    than a claim about one: each probe asks for something outside the scope and records the
    refusal with its reason.
    """

    model_config = ConfigDict(frozen=True)

    question: str
    decision: AuthorizationDecision


class AuthorizationStage(BaseModel):
    """Phase 7. One approval, one human rejection, one refusal by the platform itself."""

    model_config = ConfigDict(frozen=True)

    capability: AuthorizationCapability
    verification: CapabilityVerification
    approvals: tuple[Approval, ...]
    rejection: Approval
    rejected_option: str
    rejected_request_state: RequestState
    target_count: int
    lifetime_hours: float
    scope_probes: tuple[ScopeProbe, ...]

    assurance_refusal: str
    """Why the platform refused the notification draft, in its own words.

    Not narration. This string is the exception raised when a development identity tried to
    approve an operation whose product is meant to leave the platform. NEMESIS can currently
    establish no identity better than a fixture, so it may rehearse and may not correspond.
    The demonstration used to *say* that in prose while quietly requesting only the rehearsal
    it was allowed; now it asks for the notification, is refused, and prints the refusal."""

    assurance_refused_operation: OperationClass
    assurance_refused_by: str


class AdapterRecord(BaseModel):
    """One registered effects adapter and the property asserted across all of them."""

    model_config = ConfigDict(frozen=True)

    name: str
    operation: OperationClass
    makes_external_contact: bool


class EffectsStage(BaseModel):
    """Phase 7. The rehearsal that ran, and the two things that did not.

    The notification is refused twice over, at two different boundaries: the assurance floor
    would not let a development identity approve it, so it is absent from the capability, so
    the Effects plane refuses it for want of a permission. Either refusal alone is enough,
    which is the design — controls that only work in series are controls with one point of
    failure.
    """

    model_config = ConfigDict(frozen=True)

    results: tuple[EffectResult, ...]
    adapters: tuple[AdapterRecord, ...]
    external_contact_made: bool

    isolation: IsolationReport
    """What confinement the effects actually ran under.

    The demonstration used to assert "external contact anywhere: False" from the adapters'
    own declarations — a claim by the components under suspicion. Every effect below now
    runs in a child process that holds no signing key, is denied a socket by the kernel on
    macOS, and cannot write outside a directory removed afterwards.

    Read the report rather than this docstring for what a given run got. It is written to
    refuse to round up: a socket denied to *this process* is what the kernel established,
    and it is a weaker statement than "nothing left the system"."""


class ResurgenceLink(BaseModel):
    """One reconnection to the historical actor, with the artifact that made it."""

    model_config = ConfigDict(frozen=True)

    predecessor: str
    successor: str
    shared_artifact: str
    pivot_method: PivotMethod
    inference_claim_id: str
    explanation: Explanation
    rendered: str


class ResurgenceStage(BaseModel):
    """Phase 8. T+45 days, nothing obvious in common, two artifacts that give it away."""

    model_config = ConfigDict(frozen=True)

    as_of: datetime
    new_domain: str
    new_ip: str
    new_asn: str
    new_registrar: str
    new_persona: str
    new_forum: str
    nothing_in_common: tuple[str, ...]
    collections: tuple[DirectedCollection, ...]
    links: tuple[ResurgenceLink, ...]
    reconnected_by: tuple[str, ...]
    not_reconnected_by: tuple[str, ...]
    watch: WatchReport
    """The watch pass itself: what it examined and whether it justified resuming.

    Phase 8 previously ended with the case parked in ``MONITORING_RESURGENCE`` and nothing ever
    asking whether the adversary had come back. This is that question being asked, on the graph
    as it stands *after* the phase-8 collection landed — which is the only order in which the
    answer means anything."""

    resumed: Investigation | None
    """The reopened case, when the watch found something worth reopening on. ``None`` here is
    the expected outcome for this run and is not a failure: see the watch report's own verdict."""

    graph_signals: tuple[ResurgenceSignal, ...]
    """What a blind two-hop walk of the graph finds at this point, with no analyst input.

    Carried beside :attr:`assessment` to make one limit visible rather than arguable. The
    assessment is scored from signals whose provenance somebody established; these are what the
    graph alone offers, and the graph carries no ``SourceDescriptor`` — provenance lives on the
    evidence in the vault. So these arrive marked plantable and unjudgeable, the robustness
    margin removes them, and a run built only on them would produce a lead rather than a
    finding. The difference between the two numbers is the value of having checked where an
    observation came from."""

    assessment: ResurgenceAssessment
    """The scored judgement, from the same two artifacts the narrative above reconnects on.

    The stage's prose was hand-written for this scenario and says *that* the reconnection
    happened; this says how strongly it is supported, through the same fusion, independence
    collapse and robustness margin every other conclusion in this platform goes through. The
    two are deliberately produced side by side: the day they disagree, the narrative is
    wrong."""


# --------------------------------------------------------------------------------------
# The result
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScenarioStores:
    """The live stores the run wrote to.

    Held apart from the stage models so the serializable half of the result stays
    serializable. A caller that wants to interrogate the graph, replay the audit trail or
    re-verify the vault reaches through here; a caller that wants to render or walk the
    findings uses :meth:`ScenarioResult.stages`.
    """

    workspace: Path
    graph: JournalBackedGraphStore
    claims: JournalBackedClaimStore
    vault: FileSystemEvidenceVault
    audit: AppendOnlyAuditTrail
    authorization: SqliteAuthorizationStore
    gateway: AuthorizationGateway
    effects: EffectsRegistry


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """Every stage's output from one run, plus the stores it wrote to."""

    detect: DetectionStage
    pursue: PursuitStage
    graph: GraphStage
    darkweb: DarkWebStage
    blockchain: BlockchainStage
    resolve: ResolutionStage
    attribute: AttributionStage
    evidence: EvidenceStage
    disrupt: DisruptionStage
    authorize: AuthorizationStage
    effect: EffectsStage
    resurgence: ResurgenceStage
    stores: ScenarioStores

    def stages(self) -> tuple[tuple[str, BaseModel], ...]:
        """The twelve stages in scenario order, named as the CLI's ``--stage`` accepts."""
        return (
            ("detect", self.detect),
            ("pursue", self.pursue),
            ("graph", self.graph),
            ("darkweb", self.darkweb),
            ("blockchain", self.blockchain),
            ("resolve", self.resolve),
            ("attribute", self.attribute),
            ("evidence", self.evidence),
            ("disrupt", self.disrupt),
            ("authorize", self.authorize),
            ("effect", self.effect),
            ("resurgence", self.resurgence),
        )

    def stage(self, name: str) -> BaseModel | None:
        return dict(self.stages()).get(name)


STAGE_NAMES: Final = (
    "detect",
    "pursue",
    "graph",
    "darkweb",
    "blockchain",
    "resolve",
    "attribute",
    "evidence",
    "disrupt",
    "authorize",
    "effect",
    "resurgence",
)


def band_range(band: ConfidenceBand) -> str:
    """The numeric range behind a verbal band.

    Every output that shows a band must show this alongside it: "likely" means wildly
    different numbers to different readers, which is the whole reason the bands are
    standardised.
    """
    if band is ConfidenceBand.INSUFFICIENT_BASIS:
        return "no range — the evidence does not support an estimate"
    low, high = BAND_RANGES[band]
    return f"{low:.0%} to {high:.0%}"


# --------------------------------------------------------------------------------------
# Run context
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Context:
    """What every stage needs to write what it collected, in one place."""

    graph: JournalBackedGraphStore
    claims: JournalBackedClaimStore
    vault: FileSystemEvidenceVault
    audit: AppendOnlyAuditTrail
    authorization: SqliteAuthorizationStore
    actor: str
    sources: dict[str, SourceDescriptor]
    """Connector name to the source descriptor its claims came from."""

    claim_sources: dict[str, SourceDescriptor]
    """Claim id to the source of record, so attribution grades what it is fusing."""

    claim_confidence: dict[str, Opinion]
    """Claim id to the confidence materialization gave the edge built from it. Read rather
    than recomputed: a second derivation of the same number is a second place for it to be
    wrong."""

    quarantine: Quarantine = field(default_factory=Quarantine)
    analyser: ArtifactAnalyser = field(default_factory=StructuralAnalyser)
    """Collected bytes are examined before the vault sees them. Defaults rather than
    required parameters because a scenario that quarantined only when asked would be one that
    does not: the caller who most needs it is the one who never heard of it."""


class ScenarioError(RuntimeError):
    """The run could not complete. Raised rather than degraded: a slice that quietly
    skipped a stage would report a demonstration it did not perform."""


# --------------------------------------------------------------------------------------
# Collection helpers
# --------------------------------------------------------------------------------------


def _entity_reference(entity: Entity) -> str:
    return f"{entity.entity_type.value}:{entity.natural_key}"


async def _absorb(
    context: _Context,
    *,
    claims: Sequence[Claim],
    source: SourceDescriptor,
) -> MaterializationResult:
    """Record claims and turn them into graph structure, in the order provenance requires.

    Claims first, then entities, then edges: an edge's supporting claim must already exist
    to be looked up. Mirrors :meth:`nemesis.pursuit.engine.PursuitEngine._absorb` rather
    than improvising a second ordering.
    """
    for claim in claims:
        await context.claims.record(claim)
        context.claim_sources[claim.claim_id] = source

    result = materialize(tuple(claims), is_synthetic=True)
    for entity in result.entities:
        await context.graph.upsert_entity(entity)
    for relationship in result.relationships:
        await context.graph.add_relationship(relationship)
        for claim_id in relationship.supporting_claims:
            context.claim_confidence[claim_id] = relationship.confidence
    return result


async def _collect(
    context: _Context,
    *,
    connector: IntelligenceConnector,
    pivot_type: PivotType,
    entity_type: EntityType,
    entity_key: str,
    rationale: str,
) -> tuple[DirectedCollection, tuple[Claim, ...]]:
    """Run one analyst-directed pivot and absorb what came back.

    Evidence is sealed before the claims that cite it, and the whole thing is recorded in
    the audit trail whether it succeeded or not: "we looked and found nothing" and "we
    could not look" are different findings, and only one of them is evidence of absence.
    """
    request = PivotRequest(
        pivot_type=pivot_type,
        entity_type=entity_type,
        entity_key=entity_key,
        reason=rationale,
    )
    # Through the shared decision, not `connector.pivot` directly. This call site is why
    # `collect_confined` exists as a function rather than a method on the engine: the engine
    # was wired first, and a full `nemesis demo` still ran six hostile pivots in the main
    # process, because the reference scenario has its own collection path.
    result, isolation_failure = await collect_confined(connector, request)
    if isolation_failure is not None:
        result = PivotResult(
            request=request,
            connector_name=connector.capabilities.name,
            observations=(),
            evidence=(),
            error=isolation_failure,
        )
    assert result is not None  # collect_confined returns one or the other, never neither
    source = connector.capabilities.source

    sealed: list[str] = []
    recorded: list[Claim] = []
    materialized = MaterializationResult()

    held: list[str] = []
    if result.succeeded:
        for evidence in result.evidence:
            artifact = result.artifacts.get(evidence.evidence_id)
            if artifact is None:
                continue
            # Through the shared decision, never `vault.seal` directly. Wiring the pursuit
            # engine alone left this path — and the sensor replay below — still sealing
            # collected bytes straight into an append-only store.
            sealed_id, _report = await seal_when_released(
                context.vault,
                evidence,
                artifact,
                quarantine=context.quarantine,
                analyser=context.analyser,
            )
            if sealed_id is None:
                held.append(evidence.evidence_id)
                continue
            sealed.append(sealed_id)
        recorded = [
            claim
            for claim in result.observations
            if not (held and set(claim.supported_by_evidence) & set(held))
        ]
        materialized = await _absorb(context, claims=recorded, source=source)

    visible = tuple(
        _entity_reference(entity) for entity in materialized.entities if not entity.is_personal_data
    )
    withheld = sum(1 for entity in materialized.entities if entity.is_personal_data)

    summary = DirectedCollection(
        pivot_type=pivot_type,
        entity_type=entity_type,
        entity_key=entity_key,
        connector=result.connector_name,
        rationale=rationale,
        succeeded=result.succeeded,
        error=result.error,
        truncated=result.truncated,
        claim_count=len(recorded),
        evidence_count=len(sealed),
        discovered=visible,
        withheld_personal_data_entities=withheld,
        unmaterialized=materialized.skipped,
    )

    await context.audit.record(
        make_event(
            actor=context.actor,
            actor_kind=ActorKind.HUMAN,
            action="collection.directed",
            subject=f"{entity_type.value}:{entity_key}",
            outcome=("collected " if result.succeeded else "failed ")
            + f"{len(recorded)} claim(s), {len(sealed)} artifact(s)",
            inputs={
                "pivot": pivot_type.value,
                "connector": result.connector_name,
                "connector_version": connector.capabilities.version,
                "reason": rationale,
                "truncated": str(result.truncated),
                "error": result.error or "",
            },
        )
    )
    return summary, tuple(recorded)


def _connector_for(
    connectors: Sequence[IntelligenceConnector], pivot: PivotType, entity_type: EntityType
) -> IntelligenceConnector:
    request = PivotRequest(
        pivot_type=pivot, entity_type=entity_type, entity_key="probe", reason="capability probe"
    )
    for connector in connectors:
        if connector.capabilities.can_answer(request):
            return connector
    raise ScenarioError(f"no simulated connector answers {pivot.value} for {entity_type.value}")


def _find_claim(claims: Iterable[Claim], *, predicate: str, contains: str = "") -> Claim:
    """The one claim with this predicate whose object mentions ``contains``.

    Raises rather than returning ``None``: a stage built on a claim that is not there would
    silently demonstrate less than it says it does.
    """
    for claim in claims:
        if claim.statement.predicate != predicate:
            continue
        if contains and contains.lower() not in claim.statement.obj.lower():
            continue
        return claim
    raise ScenarioError(f"no collected claim with predicate {predicate!r} matching {contains!r}")


def _edge_summary(edge: Relationship, entities: dict[str, Entity]) -> EdgeSummary:
    explanation = edge.explain()
    selectivity = edge.selectivity
    source = entities.get(edge.source_id)
    target = entities.get(edge.target_id)
    return EdgeSummary(
        source_key=source.natural_key if source else edge.source_id,
        target_key=target.natural_key if target else edge.target_id,
        relation=edge.relation,
        pivot_method=edge.pivot_method,
        shared_attribute=selectivity.attribute if selectivity else None,
        population_size=selectivity.population_size if selectivity else None,
        population_measured_against=(
            selectivity.population_measured_against if selectivity else None
        ),
        is_informative=bool(selectivity and selectivity.is_informative),
        evidential_weight=edge.evidential_weight(),
        projected_probability=edge.confidence.projected_probability,
        band=band_of(edge.confidence),
        caveats=explanation.caveats,
    )


# --------------------------------------------------------------------------------------
# Stage 1 — DETECT
# --------------------------------------------------------------------------------------


async def _detect(context: _Context) -> tuple[DetectionStage, IncidentSeed]:
    """Build the incident seed from the phase-1 phishing event.

    Two sensors report one event. They are not two sources: both are ACME's own telemetry
    with one operator, so :meth:`SourceDescriptor.provenance_cluster` collapses them and the
    fusion result says so. A demo that showed two corroborating sources here would have
    broken dependence handling.
    """
    records: list[SensorRecord] = []
    sourced: list[SourcedOpinion] = []
    evidence_ids: list[str] = []

    for report in phase_one_detection():
        actor = connector_actor_id(report.source.identifier, CONNECTOR_VERSION)
        evidence, claim = build_observation(
            record=report.record,
            source=report.source,
            method=_SENSOR_REPLAY_METHOD,
            collected_at=DETECTED_AT,
            asserted_by=actor,
            reason="phase-1 detection: replay of the sensor record that opened the case",
        )
        sealed_id, _replay_report = await seal_when_released(
            context.vault,
            evidence,
            report.record.artifact,
            quarantine=context.quarantine,
            analyser=context.analyser,
        )
        if sealed_id is None:
            raise ScenarioError(
                "the phase-1 sensor record was held in quarantine; the reference scenario "
                "cannot proceed without the detection that opens the case"
            )
        await _absorb(context, claims=(claim,), source=report.source)
        evidence_ids.append(evidence.evidence_id)

        records.append(
            SensorRecord(
                sensor=report.source.identifier,
                operator=report.source.operator or "<unstated>",
                source_class=report.source.source_class,
                reliability=report.source.reliability,
                evidence_id=evidence.evidence_id,
                claim_id=claim.claim_id,
                independence_key=report.source.provenance_cluster(),
            )
        )
        sourced.append(
            SourcedOpinion(
                source=report.source,
                opinion=Opinion.from_admiralty(
                    report.source.reliability,
                    InformationCredibility.CONFIRMED,
                ),
                supporting_claims=(claim.claim_id,),
                label=report.source.identifier,
            )
        )

    fusion = fuse(sourced, proposition=PropositionClass.OBSERVATION)
    seed = IncidentSeed(
        entity_type=EntityType.DOMAIN,
        entity_key=SEED_DOMAIN,
        observed_at=DETECTED_AT,
        detected_by="acme-email-gateway-01",
        context={
            "sender_domain": SENDER_DOMAIN,
            "source_ip": PHISHING_SOURCE_IP,
            "subject": "Invoice INV-2026-0847 overdue",
        },
        supporting_evidence=tuple(evidence_ids),
        victim_hint="ACME Corp",
    )

    await context.audit.record(
        make_event(
            actor=context.actor,
            actor_kind=ActorKind.HUMAN,
            action="incident.seed",
            subject=f"{seed.entity_type.value}:{seed.entity_key}",
            outcome=f"seeded from {len(records)} sensor(s), "
            f"{fusion.independent_source_count} independent origin(s)",
            inputs={
                "detected_by": seed.detected_by,
                "sensors": ",".join(record.sensor for record in records),
                "independent_origins": str(fusion.independent_source_count),
            },
        )
    )

    stage = DetectionStage(
        detected_at=DETECTED_AT,
        seed_entity_type=seed.entity_type,
        seed_entity_key=seed.entity_key,
        detected_by=seed.detected_by,
        sensors=tuple(records),
        proposition=_DETECTION_PROPOSITION,
        fusion=fusion,
    )
    return stage, seed


# --------------------------------------------------------------------------------------
# Stage 2 — PURSUE
# --------------------------------------------------------------------------------------

_DIRECTED_BECAUSE: Final = (
    "The rule-based policy proposes pivots by entity type. It reaches the whole "
    "infrastructure cluster from the seed on its own, and it cannot cross from that "
    "cluster to the dark-web persona: the scenario's bridge is the Telegram channel "
    "embedded in the kit (DEMO_SCENARIO.md §2.7), and no connector answers 'which persona "
    "advertises this messaging account'. The pivots below were therefore directed by an "
    "analyst and are recorded as such, rather than presented as autonomous findings."
)


async def _pursue(
    context: _Context,
    seed: IncidentSeed,
    connectors: Sequence[IntelligenceConnector],
    *,
    total_budget: float,
    max_steps: int,
) -> tuple[PursuitStage, dict[str, tuple[Claim, ...]]]:
    """Run the autonomous pursuit, then the analyst-directed pivots it cannot reach."""
    engine = PursuitEngine(
        graph=context.graph,
        claims=context.claims,
        vault=context.vault,
        audit=context.audit,
        connectors=ConnectorRegistry(connectors),
    )
    investigation = await engine.start(seed, total_budget=total_budget)
    investigation = await engine.run(investigation, max_steps=max_steps)

    for pivot in investigation.all_executed_pivots:
        source = context.sources.get(pivot.connector)
        if source is None:
            continue
        for claim_id in pivot.claims_produced:
            context.claim_sources[claim_id] = source

    # The engine materialized these itself; re-read the resulting edges so the attribution
    # plane grades a claim by the edge that was actually built from it rather than by a
    # second derivation of the same number.
    await _index_edge_confidence(context)

    plan: tuple[tuple[PivotType, EntityType, str, str], ...] = (
        (
            PivotType.RESOLUTION_HISTORY,
            EntityType.DOMAIN,
            SENDER_DOMAIN,
            "The phase-1 email header names this sender domain; the seed is the link "
            "target, so the sender is a second observable from the same event.",
        ),
        (
            PivotType.REVERSE_RESOLUTION,
            EntityType.IP_ADDRESS,
            CDN_IP,
            "Control case (DEMO_SCENARIO.md §2.3): measure how crowded the sender's "
            "address is before treating co-location on it as a link.",
        ),
        (
            PivotType.REVERSE_RESOLUTION,
            EntityType.IP_ADDRESS,
            PHISHING_SOURCE_IP,
            "The sending address from the gateway record. Expected to fail: the fixture "
            "partition does not answer, and a failure is not an observation of absence.",
        ),
        (
            PivotType.MALWARE_LOOKUP,
            EntityType.MALWARE,
            KIT_SHA256,
            "A kit archive was recovered from an open directory on the cluster host. No "
            "connector answers 'what is in the open directory', so the sample is pivoted "
            "on directly.",
        ),
        (
            PivotType.C2_EXTRACTION,
            EntityType.MALWARE,
            KIT_SHA256,
            "Exfiltration and operator-contact endpoints embedded in the kit.",
        ),
        (
            PivotType.PERSONA_ACTIVITY,
            EntityType.PERSONA,
            PERSONA_CURRENT.lower(),
            "The kit advertises the Telegram channel @glassanvil; an analyst recognised "
            "the same channel on a DarkBazaar vendor and directed collection at it.",
        ),
        (
            PivotType.MARKETPLACE_LISTING,
            EntityType.PERSONA,
            PERSONA_CURRENT.lower(),
            "What this persona sells, and where.",
        ),
        (
            PivotType.DARK_WEB_SEARCH,
            EntityType.PERSONA,
            PERSONA_CURRENT.lower(),
            "What the forum says about this persona. Expected to return hostile content, "
            "including an identity assertion the platform must refuse.",
        ),
        (
            PivotType.PERSONA_ACTIVITY,
            EntityType.PERSONA,
            PERSONA_HISTORICAL.lower(),
            "The same PGP fingerprint appears on a 2024 ShadowMarket listing; collect the "
            "historical persona's own publication of it.",
        ),
        (
            PivotType.MARKETPLACE_LISTING,
            EntityType.PERSONA,
            PERSONA_HISTORICAL.lower(),
            "The historical listing itself, for the alias comparison.",
        ),
        (
            PivotType.WALLET_ACTIVITY,
            EntityType.CRYPTO_ADDRESS,
            WALLET_PRIMARY,
            "The escrow address the persona advertises.",
        ),
        (
            PivotType.WALLET_CLUSTERING,
            EntityType.CRYPTO_ADDRESS,
            WALLET_PRIMARY,
            "Addresses under common control, heuristically — with the heuristic named.",
        ),
        (
            PivotType.TRANSACTION_TRACE,
            EntityType.CRYPTO_ADDRESS,
            WALLET_SECOND,
            "Where the funds went, and which exchange could be notified.",
        ),
    )

    directed: list[DirectedCollection] = []
    collected: dict[str, tuple[Claim, ...]] = {}
    for pivot_type, entity_type, entity_key, rationale in plan:
        summary, claims = await _collect(
            context,
            connector=_connector_for(connectors, pivot_type, entity_type),
            pivot_type=pivot_type,
            entity_type=entity_type,
            entity_key=entity_key,
            rationale=rationale,
        )
        directed.append(summary)
        collected[f"{pivot_type.value}:{entity_key}"] = claims

    failures = tuple(
        f"{pivot.candidate.pivot_type.value} on {pivot.candidate.entity_key}: {pivot.error}"
        for pivot in investigation.all_executed_pivots
        if pivot.error is not None
    )

    stage = PursuitStage(
        investigation=mark_awaiting_authorization(investigation),
        autonomous_pivots=len(investigation.all_executed_pivots),
        autonomous_failures=failures,
        directed=tuple(directed),
        directed_because=_DIRECTED_BECAUSE,
    )
    return stage, collected


async def _index_edge_confidence(context: _Context) -> None:
    """Record the confidence of every edge reachable from the seed component.

    Run with no confidence floor and no shared-infrastructure refusal on purpose: this is
    bookkeeping, not analysis, and an index that skipped the weak edges would leave the
    attribution plane unable to grade the very pivot the scenario exists to devalue.
    """
    for entity_key, entity_type in (
        (SEED_DOMAIN, EntityType.DOMAIN),
        (CDN_IP, EntityType.IP_ADDRESS),
    ):
        entity = await context.graph.find_entity(entity_type, entity_key)
        if entity is None:
            continue
        subgraph = await context.graph.neighbourhood(
            GraphQuery(
                entity_id=entity.entity_id,
                max_depth=8,
                min_confidence=0.0,
                exclude_shared_infrastructure=False,
            )
        )
        for edge in subgraph.relationships:
            for claim_id in edge.supporting_claims:
                context.claim_confidence[claim_id] = edge.confidence


# --------------------------------------------------------------------------------------
# Stage 3 — GRAPH
# --------------------------------------------------------------------------------------

_CDN_TENANTS: Final = ("static-assets.example", "weather-widget.example")


async def _graph_stage(context: _Context) -> tuple[GraphStage, Subgraph]:
    """Query the cluster, and prove the CDN address did not build one."""
    seed = await context.graph.find_entity(EntityType.DOMAIN, SEED_DOMAIN)
    cdn = await context.graph.find_entity(EntityType.IP_ADDRESS, CDN_IP)
    if seed is None or cdn is None:
        raise ScenarioError("the seed domain or the CDN address is missing from the graph")

    cluster = await context.graph.neighbourhood(
        GraphQuery(
            entity_id=seed.entity_id,
            max_depth=4,
            min_confidence=CLUSTER_MIN_CONFIDENCE,
            exclude_shared_infrastructure=True,
        )
    )
    filtered_cdn = await context.graph.neighbourhood(
        GraphQuery(
            entity_id=cdn.entity_id,
            max_depth=2,
            min_confidence=CLUSTER_MIN_CONFIDENCE,
            exclude_shared_infrastructure=True,
        )
    )
    unfiltered_cdn = await context.graph.neighbourhood(
        GraphQuery(
            entity_id=cdn.entity_id,
            max_depth=2,
            min_confidence=0.0,
            exclude_shared_infrastructure=True,
        )
    )

    by_id = {entity.entity_id: entity for entity in cluster.entities}
    selective = next(
        (
            edge
            for edge in cluster.relationships
            if edge.selectivity is not None and edge.selectivity.attribute == CLUSTER_IP
        ),
        None,
    )
    worthless = next(
        (
            edge
            for edge in unfiltered_cdn.relationships
            if edge.selectivity is not None and edge.selectivity.attribute == CDN_IP
        ),
        None,
    )
    if selective is None or worthless is None:
        raise ScenarioError(
            "the scenario's two contrasting pivots are not both in the graph; the control "
            "case has nothing to prove itself against"
        )

    cdn_entities = {entity.entity_id: entity for entity in unfiltered_cdn.entities}
    cluster_keys = tuple(sorted(entity.natural_key for entity in cluster.entities))
    cluster_domains = tuple(
        sorted(
            entity.natural_key
            for entity in cluster.entities
            if entity.entity_type is EntityType.DOMAIN
        )
    )

    stage = GraphStage(
        entity_count=await context.graph.entity_count(),
        relationship_count=await context.graph.relationship_count(),
        min_confidence=CLUSTER_MIN_CONFIDENCE,
        cluster_entity_keys=cluster_keys,
        cluster_domains=cluster_domains,
        # Names in the cluster branded for an organization other than the one that
        # reported the incident. Two further victims, discovered by the pivot rather than
        # by anybody telling us they had been attacked (DEMO_SCENARIO.md §2.2).
        victim_domains_discovered=tuple(
            domain for domain in cluster_domains if not domain.startswith("acme")
        ),
        excluded_shared_infrastructure=tuple(
            sorted(
                by_id[entity_id].natural_key
                for entity_id in cluster.excluded_shared_infrastructure
                if entity_id in by_id
            )
        ),
        selective_pivot=_edge_summary(selective, by_id),
        worthless_pivot=_edge_summary(worthless, cdn_entities),
        cdn_tenants_in_cluster=tuple(
            sorted(tenant for tenant in _CDN_TENANTS if tenant in cluster_keys)
        ),
        cdn_tenants_behind_the_filter=tuple(
            sorted(
                entity.natural_key
                for entity in filtered_cdn.entities
                if entity.natural_key in _CDN_TENANTS
            )
        ),
        cdn_tenants_reachable_unfiltered=tuple(
            sorted(
                entity.natural_key
                for entity in unfiltered_cdn.entities
                if entity.natural_key in _CDN_TENANTS
            )
        ),
    )
    return stage, cluster


# --------------------------------------------------------------------------------------
# Stage 4 — DARK WEB
# --------------------------------------------------------------------------------------


async def _darkweb(
    context: _Context, collected: dict[str, tuple[Claim, ...]]
) -> tuple[DarkWebStage, Claim, Claim, Claim]:
    """The persona, its published key, and the two planted trails."""
    persona_claims = collected[f"{PivotType.PERSONA_ACTIVITY.value}:{PERSONA_CURRENT.lower()}"]
    historical_claims = collected[
        f"{PivotType.PERSONA_ACTIVITY.value}:{PERSONA_HISTORICAL.lower()}"
    ]
    search_claims = collected[f"{PivotType.DARK_WEB_SEARCH.value}:{PERSONA_CURRENT.lower()}"]

    persona_key_claim = _find_claim(
        persona_claims, predicate=RelationType.SIGNED_BY.value, contains=PGP_FINGERPRINT
    )
    historical_key_claim = _find_claim(
        historical_claims, predicate=RelationType.SIGNED_BY.value, contains=PGP_FINGERPRINT
    )
    identity_claim = _find_claim(
        search_claims,
        predicate=RelationType.ASSOCIATED_WITH.value,
        contains=EntityType.HUMAN_IDENTITY_LEAD.value,
    )
    injection_claim = _find_claim(search_claims, predicate=RelationType.POSTS_ON.value)

    persona = await context.graph.find_entity(EntityType.PERSONA, PERSONA_CURRENT.lower())
    pgp_key = await context.graph.find_entity(EntityType.PGP_KEY, PGP_FINGERPRINT)
    lead_key = identity_claim.statement.obj.partition(":")[2]
    lead = await context.graph.find_entity(EntityType.HUMAN_IDENTITY_LEAD, lead_key)
    if lead is None:
        raise ScenarioError("the planted identity lead was not recorded in the graph")

    deception = identity_claim.deception
    if deception is None:
        raise ScenarioError("the planted identity claim arrived without a deception assessment")

    hostile = sum(
        1
        for claims in collected.values()
        for claim in claims
        if claim.statement.qualifiers.get(QUALIFIER_HOSTILE_CONTENT) == "true"
    )

    stage = DarkWebStage(
        persona=PERSONA_CURRENT,
        forum=FORUM_CURRENT,
        historical_persona=PERSONA_HISTORICAL,
        marketplace=MARKETPLACE_HISTORICAL,
        pgp_fingerprint=PGP_FINGERPRINT,
        pgp_key_bits=len(PGP_FINGERPRINT) * 4,
        persona_in_graph=persona is not None,
        pgp_key_in_graph=pgp_key is not None,
        persona_signs_key_claim=persona_key_claim.claim_id,
        historical_signs_key_claim=historical_key_claim.claim_id,
        telegram_channel=TELEGRAM_CHANNEL,
        hostile_content_claims=hostile,
        prompt_injection=PromptInjectionRecord(
            claim_id=injection_claim.claim_id,
            posted_by_persona=injection_claim.statement.subject.partition(":")[2],
            characters_quoted=len(injection_claim.statement.natural_language),
            quoted_verbatim=injection_claim.statement.qualifiers.get("quoted_verbatim") == "true",
            marked_hostile=injection_claim.statement.qualifiers.get(QUALIFIER_HOSTILE_CONTENT)
            == "true",
            note=(
                "Collected text addressed to automated readers. It is stored as data, it "
                "reaches no component holding tool access, and the claim built from it "
                "asserts only that the post was made (invariant 5)."
            ),
        ),
        identity_lead=HumanIdentityLead(
            entity_id=lead.entity_id,
            entity_type=lead.entity_type,
            category=lead.category,
            lead_display=lead.observed_form,
            recorded_from_claim=identity_claim.claim_id,
            asserted_by_persona="helpful_anon",
            source_class=SourceClass.DARK_WEB,
            source_reliability=SourceReliability.CANNOT_BE_JUDGED,
            independent_source_count=1,
            adversary_could_plant=deception.adversary_could_plant,
            planting_cost=deception.planting_cost,
            benefits_from_belief=deception.benefits_from_belief,
            handling=(
                "Recorded as a HUMAN_IDENTITY_LEAD in the HUMAN_IDENTITY category, which "
                "carries retention, minimization and access obligations. It is never "
                "promoted to an attribution, and it is not restated in any product this "
                "run generates."
            ),
        ),
    )
    return stage, persona_key_claim, historical_key_claim, identity_claim


# --------------------------------------------------------------------------------------
# Stage 5 — BLOCKCHAIN
# --------------------------------------------------------------------------------------

_WALLET_WITHHELD_FROM: Final = (
    "persona linkage (GlassAnvil / AnvilWorks): the fixture set carries no ledger "
    "evidence on the AnvilWorks side, so a wallet-overlap signal between the two personas "
    "would be an assertion rather than an observation. DEMO_SCENARIO.md phase 5 lists one; "
    "the fixtures do not support it.",
)


def _blockchain(
    context: _Context, collected: dict[str, tuple[Claim, ...]]
) -> tuple[BlockchainStage, Claim]:
    """The wallet relationship, and exactly what it is allowed to contribute."""
    clustering = _find_claim(
        collected[f"{PivotType.WALLET_CLUSTERING.value}:{WALLET_PRIMARY}"],
        predicate=RelationType.CLUSTERED_WITH.value,
    )
    opinion = context.claim_confidence.get(clustering.claim_id)
    if opinion is None:
        raise ScenarioError("the wallet clustering claim produced no edge to grade")

    stage = BlockchainStage(
        escrow_address=WALLET_PRIMARY,
        inbound_payments=INBOUND_PAYMENT_COUNT,
        clustered_with=WALLET_SECOND,
        clustering_heuristic=CLUSTERING_HEURISTIC,
        known_failure_mode=CLUSTERING_FAILURE_MODE,
        exchange_deposit_address=WALLET_EXCHANGE_DEPOSIT,
        exchange=EXCHANGE,
        signal_claim_id=clustering.claim_id,
        signal_opinion=opinion,
        signal_band=band_of(opinion),
        contributes_to=(
            "campaign attribution: one escrow wallet behind one kit and one registration window",
            "disruption planning: an exchange deposit address is a lever a court could act on",
        ),
        withheld_from=_WALLET_WITHHELD_FROM,
    )
    return stage, clustering


# --------------------------------------------------------------------------------------
# Stage 6 — RESOLVE
# --------------------------------------------------------------------------------------

_SIGNALS_UNAVAILABLE: Final = (
    "overlapping posting hours: the fixture set records a posting routine for GlassAnvil "
    "only, so there is nothing on the AnvilWorks side to compare it against",
    "overlapping wallet cluster: no AnvilWorks-side ledger evidence exists in the fixture set",
    "alias stem population: nobody counted how many DarkBazaar personas carry the stem "
    "'anvil', so the alias signal contributes nothing by construction",
)


def _resolve(
    context: _Context,
    persona_key_claim: Claim,
    historical_key_claim: Claim,
) -> ResolutionStage:
    """Ask the one question this engine answers, and refuse the one it does not."""
    source = context.claim_sources[persona_key_claim.claim_id]
    signals: tuple[LinkageSignal, ...] = (
        shared_cryptographic_identity(
            fingerprint=PGP_FINGERPRINT,
            observed_by=source,
            demonstrated_key_control=False,
            supporting_claims=(persona_key_claim.claim_id, historical_key_claim.claim_id),
            note=(
                "Both personas publish the full 160-bit fingerprint. Publication is not "
                "possession: nothing collected shows either persona holding the private key."
            ),
        ),
        alias_similarity(
            alias_a=PERSONA_CURRENT,
            alias_b=PERSONA_HISTORICAL,
            observed_by=source,
            # Deliberately uncounted: no fixture states how many personas carry the stem,
            # and guessing a small number here would turn a copyable string into evidence.
            stem_population_size=None,
            population_corpus=None,
            supporting_claims=(historical_key_claim.claim_id,),
        ),
    )

    engine = PersonaResolutionEngine()
    assessment = engine.assess(
        PERSONA_CURRENT,
        PERSONA_HISTORICAL,
        signals,
        DARK_BAZAAR_PERSONA_POPULATION,
        population_measured_against=PERSONA_POPULATION_CORPUS,
    )
    refusal = engine.refuse_human_identity(
        PERSONA_CURRENT,
        offered_signals=signals,
        # Counted and discarded by the engine. The name is not passed through this call
        # into anything the refusal retains.
        asserted_identities=("one name asserted by a single DarkBazaar post",),
    )
    return ResolutionStage(
        assessment=assessment,
        refusal=refusal,
        signals_used=tuple(signal.kind.value for signal in signals),
        signals_unavailable=_SIGNALS_UNAVAILABLE,
    )


# --------------------------------------------------------------------------------------
# Stage 7 — ATTRIBUTE
# --------------------------------------------------------------------------------------


def _evidence_for(
    context: _Context, claim: Claim, label: str, *, direction: EvidenceDirection | None = None
) -> AttributionEvidence:
    """Package one collected claim as attribution evidence.

    The opinion is the confidence the graph gave the edge built from this claim, so
    selectivity and method reliability reach the attribution plane already applied. The
    source is the one the claim was collected from, so trust discounting grades what it is
    actually fusing.
    """
    opinion = context.claim_confidence.get(claim.claim_id)
    if opinion is None:
        raise ScenarioError(f"claim {claim.claim_id} produced no edge and cannot be graded")
    source = context.claim_sources.get(claim.claim_id)
    if source is None:
        raise ScenarioError(f"claim {claim.claim_id} has no recorded source of record")
    return AttributionEvidence(
        claim=claim,
        source=source,
        opinion=opinion,
        direction=direction or EvidenceDirection.SUPPORTS,
        label=label,
    )


_REDOCTOBER_ALTERNATIVE_ARGUMENT: Final = (
    "It rests on one string in a file the adversary controls end to end. Cost to plant: "
    "minutes. Nothing outside the kit associates the named group with this operation, and "
    "the group is real and unrelated, which is what makes naming it attractive. Retained "
    "rather than deleted: an alternative that was considered and rejected must stay "
    "readable, and this is the one an opposing expert will raise."
)


def _attribute(
    context: _Context,
    *,
    cluster_claims: dict[str, Claim],
    kit_claims: Sequence[Claim],
    persona_claims: Sequence[Claim],
    market_claims: Sequence[Claim],
    wallet_claim: Claim,
    persona_key_claim: Claim,
    historical_key_claim: Claim,
    identity_claim: Claim,
    assessed_at: datetime,
) -> AttributionStage:
    """Five dimensions, assessed separately, with a refusal where one is owed."""
    false_flag = _find_claim(
        kit_claims, predicate=RelationType.CO_OCCURS_WITH.value, contains=FRAMED_ORGANIZATION
    )
    build_path = _find_claim(
        kit_claims, predicate=RelationType.CO_OCCURS_WITH.value, contains="vpetrov"
    )
    language = _find_claim(
        kit_claims, predicate=RelationType.CO_OCCURS_WITH.value, contains="language_indicator"
    )
    kit_hosting = _find_claim(kit_claims, predicate=RelationType.HOSTED_ON.value)
    exfiltration = _find_claim(
        kit_claims, predicate=RelationType.COMMUNICATES_WITH.value, contains="email_address"
    )
    kit_channel = _find_claim(
        kit_claims, predicate=RelationType.COMMUNICATES_WITH.value, contains="messaging_account"
    )
    persona_channel = _find_claim(
        persona_claims, predicate=RelationType.COMMUNICATES_WITH.value, contains="messaging_account"
    )
    vendor_listing = _find_claim(market_claims, predicate=RelationType.SELLS_ON.value)
    escrow = _find_claim(
        persona_claims, predicate=RelationType.ASSOCIATED_WITH.value, contains="crypto_address"
    )

    request = AttributionRequest(
        subject=SCENARIO_SUBJECT,
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.INFRASTRUCTURE,
                hypothesis=(
                    "The four domains, 198.51.100.23 and the shared TLS certificate were "
                    "under one operator's control."
                ),
                evidence=(
                    _evidence_for(
                        context, cluster_claims["reverse"], "4-domain reverse resolution"
                    ),
                    _evidence_for(context, cluster_claims["certificate"], "shared TLS certificate"),
                    _evidence_for(
                        context, cluster_claims["registration"], "24-hour registration window"
                    ),
                    _evidence_for(context, cluster_claims["cdn"], "41,700-domain CDN co-location"),
                ),
                missing_evidence=(
                    MissingEvidence(
                        description=(
                            "The registrar's unredacted registrant record for the four domains."
                        ),
                        would_settle=(
                            "Whether one account registered all four, which is the fact the "
                            "24-hour window is a proxy for."
                        ),
                        availability=EvidenceAvailability.REQUIRES_LEGAL_AUTHORITY,
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.CAMPAIGN,
                hypothesis="All observed activity belongs to one campaign.",
                evidence=(
                    _evidence_for(context, kit_hosting, "one kit build across the cluster"),
                    _evidence_for(context, exfiltration, "one exfiltration endpoint"),
                    _evidence_for(
                        context, cluster_claims["registration"], "one registration window"
                    ),
                    _evidence_for(context, wallet_claim, "one escrow wallet cluster"),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.ORGANIZATION,
                hypothesis=(
                    "A coherent organized operation, rather than a lone opportunist, stands "
                    "behind Operation GLASS ANVIL."
                ),
                evidence=(
                    _evidence_for(context, vendor_listing, "escrow-backed vendor operation"),
                    _evidence_for(context, escrow, "advertised escrow address"),
                    # Offered in support, and the engine will turn it around: a marker this
                    # cheap to plant tells us more about whoever placed it than about
                    # whoever it names.
                    _evidence_for(context, false_flag, f"kit string naming {FRAMED_ORGANIZATION}"),
                ),
                alternatives=(
                    AlternativeHypothesis(
                        name=f"{FRAMED_ORGANIZATION} is responsible",
                        description=(
                            f"The recovered kit carries the string naming {FRAMED_ORGANIZATION}, "
                            "and a fake build path pointing at the same direction."
                        ),
                        opinion=Opinion.vacuous(base_rate=0.05),
                        band=band_of(Opinion.vacuous(base_rate=0.05)),
                        supporting_claims=(false_flag.claim_id, build_path.claim_id),
                        contradicting_claims=(),
                        argument_against=_REDOCTOBER_ALTERNATIVE_ARGUMENT,
                        is_deception_hypothesis=True,
                    ),
                ),
                missing_evidence=(
                    MissingEvidence(
                        description=(
                            "Any organizational artifact the operation did not author: a "
                            "payroll record, an internal chat export obtained under lawful "
                            "process, a partner report naming the same crew."
                        ),
                        would_settle=(
                            "Whether there is an organization at all, as opposed to one "
                            "operator running a vendor front."
                        ),
                        availability=EvidenceAvailability.REQUIRES_LEGAL_AUTHORITY,
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.PERSONA,
                hypothesis=f"{PERSONA_CURRENT} and {PERSONA_HISTORICAL} are one operator.",
                evidence=(
                    _evidence_for(
                        context,
                        persona_key_claim,
                        f"PGP fingerprint published by {PERSONA_CURRENT}",
                    ),
                    _evidence_for(
                        context,
                        historical_key_claim,
                        f"the same fingerprint published by {PERSONA_HISTORICAL}",
                    ),
                    _evidence_for(context, kit_channel, "Telegram channel embedded in the kit"),
                    _evidence_for(
                        context, persona_channel, "the same channel advertised by the persona"
                    ),
                ),
                missing_evidence=(
                    MissingEvidence(
                        description=(
                            "Material signed by each persona with the private key whose "
                            "fingerprint both publish."
                        ),
                        would_settle=(
                            "Whether the shared fingerprint reflects possession of the key or "
                            "only the ability to copy a published string."
                        ),
                        availability=EvidenceAvailability.COLLECTABLE,
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.HUMAN_IDENTITY,
                # The caller has the name; the engine is what must decline to restate it.
                hypothesis=(
                    "The operator behind GlassAnvil is the natural person named in a single "
                    f"post on {FORUM_CURRENT}: {identity_claim.statement.obj.partition(':')[2]}."
                ),
                evidence=(
                    _evidence_for(
                        context, identity_claim, f"single {FORUM_CURRENT} post asserting a name"
                    ),
                ),
            ),
        ),
    )

    engine = AttributionEngine(assessed_by=context.actor)
    result = engine.assess(request, assessed_at=assessed_at)
    human = result.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    return AttributionStage(
        result=result,
        false_flag_claim_id=false_flag.claim_id,
        framed_organization=FRAMED_ORGANIZATION,
        human_identity_band=human.band,
        weak_markers_not_scored=(
            f"{build_path.claim_id}: a build path in the kit's debug metadata. Recorded in "
            "the graph, offered to no dimension. It is a username, so the only dimension it "
            "speaks to is the one this platform refuses to assess, and a build path is "
            "trivially forged.",
            f"{language.claim_id}: Russian source comments throughout the kit. Recorded, and "
            "offered to no dimension: language is not nationality, nationality is not "
            "identity, and neither is an organization.",
        ),
    )


# --------------------------------------------------------------------------------------
# Stage 8 — EVIDENCE
# --------------------------------------------------------------------------------------

_CANNOT_DEFEND: Final = (
    "Nothing here is defensible against the vault operator. The hash chain is one we "
    "compute ourselves, so anyone who can rewrite the store can recompute it.",
    "No external anchor exists. The anchor recorded by this run is signed with a key this "
    "platform holds, so it is stamped 'nemesis' and counts as internal; "
    "is_defensible_against_insider stays False.",
    "Every artifact was produced by a simulated connector, so every sealed object carries "
    "the SIMULATED_COLLECTION defect and none of it could be presented as proof.",
    "Tail truncation before this process opened the log cannot be detected from the log alone.",
)


async def _evidence_stage(context: _Context) -> EvidenceStage:
    """Verify the vault, anchor its head locally, and report what that does not buy."""
    head = await context.vault.head()
    anchor = await context.vault.record_anchor(LocalHeadSigner.generate().anchor(head))
    report = await context.vault.verify_integrity()
    objects = await context.vault.list_evidence()
    export = await context.vault.export_bundle(
        requested_by=context.actor,
        reason="GLASS ANVIL demonstration: manifest of what the vault may release",
    )

    defects = sorted(
        {defect.value for obj in objects for defect in obj.admissibility()},
    )
    if report.is_defensible_against_insider:
        raise ScenarioError(
            "the vault reports itself defensible against an insider; no external anchor "
            "was recorded and this run must not claim one"
        )

    await context.audit.record(
        make_event(
            actor=context.actor,
            actor_kind=ActorKind.SYSTEM,
            action="evidence.verify",
            subject=str(context.vault.root),
            outcome=("verified " if report.is_intact else "damaged ")
            + f"{report.objects_checked} object(s), "
            f"{report.externally_anchored} external anchor(s)",
            inputs={
                "head": head,
                "hash_chain_intact": str(report.hash_chain_intact),
                "artifacts_verified": str(report.artifacts_verified),
                "defensible_against_insider": str(report.is_defensible_against_insider),
            },
        )
    )

    return EvidenceStage(
        report=report,
        head=head,
        anchor=anchor,
        anchor_is_externally_held=anchor.anchor.is_externally_held,
        is_intact=report.is_intact,
        is_defensible_against_insider=False,
        admissibility_defects=tuple(defects),
        cannot_defend=_CANNOT_DEFEND,
        export_entries=len(export.entries),
        export_withheld_restricted=export.withheld_restricted,
    )


# --------------------------------------------------------------------------------------
# Stage 9 — DISRUPT
# --------------------------------------------------------------------------------------


async def _targets_for(context: _Context, domains: Sequence[str]) -> tuple[DisruptionTarget, ...]:
    targets: list[DisruptionTarget] = []
    for domain in domains:
        entity = await context.graph.find_entity(EntityType.DOMAIN, domain)
        if entity is None:
            raise ScenarioError(f"{domain} is not in the graph and cannot be a target")
        targets.append(
            DisruptionTarget(
                entity_id=entity.entity_id,
                entity_type=entity.entity_type,
                natural_key=entity.natural_key,
                display=entity.display_name,
                # Reads like a real payments business. Whoever owns it may be uninvolved,
                # and the planner must say so before anyone acts.
                resembles_legitimate_business=domain.startswith("initech"),
            )
        )
    return tuple(targets)


async def _disrupt(context: _Context, attribution: AttributionStage) -> DisruptionStage:
    """Propose every lever, including the ones NEMESIS cannot pull."""
    infrastructure = attribution.result.for_dimension(AttributionDimension.INFRASTRUCTURE)
    ownership = OwnershipEvidence(
        opinion=infrastructure.opinion,
        independent_source_count=infrastructure.source_diversity.independent_source_count,
        basis=(
            "The infrastructure attribution: a 4-domain reverse resolution, a shared TLS "
            "certificate and a 24-hour registration window, all collected from the GLASS "
            "ANVIL fixture set."
        ),
        supporting_claims=infrastructure.supporting_claims,
    )

    domains = await _targets_for(context, CLUSTER_DOMAINS)
    seed_only = domains[:1]
    exchange_entity = await context.graph.find_entity(
        EntityType.CRYPTO_ADDRESS, WALLET_EXCHANGE_DEPOSIT
    )
    if exchange_entity is None:
        raise ScenarioError("the exchange deposit address is not in the graph")
    deposit = DisruptionTarget(
        entity_id=exchange_entity.entity_id,
        entity_type=exchange_entity.entity_type,
        natural_key=exchange_entity.natural_key,
    )

    levers = (
        DisruptionLever(
            key="registrar-suspension",
            operation=OperationClass.REGISTRAR_SUSPENSION,
            title="Suspend the four cluster domains at the registrar",
            description=(
                "Ask BulletproofReg to suspend all four domains as one coordinated action. "
                "They were registered through it inside a 24-hour window."
            ),
            targets=domains,
            unconstrained_impact=ImpactLevel.HIGH,
            impact_note="The four domains are the campaign's entire delivery surface.",
            provider_disposition=ProviderDisposition.UNRESPONSIVE,
            provider_name=REGISTRAR,
            recovery=AdversaryRecovery(
                path="re-register comparable names at another registrar",
                difficulty=RecoveryDifficulty.EASY,
                estimated_time="hours",
            ),
            ownership=ownership,
            legal_basis=LegalBasis.COURT_ORDER,
            jurisdictions=("FR", "NL"),
        ),
        DisruptionLever(
            key="hosting-termination",
            operation=OperationClass.HOSTING_TERMINATION,
            title=f"Terminate the hosting at {BULLETPROOF_HOST}",
            description=(
                f"Ask {BULLETPROOF_HOST} ({BULLETPROOF_ASN}) to terminate the servers behind "
                f"{CLUSTER_IP} and {KIT_HOST_IP}."
            ),
            targets=domains,
            unconstrained_impact=ImpactLevel.HIGH,
            impact_note=f"{CLUSTER_IP} carries the whole cluster and {KIT_HOST_IP} the kit.",
            provider_disposition=ProviderDisposition.BULLETPROOF,
            provider_name=f"{BULLETPROOF_HOST} ({BULLETPROOF_ASN})",
            recovery=AdversaryRecovery(
                path="move to another address inside the same bulletproof network",
                difficulty=RecoveryDifficulty.TRIVIAL,
                estimated_time="under an hour",
            ),
            ownership=ownership,
            legal_basis=LegalBasis.COURT_ORDER,
            jurisdictions=("FR", "NL"),
        ),
        DisruptionLever(
            key="transit-notification",
            operation=OperationClass.PROVIDER_NOTIFICATION,
            title="Notify the upstream transit provider",
            description=(
                f"Draft a factual abuse notification for the transit provider carrying "
                f"{CLUSTER_NETBLOCK}, for it to assess under its own terms of service."
            ),
            targets=seed_only,
            unconstrained_impact=ImpactLevel.MODERATE,
            impact_note=(
                "The realistic lever: an upstream that does answer, acting on its own terms."
            ),
            provider_disposition=ProviderDisposition.COOPERATIVE,
            provider_name="upstream transit provider",
            recovery=AdversaryRecovery(
                path="buy transit from a different upstream",
                difficulty=RecoveryDifficulty.MODERATE,
                estimated_time="days",
            ),
            ownership=ownership,
            legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
            jurisdictions=("FR", "NL"),
        ),
        DisruptionLever(
            key="exchange-notification",
            operation=OperationClass.EXCHANGE_NOTIFICATION,
            title=f"Notify {EXCHANGE} about the deposit address",
            description=(
                f"The clustered second address sent funds to a deposit address at {EXCHANGE}. "
                "An exchange can act on its own account, under its own obligations."
            ),
            targets=(deposit,),
            unconstrained_impact=ImpactLevel.MODERATE,
            impact_note=(
                f"Rests on {CLUSTERING_HEURISTIC}, which mixers and custodial co-spend defeat."
            ),
            provider_disposition=ProviderDisposition.SLOW,
            provider_name=EXCHANGE,
            recovery=AdversaryRecovery(
                path="open an account elsewhere, or stop cashing out through exchanges",
                difficulty=RecoveryDifficulty.MODERATE,
                estimated_time="weeks",
            ),
            ownership=ownership,
            legal_basis=LegalBasis.LAW_ENFORCEMENT_REQUEST,
            jurisdictions=("FR", "NL", "XX"),
        ),
        DisruptionLever(
            key="referral-package",
            operation=OperationClass.EVIDENCE_EXPORT,
            title="Draft the law-enforcement referral package",
            description=(
                "Export the manifest of sealed evidence for a referral. NEMESIS can draft "
                "and export; making the referral is a human act outside the platform."
            ),
            targets=seed_only,
            unconstrained_impact=ImpactLevel.LOW,
            impact_note="A package changes nothing on its own; what follows it might.",
            provider_disposition=ProviderDisposition.SLOW,
            provider_name="the receiving authority",
            recovery=AdversaryRecovery(
                path="continue operating while the referral is assessed",
                difficulty=RecoveryDifficulty.HARD,
                estimated_time="months",
            ),
            ownership=ownership,
            legal_basis=LegalBasis.LAW_ENFORCEMENT_REQUEST,
            jurisdictions=("FR",),
        ),
        DisruptionLever(
            key="law-enforcement-referral",
            operation=OperationClass.LAW_ENFORCEMENT_REFERRAL,
            title="Make the law-enforcement referral",
            description=(
                "The referral itself. Proposed at full reasoning and not executable here: "
                "NEMESIS holds no authority to refer anything to anyone."
            ),
            targets=seed_only,
            unconstrained_impact=ImpactLevel.HIGH,
            impact_note="The only lever in this plan that can reach the operator.",
            provider_disposition=ProviderDisposition.SLOW,
            provider_name="the receiving authority",
            recovery=AdversaryRecovery(
                path="none that is cheap, if a prosecution follows",
                difficulty=RecoveryDifficulty.SEVERE,
            ),
            ownership=ownership,
            legal_basis=LegalBasis.LAW_ENFORCEMENT_REQUEST,
            jurisdictions=("FR",),
        ),
        DisruptionLever(
            key="simulated-takedown",
            operation=OperationClass.SIMULATION,
            title="Simulated takedown of the four cluster domains",
            description=(
                "Exercise the whole authorization path — capability, target binding, stop "
                "conditions — against a synthetic world, and perform no effect."
            ),
            targets=domains,
            unconstrained_impact=ImpactLevel.NONE,
            impact_note=(
                "A rehearsal. It degrades nothing; its value is that the controls run for "
                "real while the effect does not."
            ),
            provider_disposition=ProviderDisposition.UNKNOWN,
            recovery=AdversaryRecovery(
                path="nothing to recover from; nothing happened",
                difficulty=RecoveryDifficulty.TRIVIAL,
            ),
            ownership=ownership,
            legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
            jurisdictions=("FR",),
        ),
    )

    plan = DisruptionPlanner().plan(levers)
    await context.audit.record(
        make_event(
            actor=context.actor,
            actor_kind=ActorKind.AGENT,
            action="disruption.plan",
            subject=SCENARIO_SUBJECT,
            outcome=f"proposed {len(plan.options)} option(s), "
            f"{len(plan.requires_legal_authority)} blocked on legal authority",
            inputs={option.key: option.expected_impact.level.value for option in plan.options},
        )
    )

    return DisruptionStage(
        plan=plan,
        executable_now=tuple(option.key for option in plan.executable_now),
        requires_legal_authority=tuple(option.key for option in plan.requires_legal_authority),
        needs_ownership_confirmation=tuple(
            option.key for option in plan.needs_ownership_confirmation
        ),
        whack_a_mole=tuple(option.key for option in plan.whack_a_mole),
        capability_degrading=tuple(option.key for option in plan.capability_degrading),
    )


# --------------------------------------------------------------------------------------
# Stage 10 — AUTHORIZE
# --------------------------------------------------------------------------------------


async def _target_fingerprints(context: _Context) -> tuple[TargetFingerprint, ...]:
    """Bind each domain to the state that made it the right target.

    Resolution and registrar, per phase 7. Between approval and execution a domain can be
    transferred and an address reassigned; binding these two is what makes the capability
    stop matching when that happens.
    """
    fingerprints: list[TargetFingerprint] = []
    for domain in CLUSTER_DOMAINS:
        entity = await context.graph.find_entity(EntityType.DOMAIN, domain)
        if entity is None:
            raise ScenarioError(f"{domain} is not in the graph and cannot be bound as a target")
        fingerprints.append(
            TargetFingerprint.create(
                entity_id=entity.entity_id,
                entity_type=entity.entity_type.value,
                natural_key=entity.natural_key,
                bound_attributes={"resolves_to": CLUSTER_IP, "registrar": REGISTRAR.lower()},
            )
        )
    return tuple(fingerprints)


async def _authorize(
    context: _Context,
    *,
    evidence_ids: Sequence[str],
    now: datetime,
) -> tuple[AuthorizationStage, AuthorizationGateway, AuthorizationCapability]:
    """One approval, one rejection, one narrowly scoped grant.

    ``now`` is the wall clock, not the scenario instant. Collection is stamped at scenario
    time so a run in 2028 does not claim to have observed 2026; a human decision and the
    rehearsal that follows it happen when the demonstration runs. The Effects plane reads
    the wall clock itself, deliberately, so a capability minted at the scenario instant
    would be refused as expired — which is the control working, not a bug to route around.
    """
    # Development identities, and the demonstration is honest about what that costs. The
    # provider stamps DEVELOPMENT assurance on everything it issues, so these principals can
    # authorize a rehearsal and are refused anything meant to leave the platform — which is
    # the whole of what "NEMESIS has no identity provider" means, expressed as a refusal
    # rather than as a sentence in a document.
    identities = LocalDevelopmentIdentityProvider()
    # One registered issuer, capped at DEVELOPMENT by the registration rather than by the
    # provider's own good manners. An assertion from anywhere else — or a Principal built by
    # a caller — does not reach the gateway at all.
    actors = PrincipalVerifier(identities.registered_issuer())
    planner = identities.enrol("Planner (development identity)", Role.ANALYST)
    lead = identities.enrol("Investigation lead (development identity)", Role.INVESTIGATION_LEAD)
    reviewer = identities.enrol("Legal reviewer (development identity)", Role.LEGAL_REVIEWER)
    case_id = new_id(IdPrefix.CASE)

    gateway = AuthorizationGateway(
        CapabilitySigningKey.generate(),
        identity=actors,
        clock=lambda: now,
        revocations=context.authorization,
    )
    targets = await _target_fingerprints(context)

    granted_request = gateway.request(
        case_id=case_id,
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=planner,
        justification=(
            "Option 'simulated-takedown'. It performs nothing: the rehearsal reports what "
            "would happen. Target ownership rests on a single synthetic origin and is "
            "recorded as unconfirmed; the option does not act on infrastructure."
        ),
        targets=targets,
        operations=(OperationClass.SIMULATION,),
        # Explicit denial. These win over any permission, including one added later by a
        # widening of the enum or of the permitted set.
        forbidden_operations=(
            OperationClass.REGISTRAR_SUSPENSION,
            OperationClass.HOSTING_TERMINATION,
            OperationClass.DOMAIN_SEIZURE,
            OperationClass.SINKHOLE,
            OperationClass.ASSET_FREEZE_REQUEST,
        ),
        jurisdictions=("FR", "NL"),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference=CASE_AUTHORITY_REFERENCE,
        max_effect_description=(
            "Four rehearsed suspensions that suspend nothing. No document is produced and "
            "no external contact is made."
        ),
        lifetime=CAPABILITY_LIFETIME,
        stop_conditions=(
            StopCondition(
                condition="target_ownership_contested",
                description=(
                    "Abort if any registrant contests ownership of a target between "
                    "approval and execution."
                ),
            ),
        ),
        supporting_evidence=tuple(evidence_ids),
    )
    approval = gateway.approve(
        granted_request.capability_id,
        approver=lead,
        rationale=(
            "Reviewed the sealed evidence manifest and the infrastructure attribution. The "
            "class is reversible and touches no infrastructure, so one approver is "
            "sufficient. Ownership is single-sourced and synthetic; that is acceptable for "
            "a rehearsal and would not be for a suspension."
        ),
        reviewed_evidence=tuple(evidence_ids),
    )
    capability = gateway.issue(granted_request.capability_id)

    # Written down, so the approval chain outlives the process that reached it. Invariant 11
    # asks for replayable, and a chain that exists only in memory is replayable exactly until
    # this process exits — which, since ADR-0007, is not even the process that acts.
    context.authorization.save_request(granted_request)
    context.authorization.save_decision(granted_request.capability_id, approval)
    context.authorization.save_capability(capability)

    rejected_request = gateway.request(
        case_id=case_id,
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=planner,
        justification=(
            "Option 'registrar-suspension': suspend all four domains at BulletproofReg."
        ),
        targets=targets,
        operations=(OperationClass.REGISTRAR_SUSPENSION,),
        jurisdictions=("FR", "NL"),
        legal_basis=LegalBasis.COURT_ORDER,
        legal_authority_reference="NONE HELD — recorded so the refusal has a subject",
        max_effect_description="Four domains suspended. Not reversible by us.",
        lifetime=CAPABILITY_LIFETIME,
        supporting_evidence=tuple(evidence_ids),
    )
    rejection = gateway.reject(
        rejected_request.capability_id,
        approver=reviewer,
        rationale=(
            "Refused. initech-payments-secure.example resembles a legitimate payments "
            "business and its ownership rests on one synthetic origin; suspending it could "
            "take down an uninvolved third party. No court order is held, and the registrar "
            "does not answer abuse reports, so the action would be both unauthorized and "
            "ineffective. Revisit if an unredacted registrant record is obtained."
        ),
        reviewed_evidence=tuple(evidence_ids),
    )
    context.authorization.save_request(rejected_request)
    context.authorization.save_decision(rejected_request.capability_id, rejection)

    for request_id, decision, outcome in (
        (
            granted_request.capability_id,
            approval,
            "approved simulated-takedown",
        ),
        (rejected_request.capability_id, rejection, "rejected registrar-suspension"),
    ):
        await context.audit.record(
            make_event(
                actor=decision.approver,
                actor_kind=ActorKind.HUMAN,
                action="authorization.decision",
                subject=request_id,
                outcome=outcome,
                inputs={
                    "approver_role": decision.approver_role,
                    "approver_assurance": decision.approver_assurance.name.lower(),
                    "authenticated_by": decision.authenticated_by,
                    "decision": str(decision.decision),
                    "rationale": decision.rationale,
                    "reviewed_evidence": str(len(decision.reviewed_evidence)),
                },
            )
        )

    # The refusal the demonstration exists to show. A provider notification produces a
    # document meant for somebody outside, so its floor is above what a fixture identity can
    # reach. Asking is the point: an option that is never requested proves nothing about
    # whether it would have been refused.
    notification_request = gateway.request(
        case_id=case_id,
        audit_id=new_id(IdPrefix.AUDIT),
        requested_by=planner,
        justification=(
            "Option 'transit-notification': draft an abuse notification to the transit "
            "provider. The draft is unsent and reversible, but it is written to be sent."
        ),
        targets=targets,
        operations=(OperationClass.PROVIDER_NOTIFICATION,),
        jurisdictions=("FR", "NL"),
        legal_basis=LegalBasis.PROVIDER_TERMS_OF_SERVICE,
        legal_authority_reference=CASE_AUTHORITY_REFERENCE,
        max_effect_description="One unsent abuse notification draft. No external contact.",
        lifetime=CAPABILITY_LIFETIME,
        supporting_evidence=tuple(evidence_ids),
    )
    try:
        gateway.approve(
            notification_request.capability_id,
            approver=lead,
            rationale="Reversible; the draft is not sent by us.",
            reviewed_evidence=tuple(evidence_ids),
        )
    except AuthorizationPolicyError as refusal:
        assurance_refusal = str(refusal)
    else:  # pragma: no cover - reaching here means the assurance floor stopped working
        raise AssertionError(
            "a development identity approved a provider notification; the assurance floor "
            "in nemesis.authz.rbac is not doing what this demonstration claims it does"
        )
    await context.audit.record(
        make_event(
            actor=lead.subject,
            actor_kind=ActorKind.HUMAN,
            action="authorization.refused_by_policy",
            subject=notification_request.capability_id,
            outcome="refused: identity assurance below the floor for provider_notification",
            inputs={
                "operation": OperationClass.PROVIDER_NOTIFICATION.value,
                "authenticated_by": lead.issuer,
                "assurance": AssuranceLevel.DEVELOPMENT.name.lower(),
                "reason": assurance_refusal,
            },
        )
    )

    unknown_target = TargetFingerprint.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=EntityType.DOMAIN.value,
        natural_key="never-approved.example",
        bound_attributes={"resolves_to": CLUSTER_IP, "registrar": REGISTRAR.lower()},
    )
    moved_target = TargetFingerprint.create(
        entity_id=targets[0].entity_id,
        entity_type=EntityType.DOMAIN.value,
        natural_key=targets[0].natural_key,
        bound_attributes={"resolves_to": "203.0.113.9", "registrar": REGISTRAR.lower()},
    )
    probes = (
        ScopeProbe(
            question="May this capability suspend a domain at the registrar?",
            decision=capability.authorizes(
                operation=OperationClass.REGISTRAR_SUSPENSION,
                target_fingerprint=targets[0].fingerprint,
                now=now,
            ),
        ),
        ScopeProbe(
            question="May it act on a target nobody approved?",
            decision=capability.authorizes(
                operation=OperationClass.SIMULATION,
                target_fingerprint=unknown_target.fingerprint,
                now=now,
            ),
        ),
        ScopeProbe(
            question="May it act on an approved domain that has since moved address?",
            decision=capability.authorizes(
                operation=OperationClass.SIMULATION,
                target_fingerprint=moved_target.fingerprint,
                now=now,
            ),
        ),
        ScopeProbe(
            question="Is it still usable one minute after expiry?",
            decision=capability.authorizes(
                operation=OperationClass.SIMULATION,
                target_fingerprint=targets[0].fingerprint,
                now=capability.expires_at + timedelta(minutes=1),
            ),
        ),
    )

    stage = AuthorizationStage(
        capability=capability,
        verification=gateway.verify(capability, now=now),
        approvals=(approval,),
        rejection=rejection,
        rejected_option="registrar-suspension",
        rejected_request_state=gateway.status(rejected_request.capability_id).state,
        target_count=len(capability.targets),
        lifetime_hours=CAPABILITY_LIFETIME.total_seconds() / 3600.0,
        scope_probes=probes,
        assurance_refusal=assurance_refusal,
        assurance_refused_operation=OperationClass.PROVIDER_NOTIFICATION,
        assurance_refused_by=lead.issuer,
    )
    return stage, gateway, capability


# --------------------------------------------------------------------------------------
# Stage 11 — EFFECT
# --------------------------------------------------------------------------------------


async def _effects(
    context: _Context,
    capability: AuthorizationCapability,
    *,
    gateway: AuthorizationGateway,
    evidence_ids: Sequence[str],
    now: datetime,
) -> tuple[EffectsStage, EffectsRegistry]:
    """Execute what was authorized, and attempt one thing that was not.

    The registry is built from the gateway's PUBLIC key and its revocation oracle. Effects
    receives the means to verify and to ask, never the means to issue.
    """
    registry = default_registry(
        verifying_key=gateway.verifying_key, revocations=gateway.revocations
    )
    # Every effect below runs through this, in its own confined child process. The registry
    # above is kept for the adapter inventory the stage reports — which adapters exist and
    # whether any declares external contact — and performs nothing.
    executor = IsolatedEffectsExecutor(
        TrustAnchor(verifying_key=gateway.verifying_key, revocations=gateway.revocations),
        # The workspace holds the evidence vault and the audit trail. `(allow default)`
        # permits reading anything, and reading the vault off disk needs no import — which
        # is how a review turned a confined worker into a reader of the investigation the
        # import contracts exist to keep it away from.
        read_denied=(
            context.vault.root.parent,
            context.audit.path.parent,
            context.authorization.path.parent,
        ),
    )
    isolation: IsolationReport | None = None
    observed = {"resolves_to": CLUSTER_IP, "registrar": REGISTRAR.lower()}
    results: list[EffectResult] = []

    for target in capability.targets:
        request = EffectRequest(
            operation_id=new_id(IdPrefix.OPERATION),
            operation=OperationClass.SIMULATION,
            target_fingerprint=target.fingerprint,
            target_natural_key=target.natural_key,
            current_target_attributes=dict(observed),
            parameters={
                "rehearsed_operation": OperationClass.REGISTRAR_SUSPENSION.value,
                "recipient": REGISTRAR,
                "stop_condition.target_ownership_contested": "cleared",
            },
            requested_by=context.actor,
            requested_at=now,
        )
        result, report = await executor.perform(
            request, capability, operation=OperationClass.SIMULATION
        )
        isolation = report if report.separate_process else isolation
        results.append(result)
        await context.audit.record_effect(
            actor=context.actor, actor_kind=ActorKind.AGENT, request=request, result=result
        )

    notification = EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=OperationClass.PROVIDER_NOTIFICATION,
        target_fingerprint=capability.targets[0].fingerprint,
        target_natural_key=capability.targets[0].natural_key,
        current_target_attributes=dict(observed),
        parameters={
            "recipient": "abuse desk, upstream transit provider",
            "observed_activity": (
                "Invoice-themed credential harvesting served from 198.51.100.23, one of "
                "four names on that address, all registered inside a 24-hour window."
            ),
            "evidence_ids": ",".join(evidence_ids),
            "stop_condition.target_ownership_contested": "cleared",
        },
        requested_by=context.actor,
        requested_at=now,
    )
    drafted, report = await executor.perform(
        notification, capability, operation=OperationClass.PROVIDER_NOTIFICATION
    )
    isolation = report if report.separate_process else isolation
    results.append(drafted)
    await context.audit.record_effect(
        actor=context.actor, actor_kind=ActorKind.AGENT, request=notification, result=drafted
    )

    # The rejected option, attempted anyway. Two independent controls refuse it: the class
    # has no adapter, and the capability forbids it. Recorded, because a pattern of denied
    # attempts is a security signal.
    forbidden = EffectRequest(
        operation_id=new_id(IdPrefix.OPERATION),
        operation=OperationClass.REGISTRAR_SUSPENSION,
        target_fingerprint=capability.targets[0].fingerprint,
        target_natural_key=capability.targets[0].natural_key,
        current_target_attributes=dict(observed),
        parameters={},
        requested_by=context.actor,
        requested_at=now,
    )
    refused, _ = await executor.perform(
        forbidden, capability, operation=OperationClass.REGISTRAR_SUSPENSION
    )
    results.append(refused)
    await context.audit.record_effect(
        actor=context.actor, actor_kind=ActorKind.AGENT, request=forbidden, result=refused
    )

    stage = EffectsStage(
        results=tuple(results),
        adapters=tuple(
            AdapterRecord(
                name=adapter.name,
                operation=adapter.operation,
                makes_external_contact=adapter.makes_external_contact,
            )
            for adapter in registry.adapters
        ),
        external_contact_made=any(result.external_contact_made for result in results),
        isolation=isolation
        or IsolationReport(mechanism="in-process", separate_process=False, network_denied=False),
    )
    return stage, registry


# --------------------------------------------------------------------------------------
# Stage 12 — RESURGENCE
# --------------------------------------------------------------------------------------

_NOTHING_IN_COMMON: Final = (
    f"new domain {RESURGENCE_DOMAIN} at a different registrar ({RESURGENCE_REGISTRAR})",
    f"new address {RESURGENCE_IP} in a different network ({RESURGENCE_ASN})",
    f"new persona {PERSONA_RESURGENT} on a different forum ({FORUM_RESURGENT})",
)

_NOT_RECONNECTED_BY: Final = (
    "alias similarity — 'AnvilForge' resembles 'AnvilWorks', and a resemblance between "
    "chosen names is exactly what an impersonator produces",
    "writing style — capped hard and never decisive; no stylometric comparison was run",
    "posting hours — a working window narrows a time zone at best",
    "hosting or registrar — deliberately different, which is the point of the phase",
)


async def _resurgence(
    context: _Context,
    connectors: Sequence[IntelligenceConnector],
    *,
    as_of: datetime,
    historical_key_claim: Claim,
) -> ResurgenceStage:
    """Collect the phase-8 material and reconnect it to the historical actor.

    The connectors handed in answer as of the resurgence instant. A phase-2 connector
    cannot see this material at all, which is what makes the reconnection a finding rather
    than something already sitting in the graph before the resurgence happened.
    """
    plan: tuple[tuple[PivotType, EntityType, str, str], ...] = (
        (
            PivotType.CERTIFICATE_REUSE,
            EntityType.TLS_CERTIFICATE,
            CERT_FINGERPRINT,
            "Standing watch on the certificate the disrupted cluster presented.",
        ),
        (
            PivotType.RESOLUTION_HISTORY,
            EntityType.DOMAIN,
            RESURGENCE_DOMAIN,
            "A new invoice-themed domain surfaced; establish where it points.",
        ),
        (
            PivotType.REGISTRATION_RECORD,
            EntityType.DOMAIN,
            RESURGENCE_DOMAIN,
            "Who registered it, and whether the registrar matches the old cluster.",
        ),
        (
            PivotType.CERTIFICATE_HISTORY,
            EntityType.IP_ADDRESS,
            RESURGENCE_IP,
            "What the new address presents.",
        ),
        (
            PivotType.NETWORK_OWNERSHIP,
            EntityType.IP_ADDRESS,
            RESURGENCE_IP,
            "Which network announces it, for the disruption estimate rather than the link.",
        ),
        (
            PivotType.PERSONA_ACTIVITY,
            EntityType.PERSONA,
            PERSONA_RESURGENT.lower(),
            "A new vendor persona appeared on NightPort; collect what it publishes.",
        ),
        # Our own edge, on both sides of the gap. Everything above arrives through a channel an
        # adversary can write into, so without these two the watch cannot reach a finding
        # whatever it finds — the robustness margin removes every plantable fact and one of
        # them is always the load-bearing one.
        (
            PivotType.OWN_TELEMETRY,
            EntityType.DOMAIN,
            SEED_DOMAIN,
            "What our own gateway captured of the original wave.",
        ),
        (
            PivotType.OWN_TELEMETRY,
            EntityType.DOMAIN,
            RESURGENCE_DOMAIN,
            "Whether our own gateway has seen this new domain arrive too.",
        ),
    )

    collections: list[DirectedCollection] = []
    claims: dict[str, tuple[Claim, ...]] = {}
    for pivot_type, entity_type, entity_key, rationale in plan:
        connector = _connector_for(connectors, pivot_type, entity_type)
        summary, collected = await _collect(
            context,
            connector=connector,
            pivot_type=pivot_type,
            entity_type=entity_type,
            entity_key=entity_key,
            rationale=rationale,
        )
        collections.append(summary)
        claims[f"{pivot_type.value}:{entity_key}"] = collected

    reuse_claims = claims[f"{PivotType.CERTIFICATE_REUSE.value}:{CERT_FINGERPRINT}"]
    historical_presentation = _find_claim(
        reuse_claims, predicate=RelationType.PRESENTS_CERTIFICATE.value, contains=CERT_FINGERPRINT
    )
    new_presentation = next(
        (
            claim
            for claim in reuse_claims
            if claim.statement.subject == f"{EntityType.IP_ADDRESS.value}:{RESURGENCE_IP}"
        ),
        None,
    )
    if new_presentation is None:
        raise ScenarioError(
            "the resurgence address does not present the historical certificate; the "
            "reconnection has nothing to rest on"
        )
    new_persona_claims = claims[f"{PivotType.PERSONA_ACTIVITY.value}:{PERSONA_RESURGENT.lower()}"]
    new_key_claim = _find_claim(
        new_persona_claims, predicate=RelationType.SIGNED_BY.value, contains=PGP_FINGERPRINT
    )

    inference_claims = (
        _succession_claim(
            context,
            subject=f"{EntityType.IP_ADDRESS.value}:{CLUSTER_IP}",
            obj=f"{EntityType.IP_ADDRESS.value}:{RESURGENCE_IP}",
            prose=(
                f"{RESURGENCE_IP} presents the same TLS certificate {CERT_FINGERPRINT} that "
                f"{CLUSTER_IP} presented before the disruption. A private key is not shared "
                "by accident; this is the operator reusing one."
            ),
            method=PivotMethod.INFRASTRUCTURE_REUSE,
            attribute=f"TLS certificate SHA-256 fingerprint {CERT_FINGERPRINT}",
            population=CERTIFICATE_POPULATION_AFTER_RESURGENCE,
            corpus=CERTIFICATE_CORPUS_RESURGENCE,
            globally_unique=False,
            inputs=(historical_presentation, new_presentation),
            as_of=as_of,
        ),
        _succession_claim(
            context,
            subject=f"{EntityType.PERSONA.value}:{PERSONA_CURRENT}",
            obj=f"{EntityType.PERSONA.value}:{PERSONA_RESURGENT}",
            prose=(
                f"{PERSONA_RESURGENT} publishes the full 160-bit PGP fingerprint "
                f"{PGP_FINGERPRINT}, the same one {PERSONA_CURRENT} published on "
                f"{FORUM_CURRENT}."
            ),
            method=PivotMethod.CRYPTOGRAPHIC_IDENTITY,
            attribute=f"PGP fingerprint {PGP_FINGERPRINT}",
            population=2,
            corpus=DARK_WEB_CORPUS,
            globally_unique=True,
            inputs=(historical_key_claim, new_key_claim),
            as_of=as_of,
        ),
    )

    materialized = await _absorb(
        context,
        claims=inference_claims,
        source=SourceDescriptor(
            source_class=SourceClass.HUMAN_ANALYST,
            identifier="nemesis-resurgence-watch",
            reliability=SourceReliability.COMPLETELY_RELIABLE,
            operator="NEMESIS",
        ),
    )
    by_claim = {
        claim_id: edge for edge in materialized.relationships for claim_id in edge.supporting_claims
    }

    links: list[ResurgenceLink] = []
    for claim, artifact in zip(
        inference_claims,
        (
            f"TLS certificate SHA-256 fingerprint {CERT_FINGERPRINT}",
            f"PGP fingerprint {PGP_FINGERPRINT}",
        ),
        strict=True,
    ):
        edge = by_claim.get(claim.claim_id)
        if edge is None:
            raise ScenarioError("a succession claim produced no SUCCEEDED_BY edge")
        explanation = edge.explain()
        links.append(
            ResurgenceLink(
                predecessor=claim.statement.subject,
                successor=claim.statement.obj,
                shared_artifact=artifact,
                pivot_method=edge.pivot_method,
                inference_claim_id=claim.claim_id,
                explanation=explanation,
                rendered=explanation.render(),
            )
        )

    await context.audit.record(
        make_event(
            actor=context.actor,
            actor_kind=ActorKind.AGENT,
            action="resurgence.reconnect",
            subject=SCENARIO_SUBJECT,
            outcome=f"reconnected {len(links)} succession(s) to the historical actor",
            inputs={
                "certificate": CERT_FINGERPRINT,
                "pgp_fingerprint": PGP_FINGERPRINT,
                "as_of": as_of.isoformat(),
            },
        )
    )

    return ResurgenceStage(
        as_of=as_of,
        new_domain=RESURGENCE_DOMAIN,
        new_ip=RESURGENCE_IP,
        new_asn=RESURGENCE_ASN,
        new_registrar=RESURGENCE_REGISTRAR,
        new_persona=PERSONA_RESURGENT,
        new_forum=FORUM_RESURGENT,
        nothing_in_common=_NOTHING_IN_COMMON,
        collections=tuple(collections),
        links=tuple(links),
        reconnected_by=(
            f"TLS certificate SHA-256 fingerprint {CERT_FINGERPRINT}",
            f"PGP fingerprint {PGP_FINGERPRINT}",
        ),
        not_reconnected_by=_NOT_RECONNECTED_BY,
        # Filled in by the caller once the watch has run over the graph this stage just
        # enriched; a stage cannot watch for a return using only what it collected itself.
        watch=WatchReport(
            investigation_id="",
            campaign="",
            checked_at=as_of,
            not_watching_reason="the watch pass runs after this stage",
        ),
        resumed=None,
        graph_signals=await assemble_resurgence_signals(
            context.graph,
            prior_entity_ids=[
                entity.entity_id
                for entity in (
                    await context.graph.find_entity(EntityType.IP_ADDRESS, CLUSTER_IP),
                    await context.graph.find_entity(EntityType.DOMAIN, CLUSTER_DOMAINS[0]),
                )
                if entity is not None
            ],
            observed_at=as_of,
            # The real resolver, not the default that knows nothing: the vault holds the
            # provenance of everything this run collected, so the walk can say who observed
            # each fact instead of declining to guess.
            provenance_of=resolve_sources(context.claims, context.vault),
        ),
        assessment=_resurgence_assessment(as_of=as_of),
    )


def _succession_claim(
    context: _Context,
    *,
    subject: str,
    obj: str,
    prose: str,
    method: PivotMethod,
    attribute: str,
    population: int,
    corpus: str,
    globally_unique: bool,
    inputs: tuple[Claim, ...],
    as_of: datetime,
) -> Claim:
    """Mint the inference that reconnects a successor to its predecessor.

    ``check_derivation`` runs first: an inference may never carry more standing than its
    weakest premise, and these premises are direct observations, so an inference is the
    strongest thing derivable from them. The qualifiers carry the artifact, its population
    and the corpus it was counted against, so the edge built from this claim explains
    itself with the certificate and the key rather than with a score.
    """
    check_derivation(ClaimKind.INFERENCE, inputs)
    qualifiers = {
        QUALIFIER_PIVOT_METHOD: method.value,
        QUALIFIER_SHARED_ATTRIBUTE: attribute,
        QUALIFIER_POPULATION_SIZE: str(population),
        QUALIFIER_POPULATION_CORPUS: corpus,
    }
    if globally_unique:
        qualifiers["globally_unique"] = "true"
    return Claim.create(
        kind=ClaimKind.INFERENCE,
        statement=Statement(
            subject=subject,
            predicate=RelationType.SUCCEEDED_BY.value,
            obj=obj,
            qualifiers=qualifiers,
            natural_language=prose,
        ),
        derivation=DerivationKind.DETERMINISTIC_RULE,
        asserted_by=context.actor,
        asserted_at=as_of,
        valid_extent=TemporalExtent.at(as_of),
        derived_from_claims=tuple(claim.claim_id for claim in inputs),
        rule_name=RESURGENCE_RULE,
        rule_version=RESURGENCE_RULE_VERSION,
        notes=(
            "The reconnection rests on a reused artifact, not on a resemblance. Reused "
            "material can also be stolen, sold or shared; that alternative is not excluded "
            "by anything collected here."
        ),
    )


# --------------------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------------------


async def run_glass_anvil_scenario_async(
    *,
    workspace: Path | None = None,
    as_of: datetime = SCENARIO_PRESENT,
    resurgence_as_of: datetime = RESURGENCE_AS_OF,
    total_budget: float = 400.0,
    max_steps: int = 400,
) -> ScenarioResult:
    """Run the whole scenario once and return every stage's output.

    ``workspace`` holds the evidence vault and the audit trail. When it is omitted a fresh
    temporary directory is created and its path is reported on the result, so ``nemesis
    verify`` can be pointed at the same store afterwards.
    """
    root = Path(workspace) if workspace is not None else Path(tempfile.mkdtemp(prefix="nemesis-"))
    root.mkdir(parents=True, exist_ok=True)

    connectors = simulated_connectors(as_of=as_of)
    context = _Context(
        # Durable, and replayed on open. The investigation itself used to live in
        # dictionaries: a restart lost what the platform believed and, worse, why — the
        # supersession history is what answers "what did we think in March?".
        graph=await JournalBackedGraphStore.open(root / "graph"),
        claims=await JournalBackedClaimStore.open(root / "graph"),
        vault=FileSystemEvidenceVault(root / "vault"),
        audit=AppendOnlyAuditTrail(root / "audit.jsonl"),
        # Durable, and shared with anything else opening the same file. The revocation list
        # used to live in one process's memory, which meant a withdrawal was forgotten on
        # restart and invisible to anyone else — the one control that already failed open
        # across a split deployment, and ADR-0007 split the deployment.
        authorization=SqliteAuthorizationStore(root / "authorization.sqlite3"),
        actor=new_id(IdPrefix.ACTOR),
        sources={
            connector.capabilities.name: connector.capabilities.source for connector in connectors
        },
        claim_sources={},
        claim_confidence={},
    )

    detect, seed = await _detect(context)
    pursue, collected = await _pursue(
        context, seed, connectors, total_budget=total_budget, max_steps=max_steps
    )
    graph_stage, cluster = await _graph_stage(context)
    darkweb, persona_key_claim, historical_key_claim, identity_claim = await _darkweb(
        context, collected
    )
    blockchain, wallet_claim = _blockchain(context, collected)
    resolve = _resolve(context, persona_key_claim, historical_key_claim)

    cluster_claims = await _cluster_claims(context, cluster, collected)
    attribute = _attribute(
        context,
        cluster_claims=cluster_claims,
        kit_claims=(
            *collected[f"{PivotType.MALWARE_LOOKUP.value}:{KIT_SHA256}"],
            *collected[f"{PivotType.C2_EXTRACTION.value}:{KIT_SHA256}"],
        ),
        persona_claims=collected[f"{PivotType.PERSONA_ACTIVITY.value}:{PERSONA_CURRENT.lower()}"],
        market_claims=collected[f"{PivotType.MARKETPLACE_LISTING.value}:{PERSONA_CURRENT.lower()}"],
        wallet_claim=wallet_claim,
        persona_key_claim=persona_key_claim,
        historical_key_claim=historical_key_claim,
        identity_claim=identity_claim,
        assessed_at=as_of,
    )

    evidence = await _evidence_stage(context)
    disrupt = await _disrupt(context, attribute)

    releasable = await context.vault.list_evidence()
    evidence_ids = tuple(obj.evidence_id for obj in releasable[:8])
    decided_at = utcnow()
    authorize, gateway, capability = await _authorize(
        context, evidence_ids=evidence_ids, now=decided_at
    )
    effect, registry = await _effects(
        context,
        capability,
        gateway=gateway,
        evidence_ids=evidence_ids,
        now=decided_at,
    )

    watching = mark_monitoring_resurgence(pursue.investigation)
    resurgence = await _resurgence(
        context,
        simulated_connectors(as_of=resurgence_as_of),
        as_of=resurgence_as_of,
        historical_key_claim=persona_key_claim,
    )

    # The loop's last edge, and it runs *after* the phase-8 collection has landed: asking
    # whether the adversary came back before collecting what they came back with would answer
    # the question against a graph that could not contain the answer.
    watch = await watch_for_resurgence(
        context.graph,
        watching,
        campaign=SCENARIO_SUBJECT,
        candidate_population=TRACKED_CAMPAIGNS,
        now=resurgence_as_of,
        provenance_of=resolve_sources(context.claims, context.vault),
    )
    resumed: Investigation | None = None
    if watch.resumes:
        finding = watch.actionable[0]
        candidate = await context.graph.find_entity(finding.candidate_type, finding.candidate_key)
        if candidate is not None:
            resumed = resume_pursuit(
                watching,
                candidate_entity_id=candidate.entity_id,
                candidate_key=candidate.natural_key,
                reason=(
                    f"resurgence watch scored {finding.assessment.band.value} on "
                    f"{finding.candidate_key}"
                ),
                now=resurgence_as_of,
                additional_budget=RESUMPTION_BUDGET,
            )
            watching = resumed
    await _record_watch(context, watch=watch, resumed=resumed is not None)
    resurgence = resurgence.model_copy(update={"watch": watch, "resumed": resumed})

    return ScenarioResult(
        detect=detect,
        pursue=pursue.model_copy(update={"investigation": watching}),
        graph=graph_stage,
        darkweb=darkweb,
        blockchain=blockchain,
        resolve=resolve,
        attribute=attribute,
        evidence=evidence,
        disrupt=disrupt,
        authorize=authorize,
        effect=effect,
        resurgence=resurgence,
        stores=ScenarioStores(
            workspace=root,
            graph=context.graph,
            claims=context.claims,
            vault=context.vault,
            audit=context.audit,
            authorization=context.authorization,
            gateway=gateway,
            effects=registry,
        ),
    )


async def _cluster_claims(
    context: _Context, cluster: Subgraph, collected: dict[str, tuple[Claim, ...]]
) -> dict[str, Claim]:
    """The four infrastructure claims phase 7 assesses, recovered from what was collected.

    Read back out of the graph and the claim store rather than remembered from the pivot
    that produced them: the attribution must grade the claim the graph actually holds.
    """
    found: dict[str, Claim] = {}
    for edge in cluster.relationships:
        selectivity = edge.selectivity
        if selectivity is None or not edge.supporting_claims:
            continue
        claim = context.claims.get_version(edge.supporting_claims[0])
        if claim is None:
            continue
        if selectivity.attribute == CLUSTER_IP and "reverse" not in found:
            found["reverse"] = claim
        elif selectivity.attribute == CERT_FINGERPRINT and "certificate" not in found:
            found["certificate"] = claim
        elif selectivity.attribute.startswith("registration through") and (
            "registration" not in found
        ):
            found["registration"] = claim

    cdn_claims = collected[f"{PivotType.REVERSE_RESOLUTION.value}:{CDN_IP}"]
    found["cdn"] = _find_claim(cdn_claims, predicate=RelationType.RESOLVES_TO.value)

    missing = sorted({"reverse", "certificate", "registration", "cdn"} - set(found))
    if missing:
        raise ScenarioError(
            f"the cluster does not carry the infrastructure claims phase 7 assesses: {missing}"
        )
    return found


def run_glass_anvil_scenario(
    *,
    workspace: Path | None = None,
    as_of: datetime = SCENARIO_PRESENT,
    resurgence_as_of: datetime = RESURGENCE_AS_OF,
    total_budget: float = 400.0,
    max_steps: int = 400,
) -> ScenarioResult:
    """Synchronous entry point. Drives :func:`run_glass_anvil_scenario_async` to completion.

    The planes are ``async`` because their ports are; nothing in them awaits I/O that could
    block, so one event loop per run is the whole concurrency story. Callers already inside
    a loop should await the async form instead.
    """
    return asyncio.run(
        run_glass_anvil_scenario_async(
            workspace=workspace,
            as_of=as_of,
            resurgence_as_of=resurgence_as_of,
            total_budget=total_budget,
            max_steps=max_steps,
        )
    )


def _resurgence_assessment(*, as_of: datetime) -> ResurgenceAssessment:
    """Score the reconnection with the engine, from the same two artifacts the stage names.

    The certificate is the strong half: a private key is not shared by accident, it is globally
    unique by construction, and the observation is our own sensor's rather than a channel an
    adversary could write into. The PGP fingerprint is the weak half and is scored as such —
    republishing a public value demonstrates nothing about holding the key, and it is the
    cheapest way to make a new operation look like an old one.

    That second signal is also what makes the finding INTERNAL_LEAD rather than a deliverable:
    it names a persona, and persona linkage is an investigative lead under founder decision D1.
    The assessment carries the classification of its most restricted part, so the wrapper cannot
    publish what its contents may not say.
    """
    return ResurgenceEngine().assess(
        campaign=SCENARIO_SUBJECT,
        signals=(
            ResurgenceSignal(
                kind=ResurgenceSignalKind.SHARED_PRIVATE_KEY,
                shared_attribute=f"tls-certificate:{CERT_FINGERPRINT}",
                selectivity=PivotSelectivity(
                    attribute=f"tls-certificate:{CERT_FINGERPRINT}",
                    is_globally_unique=True,
                ),
                observed_by=SourceDescriptor(
                    # The source the platform actually collected this through, not the one a
                    # narrative would prefer. `CERTIFICATE_REUSE` is served by the internet-scan
                    # connector, and an internet scan is a channel an adversary can write into:
                    # putting a certificate somewhere a scanner will find it is cheap.
                    #
                    # An earlier version of this function asserted OWN_SENSOR here and reported
                    # the phase at *very likely*, actionable. Nothing in the run supported that.
                    # It was caught by resolving the graph's provenance for real and finding
                    # internet_scan where the assessment claimed a sensor of ours.
                    source_class=SourceClass.INTERNET_SCAN,
                    identifier="passive-scan-fleet",
                    reliability=SourceReliability.USUALLY_RELIABLE,
                ),
                new_entity_type=EntityType.IP_ADDRESS,
                new_entity_key=RESURGENCE_IP,
                prior_entity_key=CLUSTER_IP,
                extent=TemporalExtent.at(as_of),
            ),
            ResurgenceSignal(
                kind=ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT,
                shared_attribute=f"pgp:{PGP_FINGERPRINT}",
                selectivity=PivotSelectivity(
                    attribute=f"pgp:{PGP_FINGERPRINT}",
                    is_globally_unique=True,
                ),
                observed_by=SourceDescriptor(
                    source_class=SourceClass.DARK_WEB,
                    identifier=FORUM_RESURGENT,
                    reliability=SourceReliability.FAIRLY_RELIABLE,
                ),
                new_entity_type=EntityType.PERSONA,
                new_entity_key=PERSONA_RESURGENT,
                prior_entity_key=PERSONA_CURRENT,
                extent=TemporalExtent.at(as_of),
            ),
        ),
        candidate_population=TRACKED_CAMPAIGNS,
        assessed_at=as_of,
    )


async def _record_watch(context: _Context, *, watch: WatchReport, resumed: bool) -> None:
    """Put the watch pass in the audit trail, whether or not it found anything.

    A pass that examined six candidates and resumed on none is a decision, and invariant 11
    wants decisions replayable rather than merely believed. Recording only the passes that
    found something would leave the trail unable to distinguish a watch that ran and refused
    from a watch that stopped running.
    """
    await context.audit.record(
        AuditEvent(
            audit_id=new_id(IdPrefix.AUDIT),
            occurred_at=watch.checked_at,
            actor="nemesis.pursuit.watch",
            actor_kind="rule",
            action="resurgence.watch",
            subject=watch.investigation_id,
            outcome="resumed" if resumed else "no candidate cleared the bar",
            inputs={
                "campaign": watch.campaign,
                "candidates_examined": str(watch.candidates_examined),
                "actionable": str(len(watch.actionable)),
                "not_watching_reason": watch.not_watching_reason or "",
            },
        )
    )
