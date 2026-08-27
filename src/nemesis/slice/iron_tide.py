"""Operation IRON TIDE: one address in a firewall log, followed until it stops being followable.

GLASS ANVIL (:mod:`nemesis.slice.scenario`) starts from a domain somebody clicked. This starts
from the seed an incident actually starts from — **an IP address** — and that changes what the
platform has to do before it may believe anything.

A domain carries a registration, a certificate history and a resolution history, and the rule
policy has four questions to ask it before it has to think. An address carries none of that. It
carries whatever else is on it, and *whatever else is on it* is worth everything or nothing
depending on a number nobody has yet counted. Three names on a dedicated lease is a finding.
Three names sampled from twelve thousand on a shared hosting platform is noise wearing the same
shape. Until something counts the tenants, the two are the same observation.

So this run is organised around earning each hop:

1. **DETECT** — two of NORTHWIND's own sensors, one operator. A netflow record of a beacon and
   an EDR record of the implant that opened it. Between them: an address, a sample, and no
   claim whatsoever about whose the address is.
2. **PURSUE** — the rule policy drives itself from the address. It asks who announces it (worth
   nothing, correctly), what else resolves there, **what kind of address it is**, and what it
   presents. The certificate it finds is what turns one address into three.
3. **PILOT** — the pivots the rule policy has no rule for, driven through
   :meth:`~nemesis.pursuit.engine.PursuitEngine.execute_pivot` — the seam NEMESIS exists to put
   an external model behind. The pilot names the pivot; the engine keeps the budget, the
   routing, the provenance ordering and the audit line. It is the same enforcement, chosen from
   outside.
4. **BRIDGE** — the one leap neither can make. No connector answers "which vendor advertises
   this onion service", so the crossing from infrastructure to persona is an analyst's, is
   recorded as ``collection.directed``, and is reported apart from everything above it.
5. **STANDING** — whose each node is, derived rather than asserted, including the two the
   platform must refuse to call the adversary's.
6. **ATTRIBUTE** — four dimensions assessed and one refused.

**Three tiers of agency, reported separately.** GLASS ANVIL has two — autonomous and directed —
and folds the pilot into the second. Keeping the pilot's pivots distinct is the point of the
architecture: a move an external model chose and the engine executed is not a move the engine
chose, and it is not a move a human made either. A run that presented all three as one number
would be unreviewable in exactly the way ADR-0008 exists to prevent.

**What this run does not reach, and why it is stated here rather than discovered later.** It
ends at a persona and a free-text attribution subject. There is no code path in this repository
that mints a :attr:`~nemesis.core.entities.EntityType.THREAT_ACTOR` node — the enum member
exists, nothing constructs one — so "the actor" is a string on an
:class:`~nemesis.attribute.engine.AttributionRequest` and not a node anything can be attached
to. :attr:`IronTideResult.actor_gap` says so on every run rather than leaving a reader to infer
that a persona is an actor.

Status: `SIMULATED`. Every connector reads a fixture, every entity and claim is flagged
synthetic, and the only I/O is a local workspace holding the evidence vault and the audit trail.
There is no network code here and none reachable from here.
"""

from __future__ import annotations

import asyncio
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict

from nemesis.attribute.dimensions import (
    AlternativeHypothesis,
    AttributionDimension,
    DimensionAssessment,
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
from nemesis.authz.store import SqliteAuthorizationStore
from nemesis.collect.base import CONNECTOR_VERSION, build_observation, connector_actor_id
from nemesis.collect.fixtures.iron_tide import (
    BEACON_SESSIONS,
    CERT_FINGERPRINT,
    CLUSTER_DOMAINS,
    DETECTED_AT,
    FRAMED_ORGANIZATION,
    IMPLANT_SHA256,
    MALWARE_FAMILY,
    MESSAGING_ACCOUNT,
    NAMED_PERSON,
    ONION_PANEL,
    PERSONA,
    REGISTRATION_WINDOW_HOURS,
    SCENARIO_PRESENT,
    SECOND_C2_IP,
    SEED_IP,
    SHARED_HOST_IP,
    SHARED_HOST_OPERATOR,
    SHARED_HOST_POPULATION,
    VICTIM,
    phase_one_detection,
)
from nemesis.collect.isolation import collect_confined
from nemesis.collect.quarantine import (
    ArtifactAnalyser,
    Quarantine,
    StructuralAnalyser,
    seal_when_released,
)
from nemesis.collect.simulated import iron_tide_connectors
from nemesis.core.claims import Claim
from nemesis.core.confidence import BAND_RANGES, ConfidenceBand, Opinion, band_of
from nemesis.core.entities import Entity, EntityType
from nemesis.core.fusion import FusionResult, SourcedOpinion, fuse, summarize_fact
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.infrastructure import (
    ControlFacet,
    InfrastructureRole,
    RoleAssessment,
)
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import (
    CollectionMethod,
    InformationCredibility,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
)
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.evidence.escalation import Register
from nemesis.evidence.vault import FileSystemEvidenceVault, FileSystemVaultIntegrityReport
from nemesis.graph.journal import JournalBackedClaimStore, JournalBackedGraphStore
from nemesis.ports.collection import IntelligenceConnector, PivotRequest, PivotResult, PivotType
from nemesis.ports.storage import GraphQuery, ObligationSink, Subgraph
from nemesis.pursuit.engine import ConnectorRegistry, PursuitEngine
from nemesis.pursuit.investigation import ExecutedPivot, IncidentSeed, Investigation
from nemesis.pursuit.materialize import MaterializationResult, materialize
from nemesis.pursuit.standing import assess_entity_standing

# --------------------------------------------------------------------------------------
# Constants this module chooses for itself
# --------------------------------------------------------------------------------------

SCENARIO_SUBJECT: Final = "the operator behind Operation IRON TIDE"
"""What the attribution is *about*, as a string, because a string is all the engine takes.

:attr:`~nemesis.attribute.engine.AttributionRequest.subject` is
``Annotated[str, Field(max_length=512)]``. There is no entity on the other end of it and
nothing in this repository creates one. See :attr:`IronTideResult.actor_gap`."""

DETECTION_PROPOSITION: Final = (
    "the beaconing session and the quarantined implant are one intrusion at NORTHWIND"
)

TOTAL_BUDGET: Final = 400.0
MAX_STEPS: Final = 400

ACTOR_GAP: Final = (
    "This run ends at a persona. NEMESIS has an EntityType.THREAT_ACTOR member and no code "
    "that constructs one: the only production references are the enum declaration and the "
    "adversary-type table it appears in. `AttributionRequest.subject` is free text, so the "
    "assessment below is *about* a string, and nothing in the graph carries it. Minting an "
    "actor node is not a missing line — it changes the node's disclosure class from "
    "INTERNAL_LEAD (persona) to DELIVERABLE (actor), which is the boundary the identity wall "
    "is built on, so it needs its own decision and its own test before it is a feature."
)

MALWARE_SIMILARITY_NOTE: Final = (
    "MALWARE_SIMILARITY was requested and the source refused it: code-similarity search is a "
    "licensed capability this deployment does not hold. Recorded as a failure, never as an "
    "observation that no related samples exist."
)

_SENSOR_REPLAY_METHOD: Final = CollectionMethod(
    collector_name="phase-one-sensor-replay",
    collector_version=CONNECTOR_VERSION,
    parameters={"phase": "1", "fixture_set": "iron-tide"},
    is_simulated=True,
)


class IronTideError(RuntimeError):
    """A stage could not be built from what was actually collected."""


# --------------------------------------------------------------------------------------
# Stage models
# --------------------------------------------------------------------------------------


class SensorRecord(BaseModel):
    """One phase-1 sensor, and the origin it collapses into."""

    model_config = ConfigDict(frozen=True)

    sensor: str
    operator: str
    source_class: SourceClass
    reliability: SourceReliability
    evidence_id: str
    claim_id: str
    independence_key: str


class DetectionStage(BaseModel):
    model_config = ConfigDict(frozen=True)

    detected_at: datetime
    seed_entity_type: EntityType
    seed_entity_key: str
    detected_by: str
    sensors: tuple[SensorRecord, ...]
    proposition: str
    fusion: FusionResult
    what_the_seed_does_not_say: tuple[str, ...]


class PivotRecord(BaseModel):
    """One executed pivot, whoever chose it."""

    model_config = ConfigDict(frozen=True)

    chosen_by: str
    """``policy``, ``pilot`` or ``analyst``. The whole reason this model exists."""

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
    cost: float = 0.0
    unmaterialized: tuple[str, ...] = ()


class RefusedLead(BaseModel):
    """The one place in this result where the planted name is allowed to be.

    Both halves are required and they pull in opposite directions. That the assertion is
    recorded *somewhere* is not a concession: a platform that silently drops it cannot show an
    analyst what it declined to act on, and cannot honour the retention obligations that
    attach to a natural person's data the moment it is held. That it appears *nowhere else* is
    what the platform is for.

    ``promoted_to_attribution`` is stored rather than derived so that a future change which
    starts promoting leads has to edit this field, in a diff a reviewer reads.
    """

    model_config = ConfigDict(frozen=True)

    lead_display: str
    entity_type: EntityType
    claim_id: str
    asserted_by_source: SourceClass
    promoted_to_attribution: bool
    is_personal_data: bool
    why_refused: str


class PursuitStage(BaseModel):
    model_config = ConfigDict(frozen=True)

    investigation: Investigation
    autonomous: tuple[PivotRecord, ...]
    pilot: tuple[PivotRecord, ...]
    analyst: tuple[PivotRecord, ...]
    pilot_because: str
    analyst_because: str
    refused_lead: RefusedLead

    @property
    def budget_spent(self) -> float:
        return sum(p.cost for p in (*self.autonomous, *self.pilot, *self.analyst))


class EdgeSummary(BaseModel):
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


class ClusterStage(BaseModel):
    """The graph the pursuit built, split the way the domain model splits it.

    Three buckets rather than two, because "informative" and "not informative" are not
    opposites here. An edge with a *counted* population is either selective or it is not; an
    edge with no population is neither — it is a direct observation, where nothing was
    inferred from a shared attribute and :class:`PivotSelectivity` is meaningless by
    construction. Folding the third into the first would report every certificate sighting as
    a selective pivot.
    """

    model_config = ConfigDict(frozen=True)

    entity_count: int
    edge_count: int
    selective_edges: tuple[EdgeSummary, ...]
    """Counted, and narrow enough to mean something."""

    worthless_edges: tuple[EdgeSummary, ...]
    """Counted, and too crowded to mean anything. The control lives here."""

    direct_observations: int
    """No shared attribute was pivoted on, so selectivity does not apply."""

    the_control: str
    bystanders: tuple[str, ...]
    """Third parties the planner walked onto and the graph then refused to believe anything
    about. Reported because they are in the case now, which is a cost the budget line does
    not show."""

    bystander_pivots: int


class StandingRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_key: str
    entity_type: EntityType
    role: InfrastructureRole
    projected_probability: float
    facets: tuple[ControlFacet, ...]
    reasoning: tuple[str, ...]


class StandingStage(BaseModel):
    model_config = ConfigDict(frozen=True)

    records: tuple[StandingRecord, ...]
    refused_to_call_adversary: tuple[str, ...]


class AttributionStage(BaseModel):
    model_config = ConfigDict(frozen=True)

    result: AttributionResult
    false_flag_claim_id: str
    framed_organization: str
    human_identity_band: ConfidenceBand
    weak_markers_not_scored: tuple[str, ...]
    what_the_margin_removed: tuple[str, ...]

    def dimension(self, dimension: AttributionDimension) -> DimensionAssessment:
        return self.result.for_dimension(dimension)


class EvidenceStage(BaseModel):
    model_config = ConfigDict(frozen=True)

    sealed_objects: int
    vault_intact: bool
    audit_events: int
    audit_chain_intact: bool
    cannot_defend: tuple[str, ...]


@dataclass(slots=True)
class IronTideStores:
    workspace: Path
    graph: JournalBackedGraphStore
    claims: JournalBackedClaimStore
    vault: FileSystemEvidenceVault
    audit: AppendOnlyAuditTrail
    authorization: SqliteAuthorizationStore


@dataclass(frozen=True, slots=True)
class IronTideResult:
    detect: DetectionStage
    pursue: PursuitStage
    cluster: ClusterStage
    standing: StandingStage
    attribute: AttributionStage
    evidence: EvidenceStage
    stores: IronTideStores
    actor_gap: str = ACTOR_GAP

    def stages(self) -> tuple[tuple[str, BaseModel], ...]:
        return (
            ("detect", self.detect),
            ("pursue", self.pursue),
            ("cluster", self.cluster),
            ("standing", self.standing),
            ("attribute", self.attribute),
            ("evidence", self.evidence),
        )


STAGE_NAMES: Final = ("detect", "pursue", "cluster", "standing", "attribute", "evidence")


def band_range(band: ConfidenceBand) -> str:
    """The numeric range behind a verbal band, which every output must print alongside it."""
    if band is ConfidenceBand.INSUFFICIENT_BASIS:
        return "no range — the evidence does not support an estimate"
    low, high = BAND_RANGES[band]
    return f"{low:.0%} to {high:.0%}"


# --------------------------------------------------------------------------------------
# Run context
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Context:
    graph: JournalBackedGraphStore
    claims: JournalBackedClaimStore
    vault: FileSystemEvidenceVault
    audit: AppendOnlyAuditTrail
    authorization: SqliteAuthorizationStore
    actor: str
    sources: dict[str, SourceDescriptor]
    claim_sources: dict[str, SourceDescriptor] = field(default_factory=dict)
    claim_confidence: dict[str, Opinion] = field(default_factory=dict)
    quarantine: Quarantine = field(default_factory=Quarantine)
    analyser: ArtifactAnalyser = field(default_factory=StructuralAnalyser)
    # Defaulted for the same reason the quarantine beside it is: a demonstration that opened
    # an obligation only when asked would be one that does not, and the reader who most needs
    # to see the backlog is the one who never heard of the register.
    obligations: ObligationSink = field(default_factory=Register)


def _reference(entity: Entity) -> str:
    return f"{entity.entity_type.value}:{entity.natural_key}"


async def _absorb(
    context: _Context, *, claims: Sequence[Claim], source: SourceDescriptor
) -> MaterializationResult:
    """Record claims and turn them into graph structure, in the order provenance requires."""
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


def _connector_for(
    connectors: Sequence[IntelligenceConnector], pivot: PivotType, entity_type: EntityType
) -> IntelligenceConnector:
    request = PivotRequest(
        pivot_type=pivot, entity_type=entity_type, entity_key="probe", reason="capability probe"
    )
    for connector in connectors:
        if connector.capabilities.can_answer(request):
            return connector
    raise IronTideError(f"no simulated connector answers {pivot.value} for {entity_type.value}")


def _find_claim(claims: Iterable[Claim], *, predicate: str, contains: str = "") -> Claim:
    for claim in claims:
        if claim.statement.predicate != predicate:
            continue
        if contains and contains.lower() not in claim.statement.obj.lower():
            continue
        return claim
    raise IronTideError(f"no collected claim with predicate {predicate!r} matching {contains!r}")


def _find_claim_by_source(
    claims: Iterable[Claim],
    context: _Context,
    *,
    predicate: str,
    contains: str,
    source_class: SourceClass,
) -> Claim:
    """The claim asserting this statement *through a particular kind of channel*.

    Needed because the run deliberately collects one statement twice — once through a channel
    an adversary can write into and once through one they cannot — and the two are different
    claims with different provenance. Picking "the first one with this predicate" would pick
    whichever pivot happened to run first, and the attribution would then rest on a plantable
    fact or an unplantable one depending on pivot ordering.
    """
    for claim in claims:
        if claim.statement.predicate != predicate:
            continue
        if contains.lower() not in claim.statement.obj.lower():
            continue
        source = context.claim_sources.get(claim.claim_id)
        if source is not None and source.source_class is source_class:
            return claim
    raise IronTideError(
        f"no {source_class.value} claim with predicate {predicate!r} matching {contains!r}"
    )


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

_SEED_SILENCE: Final = (
    "Nothing here says who operates 203.0.113.201. A netflow record establishes that traffic "
    "went there; it is the same record a legitimate service would produce.",
    "Nothing here says the address is the adversary's rather than a compromised third party's "
    "or a shared platform's. That question is open and is what the next stage spends on.",
    "Two sensors, one operator. They collapse to one origin, so their agreement is not "
    "corroboration — what they buy is two distinct facts in an unplantable channel.",
)


async def _detect(context: _Context) -> tuple[DetectionStage, IncidentSeed]:
    """Build the incident seed from the beacon and the implant."""
    records: list[SensorRecord] = []
    sourced: list[SourcedOpinion] = []
    evidence_ids: list[str] = []
    claims: list[Claim] = []

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
        sealed_id, _report = await seal_when_released(
            context.vault,
            evidence,
            report.record.artifact,
            quarantine=context.quarantine,
            analyser=context.analyser,
            obligations=context.obligations,
        )
        if sealed_id is None:
            raise IronTideError(
                "a phase-1 sensor record was held in quarantine; the run cannot proceed "
                "without the detection that opens the case"
            )
        await _absorb(context, claims=(claim,), source=report.source)
        evidence_ids.append(evidence.evidence_id)
        claims.append(claim)

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
                fact_key=claim.statement.canonical(),
                source=report.source,
                opinion=Opinion.from_admiralty(
                    report.source.reliability, InformationCredibility.CONFIRMED
                ),
                supporting_claims=(claim.claim_id,),
                label=report.source.identifier,
            )
        )

    fusion = fuse(sourced, proposition=PropositionClass.OBSERVATION)
    seed = IncidentSeed(
        entity_type=EntityType.IP_ADDRESS,
        entity_key=SEED_IP,
        observed_at=DETECTED_AT,
        detected_by="northwind-egress-netflow-02",
        context={
            "destination_port": "8443",
            "sessions": str(BEACON_SESSIONS),
            "implant_sha256": IMPLANT_SHA256,
        },
        supporting_evidence=tuple(evidence_ids),
        victim_hint=VICTIM,
    )

    await context.audit.record(
        make_event(
            actor=context.actor,
            actor_kind=ActorKind.HUMAN,
            action="incident.seed",
            subject=f"{seed.entity_type.value}:{seed.entity_key}",
            outcome=(
                f"seeded from {len(records)} sensor(s), "
                f"{fusion.independent_source_count} independent origin(s)"
            ),
            inputs={
                "detected_by": seed.detected_by,
                "sensors": ",".join(record.sensor for record in records),
                "independent_origins": str(fusion.independent_source_count),
                "unplantable_facts": str(fusion.unplantable_facts),
            },
        )
    )

    return (
        DetectionStage(
            detected_at=DETECTED_AT,
            seed_entity_type=seed.entity_type,
            seed_entity_key=seed.entity_key,
            detected_by=seed.detected_by,
            sensors=tuple(records),
            proposition=DETECTION_PROPOSITION,
            fusion=fusion,
            what_the_seed_does_not_say=_SEED_SILENCE,
        ),
        seed,
    )


# --------------------------------------------------------------------------------------
# Stage 2 — PURSUE
# --------------------------------------------------------------------------------------

_PILOT_BECAUSE: Final = (
    "The rule policy proposes pivots by entity type and reaches the whole infrastructure "
    "cluster from the address on its own. It has no rule that says 'ask our own sensors what "
    "they already recorded about this address', and no rule that says 'the implant is in the "
    "graph, pivot on it' — OWN_TELEMETRY appears in no row of PIVOTS_FOR_ENTITY, and the "
    "implant entered the graph from the detection rather than from a pivot, so no branch "
    "opened on it. Those are the moves an external pilot exists to make. They run through "
    "PursuitEngine.execute_pivot, which keeps the routing, the budget, the provenance ordering "
    "and the audit line in the engine: the pilot names a pivot and the engine decides whether "
    "it happens."
)

_ANALYST_BECAUSE: Final = (
    "One leap is neither the policy's nor the pilot's, because no connector can answer it at "
    "any price. The implant configuration yields an onion address and a messaging handle; the "
    "dark-web connector answers only for PERSONA, FORUM and MARKETPLACE entities, and nothing "
    "maps a handle or an onion address to a vendor. A human recognised the panel on a SaltPier "
    "vendor profile. That is a person's inference and is recorded as collection.directed with "
    "the reason attached, rather than presented as something a machine found."
)


def _pivot_record(
    executed: ExecutedPivot, *, chosen_by: str, discovered: tuple[str, ...] = ()
) -> PivotRecord:
    return PivotRecord(
        chosen_by=chosen_by,
        pivot_type=executed.candidate.pivot_type,
        entity_type=executed.candidate.entity_type,
        entity_key=executed.candidate.entity_key,
        connector=executed.connector,
        rationale=executed.candidate.rationale,
        succeeded=executed.succeeded,
        error=executed.error,
        truncated=executed.truncated,
        claim_count=len(executed.claims_produced),
        evidence_count=len(executed.evidence_produced),
        discovered=discovered or tuple(executed.entities_discovered),
        cost=executed.actual_cost,
    )


async def _index_edge_confidence(context: _Context, *keys: tuple[EntityType, str]) -> None:
    """Record the confidence of every edge reachable from the named components.

    No confidence floor and no shared-infrastructure refusal: this is bookkeeping, and an index
    that skipped the weak edges would leave the attribution unable to grade the very pivot this
    run exists to devalue.
    """
    for entity_type, entity_key in keys:
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


async def _pursue(
    context: _Context,
    seed: IncidentSeed,
    connectors: Sequence[IntelligenceConnector],
) -> tuple[PursuitStage, dict[str, tuple[Claim, ...]]]:
    """Autonomous pursuit, then the pilot's pivots, then the analyst's one leap."""
    engine = PursuitEngine(
        graph=context.graph,
        claims=context.claims,
        vault=context.vault,
        audit=context.audit,
        connectors=ConnectorRegistry(connectors),
    )
    investigation = await engine.start(seed, total_budget=TOTAL_BUDGET)
    investigation = await engine.run(investigation, max_steps=MAX_STEPS)

    for pivot in investigation.all_executed_pivots:
        source = context.sources.get(pivot.connector)
        if source is None:
            continue
        for claim_id in pivot.claims_produced:
            context.claim_sources[claim_id] = source

    autonomous = tuple(
        _pivot_record(pivot, chosen_by="policy") for pivot in investigation.all_executed_pivots
    )

    # --- the pilot's moves, through the engine ---------------------------------------
    collected: dict[str, tuple[Claim, ...]] = {}
    pilot: list[PivotRecord] = []

    pilot_plan: tuple[tuple[EntityType, str, PivotType, str], ...] = (
        (
            EntityType.IP_ADDRESS,
            SEED_IP,
            PivotType.OWN_TELEMETRY,
            "Before spending anything outside, ask what we already hold. Our resolver logged "
            "the quarantined process's queries; those are facts in a channel the adversary "
            "cannot author, and the run has no others.",
        ),
        (
            EntityType.MALWARE,
            IMPLANT_SHA256,
            PivotType.MALWARE_LOOKUP,
            "The implant is in the graph from the detection, so no branch opened on it. What "
            "the sample is, and what it carries that somebody wanted found.",
        ),
        (
            EntityType.MALWARE,
            IMPLANT_SHA256,
            PivotType.C2_EXTRACTION,
            "The configuration block: every host the implant is built to reach, and the "
            "fallback channel that leaves the infrastructure cluster.",
        ),
        (
            EntityType.MALWARE,
            IMPLANT_SHA256,
            PivotType.MALWARE_SIMILARITY,
            "Related samples by code similarity. Expected to be refused: the capability is "
            "licensed and this deployment does not hold it. A refusal is not an absence.",
        ),
        (
            EntityType.IP_ADDRESS,
            SHARED_HOST_IP,
            PivotType.HOSTING_NEIGHBOURS,
            "The certificate reached this address. Before anything is inferred from what else "
            "is on it, establish whose it is — the abuse desk's own statement of ownership.",
        ),
    )

    for entity_type, entity_key, pivot_type, rationale in pilot_plan:
        entity = await context.graph.find_entity(entity_type, entity_key)
        if entity is None:
            raise IronTideError(
                f"the pilot named {pivot_type.value} on {entity_type.value}:{entity_key}, "
                "which is not in the graph; the engine refuses pivots on unknown entities"
            )
        investigation, executed = await engine.execute_pivot(
            investigation,
            entity_id=entity.entity_id,
            pivot_type=pivot_type,
            rationale=rationale,
        )
        if executed is None:
            raise IronTideError(
                f"the engine returned no record for the pilot's {pivot_type.value} on {entity_key}"
            )
        source = context.sources.get(executed.connector)
        produced: list[Claim] = []
        for claim_id in executed.claims_produced:
            claim = context.claims.get_version(claim_id)
            if claim is None:
                continue
            produced.append(claim)
            if source is not None:
                context.claim_sources[claim_id] = source
        collected[f"{pivot_type.value}:{entity_key}"] = tuple(produced)
        pilot.append(_pivot_record(executed, chosen_by="pilot"))

    # --- the analyst's leap ----------------------------------------------------------
    analyst: list[PivotRecord] = []
    analyst_plan: tuple[tuple[PivotType, EntityType, str, str], ...] = (
        (
            PivotType.PERSONA_ACTIVITY,
            EntityType.PERSONA,
            PERSONA.lower(),
            f"The implant's fallback channel is {ONION_PANEL[:16]}…. An analyst recognised the "
            f"same panel linked from the {PERSONA} vendor profile on SaltPier. No connector "
            "answers 'which vendor advertises this onion service'; the recognition is a "
            "person's and is recorded as one.",
        ),
        (
            PivotType.MARKETPLACE_LISTING,
            EntityType.PERSONA,
            PERSONA.lower(),
            "What this vendor sells, and when.",
        ),
        (
            PivotType.DARK_WEB_SEARCH,
            EntityType.PERSONA,
            PERSONA.lower(),
            "What the forum says about the vendor. Expected to return hostile content, "
            "including an identity assertion the platform must refuse.",
        ),
    )
    for pivot_type, entity_type, entity_key, rationale in analyst_plan:
        record, claims = await _collect(
            context,
            connector=_connector_for(connectors, pivot_type, entity_type),
            pivot_type=pivot_type,
            entity_type=entity_type,
            entity_key=entity_key,
            rationale=rationale,
        )
        analyst.append(record)
        collected[f"{pivot_type.value}:{entity_key}"] = claims

    await _index_edge_confidence(
        context,
        (EntityType.IP_ADDRESS, SEED_IP),
        (EntityType.MALWARE, IMPLANT_SHA256),
        (EntityType.PERSONA, PERSONA),
    )

    stage = PursuitStage(
        investigation=investigation,
        autonomous=autonomous,
        pilot=tuple(pilot),
        analyst=tuple(analyst),
        pilot_because=_PILOT_BECAUSE,
        analyst_because=_ANALYST_BECAUSE,
        refused_lead=_refused_lead(context, collected),
    )
    return stage, collected


def _refused_lead(context: _Context, collected: dict[str, tuple[Claim, ...]]) -> RefusedLead:
    """Record the identity assertion the forum made, as a lead and never as a finding."""
    claim = _find_claim(
        collected[f"{PivotType.DARK_WEB_SEARCH.value}:{PERSONA.lower()}"],
        predicate=RelationType.CO_OCCURS_WITH.value,
        contains="human_identity_lead",
    )
    source = context.claim_sources.get(claim.claim_id)
    if source is None:
        raise IronTideError("the identity lead has no recorded source of record")
    return RefusedLead(
        lead_display=claim.statement.obj.partition(":")[2],
        entity_type=EntityType.HUMAN_IDENTITY_LEAD,
        claim_id=claim.claim_id,
        asserted_by_source=source.source_class,
        promoted_to_attribution=False,
        is_personal_data=True,
        why_refused=(
            "One anonymous post, one origin, in a channel the adversary writes into, about a "
            "persona with no history we can check. The human-identity gate refuses "
            "structurally — before anything is scored — so there is no number to hedge."
        ),
    )


async def _collect(
    context: _Context,
    *,
    connector: IntelligenceConnector,
    pivot_type: PivotType,
    entity_type: EntityType,
    entity_key: str,
    rationale: str,
) -> tuple[PivotRecord, tuple[Claim, ...]]:
    """Run one analyst-directed pivot and absorb what came back.

    Evidence is sealed before the claims that cite it, and the whole thing is recorded whether
    it succeeded or not: "we looked and found nothing" and "we could not look" are different
    findings and only one of them is evidence of absence.
    """
    request = PivotRequest(
        pivot_type=pivot_type,
        entity_type=entity_type,
        entity_key=entity_key,
        reason=rationale,
    )
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
    held: list[str] = []
    recorded: list[Claim] = []
    materialized = MaterializationResult()

    if result.succeeded:
        for evidence in result.evidence:
            artifact = result.artifacts.get(evidence.evidence_id)
            if artifact is None:
                continue
            sealed_id, _report = await seal_when_released(
                context.vault,
                evidence,
                artifact,
                quarantine=context.quarantine,
                analyser=context.analyser,
                obligations=context.obligations,
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

    record = PivotRecord(
        chosen_by="analyst",
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
        discovered=tuple(
            _reference(entity) for entity in materialized.entities if not entity.is_personal_data
        ),
        cost=connector.capabilities.cost_per_call,
        unmaterialized=materialized.skipped,
    )
    return record, tuple(recorded)


# --------------------------------------------------------------------------------------
# Stage 3 — CLUSTER
# --------------------------------------------------------------------------------------


def _bystanders(pursue: PursuitStage) -> tuple[tuple[str, ...], int]:
    """Names the planner walked onto through the shared host, and what looking cost.

    Measured rather than declared. :func:`nemesis.pursuit.engine.PursuitEngine._spawn_branches`
    does not consult edge confidence, so a co-tenant of a 12,400-name platform gets a branch
    and a budget exactly like a name on a dedicated lease. The graph then correctly declines to
    believe anything about it — every pivot below returns nothing — but the name is in the case
    by then, and the pivots were paid for.

    Surfaced as its own number because a budget line reading "59 spent" hides it, and because
    the cost that matters is not the budget: it is three uninvolved parties appearing in an
    investigation's graph.
    """
    tenants = set(_SHARED_HOST_TENANT_SAMPLE)
    touched = tuple(sorted({p.entity_key for p in pursue.autonomous if p.entity_key in tenants}))
    spent = sum(1 for p in pursue.autonomous if p.entity_key in tenants)
    return touched, spent


_SHARED_HOST_TENANT_SAMPLE: Final = (
    "ridgeline-freight.example",
    "bramblewood-dental.example",
    "st-aidans-pcc.example",
)
"""The three co-tenants the shared-host reverse resolution returns.

Named here rather than derived from the fixture so that a change to the fixture that quietly
stops returning bystanders shows up as an empty measurement rather than as silence."""


_THE_CONTROL: Final = (
    f"{SHARED_HOST_IP} is reached by the strongest pivot in the run — the same private key — "
    f"and its own reverse resolution samples {SHARED_HOST_POPULATION:,} names. The certificate "
    "edge onto it is worth something; every edge out of it is worth nothing. A strong link to "
    "a node licenses nothing from it, and this is the pair that shows it."
)


async def _cluster(
    context: _Context, *, bystanders: tuple[str, ...], bystander_pivots: int
) -> ClusterStage:
    seed = await context.graph.find_entity(EntityType.IP_ADDRESS, SEED_IP)
    if seed is None:
        raise IronTideError("the seed address is not in the graph after the pursuit")
    subgraph: Subgraph = await context.graph.neighbourhood(
        GraphQuery(
            entity_id=seed.entity_id,
            max_depth=8,
            min_confidence=0.0,
            exclude_shared_infrastructure=False,
        )
    )
    entities = {entity.entity_id: entity for entity in subgraph.entities}
    # A neighbourhood returns the nodes it walked, and an edge may still name one outside
    # them. Resolving the stragglers from the store keeps every summary reading as a natural
    # key: a report that falls back to `ent_01a03…` for some rows is a report an analyst
    # cannot check, and the id is meaningless outside this process anyway.
    for edge in subgraph.relationships:
        for entity_id in (edge.source_id, edge.target_id):
            if entity_id in entities:
                continue
            found = await context.graph.get_entity(entity_id)
            if found is not None:
                entities[entity_id] = found
    summaries = [_edge_summary(edge, entities) for edge in subgraph.relationships]
    counted = [s for s in summaries if s.population_size is not None]
    return ClusterStage(
        entity_count=len(subgraph.entities),
        edge_count=len(subgraph.relationships),
        selective_edges=tuple(s for s in counted if s.is_informative),
        worthless_edges=tuple(s for s in counted if not s.is_informative),
        direct_observations=len(summaries) - len(counted),
        the_control=_THE_CONTROL,
        bystanders=bystanders,
        bystander_pivots=bystander_pivots,
    )


# --------------------------------------------------------------------------------------
# Stage 4 — STANDING
# --------------------------------------------------------------------------------------


async def _standing(context: _Context, *, assessed_at: datetime) -> StandingStage:
    """Whose each node is, derived from the graph rather than written onto it."""
    interesting: tuple[tuple[EntityType, str], ...] = (
        (EntityType.IP_ADDRESS, SEED_IP),
        (EntityType.IP_ADDRESS, SECOND_C2_IP),
        (EntityType.IP_ADDRESS, SHARED_HOST_IP),
        (EntityType.VICTIM, VICTIM),
        (EntityType.HOSTING_PROVIDER, SHARED_HOST_OPERATOR),
    )
    records: list[StandingRecord] = []
    refused: list[str] = []
    stored_claims = context.claims.claims()

    for entity_type, entity_key in interesting:
        entity = await context.graph.find_entity(entity_type, entity_key)
        if entity is None:
            continue
        assessment: RoleAssessment = await assess_entity_standing(
            context.graph, entity, claims=stored_claims, assessed_at=assessed_at
        )
        records.append(
            StandingRecord(
                entity_key=entity.natural_key,
                entity_type=entity.entity_type,
                role=assessment.role,
                projected_probability=assessment.opinion.projected_probability,
                facets=tuple(facet.facet for facet in assessment.facets),
                reasoning=assessment.reasoning,
            )
        )
        if assessment.role in {
            InfrastructureRole.SHARED_INFRASTRUCTURE,
            InfrastructureRole.VICTIM_INFRASTRUCTURE,
            InfrastructureRole.COMPROMISED_LEGITIMATE,
            InfrastructureRole.ABUSED_LEGITIMATE_SERVICE,
        }:
            refused.append(
                f"{entity.natural_key} ({entity.entity_type.value}): {assessment.role.value}"
            )

    return StandingStage(records=tuple(records), refused_to_call_adversary=tuple(refused))


# --------------------------------------------------------------------------------------
# Stage 5 — ATTRIBUTE
# --------------------------------------------------------------------------------------

_FRAMED_ARGUMENT: Final = (
    f"It rests on one string in a file the adversary controls end to end. Cost to plant: "
    f"minutes. Nothing outside the sample associates {FRAMED_ORGANIZATION} with this "
    "operation, and the group is real and unrelated, which is what makes naming it "
    "attractive. Retained rather than deleted: an alternative that was considered and "
    "rejected must stay readable, and this is the one an opposing expert will raise."
)


def _evidence_for(
    context: _Context,
    claim: Claim,
    label: str,
    *,
    direction: EvidenceDirection | None = None,
) -> AttributionEvidence:
    """Package one collected claim as attribution evidence.

    The opinion is the confidence the graph gave the edge built from this claim, so selectivity
    and method reliability reach the attribution plane already applied. The source is the one
    the claim was collected from, so trust discounting grades what it is actually fusing.
    """
    opinion = context.claim_confidence.get(claim.claim_id)
    if opinion is None:
        raise IronTideError(f"claim {claim.claim_id} produced no edge and cannot be graded")
    source = context.claim_sources.get(claim.claim_id)
    if source is None:
        raise IronTideError(f"claim {claim.claim_id} has no recorded source of record")
    return AttributionEvidence(
        claim=claim,
        source=source,
        opinion=opinion,
        direction=direction or EvidenceDirection.SUPPORTS,
        label=label,
    )


def _attribute(
    context: _Context,
    *,
    infrastructure: dict[str, Claim],
    campaign: dict[str, Claim],
    persona: dict[str, Claim],
    organization: dict[str, Claim],
    identity_claim: Claim,
    assessed_at: datetime,
) -> AttributionStage:
    request = AttributionRequest(
        subject=SCENARIO_SUBJECT,
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.INFRASTRUCTURE,
                hypothesis=(
                    f"{SEED_IP}, {SECOND_C2_IP}, the five domains and the shared certificate "
                    "were under one operator's control."
                ),
                evidence=(
                    _evidence_for(
                        context, infrastructure["reverse"], "3-name reverse resolution on the seed"
                    ),
                    _evidence_for(
                        context, infrastructure["certificate"], "one private key on 3 addresses"
                    ),
                    _evidence_for(
                        context,
                        infrastructure["registration"],
                        f"{REGISTRATION_WINDOW_HOURS}-hour registration window",
                    ),
                    _evidence_for(
                        context,
                        infrastructure["shared"],
                        f"{SHARED_HOST_POPULATION:,}-name shared-hosting co-location",
                    ),
                ),
                missing_evidence=(
                    MissingEvidence(
                        description=(
                            "The registrar's unredacted registrant records for the five domains, "
                            "and the two hosting providers' customer records for the leases."
                        ),
                        would_settle=(
                            "Whether one account paid for all of it, which is the fact the "
                            "registration window and the tenant counts are proxies for."
                        ),
                        availability=EvidenceAvailability.REQUIRES_LEGAL_AUTHORITY,
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.CAMPAIGN,
                hypothesis=(
                    "The beaconing at NORTHWIND and the whole observed infrastructure belong "
                    "to one operation."
                ),
                evidence=(
                    _evidence_for(
                        context,
                        campaign["own_sensor_c2"],
                        "our own resolver: the implant queried the cluster names",
                    ),
                    _evidence_for(
                        context,
                        campaign["config_c2"],
                        "extracted configuration: the same names, from a commercial feed",
                    ),
                    _evidence_for(
                        context, campaign["family"], f"the sample is a {MALWARE_FAMILY} loader"
                    ),
                    _evidence_for(
                        context, campaign["certificate"], "one private key across the cluster"
                    ),
                ),
                missing_evidence=(
                    MissingEvidence(
                        description=("Telemetry from a second victim reached by the same cluster."),
                        would_settle=(
                            "Whether this is one operation with many targets or one intrusion "
                            "that happens to share a toolchain."
                        ),
                        availability=EvidenceAvailability.COLLECTABLE,
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.PERSONA,
                hypothesis=(
                    f"{PERSONA} operates the IRON TIDE infrastructure rather than merely "
                    "advertising access to it."
                ),
                evidence=(
                    _evidence_for(
                        context,
                        persona["panel_certificate"],
                        "the advertised panel presents the cluster's private key",
                    ),
                    _evidence_for(
                        context, persona["panel_control"], f"{PERSONA} advertises the panel"
                    ),
                    _evidence_for(
                        context,
                        persona["listing"],
                        "an access listing matching the victim's sector and week",
                    ),
                    # Offered in support and expected to be turned around: a handle in a
                    # config file and a handle in a forum profile are one cheap string twice.
                    _evidence_for(
                        context,
                        persona["handle"],
                        f"{MESSAGING_ACCOUNT} on both sides",
                    ),
                ),
                missing_evidence=(
                    MissingEvidence(
                        description=(
                            "A challenge signed by the panel's key at a nonce we chose, or the "
                            "hosting provider's confirmation of who leases the two addresses."
                        ),
                        would_settle=(
                            "Whether the vendor holds the key or was handed a panel by whoever "
                            "does."
                        ),
                        availability=EvidenceAvailability.REQUIRES_LEGAL_AUTHORITY,
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.ORGANIZATION,
                hypothesis=(
                    "A coherent organized operation, rather than a lone opportunist, stands "
                    "behind Operation IRON TIDE."
                ),
                evidence=(
                    _evidence_for(
                        context, organization["listing"], "an escrowed access-broker operation"
                    ),
                    _evidence_for(
                        context,
                        organization["false_flag"],
                        f"build tag naming {FRAMED_ORGANIZATION}",
                    ),
                ),
                alternatives=(
                    AlternativeHypothesis(
                        name=f"{FRAMED_ORGANIZATION} is responsible",
                        description=(
                            f"The recovered loader carries a build tag naming "
                            f"{FRAMED_ORGANIZATION}."
                        ),
                        opinion=Opinion.vacuous(base_rate=0.05),
                        band=band_of(Opinion.vacuous(base_rate=0.05)),
                        supporting_claims=(organization["false_flag"].claim_id,),
                        contradicting_claims=(),
                        argument_against=_FRAMED_ARGUMENT,
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
                dimension=AttributionDimension.HUMAN_IDENTITY,
                hypothesis=(
                    f"The operator behind {PERSONA} is the natural person named in a single "
                    f"anonymous post on SaltPier: {NAMED_PERSON}."
                ),
                evidence=(
                    _evidence_for(
                        context, identity_claim, "single anonymous post asserting a name"
                    ),
                ),
            ),
        ),
    )

    engine = AttributionEngine(assessed_by=context.actor)
    result = engine.assess(request, assessed_at=assessed_at)
    human = result.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    # Through `summarize_fact`, never the raw key. A fact key is a JSON object carrying the
    # subject, the predicate and every qualifier — including, on another dimension, a persona
    # handle. This repository has already had that structure leak into an external product
    # twice (see the function's docstring); a third surface rendering it verbatim would be the
    # same defect a third time.
    removed: list[str] = []
    for assessment in result.assessments:
        if assessment.removed_fact:
            removed.append(
                f"{assessment.dimension.value}: {assessment.margin_outcome} — dropped "
                f"{summarize_fact(assessment.removed_fact)}"
            )
        else:
            removed.append(f"{assessment.dimension.value}: {assessment.margin_outcome}")

    return AttributionStage(
        result=result,
        false_flag_claim_id=organization["false_flag"].claim_id,
        framed_organization=FRAMED_ORGANIZATION,
        human_identity_band=human.band,
        weak_markers_not_scored=(
            f"{organization['build_metadata'].claim_id}: the loader's build identifier and a "
            "single non-default language resource. Recorded in the graph, offered to no "
            "dimension. Language is not nationality, nationality is not identity, and neither "
            "is an organization.",
            f"{MALWARE_SIMILARITY_NOTE}",
        ),
        what_the_margin_removed=tuple(removed),
    )


# --------------------------------------------------------------------------------------
# Stage 6 — EVIDENCE
# --------------------------------------------------------------------------------------

_CANNOT_DEFEND: Final = (
    "Nothing here is defensible against the vault operator. The hash chain is one we compute "
    "ourselves, so anyone who can rewrite the store can recompute it.",
    "Every artifact is synthetic and carries AdmissibilityDefect.SIMULATED_COLLECTION. This is "
    "a demonstration of provenance machinery, not a case.",
    "No external anchor is recorded by this run at all, so the chain's only witness is itself.",
)


async def _evidence(context: _Context) -> EvidenceStage:
    report: FileSystemVaultIntegrityReport = await context.vault.verify_integrity()
    chain = await context.audit.verify()
    sealed = await context.vault.list_evidence()
    return EvidenceStage(
        sealed_objects=len(sealed),
        vault_intact=report.is_intact,
        audit_events=await context.audit.entry_count(),
        audit_chain_intact=chain.intact,
        cannot_defend=_CANNOT_DEFEND,
    )


# --------------------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------------------


async def _infrastructure_claims(
    context: _Context, collected: dict[str, tuple[Claim, ...]]
) -> dict[str, Claim]:
    """The four infrastructure claims, recovered from the graph the pursuit actually built.

    Read back out of the edges rather than remembered from the pivot that produced them: the
    attribution must grade the claim the graph holds, not a second derivation of the same
    number.
    """
    seed = await context.graph.find_entity(EntityType.IP_ADDRESS, SEED_IP)
    if seed is None:
        raise IronTideError("the seed address is not in the graph")
    subgraph = await context.graph.neighbourhood(
        GraphQuery(
            entity_id=seed.entity_id,
            max_depth=8,
            min_confidence=0.0,
            exclude_shared_infrastructure=False,
        )
    )
    found: dict[str, Claim] = {}
    for edge in subgraph.relationships:
        selectivity = edge.selectivity
        if selectivity is None or not edge.supporting_claims:
            continue
        claim = context.claims.get_version(edge.supporting_claims[0])
        if claim is None:
            continue
        attribute = selectivity.attribute
        if attribute == SEED_IP and "reverse" not in found:
            found["reverse"] = claim
        elif attribute == CERT_FINGERPRINT and "certificate" not in found:
            found["certificate"] = claim
        elif attribute.startswith("registration through") and "registration" not in found:
            found["registration"] = claim
        elif attribute == SHARED_HOST_IP and "shared" not in found:
            found["shared"] = claim

    missing = sorted({"reverse", "certificate", "registration", "shared"} - set(found))
    if missing:
        raise IronTideError(
            f"the cluster does not carry the infrastructure claims the attribution "
            f"assesses: {missing}"
        )
    _ = collected
    return found


async def run_iron_tide_async(
    *,
    workspace: Path | None = None,
    as_of: datetime = SCENARIO_PRESENT,
) -> IronTideResult:
    """Run the whole operation once and return every stage's output."""
    root = Path(workspace) if workspace is not None else Path(tempfile.mkdtemp(prefix="nemesis-"))
    root.mkdir(parents=True, exist_ok=True)

    connectors = iron_tide_connectors(as_of=as_of)
    context = _Context(
        graph=await JournalBackedGraphStore.open(root / "graph"),
        claims=await JournalBackedClaimStore.open(root / "graph"),
        vault=FileSystemEvidenceVault(root / "vault"),
        audit=AppendOnlyAuditTrail(root / "audit.jsonl"),
        authorization=SqliteAuthorizationStore(root / "authorization.sqlite3"),
        actor=new_id(IdPrefix.ACTOR),
        sources={
            connector.capabilities.name: connector.capabilities.source for connector in connectors
        },
    )

    detect, seed = await _detect(context)
    pursue, collected = await _pursue(context, seed, connectors)
    bystanders, bystander_pivots = _bystanders(pursue)
    cluster = await _cluster(context, bystanders=bystanders, bystander_pivots=bystander_pivots)
    standing = await _standing(context, assessed_at=as_of)

    infrastructure = await _infrastructure_claims(context, collected)

    own_claims = collected[f"{PivotType.OWN_TELEMETRY.value}:{SEED_IP}"]
    lookup_claims = collected[f"{PivotType.MALWARE_LOOKUP.value}:{IMPLANT_SHA256}"]
    config_claims = collected[f"{PivotType.C2_EXTRACTION.value}:{IMPLANT_SHA256}"]
    persona_claims = collected[f"{PivotType.PERSONA_ACTIVITY.value}:{PERSONA.lower()}"]
    listing_claims = collected[f"{PivotType.MARKETPLACE_LISTING.value}:{PERSONA.lower()}"]
    forum_claims = collected[f"{PivotType.DARK_WEB_SEARCH.value}:{PERSONA.lower()}"]

    first_domain = CLUSTER_DOMAINS[0]
    campaign = {
        "own_sensor_c2": _find_claim(
            own_claims, predicate=RelationType.COMMUNICATES_WITH.value, contains=first_domain
        ),
        "config_c2": _find_claim(
            config_claims, predicate=RelationType.COMMUNICATES_WITH.value, contains=first_domain
        ),
        "family": _find_claim(lookup_claims, predicate=RelationType.BELONGS_TO_FAMILY.value),
        "certificate": infrastructure["certificate"],
    }
    persona = {
        "panel_certificate": _find_claim(
            persona_claims, predicate=RelationType.PRESENTS_CERTIFICATE.value
        ),
        "panel_control": _find_claim(persona_claims, predicate=RelationType.CONTROLS.value),
        "listing": _find_claim(listing_claims, predicate=RelationType.SELLS_ON.value),
        "handle": _find_claim(
            persona_claims,
            predicate=RelationType.COMMUNICATES_WITH.value,
            contains="messaging_account",
        ),
    }
    organization = {
        "listing": persona["listing"],
        "false_flag": _find_claim(
            lookup_claims,
            predicate=RelationType.CO_OCCURS_WITH.value,
            contains=FRAMED_ORGANIZATION,
        ),
        "build_metadata": _find_claim(
            lookup_claims,
            predicate=RelationType.CO_OCCURS_WITH.value,
            contains="source_code_artifact",
        ),
    }
    identity_claim = _find_claim(
        forum_claims,
        predicate=RelationType.CO_OCCURS_WITH.value,
        contains="human_identity_lead",
    )

    attribute = _attribute(
        context,
        infrastructure=infrastructure,
        campaign=campaign,
        persona=persona,
        organization=organization,
        identity_claim=identity_claim,
        assessed_at=as_of,
    )
    evidence = await _evidence(context)

    return IronTideResult(
        detect=detect,
        pursue=pursue,
        cluster=cluster,
        standing=standing,
        attribute=attribute,
        evidence=evidence,
        stores=IronTideStores(
            workspace=root,
            graph=context.graph,
            claims=context.claims,
            vault=context.vault,
            audit=context.audit,
            authorization=context.authorization,
        ),
    )


def run_iron_tide(
    *,
    workspace: Path | None = None,
    as_of: datetime = SCENARIO_PRESENT,
) -> IronTideResult:
    """Synchronous entry point. Drives :func:`run_iron_tide_async` to completion."""
    return asyncio.run(run_iron_tide_async(workspace=workspace, as_of=as_of))


__all__ = [
    "ACTOR_GAP",
    "STAGE_NAMES",
    "AttributionStage",
    "ClusterStage",
    "DetectionStage",
    "EdgeSummary",
    "EvidenceStage",
    "IronTideError",
    "IronTideResult",
    "IronTideStores",
    "PivotRecord",
    "PursuitStage",
    "StandingRecord",
    "StandingStage",
    "band_range",
    "run_iron_tide",
    "run_iron_tide_async",
]
