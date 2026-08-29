"""Plane 2 — the Pursuit Engine, its policy, and what it refuses to build.

The engine is the autonomous part of NEMESIS, so the properties worth testing are the ones
that keep an autonomous thing accountable and cheap to be wrong about:

- **Reproducibility.** Invariant 11 requires that agent actions be replayable. A policy that
  proposed a different pivot order on a second run would make an investigation's conclusions
  indefensible — nobody could reconstruct what the engine was choosing between.
- **Recorded abandonment.** An investigation that quietly stops exploring a direction is
  indistinguishable from one that explored it and found nothing.
- **Refusal to build a meaningless cluster.** Branching on shared infrastructure reaches most
  of the internet in two hops and returns something that looks like a finding.
- **Refusal to guess.** A claim whose predicate is unknown is reported, never coerced into a
  generic edge. A generic edge joins the cluster and nobody can later say what it meant.

The ports are faked here on purpose: the pursuit plane must be exercisable with no collection
plane at all, which is also the arrangement in which "no connector can answer this" has to be
recorded rather than swallowed.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from nemesis.collect.quarantine import StructuralAnalyser
from nemesis.core.claims import Claim, ClaimKind, DerivationKind, Statement
from nemesis.core.confidence import ConfidenceBand, band_of
from nemesis.core.entities import Entity, EntityType
from nemesis.core.evidence import ArtifactKind, EvidenceObject
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
)
from nemesis.core.relationships import (
    Explanation,
    PivotMethod,
    Relationship,
    RelationType,
)
from nemesis.core.temporal import TemporalExtent
from nemesis.ports.collection import (
    ConnectorCapabilities,
    IntelligenceConnector,
    PivotRequest,
    PivotResult,
    PivotType,
)
from nemesis.ports.storage import (
    AuditEvent,
    GraphQuery,
    Subgraph,
    VaultIntegrityReport,
)
from nemesis.pursuit.engine import ConnectorRegistry, PursuitEngine
from nemesis.pursuit.investigation import (
    BranchState,
    ExecutedPivot,
    Hypothesis,
    HypothesisState,
    IncidentSeed,
    InvestigationBranch,
    PivotCandidate,
)
from nemesis.pursuit.materialize import materialize, parse_reference
from nemesis.pursuit.policy import (
    MAX_CONSECUTIVE_UNINFORMATIVE,
    RuleBasedPursuitPolicy,
)

NOW = datetime(2026, 3, 2, 8, 14, tzinfo=UTC)
EXTENT = TemporalExtent.between(NOW - timedelta(days=10), NOW)

SEED_DOMAIN = "acme-invoice-portal.example"
HOST_IP = "198.51.100.23"
CDN_IP = "192.0.2.10"
HOST_ASN = "AS64512"

ANALYST = new_id(IdPrefix.ACTOR)


# --- Builders -----------------------------------------------------------------


def _evidence(payload: bytes, *, is_simulated: bool = True) -> EvidenceObject:
    return EvidenceObject.seal(
        artifact=payload,
        artifact_kind=ArtifactKind.DNS_RECORD,
        provenance=ProvenanceChain(
            collection_id=new_id(IdPrefix.COLLECTION),
            source=SourceDescriptor(
                source_class=SourceClass.INTERNET_SCAN,
                identifier="passive-dns-fixture",
            ),
            method=CollectionMethod(
                collector_name="passive-dns-fixture",
                collector_version="0.1.0",
                is_simulated=is_simulated,
            ),
            collected_at=NOW,
        ),
        observed_extent=EXTENT,
        vault_locator="memory://fixture",
    )


def _claim(
    subject: str,
    predicate: str,
    obj: str,
    *,
    qualifiers: dict[str, str] | None = None,
    evidence: tuple[str, ...] = (),
    kind: ClaimKind = ClaimKind.CORRELATION,
) -> Claim:
    return Claim.create(
        kind=kind,
        statement=Statement(
            subject=subject,
            predicate=predicate,
            obj=obj,
            qualifiers=qualifiers or {},
            natural_language=f"{subject} {predicate} {obj}",
        ),
        derivation=DerivationKind.DIRECT_COLLECTION,
        asserted_by=ANALYST,
        asserted_at=NOW,
        valid_extent=EXTENT,
        supported_by_evidence=evidence,
    )


def _entity(entity_type: EntityType, observed_form: str) -> Entity:
    return Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=observed_form,
        extent=EXTENT,
        is_synthetic=True,
    )


def _branch(**overrides: object) -> InvestigationBranch:
    defaults: dict[str, object] = {
        "branch_id": "B0",
        "focus_entity_id": new_id(IdPrefix.ENTITY),
        "focus_entity_key": SEED_DOMAIN,
        "hypothesis_id": "H1",
    }
    return InvestigationBranch(**(defaults | overrides))


def _executed(*, succeeded: bool = True, claims: int = 0) -> ExecutedPivot:
    return ExecutedPivot(
        candidate=PivotCandidate(
            pivot_type=PivotType.RESOLUTION_HISTORY,
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type=EntityType.DOMAIN,
            entity_key=SEED_DOMAIN,
            expected_information_gain=0.8,
            estimated_cost=1.0,
            rationale="Where the domain pointed, and when.",
        ),
        executed_at=NOW,
        connector="passive-dns-fixture",
        succeeded=succeeded,
        claims_produced=tuple(
            _claim(f"domain:d{i}.example", "resolves_to", f"ip_address:198.51.100.{i}").claim_id
            for i in range(claims)
        ),
    )


# --- Fakes for the ports ------------------------------------------------------


class FakeGraph:
    """In-memory graph that merges on (type, natural key), as the port requires.

    Carries ``erase_entity`` because the port grew it when retention was applied. A double
    that lags the port is a double for a shape the production code no longer has, and the
    type checker is the only thing that notices.
    """

    def __init__(self, log: list[str] | None = None) -> None:
        self._by_id: dict[str, Entity] = {}
        self._by_key: dict[tuple[EntityType, str], str] = {}
        self.relationships: list[Relationship] = []
        self._log = log if log is not None else []

    async def upsert_entity(self, entity: Entity) -> Entity:
        existing = self._by_key.get(entity.identity())
        if existing is not None:
            return self._by_id[existing]
        self._by_id[entity.entity_id] = entity
        self._by_key[entity.identity()] = entity.entity_id
        self._log.append(f"entity:{entity.entity_type.value}:{entity.natural_key}")
        return entity

    async def get_entity(self, entity_id: str) -> Entity | None:
        return self._by_id.get(entity_id)

    async def find_entity(self, entity_type: EntityType, natural_key: str) -> Entity | None:
        entity_id = self._by_key.get((entity_type, natural_key))
        return self._by_id.get(entity_id) if entity_id else None

    async def add_relationship(self, relationship: Relationship) -> Relationship:
        self.relationships.append(relationship)
        return relationship

    async def neighbourhood(self, query: GraphQuery) -> Subgraph:
        """Depth-1 only: the edges touching one node.

        This used to raise "the engine does not traverse the graph", which was true when it was
        written. The engine now reassesses whose each touched node is after a pivot, and whose a
        node is, is answered by the edges on it — so it reads them. Kept deliberately dumb: a
        richer fake would start to disagree with InMemoryGraphStore, and the fake is here to
        record what the engine asked for, not to be a second graph implementation.
        """
        touching = tuple(
            edge
            for edge in self.relationships
            if query.entity_id in {edge.source_id, edge.target_id}
        )
        return Subgraph(entities=(), relationships=touching, explanations=())

    async def explain_connection(
        self, source_id: str, target_id: str, *, max_depth: int = 4
    ) -> tuple[Explanation, ...]:
        raise NotImplementedError("the engine does not explain paths")

    async def entity_count(self) -> int:
        return len(self._by_id)

    async def erase_entity(self, entity_id: str) -> bool:
        """Mirrors the port: drop the node and every edge touching it.

        Leaving the edges would leave dangling references to a node the platform has
        undertaken to forget, and a traversal would still show its shape.
        """
        if self._by_id.pop(entity_id, None) is None:
            return False
        self._by_key = {k: v for k, v in self._by_key.items() if v != entity_id}
        self.relationships = [
            r for r in self.relationships if entity_id not in (r.source_id, r.target_id)
        ]
        return True


class FakeClaimStore:
    def __init__(self, log: list[str] | None = None) -> None:
        self.claims: dict[str, Claim] = {}
        self._log = log if log is not None else []

    async def record(self, claim: Claim) -> Claim:
        self.claims.setdefault(claim.claim_id, claim)
        self._log.append(f"claim:{claim.claim_id}")
        return self.claims[claim.claim_id]

    async def get(self, claim_id: str) -> Claim | None:
        return self.claims.get(claim_id)

    async def supersede(self, claim_id: str, replacement: Claim, *, reason: str) -> Claim:
        raise NotImplementedError

    async def supporting(self, claim_id: str) -> tuple[Claim, ...]:
        return ()

    async def derivation_chain(self, claim_id: str) -> tuple[Claim, ...]:
        return ()

    async def contradicting(self, claim_id: str) -> tuple[Claim, ...]:
        return ()


class FakeVault:
    def __init__(self, log: list[str] | None = None) -> None:
        self.sealed: dict[str, bytes] = {}
        self._objects: dict[str, EvidenceObject] = {}
        self._log = log if log is not None else []

    async def seal(self, evidence: EvidenceObject, artifact: bytes) -> EvidenceObject:
        if not evidence.verify_artifact(artifact):
            raise ValueError("artifact does not hash to the evidence object's content hash")
        self.sealed[evidence.evidence_id] = artifact
        self._objects[evidence.evidence_id] = evidence
        self._log.append(f"seal:{evidence.evidence_id}")
        return evidence

    async def get(self, evidence_id: str) -> EvidenceObject | None:
        return self._objects.get(evidence_id)

    async def retrieve_artifact(self, evidence_id: str, *, accessed_by: str, reason: str) -> bytes:
        return self.sealed[evidence_id]

    async def verify_integrity(self) -> VaultIntegrityReport:
        return VaultIntegrityReport(
            checked_at=NOW,
            objects_checked=len(self.sealed),
            hash_chain_intact=True,
            artifacts_verified=len(self.sealed),
        )

    async def head(self) -> str:
        return "sha256:" + "0" * 64


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def record(self, event: AuditEvent) -> AuditEvent:
        self.events.append(event)
        return event

    async def query(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> Sequence[AuditEvent]:
        return [event for event in self.events if action is None or event.action == action][:limit]

    async def verify_chain(self) -> bool:
        return True


class FakeConnector:
    """A connector that answers exactly the pivots it declares, from a fixed script."""

    def __init__(
        self,
        *,
        name: str,
        pivots: frozenset[PivotType],
        entity_types: frozenset[EntityType],
        responder: Callable[[PivotRequest], PivotResult],
        cost: float = 1.0,
        is_simulated: bool = True,
    ) -> None:
        self._responder = responder
        self.requests: list[PivotRequest] = []
        self._capabilities = ConnectorCapabilities(
            name=name,
            version="0.1.0",
            source=SourceDescriptor(source_class=SourceClass.INTERNET_SCAN, identifier=name),
            supported_pivots=pivots,
            supported_entity_types=entity_types,
            is_simulated=is_simulated,
            cost_per_call=cost,
        )

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return self._capabilities

    async def pivot(self, request: PivotRequest) -> PivotResult:
        self.requests.append(request)
        return self._responder(request)

    async def health(self) -> bool:
        return True


def _resolution_result(request: PivotRequest, *, is_simulated: bool = True) -> PivotResult:
    """One pivot that discovers a host and the network announcing it.

    The ASN is the shared-infrastructure control: it is a real, recordable fact about the
    host and must not become a line of enquiry of its own.
    """
    artifact = b'{"answer": "198.51.100.23", "first_seen": "2026-02-20"}'
    evidence = _evidence(artifact, is_simulated=is_simulated)
    return PivotResult(
        request=request,
        connector_name="passive-dns-fixture",
        observations=(
            _claim(
                f"domain:{SEED_DOMAIN}",
                RelationType.RESOLVES_TO.value,
                f"ip_address:{HOST_IP}",
                evidence=(evidence.evidence_id,),
                kind=ClaimKind.OBSERVATION,
            ),
            _claim(
                f"ip_address:{HOST_IP}",
                RelationType.ANNOUNCED_BY.value,
                f"asn:{HOST_ASN}",
                evidence=(evidence.evidence_id,),
                kind=ClaimKind.OBSERVATION,
            ),
        ),
        evidence=(evidence,),
        artifacts={evidence.evidence_id: artifact},
    )


def _engine(
    *,
    connectors: Sequence[IntelligenceConnector] = (),
    graph: FakeGraph | None = None,
    claims: FakeClaimStore | None = None,
    vault: FakeVault | None = None,
    audit: FakeAudit | None = None,
) -> PursuitEngine:
    return PursuitEngine(
        graph=graph or FakeGraph(),
        claims=claims or FakeClaimStore(),
        vault=vault or FakeVault(),
        audit=audit or FakeAudit(),
        connectors=ConnectorRegistry(connectors),
        # Named, because the engine's default confines by material and these fixtures declare
        # themselves real. `ConfinedWhenReal` would then require the kernel — correctly, and
        # fail-closed where it is absent, which on the Linux CI would hold every artifact and
        # make these tests assert the confinement rather than the pursuit logic they are about.
        # A deployment gets the default; this suite says what it wants.
        analyser=StructuralAnalyser(),
        actor=ANALYST,
        clock=lambda: NOW,
    )


def _seed() -> IncidentSeed:
    return IncidentSeed(
        entity_type=EntityType.DOMAIN,
        entity_key=SEED_DOMAIN,
        observed_at=NOW,
        detected_by="acme-email-gateway",
    )


# --- The policy is deterministic ----------------------------------------------


def test_the_policy_proposes_the_same_order_every_time() -> None:
    """Invariant 11: an investigation whose branching cannot be reproduced is one whose
    conclusions cannot be defended. Asserted three ways — the same policy asked twice, a
    freshly built policy asked about an equal state, and the concrete order pinned — so a
    regression that reorders pivots cannot pass by accident."""
    entity = _entity(EntityType.DOMAIN, SEED_DOMAIN)
    branch = _branch(focus_entity_id=entity.entity_id)
    hypotheses = (
        Hypothesis(
            hypothesis_id="H1",
            statement=f"{SEED_DOMAIN} is attacker infrastructure.",
            would_be_confirmed_by="Registration inside the campaign window.",
            would_be_refuted_by="A legitimate registrant predating the campaign.",
        ),
    )

    policy = RuleBasedPursuitPolicy()
    first = policy.propose(branch, entity, hypotheses)
    second = policy.propose(branch, entity, hypotheses)
    third = RuleBasedPursuitPolicy().propose(branch, entity, hypotheses)

    assert first == second
    assert first == third
    assert [candidate.pivot_type for candidate in first] == [
        PivotType.RESOLUTION_HISTORY,
        PivotType.CERTIFICATE_HISTORY,
        PivotType.REGISTRATION_RECORD,
        PivotType.SUBDOMAIN_DISCOVERY,
    ]


def test_connector_cost_reorders_the_queue_deterministically() -> None:
    """Ranking is value per cost, so a cheap pivot can overtake a more informative one —
    and the resulting order must still be reproducible from the declared costs alone."""
    entity = _entity(EntityType.DOMAIN, SEED_DOMAIN)
    branch = _branch(focus_entity_id=entity.entity_id)
    policy = RuleBasedPursuitPolicy(
        connector_costs={PivotType.RESOLUTION_HISTORY: 8.0, PivotType.REGISTRATION_RECORD: 0.5}
    )

    order = [candidate.pivot_type for candidate in policy.propose(branch, entity, ())]
    assert order[0] is PivotType.REGISTRATION_RECORD
    assert order[-1] is PivotType.RESOLUTION_HISTORY
    assert order == [candidate.pivot_type for candidate in policy.propose(branch, entity, ())]


def test_a_pivot_already_run_is_not_proposed_again() -> None:
    entity = _entity(EntityType.DOMAIN, SEED_DOMAIN)
    branch = _branch(focus_entity_id=entity.entity_id, executed=(_executed(claims=1),))

    proposed = {c.pivot_type for c in RuleBasedPursuitPolicy().propose(branch, entity, ())}
    assert PivotType.RESOLUTION_HISTORY not in proposed


def test_a_pivot_addresses_the_first_unsettled_hypothesis() -> None:
    """A pivot that answers nothing anyone is asking is spend without a question."""
    entity = _entity(EntityType.DOMAIN, SEED_DOMAIN)
    branch = _branch(focus_entity_id=entity.entity_id)
    settled = Hypothesis(
        hypothesis_id="H1",
        statement="Already answered.",
        state=HypothesisState.SUPPORTED,
        would_be_confirmed_by="x",
        would_be_refuted_by="y",
    )
    open_one = Hypothesis(
        hypothesis_id="H2",
        statement="Still open.",
        would_be_confirmed_by="x",
        would_be_refuted_by="y",
    )

    candidates = RuleBasedPursuitPolicy().propose(branch, entity, (settled, open_one))
    assert {candidate.addresses_hypothesis for candidate in candidates} == {"H2"}


# --- Abandonment is a recorded decision ---------------------------------------


def test_a_branch_cannot_be_abandoned_without_a_stated_reason() -> None:
    """An unexplained abandonment is indistinguishable from an unexplored line."""
    with pytest.raises(ValidationError, match="without a stated reason"):
        _branch(state=BranchState.ABANDONED_UNINFORMATIVE)

    with pytest.raises(ValidationError, match="without a stated reason"):
        _branch(state=BranchState.ABANDONED_BUDGET)

    # A completed line needs no such reason: exhausting the worthwhile pivots is not a
    # decision to stop looking, it is having looked.
    assert _branch(state=BranchState.EXHAUSTED).abandonment_reason is None


def test_a_branch_is_abandoned_after_the_uninformative_ceiling() -> None:
    """Successful pivots that moved no hypothesis. One below the ceiling the branch stays
    open, at the ceiling it closes with the count in its reason."""
    assert MAX_CONSECUTIVE_UNINFORMATIVE == 3
    policy = RuleBasedPursuitPolicy()

    below = _branch(executed=tuple(_executed() for _ in range(MAX_CONSECUTIVE_UNINFORMATIVE - 1)))
    assert below.consecutive_uninformative == 2
    assert policy.should_abandon(below) is None

    at_ceiling = _branch(executed=tuple(_executed() for _ in range(MAX_CONSECUTIVE_UNINFORMATIVE)))
    verdict = policy.should_abandon(at_ceiling)
    assert verdict is not None
    state, reason = verdict
    assert state is BranchState.ABANDONED_UNINFORMATIVE
    assert "3 consecutive pivots" in reason


def test_a_productive_pivot_resets_the_uninformative_run() -> None:
    """Otherwise a branch that keeps paying off would still be abandoned on its history."""
    branch = _branch(
        executed=(
            _executed(),
            _executed(),
            _executed(claims=1),
            _executed(),
        )
    )
    assert branch.consecutive_uninformative == 1
    assert RuleBasedPursuitPolicy().should_abandon(branch) is None


def test_an_exhausted_budget_closes_a_branch_with_its_reason() -> None:
    branch = _branch(budget_allocated=4.0, budget_spent=4.0)
    verdict = RuleBasedPursuitPolicy().should_abandon(branch)
    assert verdict is not None
    assert verdict[0] is BranchState.ABANDONED_BUDGET
    assert "budget" in verdict[1]


def test_an_already_closed_branch_is_not_re_abandoned() -> None:
    closed = _branch(state=BranchState.EXHAUSTED)
    assert RuleBasedPursuitPolicy().should_abandon(closed) is None


# --- Shared infrastructure is not a line of enquiry ---------------------------


def test_the_policy_never_branches_on_shared_infrastructure() -> None:
    """Branching on a CDN address, an ASN or a registrar expands into every unrelated party
    behind it. The resulting cluster is large, fast to compute and entirely meaningless."""
    policy = RuleBasedPursuitPolicy()

    assert policy.should_branch_on(_entity(EntityType.DOMAIN, SEED_DOMAIN), 1)
    assert policy.should_branch_on(_entity(EntityType.IP_ADDRESS, HOST_IP), 1)

    assert not policy.should_branch_on(_entity(EntityType.ASN, HOST_ASN), 1)
    assert not policy.should_branch_on(_entity(EntityType.REGISTRAR, "BulletproofReg"), 1)
    assert not policy.should_branch_on(_entity(EntityType.NETBLOCK, "198.51.100.0/24"), 1)


def test_branching_stops_at_the_depth_limit() -> None:
    """Links this far from the seed are rarely defensible, however cheap they are to draw."""
    policy = RuleBasedPursuitPolicy(max_depth=2)
    domain = _entity(EntityType.DOMAIN, SEED_DOMAIN)

    assert policy.should_branch_on(domain, 2)
    assert not policy.should_branch_on(domain, 3)


def test_a_shared_infrastructure_pivot_is_discounted_rather_than_forbidden() -> None:
    """Sometimes the CDN address really is the answer, so the pivot survives — with its
    expected value collapsed, so it runs only when nothing better is left."""
    asn = _entity(EntityType.ASN, HOST_ASN)
    candidates = RuleBasedPursuitPolicy().propose(_branch(focus_entity_id=asn.entity_id), asn, ())

    assert len(candidates) == 1
    assert candidates[0].would_pivot_through_shared_infrastructure
    assert candidates[0].expected_information_gain < 0.05
    assert "shared by unrelated parties" in candidates[0].rationale


# --- Materialization: what the connector said becomes graph structure ---------


def test_an_unknown_predicate_is_skipped_and_reported() -> None:
    """A generic catch-all edge is worse than a missing one: it looks like a finding, joins
    the cluster, and nobody can later say what it was supposed to mean."""
    claim = _claim(f"domain:{SEED_DOMAIN}", "definitely_the_same_guy", f"ip_address:{HOST_IP}")
    result = materialize((claim,), is_synthetic=True)

    assert [edge.relation for edge in result.relationships] == []
    assert RelationType.ASSOCIATED_WITH not in {edge.relation for edge in result.relationships}
    assert len(result.skipped) == 1
    assert "definitely_the_same_guy" in result.skipped[0]
    assert "not coerced into a generic edge" in result.skipped[0]


def test_one_unmappable_claim_does_not_cost_the_rest_of_the_batch() -> None:
    good = _claim(f"domain:{SEED_DOMAIN}", RelationType.RESOLVES_TO.value, f"ip_address:{HOST_IP}")
    bad = _claim("not-an-entity-reference", RelationType.RESOLVES_TO.value, f"ip_address:{HOST_IP}")

    result = materialize((bad, good), is_synthetic=True)
    assert len(result.relationships) == 1
    assert len(result.skipped) == 1
    assert "is not '<entity_type>:<key>'" in result.skipped[0]


def test_incoherent_selectivity_qualifiers_cost_one_claim_not_the_whole_pivot() -> None:
    """Qualifiers cross the collection boundary, where content is hostile by default
    (invariant 5). A connector claiming an attribute is globally unique *and* shared by
    forty thousand entities is either drifting or being fed. Either way it must not be able
    to abort the step and take every other claim in the batch with it."""
    poisoned = _claim(
        f"ip_address:{CDN_IP}",
        RelationType.RESOLVES_TO.value,
        "domain:globex-invoice-portal.example",
        qualifiers={
            "shared_attribute": CDN_IP,
            "population_size": "41700",
            "population_measured_against": "passive DNS, 2026-03 snapshot",
            "globally_unique": "true",
        },
    )
    healthy = _claim(
        f"domain:{SEED_DOMAIN}", RelationType.RESOLVES_TO.value, f"ip_address:{HOST_IP}"
    )

    result = materialize((poisoned, healthy), is_synthetic=True)

    assert len(result.relationships) == 1
    assert result.relationships[0].target_type is EntityType.IP_ADDRESS
    assert len(result.skipped) == 1
    assert "not coherent" in result.skipped[0]


def test_an_ipv6_reference_survives_its_own_colons() -> None:
    """``ip_address:2001:db8::1`` splits on the first colon only, and the prefix must be a
    known entity type — otherwise ``2001`` becomes an entity type and the address becomes
    ``db8::1``, which is a different host."""
    reference = parse_reference("ip_address:2001:db8::1")
    assert reference is not None
    assert reference.entity_type is EntityType.IP_ADDRESS
    assert reference.natural_key == "2001:db8::1"

    # A bare address is not a reference: nothing names what kind of thing it is.
    assert parse_reference("2001:db8::1") is None
    assert parse_reference("2001:db8::1:resolves_to") is None

    claim = _claim(
        f"domain:{SEED_DOMAIN}", RelationType.RESOLVES_TO.value, "ip_address:2001:db8::1"
    )
    result = materialize((claim,), is_synthetic=True)
    keys = {entity.natural_key for entity in result.entities}
    assert keys == {SEED_DOMAIN, "2001:db8::1"}


def test_equivalent_ipv6_forms_collapse_to_one_entity() -> None:
    """Entity duplication is how three weak links become an apparent cluster."""
    expanded = _claim(
        f"domain:{SEED_DOMAIN}",
        RelationType.RESOLVES_TO.value,
        "ip_address:2001:0db8:0000:0000:0000:0000:0000:0001",
    )
    compact = _claim(
        "domain:globex-invoice-portal.example",
        RelationType.RESOLVES_TO.value,
        "ip_address:2001:db8::1",
    )

    result = materialize((expanded, compact), is_synthetic=True)
    addresses = [e for e in result.entities if e.entity_type is EntityType.IP_ADDRESS]
    assert len(addresses) == 1


def test_the_selective_pivot_and_the_worthless_one_get_different_confidence() -> None:
    """DEMO_SCENARIO.md §2.2 and §2.3. Same relation, same observation, opposite analytic
    value — and the difference has to land in the edge's own confidence, or an analyst who
    pivots through a CDN address gets a link that looks like all the others."""
    selective = materialize(
        (
            _claim(
                f"ip_address:{HOST_IP}",
                RelationType.RESOLVES_TO.value,
                "domain:initech-payments-secure.example",
                qualifiers={
                    "shared_attribute": HOST_IP,
                    "population_size": "4",
                    "population_measured_against": "passive DNS, 2026-03 snapshot",
                },
            ),
        ),
        is_synthetic=True,
    ).relationships[0]

    worthless = materialize(
        (
            _claim(
                f"ip_address:{CDN_IP}",
                RelationType.RESOLVES_TO.value,
                "domain:unrelated-shop.example",
                qualifiers={
                    "shared_attribute": CDN_IP,
                    "population_size": "41700",
                    "population_measured_against": "passive DNS, 2026-03 snapshot",
                },
            ),
        ),
        is_synthetic=True,
    ).relationships[0]

    assert selective.selectivity is not None
    assert selective.selectivity.is_informative
    assert band_of(selective.confidence) is ConfidenceBand.LIKELY

    assert worthless.selectivity is not None
    assert not worthless.selectivity.is_informative
    assert band_of(worthless.confidence) is ConfidenceBand.INSUFFICIENT_BASIS
    assert any("too many" in caveat for caveat in worthless.explain().caveats)


def test_an_uncounted_population_is_never_treated_as_selective() -> None:
    """A count with no stated corpus cannot be interpreted or challenged, so it is discarded
    rather than kept as a number that looks meaningful."""
    edge = materialize(
        (
            _claim(
                f"ip_address:{HOST_IP}",
                RelationType.RESOLVES_TO.value,
                "domain:globex-invoice-portal.example",
                qualifiers={"shared_attribute": HOST_IP, "population_size": "4"},
            ),
        ),
        is_synthetic=True,
    ).relationships[0]

    assert edge.selectivity is not None
    assert edge.selectivity.population_size is None
    assert edge.confidence.is_vacuous
    assert any("never counted" in caveat for caveat in edge.explain().caveats)


def test_a_pivot_through_a_registrar_carries_a_justification_it_did_not_earn() -> None:
    """DEMO_SCENARIO.md §2.5: linking two domains because they share a registrar needs an
    explicit justification. When the connector supplies none, the edge is still built — and
    it carries, in writing, the statement that it carries no weight on its own."""
    edge = materialize(
        (
            _claim(
                f"domain:{SEED_DOMAIN}",
                RelationType.REGISTERED_THROUGH.value,
                "registrar:bulletproofreg",
                qualifiers={
                    "shared_attribute": "registrar",
                    "pivot_method": PivotMethod.SHARED_ATTRIBUTE.value,
                },
            ),
        ),
        is_synthetic=True,
    ).relationships[0]

    assert edge.shared_infrastructure_justification is not None
    assert "carries no weight on its own" in edge.shared_infrastructure_justification


def test_a_self_referential_claim_builds_no_edge() -> None:
    claim = _claim(f"domain:{SEED_DOMAIN}", RelationType.RESOLVES_TO.value, f"domain:{SEED_DOMAIN}")
    result = materialize((claim,), is_synthetic=True)

    assert result.relationships == ()
    assert "same entity" in result.skipped[0]


# --- The engine ---------------------------------------------------------------


def test_a_pivot_with_no_available_connector_is_recorded_as_a_failure() -> None:
    """ "We looked and found nothing" and "we could not look" are different findings, and
    only one of them is evidence of absence. The attempt must survive in the record with
    the reason it could not be made."""
    audit = FakeAudit()
    engine = _engine(audit=audit)

    investigation = asyncio.run(engine.start(_seed(), total_budget=10.0))
    investigation = asyncio.run(engine.step(investigation))

    executed = investigation.all_executed_pivots
    assert len(executed) == 1
    assert not executed[0].succeeded
    assert executed[0].error is not None
    assert "No connector can answer" in executed[0].error
    assert "REQUIRES_EXTERNAL_DATA" in executed[0].error
    assert executed[0].connector == "none"
    assert not executed[0].was_informative

    failure = next(event for event in audit.events if event.action == "pivot.execute")
    assert failure.outcome == "failed"
    assert "No connector can answer" in failure.inputs["error"]


def test_the_engine_records_the_asn_but_opens_no_branch_on_it() -> None:
    """DEMO_SCENARIO.md §2.6: the announcing network is a fact worth holding and a terrible
    place to keep pursuing. Recording it without branching is the distinction; dropping it
    would lose the disruption planner's input, and branching on it would build the cluster
    this control exists to prevent."""
    graph = FakeGraph()
    connector = FakeConnector(
        name="passive-dns-fixture",
        pivots=frozenset({PivotType.RESOLUTION_HISTORY}),
        entity_types=frozenset({EntityType.DOMAIN}),
        responder=_resolution_result,
    )
    audit = FakeAudit()
    engine = _engine(connectors=(connector,), graph=graph, audit=audit)

    investigation = asyncio.run(engine.start(_seed(), total_budget=10.0))
    investigation = asyncio.run(engine.step(investigation))

    assert asyncio.run(graph.find_entity(EntityType.ASN, HOST_ASN)) is not None
    assert {branch.focus_entity_key for branch in investigation.branches} == {SEED_DOMAIN, HOST_IP}

    spawned = next(branch for branch in investigation.branches if branch.branch_id != "B0")
    assert spawned.parent_branch_id == "B0"
    assert spawned.depth == 1
    assert len(graph.relationships) == 2

    event = next(item for item in audit.events if item.action == "pivot.execute")
    assert json.loads(event.inputs["materialized_entities"]) == [
        ["asn", HOST_ASN],
        ["domain", SEED_DOMAIN],
        ["ip_address", HOST_IP],
    ]


def test_real_collection_never_marks_the_seed_or_discoveries_as_synthetic() -> None:
    """A real connector routed through pursuit must not leave a simulated graph behind.

    Reproduced while preparing the first live onion snapshot: ``start`` hard-coded the seed
    to synthetic and ``_absorb`` did the same to every entity materialized from connector
    output. The evidence correctly said ``is_simulated=False`` while both graph endpoints
    said the opposite.
    """
    graph = FakeGraph()
    connector = FakeConnector(
        name="real-passive-source",
        pivots=frozenset({PivotType.RESOLUTION_HISTORY}),
        entity_types=frozenset({EntityType.DOMAIN}),
        responder=lambda request: _resolution_result(request, is_simulated=False),
        is_simulated=False,
    )
    engine = _engine(connectors=(connector,), graph=graph)
    seed = _seed().model_copy(update={"is_synthetic": False})

    investigation = asyncio.run(engine.start(seed, total_budget=10.0))
    investigation = asyncio.run(engine.step(investigation))

    stored_seed = asyncio.run(graph.find_entity(EntityType.DOMAIN, SEED_DOMAIN))
    discovered = asyncio.run(graph.find_entity(EntityType.IP_ADDRESS, HOST_IP))
    assert stored_seed is not None and stored_seed.is_synthetic is False
    assert discovered is not None and discovered.is_synthetic is False
    assert investigation.branches[0].executed[0].connector == "passive-dns-fixture"


def test_evidence_is_sealed_before_the_claims_that_cite_it() -> None:
    """Invariant 3: a claim referencing evidence that failed to seal would be a claim with
    unresolvable provenance. The ordering is the only thing preventing that."""
    log: list[str] = []
    vault = FakeVault(log)
    claims = FakeClaimStore(log)
    connector = FakeConnector(
        name="passive-dns-fixture",
        pivots=frozenset({PivotType.RESOLUTION_HISTORY}),
        entity_types=frozenset({EntityType.DOMAIN}),
        responder=_resolution_result,
    )
    engine = _engine(connectors=(connector,), vault=vault, claims=claims)

    investigation = asyncio.run(engine.start(_seed(), total_budget=10.0))
    investigation = asyncio.run(engine.step(investigation))

    seals = [index for index, entry in enumerate(log) if entry.startswith("seal:")]
    recorded = [index for index, entry in enumerate(log) if entry.startswith("claim:")]
    assert seals and recorded
    assert max(seals) < min(recorded)

    executed = investigation.all_executed_pivots[0]
    assert len(executed.evidence_produced) == 1
    assert len(executed.claims_produced) == 2
    assert vault.sealed


def test_the_seed_entity_does_not_get_a_second_branch() -> None:
    """The pivot's own subject comes back through materialization. Merging on (type, natural
    key) is what stops one real-world thing becoming two nodes and two lines of enquiry."""
    connector = FakeConnector(
        name="passive-dns-fixture",
        pivots=frozenset({PivotType.RESOLUTION_HISTORY}),
        entity_types=frozenset({EntityType.DOMAIN}),
        responder=_resolution_result,
    )
    engine = _engine(connectors=(connector,))

    investigation = asyncio.run(engine.start(_seed(), total_budget=10.0))
    investigation = asyncio.run(engine.step(investigation))

    focuses = [branch.focus_entity_key for branch in investigation.branches]
    assert focuses.count(SEED_DOMAIN) == 1


def test_a_whole_run_replays_identically() -> None:
    """The same seed, the same fixtures and the same policy must produce the same sequence
    of decisions — including which branches were closed and why. Without this an audit can
    read what the engine did but cannot check whether it should have."""

    def transcript() -> tuple[tuple[str, str, bool], ...]:
        connector = FakeConnector(
            name="passive-dns-fixture",
            pivots=frozenset({PivotType.RESOLUTION_HISTORY}),
            entity_types=frozenset({EntityType.DOMAIN}),
            responder=_resolution_result,
        )
        audit = FakeAudit()
        engine = _engine(connectors=(connector,), audit=audit)
        investigation = asyncio.run(engine.start(_seed(), total_budget=20.0))
        investigation = asyncio.run(engine.run(investigation, max_steps=30))
        return tuple(
            (branch.branch_id, pivot.candidate.pivot_type.value, pivot.succeeded)
            for branch in investigation.branches
            for pivot in branch.executed
        ) + tuple(
            (branch.branch_id, branch.state.value, branch.abandonment_reason is not None)
            for branch in investigation.branches
        )

    first = transcript()
    second = transcript()

    assert first == second
    assert first  # a run that did nothing would make this test vacuous


def test_a_run_that_finds_nothing_closes_its_branches_with_reasons() -> None:
    """The end state an analyst reads: every line of enquiry either exhausted or abandoned
    with a stated reason, and no branch left silently open."""
    engine = _engine()
    investigation = asyncio.run(engine.start(_seed(), total_budget=20.0))
    investigation = asyncio.run(engine.run(investigation, max_steps=30))

    assert investigation.open_branches == ()
    for branch in investigation.branches:
        if branch.state.value.startswith("abandoned"):
            assert branch.abandonment_reason
    assert "abandoned" in investigation.summary() or "0 abandoned" in investigation.summary()


def test_the_step_ceiling_is_recorded_as_a_halt_not_a_completion() -> None:
    """An investigation stopped by a safety net has not finished, and the difference must be
    readable — otherwise a policy bug looks like a conclusion."""
    connector = FakeConnector(
        name="passive-dns-fixture",
        pivots=frozenset({PivotType.RESOLUTION_HISTORY}),
        entity_types=frozenset({EntityType.DOMAIN}),
        responder=_resolution_result,
    )
    engine = _engine(connectors=(connector,))

    investigation = asyncio.run(engine.start(_seed(), total_budget=50.0))
    investigation = asyncio.run(engine.run(investigation, max_steps=2))

    assert investigation.open_branches
    assert any("halt, not a completion" in note for note in investigation.notes)


def test_starting_an_investigation_opens_the_exculpatory_hypothesis_too() -> None:
    """Starting with only the incriminating hypothesis is how an investigation confirms
    itself. The seed being someone else's compromised infrastructure, and the seed being
    staged to misdirect, are both open from the first step."""
    engine = _engine()
    investigation = asyncio.run(engine.start(_seed(), total_budget=10.0))

    statements = " ".join(h.statement for h in investigation.hypotheses)
    assert len(investigation.open_hypotheses) == 3
    assert "unrelated party" in statements
    assert "misdirect" in statements


def test_an_investigation_is_replaced_wholesale_rather_than_mutated() -> None:
    """Mutating state in place would make the decision sequence unreconstructable."""
    engine = _engine()
    before = asyncio.run(engine.start(_seed(), total_budget=10.0))
    after = asyncio.run(engine.step(before))

    assert before is not after
    assert before.step_count == 0
    assert after.step_count == 1
    assert before.branches[0].executed == ()
