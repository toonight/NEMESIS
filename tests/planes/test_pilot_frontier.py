"""The pilot is shown what NEMESIS thinks is worth doing next, and its pivots address a hypothesis.

Two defects motivate this file, both measured across seven live Codex-directed runs under
``artifacts/poc-public-ioc-2026-09-07/``: every one of the fifty executed pivots carried
``expected_information_gain == 0.0`` and ``addresses_hypothesis is None``.

The cause is not that the machinery is missing. :class:`RuleBasedPursuitPolicy` scores
candidates, discounts shared infrastructure and links an open hypothesis; ``PursuitEngine.start``
opens three competing hypotheses including the deception one. But ``execute_pivot`` — the seam a
model-driven pilot sits behind — built its candidate by hand with the gain hardcoded, and the
mediator held no policy at all. So the engine's own navigator was switched off exactly when a
frontier model was flying.

That matters beyond tidiness: with no scored frontier the pilot cannot be *compared* to the
policy, and "did the model choose better than the rules" is the question this system exists to
answer.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from nemesis.authz.envelope import AutonomyEnvelope
from nemesis.authz.gateway import RevocationRegistry
from nemesis.authz.keys import CapabilitySigningKey
from nemesis.collect.simulated import simulated_connectors
from nemesis.core.authorization import (
    Approval,
    AuthorizationCapability,
    LegalBasis,
    OperationClass,
    TargetFingerprint,
)
from nemesis.core.entities import Entity, EntityType
from nemesis.core.evidence import EvidenceObject
from nemesis.core.identity import Role
from nemesis.core.ids import EvidenceId, IdPrefix, new_id
from nemesis.core.temporal import TemporalExtent
from nemesis.effects.isolation import InProcessEffectsExecutor
from nemesis.effects.registry import default_registry
from nemesis.graph.memory import InMemoryClaimStore, InMemoryGraphStore
from nemesis.pilot.mediator import PilotMediator
from nemesis.pilot.moves import Briefing, Conclude, PilotMove
from nemesis.ports.collection import PivotType
from nemesis.ports.storage import AuditEvent, VaultIntegrityReport
from nemesis.pursuit.engine import ConnectorRegistry, PursuitEngine
from nemesis.pursuit.investigation import IncidentSeed
from nemesis.pursuit.policy import PIVOTS_FOR_ENTITY, RuleBasedPursuitPolicy

NOW = datetime(2026, 3, 10, tzinfo=UTC)
EXTENT = TemporalExtent.at(NOW)
SEED_DOMAIN = "acme-invoice-portal.example"
SIGNING_KEY = CapabilitySigningKey.generate()


class RecordingVault:
    """Enough vault for the engine: seal returns the evidence and remembers it."""

    def __init__(self) -> None:
        self.sealed: list[str] = []

    async def seal(self, evidence: EvidenceObject, artifact: bytes) -> EvidenceObject:
        self.sealed.append(evidence.evidence_id)
        return evidence

    async def get(self, evidence_id: EvidenceId) -> EvidenceObject | None:
        raise NotImplementedError("these tests never read evidence back")

    async def retrieve_artifact(
        self, evidence_id: EvidenceId, *, accessed_by: str, reason: str
    ) -> bytes:
        raise NotImplementedError("these tests never read evidence back")

    async def verify_integrity(self) -> VaultIntegrityReport:
        raise NotImplementedError("integrity is tested against the real vault")

    async def head(self) -> str:
        raise NotImplementedError("anchoring is tested against the real vault")


class RecordingAudit:
    """Enough audit sink for the engine and mediator to write to."""

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
        raise NotImplementedError("these tests inspect .events directly")

    async def verify_chain(self) -> bool:
        raise NotImplementedError("chain verification is tested against the real audit trail")


class RecordingPilot:
    """Concludes immediately, keeping every briefing it was handed."""

    def __init__(self) -> None:
        self.briefings: list[Briefing] = []

    @property
    def name(self) -> str:
        return "recording-pilot"

    async def propose(self, briefing: Briefing) -> PilotMove | Mapping[str, Any]:
        self.briefings.append(briefing)
        return Conclude(summary="captured the briefing")


def _capability(target: TargetFingerprint) -> AuthorizationCapability:
    real = datetime.now(UTC)
    approval = Approval(
        approver=new_id(IdPrefix.ACTOR),
        approver_roles=frozenset({Role.INVESTIGATION_LEAD}),
        decided_at=real,
        decision=True,
        rationale="Frontier projection test; synthetic target; no effect is executed.",
    )
    unsigned = AuthorizationCapability(
        capability_id=new_id(IdPrefix.CAPABILITY),
        case_id=new_id(IdPrefix.CASE),
        audit_id=new_id(IdPrefix.AUDIT),
        issued_at=real - timedelta(minutes=1),
        not_before=real - timedelta(minutes=1),
        expires_at=real + timedelta(hours=4),
        targets=(target,),
        permitted_operations=frozenset({OperationClass.SIMULATION}),
        forbidden_operations=frozenset({OperationClass.REGISTRAR_SUSPENSION}),
        jurisdictions=("FR",),
        legal_basis=LegalBasis.NONE_SIMULATION_ONLY,
        legal_authority_reference=None,
        max_targets=4,
        max_effect_description="Nothing is executed in this test.",
        approvals=(approval,),
        required_approvals=1,
    )
    return unsigned.model_copy(update={"signature": SIGNING_KEY.sign(unsigned.signing_payload())})


def _engine(graph: InMemoryGraphStore, audit: RecordingAudit) -> PursuitEngine:
    return PursuitEngine(
        graph=graph,
        claims=InMemoryClaimStore(),
        vault=RecordingVault(),
        audit=audit,
        connectors=ConnectorRegistry(simulated_connectors(as_of=NOW)),
    )


def _seed() -> IncidentSeed:
    return IncidentSeed(
        entity_type=EntityType.DOMAIN,
        entity_key=SEED_DOMAIN,
        observed_at=NOW,
        detected_by="frontier-test",
    )


# --- Point 2: a pilot-named pivot addresses a hypothesis and carries a real prior -----------


def test_pilot_named_pivot_is_linked_to_an_open_hypothesis() -> None:
    """``addresses_hypothesis`` was ``None`` on all fifty pivots of all seven live runs.

    A pivot that names no hypothesis cannot be scored, cannot settle anything, and leaves the
    branch's ``consecutive_uninformative`` counter measuring nothing.
    """

    async def scenario() -> None:
        graph = InMemoryGraphStore()
        engine = _engine(graph, RecordingAudit())
        investigation = await engine.start(_seed())
        entity_id = investigation.branches[0].focus_entity_id

        _, executed = await engine.execute_pivot(
            investigation,
            entity_id=entity_id,
            pivot_type=PivotType.RESOLUTION_HISTORY,
            rationale="Where the domain pointed.",
        )

        assert executed is not None
        assert executed.candidate.addresses_hypothesis == "H1", (
            "the branch opens on H1; a pilot-named pivot must say which hypothesis it serves"
        )

    asyncio.run(scenario())


def test_pilot_named_pivot_carries_the_policys_prior_gain() -> None:
    """The engine hardcoded ``expected_information_gain=0.0`` on this path.

    The prior belongs to the (entity type, pivot type) pair, not to whoever chose it — which is
    precisely what makes pilot choices comparable to the policy's ranking after the fact.
    """

    async def scenario() -> None:
        graph = InMemoryGraphStore()
        engine = _engine(graph, RecordingAudit())
        investigation = await engine.start(_seed())
        entity_id = investigation.branches[0].focus_entity_id

        expected = {pivot: gain for pivot, gain, _ in PIVOTS_FOR_ENTITY[EntityType.DOMAIN]}[
            PivotType.RESOLUTION_HISTORY
        ]

        _, executed = await engine.execute_pivot(
            investigation,
            entity_id=entity_id,
            pivot_type=PivotType.RESOLUTION_HISTORY,
            rationale="Where the domain pointed.",
        )

        assert executed is not None
        assert executed.candidate.expected_information_gain == pytest.approx(expected)

    asyncio.run(scenario())


def test_an_unknown_pivot_pair_keeps_a_zero_prior() -> None:
    """No prior is an honest 0.0, not an invented number.

    ``EMAIL_ADDRESS`` has exactly one scored pivot; anything else asked of it is a pair the
    policy has no opinion about, and the engine must not manufacture one.
    """

    async def scenario() -> None:
        graph = InMemoryGraphStore()
        engine = _engine(graph, RecordingAudit())
        investigation = await engine.start(_seed())

        stored = await graph.upsert_entity(
            Entity.create(
                entity_id=new_id(IdPrefix.ENTITY),
                entity_type=EntityType.EMAIL_ADDRESS,
                observed_form="operator@mail.example",
                extent=EXTENT,
                is_synthetic=True,
            )
        )

        _, executed = await engine.execute_pivot(
            investigation,
            entity_id=stored.entity_id,
            pivot_type=PivotType.CERTIFICATE_REUSE,
            rationale="A pair the policy scores for nobody.",
        )

        assert executed is not None
        assert executed.candidate.expected_information_gain == 0.0

    asyncio.run(scenario())


def test_shared_infrastructure_is_discounted_on_the_pilot_path_too() -> None:
    """The 0.1 discount is the control that stops a CDN pivot looking as good as a key pivot.

    Applying it only on the engine's own path would mean a pilot could walk into exactly the
    trap the policy exists to avoid, and the audit line would rate the move as if it had not.
    """

    async def scenario() -> None:
        graph = InMemoryGraphStore()
        engine = _engine(graph, RecordingAudit())
        investigation = await engine.start(_seed())

        stored = await graph.upsert_entity(
            Entity.create(
                entity_id=new_id(IdPrefix.ENTITY),
                entity_type=EntityType.ASN,
                observed_form="AS20473",
                extent=EXTENT,
                is_synthetic=True,
            )
        )

        undiscounted = {pivot: gain for pivot, gain, _ in PIVOTS_FOR_ENTITY[EntityType.ASN]}[
            PivotType.NETWORK_OWNERSHIP
        ]

        _, executed = await engine.execute_pivot(
            investigation,
            entity_id=stored.entity_id,
            pivot_type=PivotType.NETWORK_OWNERSHIP,
            rationale="Who announces this network.",
        )

        assert executed is not None
        assert executed.candidate.would_pivot_through_shared_infrastructure is True
        assert executed.candidate.expected_information_gain == pytest.approx(undiscounted * 0.1)

    asyncio.run(scenario())


# --- Point 1: the briefing carries a ranked frontier ----------------------------------------


async def _brief_once(*, policy: RuleBasedPursuitPolicy | None) -> Briefing:
    graph = InMemoryGraphStore()
    audit = RecordingAudit()
    engine = _engine(graph, audit)

    seed_entity = await graph.upsert_entity(
        Entity.create(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type=EntityType.DOMAIN,
            observed_form=SEED_DOMAIN,
            extent=EXTENT,
            is_synthetic=True,
        )
    )
    target = TargetFingerprint.create(
        entity_id=seed_entity.entity_id,
        entity_type="domain",
        natural_key=seed_entity.natural_key,
        bound_attributes=dict(seed_entity.attributes),
    )
    mediator = PilotMediator(
        engine=engine,
        graph=graph,
        envelope=AutonomyEnvelope(_capability(target), max_autonomous_effects=0),
        effects=InProcessEffectsExecutor(
            default_registry(
                verifying_key=SIGNING_KEY.verifying_key, revocations=RevocationRegistry()
            )
        ),
        claims=InMemoryClaimStore(),
        audit=audit,
        clock=lambda: NOW,
        policy=policy,
    )
    pilot = RecordingPilot()
    await mediator.drive(pilot, _seed())
    assert pilot.briefings, "the pilot was never briefed"
    return pilot.briefings[0]


def test_without_a_policy_the_frontier_is_empty() -> None:
    """The seam stays exactly as it was for every caller that does not opt in."""
    briefing = asyncio.run(_brief_once(policy=None))
    assert briefing.frontier == ()


def test_the_frontier_is_ranked_and_scored() -> None:
    """What the pilot has never had: the leads NEMESIS thinks are worth taking, in order."""
    briefing = asyncio.run(_brief_once(policy=RuleBasedPursuitPolicy()))

    assert briefing.frontier, "a domain seed has four scored pivots; the frontier cannot be empty"
    scores = [entry.value_per_cost for entry in briefing.frontier]
    assert scores == sorted(scores, reverse=True), "the frontier must arrive ranked"
    assert all(entry.expected_information_gain > 0.0 for entry in briefing.frontier)
    assert all(entry.rationale for entry in briefing.frontier), "every lead says what it buys"


def test_the_frontier_names_the_hypothesis_each_lead_would_move() -> None:
    briefing = asyncio.run(_brief_once(policy=RuleBasedPursuitPolicy()))
    assert {entry.addresses_hypothesis for entry in briefing.frontier} == {"H1"}


def test_the_frontier_only_offers_entities_the_pilot_is_already_shown() -> None:
    """The disclosure wall governs the frontier or it is a hole straight through it.

    A frontier built from the investigation's raw entity list would hand the pilot — and, for a
    hosted model, the vendor — the natural key of an internal-class node in a ``entity_key``
    field, having spent considerable care keeping that same node out of ``entities``.
    """
    briefing = asyncio.run(_brief_once(policy=RuleBasedPursuitPolicy()))

    briefed = {entity.entity_id for entity in briefing.entities}
    offered = {entry.entity_id for entry in briefing.frontier}
    assert offered <= briefed, f"frontier offers entities not in the briefing: {offered - briefed}"
