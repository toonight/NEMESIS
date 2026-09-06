"""SIMULATED public-report replay; labels are consumed only by the offline scorer.

This measures retrieval through the real mediator, not novel threat discovery or attribution.
Inputs contain manually reconstructed report assertions; neither raw telemetry nor malware.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from nemesis.collect.base import FixtureAnswer, ObservationRecord, SimulatedConnector
from nemesis.core.claims import ClaimKind, Statement
from nemesis.core.entities import EntityType
from nemesis.core.evidence import ArtifactKind
from nemesis.core.provenance import SourceClass, SourceDescriptor
from nemesis.core.temporal import TemporalExtent
from nemesis.pilot.moves import Briefing, Conclude, PilotMove, ResearchContext, RunPivot
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilot.providers.contract import MeteredPilot, PilotDecision, ProviderIdentity
from nemesis.pilotbench.harness import run_scenario
from nemesis.pilotbench.scenario import BenchScenario, EnvelopeSpec
from nemesis.ports.collection import ConnectorCapabilities, PivotType

# Fixed for every case and arm. No case names or evaluator labels drive this order.
PIVOTS: dict[EntityType, tuple[PivotType, ...]] = {
    EntityType.DOMAIN: (PivotType.RESOLUTION_HISTORY, PivotType.THREAT_INTEL_LOOKUP),
    EntityType.IP_ADDRESS: (PivotType.REVERSE_RESOLUTION,),
    EntityType.MALWARE: (PivotType.MALWARE_LOOKUP, PivotType.C2_EXTRACTION),
}


class Route(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    pivot_type: PivotType
    entity_key: str


class ReplayRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    record_id: str
    statement: Statement
    observed_at: datetime
    routes: tuple[Route, ...]


class ReplayCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    case_id: str
    seed: str
    as_of: datetime
    source_id: str
    records: tuple[ReplayRecord, ...]


def read_cases(path: Path) -> tuple[ReplayCase, ...]:
    data = json.loads(path.read_text())
    if data["status"] != "SIMULATED" or data["version"] != "public-replay-v1":
        raise ValueError("Expected SIMULATED public-replay-v1 inputs")
    cases = tuple(ReplayCase.model_validate(case) for case in data["cases"])
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("Duplicate case identifier")
    for case in cases:
        if len({r.record_id for r in case.records}) != len(case.records):
            raise ValueError("Duplicate record identifier")
    return cases


def connector(case: ReplayCase) -> SimulatedConnector:
    fixtures: dict[tuple[PivotType, str], FixtureAnswer] = {}
    for item in case.records:
        record = ObservationRecord(
            artifact=item.model_dump_json().encode(),
            artifact_kind=ArtifactKind.STRUCTURED_FEED_RECORD,
            statement=item.statement.model_copy(
                update={
                    "qualifiers": {**item.statement.qualifiers, "replay_record": item.record_id}
                }
            ),
            extent=TemporalExtent.at(item.observed_at),
            available_from=case.as_of,
            notes="SIMULATED: anonymized reconstruction of a published assertion, not telemetry.",
        )
        for route in item.routes:
            key = (route.pivot_type, route.entity_key)
            existing = fixtures.get(key, FixtureAnswer())
            fixtures[key] = FixtureAnswer(records=(*existing.records, record))
    return SimulatedConnector(
        capabilities=ConnectorCapabilities(
            name=f"replay-{case.source_id}",
            version="1",
            source=SourceDescriptor(
                source_class=SourceClass.OPEN_SOURCE,
                identifier=case.source_id,
                operator="public-report-reconstruction",
                upstream_of_record=case.source_id,
            ),
            supported_pivots=frozenset(pivot for family in PIVOTS.values() for pivot in family),
            supported_entity_types=frozenset(PIVOTS),
            is_simulated=True,
            cost_per_call=1.0,
        ),
        fixtures=fixtures,
        as_of=case.as_of,
        fixture_set="public-replay-v1",
    )


class BreadthFirstPilot:
    """Simple baseline: each visible entity, each supported pivot, once; then stop."""

    name = "breadth-first"

    def __init__(self) -> None:
        self.tried: set[tuple[str, PivotType]] = set()

    async def propose(self, briefing: Briefing) -> PilotMove:
        for entity in briefing.entities:
            for pivot in PIVOTS.get(EntityType(entity.entity_type), ()):
                key = (entity.entity_id, pivot)
                if key not in self.tried:
                    self.tried.add(key)
                    return RunPivot(
                        entity_id=entity.entity_id,
                        pivot_type=pivot,
                        rationale="Visit each available entity/pivot pair once in discovery order.",
                    )
        return Conclude(summary="Available replay queries exhausted; no attribution asserted.")


class ReplaySeat:
    """Same bounded query menu and attempt history for both arms; no store or labels.

    The provider still sees only Briefing. Captures precisely those inputs for later review.
    Raw report text, case title, mappings, and expected findings are never added here.
    """

    def __init__(self, pilot: AutonomousPilot) -> None:
        self.pilot = pilot
        self.name = pilot.name
        self.history: list[str] = []
        self.briefings: list[Briefing] = []
        self.identity = (
            pilot.identity
            if isinstance(pilot, MeteredPilot)
            else ProviderIdentity(provider="scripted", model=pilot.name, seat=pilot.name)
        )

    async def decide(self, briefing: Briefing) -> PilotDecision:
        enriched = briefing.model_copy(
            update={
                "research_context": ResearchContext(
                    open_questions=(
                        "Retrieve report assertions reachable from the seed within the budget.",
                        "Available queries: domain=resolution_history,threat_intel_lookup; "
                        "ip_address=reverse_resolution; malware=malware_lookup,c2_extraction.",
                        "Missing replay answers mean unrecorded in this excerpt, not benign.",
                        "No effects are authorized. Conclude when useful queries are exhausted.",
                    ),
                    recent_negative_results=(),
                    exhausted_directions=tuple(self.history[-8:]),
                )
            }
        )
        self.briefings.append(enriched)
        decision = (
            await self.pilot.decide(enriched)
            if isinstance(self.pilot, MeteredPilot)
            else PilotDecision(raw=await self.pilot.propose(enriched))
        )
        raw = decision.raw
        values = raw.model_dump() if isinstance(raw, BaseModel) else raw
        if values.get("kind") == "run_pivot":
            eid = values.get("entity_id")
            key = next((e.natural_key for e in briefing.entities if e.entity_id == eid), str(eid))
            self.history.append(f"Attempted {values.get('pivot_type')} on {key}"[:210])
        return decision

    async def propose(self, briefing: Briefing) -> PilotMove | Mapping[str, Any]:
        # Any: the untrusted JSON-shaped move crosses the existing pilot protocol.
        return (await self.decide(briefing)).raw


async def run_replay(
    case: ReplayCase, pilot: AutonomousPilot, *, workspace: Path, max_moves: int = 8
) -> dict[str, Any]:
    # Any: JSON report includes independently typed claim, briefing, and provider schemas.
    seed_type, seed_key = case.seed.split(":", 1)
    scenario = BenchScenario(
        scenario_id=case.case_id,
        title="SIMULATED public-report replay",
        premise="Offline reconstruction, not an operational investigation.",
        seed_domain=seed_key,
        seed_entity_type=EntityType(seed_type),
        as_of=case.as_of,
        envelope=EnvelopeSpec(approved_domain=seed_key, approved_attributes={}, effect_budget=0),
        max_moves=max_moves,
        total_budget=float(max_moves),
    )
    seat = ReplaySeat(pilot)
    started = time.perf_counter()
    run = await run_scenario(
        scenario, seat, workspace=workspace, connectors=(connector(case),), propose_timeout=180.0
    )
    elapsed = time.perf_counter() - started
    pivots = run.session.investigation.all_executed_pivots
    query_keys = [(p.candidate.entity_key, p.candidate.pivot_type.value) for p in pivots]
    observed = {
        claim.statement.qualifiers["replay_record"]
        for claim in run.claims.claims()
        if claim.kind is ClaimKind.OBSERVATION and "replay_record" in claim.statement.qualifiers
    }
    turns = run.session.transcript
    usage = [t.metadata.usage.total_tokens if t.metadata else None for t in turns]
    return {
        "status": "SIMULATED",
        "case_id": case.case_id,
        "pilot": seat.name,
        "identity": seat.identity.model_dump(mode="json"),
        "elapsed_seconds": elapsed,
        "max_moves": max_moves,
        "moves": len(turns),
        "query_attempts": len(pivots),
        "connector_calls": sum(p.connector != "none" for p in pivots),
        "query_cost_units": sum(p.actual_cost for p in pivots),
        "duplicate_queries": len(query_keys) - len(set(query_keys)),
        "failed_queries": sum(not p.succeeded for p in pivots),
        "empty_queries": sum(p.succeeded and not p.claims_produced for p in pivots),
        "refused_moves": sum(not t.ruling.accepted for t in turns),
        "reported_tokens": sum(t for t in usage if t is not None)
        if all(t is not None for t in usage)
        else None,
        "tokens_complete": all(t is not None for t in usage),
        "monetary_cost": None,
        "cost_notice": "Unitless query budget. Electricity, hardware and analyst time unmeasured.",
        "observed_record_ids": sorted(observed),
        "concluded": run.session.concluded,
        "halted_reason": run.session.halted_reason,
        "outcome": run.session.outcome.value,
        "briefings": [b.model_dump(mode="json") for b in seat.briefings],
        "transcript": [
            {
                "move": t.move.model_dump(mode="json") if t.move else None,
                "ruling": t.ruling.model_dump(mode="json"),
                "metadata": t.metadata.model_dump(mode="json") if t.metadata else None,
            }
            for t in turns
        ],
        "pivots": [p.model_dump(mode="json") for p in pivots],
        "claims": [c.model_dump(mode="json") for c in run.claims.claims()],
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def score_report(run: Mapping[str, Any], expected: set[str]) -> dict[str, Any]:
    # Any: scoring a persisted JSON record, not reaching a running pilot or its stores.
    observed = set(run["observed_record_ids"])
    found = observed & expected
    return {
        "case_id": run["case_id"],
        "pilot": run["pilot"],
        "retrieved": len(found),
        "expected": len(expected),
        "query_attempts": run.get("query_attempts", run.get("connector_calls")),
        "recall": len(found) / len(expected) if expected else None,
        "missing": sorted(expected - observed),
        "unexpected_record_ids": sorted(observed - expected),
        "attribution_accuracy": None,
        "false_positive_rate": None,
        "accuracy_notice": "Retrieval only. Free-text conclusions require separate human review; "
        "unlabelled claims are not automatically false.",
        **{
            key: run[key]
            for key in (
                "elapsed_seconds",
                "moves",
                "connector_calls",
                "duplicate_queries",
                "failed_queries",
                "empty_queries",
                "refused_moves",
                "reported_tokens",
                "tokens_complete",
                "monetary_cost",
                "halted_reason",
                "concluded",
            )
        },
    }
