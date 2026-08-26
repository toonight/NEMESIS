"""Plane 2 — the Pursuit Engine.

Takes an incident seed and pursues it: proposing pivots, spending a budget, evaluating what
comes back, opening new lines of enquiry, and abandoning the ones going nowhere. It is the
autonomous part of NEMESIS, which is exactly why its every decision is recorded before it
is taken rather than after.

The engine is a **state machine over an immutable** :class:`Investigation`. Each step
returns a new investigation rather than mutating one. That makes the whole pursuit
replayable: given the seed, the fixtures and the policy, the sequence reproduces, and an
analyst can ask not only what the engine looked at but what it was choosing between when it
decided.

Ordering inside a step matters and is deliberate:

1. Evidence is sealed **before** the claims that cite it are recorded. A claim referencing
   evidence that failed to seal would be a claim with unresolvable provenance, which
   invariant 3 forbids.
2. Entities and edges are materialized **after** claims are stored, so every edge's
   supporting claim already exists to be looked up.
3. The audit entry is written last and records the outcome, including failure. A step that
   dies halfway leaves sealed evidence and no audit line — visible as an inconsistency
   rather than as a clean absence.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from datetime import datetime

from nemesis.collect.isolation import collect_confined
from nemesis.collect.quarantine import (
    ArtifactAnalyser,
    Quarantine,
    StructuralAnalyser,
    seal_when_released,
)
from nemesis.core.claims import Claim
from nemesis.core.entities import Entity
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.infrastructure import InfrastructureRole
from nemesis.core.relationships import Relationship
from nemesis.core.temporal import TemporalExtent, utcnow
from nemesis.ports.collection import (
    ConnectorCapabilities,
    IntelligenceConnector,
    PivotRequest,
    PivotResult,
    PivotType,
)
from nemesis.ports.storage import AuditEvent, AuditSink, ClaimStore, EvidenceVault, GraphStore
from nemesis.pursuit.investigation import (
    BranchState,
    ExecutedPivot,
    Hypothesis,
    IncidentSeed,
    Investigation,
    InvestigationBranch,
    InvestigationState,
    PivotCandidate,
)
from nemesis.pursuit.materialize import materialize
from nemesis.pursuit.policy import PursuitPolicy, RuleBasedPursuitPolicy
from nemesis.pursuit.standing import reassess_standing

ENGINE_ACTOR_KIND = "agent"


class ConnectorRegistry:
    """Routes a pivot request to a connector that can answer it.

    Where several can, the cheapest wins. Cost comes from the connector's own declared
    capabilities, so the engine plans over the numbers the adapters publish rather than
    over a hardcoded table that will drift.
    """

    def __init__(self, connectors: Sequence[IntelligenceConnector]) -> None:
        self._connectors = tuple(connectors)

    @property
    def connectors(self) -> tuple[IntelligenceConnector, ...]:
        return self._connectors

    def capabilities(self) -> tuple[ConnectorCapabilities, ...]:
        return tuple(connector.capabilities for connector in self._connectors)

    def find(self, request: PivotRequest) -> IntelligenceConnector | None:
        able = [c for c in self._connectors if c.capabilities.can_answer(request)]
        if not able:
            return None
        return min(able, key=lambda c: c.capabilities.cost_per_call)

    def cost_table(self) -> dict[str, float]:
        costs: dict[str, float] = {}
        for connector in self._connectors:
            for pivot in connector.capabilities.supported_pivots:
                current = costs.get(pivot.value)
                cost = connector.capabilities.cost_per_call
                costs[pivot.value] = cost if current is None else min(current, cost)
        return costs


class PursuitEngine:
    """Drives an investigation forward, one auditable step at a time."""

    def __init__(
        self,
        *,
        graph: GraphStore,
        claims: ClaimStore,
        vault: EvidenceVault,
        audit: AuditSink,
        connectors: ConnectorRegistry,
        policy: PursuitPolicy | None = None,
        quarantine: Quarantine | None = None,
        analyser: ArtifactAnalyser | None = None,
        actor: str | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._graph = graph
        self._claims = claims
        self._vault = vault
        self._audit = audit
        # On by default. An engine that quarantined only when asked would be one that does
        # not quarantine, because the caller who most needs it is the one who never heard of
        # it. `StructuralAnalyser` opens nothing and reports `confined=False`; a deployment
        # taking up the extension point supplies one that runs under a real sandbox.
        self._quarantine = quarantine if quarantine is not None else Quarantine()
        self._analyser = analyser if analyser is not None else StructuralAnalyser()
        self._connectors = connectors
        self._clock = clock
        self._actor = actor or new_id(IdPrefix.ACTOR)

        costs = {
            PivotType(pivot_name): cost for pivot_name, cost in connectors.cost_table().items()
        }
        self._policy = policy or RuleBasedPursuitPolicy(connector_costs=costs)

    @property
    def actor(self) -> str:
        return self._actor

    # -- lifecycle ------------------------------------------------------------

    async def start(self, seed: IncidentSeed, *, total_budget: float = 100.0) -> Investigation:
        """Open an investigation and its first branch.

        The initial hypotheses are the ones any competent analyst forms on seeing a
        malicious domain — including, deliberately, the one that says the seed might be
        someone else's compromised infrastructure rather than the adversary's own. Starting
        with only the incriminating hypothesis is how an investigation confirms itself.
        """
        investigation_id = new_id(IdPrefix.INVESTIGATION)

        entity = Entity.create(
            entity_id=new_id(IdPrefix.ENTITY),
            entity_type=seed.entity_type,
            observed_form=seed.entity_key,
            extent=TemporalExtent.at(seed.observed_at),
            is_synthetic=seed.is_synthetic,
        )
        stored = await self._graph.upsert_entity(entity)

        hypotheses = (
            Hypothesis(
                hypothesis_id="H1",
                statement=f"{seed.entity_key} is infrastructure operated by the attacker.",
                would_be_confirmed_by=(
                    "Registration, hosting or key material tying it to other attacker assets."
                ),
                would_be_refuted_by=(
                    "Evidence that it belongs to a legitimate party and was compromised, "
                    "or that it is shared infrastructure with no attacker-specific link."
                ),
            ),
            Hypothesis(
                hypothesis_id="H2",
                statement=(
                    f"{seed.entity_key} belongs to an unrelated party whose infrastructure "
                    "was compromised or abused."
                ),
                would_be_confirmed_by=(
                    "A legitimate registrant with history predating the campaign, or "
                    "co-location with a large unrelated population."
                ),
                would_be_refuted_by=(
                    "Registration inside the campaign window with attacker-linked artifacts."
                ),
            ),
            Hypothesis(
                hypothesis_id="H3",
                statement="The observable was staged to misdirect attribution.",
                would_be_confirmed_by=(
                    "Artifacts that are cheap to plant and point conveniently at a third "
                    "party, with no corroboration from channels the adversary cannot shape."
                ),
                would_be_refuted_by=(
                    "Independent corroboration from sources the adversary does not control."
                ),
            ),
        )

        branch = InvestigationBranch(
            branch_id="B0",
            focus_entity_id=stored.entity_id,
            focus_entity_key=stored.natural_key,
            hypothesis_id="H1",
            depth=0,
            budget_allocated=total_budget * 0.5,
        )

        investigation = Investigation(
            investigation_id=investigation_id,
            seed=seed,
            branches=(branch,),
            hypotheses=hypotheses,
            total_budget=total_budget,
        )

        await self._record(
            action="investigation.start",
            subject=investigation_id,
            outcome="opened",
            inputs={
                "seed_type": seed.entity_type.value,
                "seed_key": seed.entity_key,
                "detected_by": seed.detected_by,
                "budget": str(total_budget),
                "is_synthetic": str(seed.is_synthetic),
            },
        )
        return investigation

    async def run(self, investigation: Investigation, *, max_steps: int = 40) -> Investigation:
        """Step until nothing is worth doing, or the step ceiling is reached.

        The ceiling is a safety net against a policy bug producing an unbounded loop, not a
        budget. When it is hit, that is recorded — an investigation stopped by a ceiling is
        not an investigation that finished.
        """
        for _ in range(max_steps):
            if not investigation.open_branches or investigation.budget_remaining <= 0:
                break
            stepped = await self.step(investigation)
            if stepped.step_count == investigation.step_count:
                break  # nothing left to do
            investigation = stepped
        else:
            investigation = investigation.model_copy(
                update={
                    "notes": (
                        *investigation.notes,
                        f"Stopped at the {max_steps}-step ceiling with "
                        f"{len(investigation.open_branches)} branch(es) still open. This is "
                        "a halt, not a completion.",
                    )
                }
            )
        return investigation

    async def execute_pivot(
        self,
        investigation: Investigation,
        *,
        entity_id: str,
        pivot_type: PivotType,
        rationale: str,
    ) -> tuple[Investigation, ExecutedPivot | None]:
        """Run one pivot an external driver chose, through the same machinery ``step`` uses.

        This is the seam a model-driven driver sits behind. ``step`` lets the engine's own
        deterministic policy choose the next pivot; this lets a caller outside the engine
        choose it — a frontier-model pilot, in the shape NEMESIS is built for — while keeping
        every enforcement ``step`` applies. Connector routing, the cost pulled from the
        connector's own capabilities, budget accounting, the provenance ordering in
        :meth:`_absorb` (evidence sealed before the claims that cite it) and the audit line
        are all the engine's, not the caller's.

        Nothing here trusts the caller past letting it *name* a pivot. An unknown entity or an
        unaffordable one is returned as a refusal — ``None``, or a failed :class:`ExecutedPivot`
        — and never executed on the caller's say-so. The pilot proposes; the engine disposes,
        which is invariant 7 pushed up one level from effects into investigation itself.
        """
        entity = await self._graph.get_entity(entity_id)
        if entity is None:
            return investigation, None

        branch = next(iter(investigation.open_branches), None) or investigation.branches[0]
        candidate = PivotCandidate(
            pivot_type=pivot_type,
            entity_id=entity.entity_id,
            entity_type=entity.entity_type,
            entity_key=entity.natural_key,
            expected_information_gain=0.0,
            estimated_cost=self._connectors.cost_table().get(pivot_type.value, 1.0),
            rationale=rationale or f"Pilot-selected {pivot_type.value} on {entity.natural_key}.",
        )

        if candidate.estimated_cost > investigation.budget_remaining:
            # Recorded as a refusal the caller can read, without spending anything. The
            # engine budget is a hard ceiling on a pilot that would otherwise pivot forever.
            return investigation, ExecutedPivot(
                candidate=candidate,
                executed_at=self._clock(),
                connector="none",
                succeeded=False,
                error=(
                    f"pivot cost {candidate.estimated_cost:.2f} exceeds the remaining budget "
                    f"of {investigation.budget_remaining:.2f}; not executed"
                ),
            )

        investigation = await self._execute(investigation, branch, candidate)
        executed = next(
            (
                pivot
                for b in investigation.branches
                if b.branch_id == branch.branch_id
                for pivot in reversed(b.executed)
            ),
            None,
        )
        return investigation, executed

    async def step(self, investigation: Investigation) -> Investigation:
        """Run exactly one pivot, or close a branch that has nothing left worth doing."""
        branch = self._select_branch(investigation)
        if branch is None:
            return investigation

        verdict = self._policy.should_abandon(branch)
        if verdict is not None:
            state, reason = verdict
            return await self._close_branch(investigation, branch, state, reason)

        entity = await self._graph.get_entity(branch.focus_entity_id)
        if entity is None:
            return await self._close_branch(
                investigation,
                branch,
                BranchState.ABANDONED_UNINFORMATIVE,
                "Focus entity is no longer present in the graph.",
            )

        candidates = self._policy.propose(branch, entity, investigation.hypotheses)
        affordable = [
            candidate
            for candidate in candidates
            if candidate.estimated_cost <= investigation.budget_remaining
        ]
        if not affordable:
            state, reason = (
                (BranchState.ABANDONED_BUDGET, "No affordable pivot remains for this branch.")
                if candidates
                else (BranchState.EXHAUSTED, "Every worthwhile pivot for this entity has run.")
            )
            return await self._close_branch(investigation, branch, state, reason)

        return await self._execute(investigation, branch, affordable[0])

    # -- internals ------------------------------------------------------------

    def _select_branch(self, investigation: Investigation) -> InvestigationBranch | None:
        """Shallowest open branch first, ties broken by id.

        Breadth-first, because depth-first on a graph pursuit chases one thread to
        exhaustion while an obvious lead sits unexamined one hop from the seed. The tie
        break on id keeps the order deterministic, which is what makes the run replayable.
        """
        open_branches = investigation.open_branches
        if not open_branches:
            return None
        return min(open_branches, key=lambda b: (b.depth, b.branch_id))

    async def _close_branch(
        self,
        investigation: Investigation,
        branch: InvestigationBranch,
        state: BranchState,
        reason: str,
    ) -> Investigation:
        closed = branch.model_copy(
            update={
                "state": state,
                "abandonment_reason": reason if state.value.startswith("abandoned") else None,
                "closed_at": self._clock(),
            }
        )
        await self._record(
            action="branch.close",
            subject=f"{investigation.investigation_id}/{branch.branch_id}",
            outcome=state.value,
            inputs={"reason": reason, "pivots_run": str(len(branch.executed))},
        )
        return investigation.with_branch(closed).model_copy(
            update={"step_count": investigation.step_count + 1, "last_step_at": self._clock()}
        )

    async def _execute(
        self,
        investigation: Investigation,
        branch: InvestigationBranch,
        candidate: PivotCandidate,
    ) -> Investigation:
        request = PivotRequest(
            pivot_type=candidate.pivot_type,
            entity_type=candidate.entity_type,
            entity_key=candidate.entity_key,
            reason=candidate.rationale,
        )
        connector = self._connectors.find(request)

        if connector is None:
            executed = ExecutedPivot(
                candidate=candidate,
                executed_at=self._clock(),
                connector="none",
                succeeded=False,
                error=(
                    f"No connector can answer {candidate.pivot_type.value} for "
                    f"{candidate.entity_type.value}. REQUIRES_EXTERNAL_DATA."
                ),
            )
            return await self._absorb(
                investigation,
                branch,
                executed,
                result=None,
                is_synthetic=investigation.seed.is_synthetic,
            )

        result, isolation_failure = await collect_confined(connector, request)
        if isolation_failure is not None:
            executed = ExecutedPivot(
                candidate=candidate,
                executed_at=self._clock(),
                connector=connector.capabilities.name,
                succeeded=False,
                error=isolation_failure,
                actual_cost=connector.capabilities.cost_per_call,
            )
            return await self._absorb(
                investigation,
                branch,
                executed,
                result=None,
                is_synthetic=connector.capabilities.is_simulated,
            )

        assert result is not None  # _collect returns one or the other, never neither
        executed = ExecutedPivot(
            candidate=candidate,
            executed_at=self._clock(),
            connector=result.connector_name,
            succeeded=result.succeeded,
            error=result.error,
            truncated=result.truncated,
            actual_cost=connector.capabilities.cost_per_call,
        )
        return await self._absorb(
            investigation,
            branch,
            executed,
            result=result,
            is_synthetic=connector.capabilities.is_simulated,
        )

    async def _absorb(
        self,
        investigation: Investigation,
        branch: InvestigationBranch,
        executed: ExecutedPivot,
        *,
        result: PivotResult | None,
        is_synthetic: bool,
    ) -> Investigation:
        """Persist what came back, in the order provenance requires."""
        sealed: list[str] = []
        held: list[str] = []
        recorded: list[Claim] = []
        discovered: list[str] = []
        materialized_entities: dict[tuple[str, str], None] = {}
        materialized_edges: list[Relationship] = []
        skipped: tuple[str, ...] = ()

        if result is not None and result.succeeded:
            # Evidence first: a claim citing evidence that failed to seal would have
            # unresolvable provenance.
            for evidence in result.evidence:
                artifact = result.artifacts.get(evidence.evidence_id)
                if artifact is None:
                    continue

                sealed_id, _report = await seal_when_released(
                    self._vault,
                    evidence,
                    artifact,
                    quarantine=self._quarantine,
                    analyser=self._analyser,
                )
                if sealed_id is None:
                    # Held. Failure holds rather than releases, so neither the artifact nor
                    # anything citing it reaches the vault.
                    held.append(evidence.evidence_id)
                    continue
                sealed.append(sealed_id)

            for claim in result.observations:
                # A claim citing held evidence would have unresolvable provenance — invariant
                # 3 — so it is dropped with the artifact rather than recorded pointing at
                # nothing.
                if held and set(claim.supported_by_evidence) & set(held):
                    continue
                recorded.append(await self._claims.record(claim))

            materialized = materialize(tuple(recorded), is_synthetic=is_synthetic)
            skipped = materialized.skipped
            for entity in materialized.entities:
                stored = await self._graph.upsert_entity(entity)
                discovered.append(stored.entity_id)
                materialized_entities[(stored.entity_type.value, stored.natural_key)] = None
            for relationship in materialized.relationships:
                await self._graph.add_relationship(relationship)
                materialized_edges.append(relationship)

        # Reassess whose each *affected* node is, now that this pivot's edges and claims are in
        # the graph. Done here rather than at approval time because this is where the knowledge
        # changes: a node that looked like the adversary's before an ownership claim arrived
        # must stop looking like it the moment one does, and a capability signed against the
        # old answer stops matching its target fingerprint on its own.
        #
        # Both ends of every new edge, not merely the entities this pivot discovered. Assessing
        # `discovered` alone classifies a node when it is *found* and never again, so a control
        # edge landing on an already-known node three pivots later would change the evidence and
        # not the classification.
        #
        # Honest note on how well this is tested: the change is **not** observable on the
        # reference scenario. Its only control edges are three `operated_by` edges running
        # asn -> organization — a host operating its own ASN — which correctly move no standing
        # because an ORGANIZATION is not the adversary. The tally there is 11 classified nodes
        # before and after. The gap this closes is covered by unit tests, not by the demo.
        affected = [
            *discovered,
            *(edge.source_id for edge in materialized_edges),
            *(edge.target_id for edge in materialized_edges),
        ]
        standing = await reassess_standing(
            self._graph,
            affected,
            claims=recorded,
            assessed_at=self._clock(),
        )

        executed = executed.model_copy(
            update={
                "claims_produced": tuple(claim.claim_id for claim in recorded),
                "evidence_produced": tuple(sealed),
                "entities_discovered": tuple(discovered),
            }
        )

        updated_branch = branch.model_copy(
            update={
                "executed": (*branch.executed, executed),
                "budget_spent": branch.budget_spent + executed.actual_cost,
            }
        )
        investigation = investigation.with_branch(updated_branch).model_copy(
            update={
                "budget_spent": investigation.budget_spent + executed.actual_cost,
                "step_count": investigation.step_count + 1,
                "last_step_at": self._clock(),
            }
        )

        investigation = await self._spawn_branches(investigation, updated_branch, discovered)

        await self._record(
            action="pivot.execute",
            subject=f"{investigation.investigation_id}/{branch.branch_id}",
            outcome="succeeded" if executed.succeeded else "failed",
            inputs={
                "pivot": executed.candidate.pivot_type.value,
                "entity": executed.candidate.entity_key,
                # The type as well as the key, because a persona and a domain can spell the
                # same string and the cross-case index keys on the pair. Without it the two
                # merge, and a merged node is the second way an attribution engine deceives
                # itself: three weak links become an apparent cluster.
                "entity_type": executed.candidate.entity_type.value,
                "connector": executed.connector,
                "reason": executed.candidate.rationale,
                "expected_gain": f"{executed.candidate.expected_information_gain:.2f}",
                "claims": str(len(recorded)),
                "evidence_sealed": str(len(sealed)),
                "entities": str(len(discovered)),
                # The count above detects gross drift and cannot reconstruct which nodes
                # entered the case. The typed natural keys are the durable filing record:
                # entity ids are graph-local aliases and disappear at process boundaries.
                # Sorted and compact so the same connector answer produces the same audit
                # input regardless of claim ordering. PivotRequest.max_results bounds the
                # list; this never serializes an unbounded graph traversal.
                "materialized_entities": json.dumps(
                    sorted(materialized_entities), separators=(",", ":")
                ),
                "truncated": str(executed.truncated),
                "error": executed.error or "",
                "unmaterialized_claims": str(len(skipped)),
                # Recorded as a tally so a run where classification silently stopped
                # happening shows up as a changed count rather than as nothing.
                "standing_assessed": str(len(standing)),
                "standing_unknown": str(
                    sum(1 for role in standing.values() if role is InfrastructureRole.UNKNOWN)
                ),
            },
        )
        return investigation

    async def _spawn_branches(
        self,
        investigation: Investigation,
        parent: InvestigationBranch,
        discovered: Sequence[str],
    ) -> Investigation:
        existing = {b.focus_entity_id for b in investigation.branches}
        depth = parent.depth + 1
        counter = len(investigation.branches)

        for entity_id in discovered:
            if entity_id in existing:
                continue
            entity = await self._graph.get_entity(entity_id)
            if entity is None or not self._policy.should_branch_on(entity, depth):
                continue

            investigation = investigation.with_branch(
                InvestigationBranch(
                    branch_id=f"B{counter}",
                    parent_branch_id=parent.branch_id,
                    focus_entity_id=entity.entity_id,
                    focus_entity_key=entity.natural_key,
                    hypothesis_id=parent.hypothesis_id,
                    depth=depth,
                    budget_allocated=max(2.0, parent.budget_allocated * 0.4),
                )
            )
            existing.add(entity_id)
            counter += 1

        return investigation

    async def _record(
        self, *, action: str, subject: str, outcome: str, inputs: dict[str, str]
    ) -> None:
        await self._audit.record(
            AuditEvent(
                audit_id=new_id(IdPrefix.AUDIT),
                occurred_at=self._clock(),
                actor=self._actor,
                actor_kind=ENGINE_ACTOR_KIND,
                action=action,
                subject=subject,
                outcome=outcome,
                inputs=inputs,
            )
        )


def mark_awaiting_authorization(investigation: Investigation) -> Investigation:
    return investigation.model_copy(update={"state": InvestigationState.AWAITING_AUTHORIZATION})


def mark_monitoring_resurgence(investigation: Investigation) -> Investigation:
    """A takedown closes no case. Invariant 14."""
    return investigation.model_copy(update={"state": InvestigationState.MONITORING_RESURGENCE})
