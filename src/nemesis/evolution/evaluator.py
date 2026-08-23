"""What counts as progress, measured from structure the model cannot write.

This is the most important module in the plane, and its whole design follows from one refusal:
**nothing a model says about its own work may raise a score here.** "I am 95% confident", "this is
almost certainly actor X", a long and fluent rationale — each of those is a
:class:`~nemesis.core.claims.Claim` of kind HYPOTHESIS somewhere in the claim store, and none of
them appears in any term below. What is measured is what the platform *observed*: evidence objects
that sealed, the provenance clusters behind them, entities that are not shared infrastructure,
edges whose population was actually counted, and hypotheses whose state the engine moved.

The evaluation is **hierarchical, not weighted** (see :class:`~nemesis.evolution.models.
ScoreVector`), and it runs in a fixed order:

    gate 0  hard validity      → INVALID, at any apparent gain
    tier 1  epistemic progress → did the investigation learn something
    tier 2  investigation utility → were the discoveries discriminating
    tier 3  efficiency         → tie-break only

AVO's correctness requirement is the analogue of gate 0 and the analogy is exact: a very fast CUDA
kernel that computes the wrong answer is not an improvement. What is *not* analogous is the
objective. AVO optimises a benchmark that is right by construction; there is no such oracle for
attribution, so this module deliberately measures the *shape* of investigative progress rather than
the confidence of a conclusion.

**Honesty about what currently moves.** Three tier-1 terms are computed from state that nothing in
the shipped engine writes: ``hypotheses_settled`` and ``uncertainty_reduction`` read
:class:`~nemesis.pursuit.investigation.Hypothesis`, whose state and
:class:`~nemesis.core.confidence.Opinion` the pursuit engine never updates, and
``contradictions_resolved`` reads :attr:`~nemesis.core.claims.Claim.contradicted_by_claims`, which
no shipped connector populates. The code is real and unit-tested against constructed state; in the
reference demonstration those three terms are always zero. Stating that here rather than letting a
reader infer movement from the presence of a field: a metric that cannot move is not a metric that
is working.

Status: `IMPLEMENTED`. The scoring *shape* is a documented choice and not a measurement — like
every other calibration constant in this repository, it is frozen so it can be argued with, and it
has never been validated against a resolved case because none exists.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from nemesis.core.claims import Claim, ClaimKind, DerivationKind
from nemesis.core.disclosure import DisclosureClass, disclosure_of_entity
from nemesis.core.entities import Entity
from nemesis.core.provenance import SourceDescriptor
from nemesis.evolution.memory import ResearchMemory
from nemesis.evolution.models import (
    MAX_REFS,
    CandidateStatus,
    CheckpointRefs,
    EpistemicGate,
    EvaluationResult,
    GateFinding,
    ScoreVector,
    TrajectoryMeasurement,
)
from nemesis.evolution.ports import ClaimReader, EntityReader, EvidenceReader
from nemesis.pilot.mediator import PilotSession
from nemesis.pilot.moves import RulingStatus, RunPivot
from nemesis.ports.storage import GraphQuery
from nemesis.pursuit.investigation import Investigation

NEIGHBOURHOOD_DEPTH = 2
"""How far the evaluator traverses to count discriminating edges.

Two hops, and bounded on purpose. The point is to see the edges this trajectory created, not to
walk the graph — and a traversal that grew with the investigation would make evaluation cost grow
with the thing it is evaluating, which is how a long-horizon loop becomes quadratic.
"""


@dataclass(frozen=True)
class StepObservation:
    """Everything the evaluator is allowed to look at for one variation step.

    A dataclass rather than a model because it is assembled and consumed inside one process and
    never persisted — what *is* persisted is the :class:`~nemesis.evolution.models.
    InvestigationCheckpoint` built from the result.
    """

    session: PilotSession
    investigation: Investigation
    memory: ResearchMemory
    moves_allowed: int


class PursuitEvaluator:
    """Measures an investigation's state and scores what one step changed.

    Holds three read-only ports and nothing else. It cannot write the graph, mint a claim, seal
    evidence or spend a capability — which is what makes its own measurements trustworthy, because
    a component that could improve the thing it measures is a component that eventually will.
    """

    def __init__(
        self,
        *,
        entities: EntityReader,
        claims: ClaimReader,
        evidence: EvidenceReader,
    ) -> None:
        self._entities = entities
        self._claims = claims
        self._evidence = evidence

    # -- measurement -----------------------------------------------------------

    async def measure(self, investigation: Investigation) -> TrajectoryMeasurement:
        """The absolute structural state of one investigation. No comparison, no judgement."""
        executed = investigation.all_executed_pivots
        evidence_ids = tuple(
            dict.fromkeys(eid for pivot in executed for eid in pivot.evidence_produced)
        )
        claim_ids = tuple(dict.fromkeys(cid for pivot in executed for cid in pivot.claims_produced))
        entity_ids = tuple(
            dict.fromkeys(eid for pivot in executed for eid in pivot.entities_discovered)
        )

        sources = await self._sources_of(evidence_ids)
        origins = _origins(sources)
        claims = await self._claims_of(claim_ids)
        entities = await self._entities_of(entity_ids)

        useful = sum(1 for entity in entities if not entity.is_shared_infrastructure)
        shared = len(entities) - useful

        return TrajectoryMeasurement(
            evidence_count=len(evidence_ids),
            independent_origins=len(origins.clusters),
            origin_floor=origins.floor,
            unplantable_origins=len(origins.unplantable),
            claim_count=len(claims),
            evidence_backed_claims=sum(1 for claim in claims if claim.supported_by_evidence),
            open_contradictions=_open_contradictions(claims),
            settled_hypotheses=sum(1 for h in investigation.hypotheses if h.is_settled),
            total_hypothesis_uncertainty=sum(
                h.confidence.uncertainty for h in investigation.hypotheses
            ),
            useful_entities=useful,
            shared_infrastructure_entities=shared,
            discriminating_relationships=await self._discriminating_edges(investigation),
            pivots_executed=len(executed),
            informative_pivots=sum(1 for pivot in executed if pivot.was_informative),
            budget_spent=investigation.budget_spent,
        )

    # -- evaluation ------------------------------------------------------------

    async def evaluate(
        self,
        observation: StepObservation,
        *,
        parent: TrajectoryMeasurement | None,
    ) -> EvaluationResult:
        """Gate, measure, score. In that order, and the order is the design.

        Gate findings are collected *before* any gain is computed and are never traded against
        one. A candidate that failed a hard gate is returned INVALID with the score it happened to
        earn, so an operator can see what it was about to buy — reporting a zero score there would
        hide the size of the temptation.
        """
        findings = await self._gate(observation)
        measurement = await self.measure(observation.investigation)
        score = self._score(observation, measurement, parent)
        refs = await self._refs(observation.investigation)
        if findings:
            return EvaluationResult(
                status=CandidateStatus.INVALID,
                score=score,
                measurement=measurement,
                refs=refs,
                gate_findings=findings,
                notes=(
                    "a hard gate failed; the score is reported so the gain this candidate would "
                    "have been promoted for is visible, not so it can be weighed against the gate",
                ),
            )
        return EvaluationResult(
            status=CandidateStatus.REJECTED,
            score=score,
            measurement=measurement,
            refs=refs,
        )

    async def _refs(self, investigation: Investigation) -> CheckpointRefs:
        """The references a checkpoint may carry, filtered to deliverable-class material.

        Built here rather than in the controller so that what a checkpoint *carries* and what the
        gates *check* cannot disagree — they did, and the disagreement was sticky. Founder decision
        D1 governs a checkpoint exactly as it governs an export, and the mediator's own treatment of
        an internal-class entity is the model: filter the projection, count what was withheld, and
        keep the gate as a fail-closed backstop over what is left.
        """
        executed = investigation.all_executed_pivots
        evidence_ids = tuple(
            dict.fromkeys(eid for pivot in executed for eid in pivot.evidence_produced)
        )
        entity_ids = tuple(
            dict.fromkeys(eid for pivot in executed for eid in pivot.entities_discovered)
        )
        claim_ids = tuple(dict.fromkeys(cid for pivot in executed for cid in pivot.claims_produced))

        deliverable: list[str] = []
        withheld = 0
        for entity_id in entity_ids:
            entity = await self._entities.get_entity(entity_id)
            if entity is None:
                continue
            if disclosure_of_entity(entity.entity_type) is not DisclosureClass.DELIVERABLE:
                withheld += 1
                continue
            deliverable.append(entity_id)

        sources = await self._sources_of(evidence_ids)
        return CheckpointRefs(
            evidence_refs=evidence_ids[:MAX_REFS],
            entity_refs=tuple(deliverable)[:MAX_REFS],
            claim_refs=claim_ids[:MAX_REFS],
            origin_cluster_refs=_origins(sources).clusters[:MAX_REFS],
            withheld_entities=withheld,
        )

    # -- gate 0 ----------------------------------------------------------------

    async def _gate(self, observation: StepObservation) -> tuple[GateFinding, ...]:
        findings: list[GateFinding] = []
        session = observation.session
        investigation = observation.investigation

        # AUTHORIZATION_BOUNDARY. Fail-closed by construction: `any_effect_left_the_platform`
        # treats an accepted effect that came back without saying as having left.
        if session.any_effect_left_the_platform():
            findings.append(
                GateFinding(
                    gate=EpistemicGate.AUTHORIZATION_BOUNDARY,
                    detail=(
                        "an effect in this step reported contact with the outside world, or ran "
                        "and did not say. Invariant 15 admits no trajectory that did"
                    ),
                )
            )

        # POLICY. The mediator bounds the move count; this checks the bound held, because a
        # segment that spent more than it was allowed is a control that did not.
        if len(session.transcript) > observation.moves_allowed:
            findings.append(
                GateFinding(
                    gate=EpistemicGate.POLICY,
                    detail=(
                        f"the step spent {len(session.transcript)} moves against a ceiling of "
                        f"{observation.moves_allowed}"
                    ),
                )
            )

        # EVIDENCE_SEMANTICS. Every belief the pilot recorded, re-read from the store and checked
        # against invariant 1 at the exact point where a search would benefit from it being false.
        for ruling in session.rulings:
            if not ruling.recorded_claim_id:
                continue
            claim = await self._claims.get(ruling.recorded_claim_id)
            if claim is None:
                findings.append(
                    GateFinding(
                        gate=EpistemicGate.PROVENANCE,
                        detail=(
                            f"the step reports recording claim {ruling.recorded_claim_id} and the "
                            "claim store does not hold it"
                        ),
                    )
                )
                continue
            if claim.kind is not ClaimKind.HYPOTHESIS or (
                claim.derivation is not DerivationKind.MODEL_ASSERTION
            ):
                findings.append(
                    GateFinding(
                        gate=EpistemicGate.EVIDENCE_SEMANTICS,
                        detail=(
                            f"claim {claim.claim_id} recorded by the pilot is "
                            f"{claim.kind.value}/{claim.derivation.value}; a pilot belief is a "
                            "HYPOTHESIS from a MODEL_ASSERTION and nothing else"
                        ),
                    )
                )

        # PROVENANCE and SCOPE and IDENTITY, over what this investigation actually produced.
        for pivot in investigation.all_executed_pivots:
            for evidence_id in pivot.evidence_produced:
                if await self._evidence.get(evidence_id) is None:
                    findings.append(
                        GateFinding(
                            gate=EpistemicGate.PROVENANCE,
                            detail=(
                                f"evidence {evidence_id} is cited by the trajectory and does not "
                                "resolve in the vault"
                            ),
                        )
                    )
                    break
            for entity_id in pivot.entities_discovered:
                entity = await self._entities.get_entity(entity_id)
                if entity is None:
                    findings.append(
                        GateFinding(
                            gate=EpistemicGate.SCOPE,
                            detail=(
                                f"entity {entity_id} is cited by the trajectory and the graph does "
                                "not hold it"
                            ),
                        )
                    )
                    break

        # SOURCE_INDEPENDENCE. Re-derived from the descriptors rather than trusted from the
        # measurement, so a future change that turned missing provenance into asserted
        # independence fails a gate instead of raising a score.
        #
        # The first version of this check was **dead**, and an adversarial review proved it by
        # showing the predicate was unsatisfiable: it counted how many times the unknown-lineage
        # key appeared in a *deduplicated* tuple, which is zero or one and never more. A gate that
        # cannot fire is worse than a missing one, because its presence is read as coverage. What
        # is checked now is the property the gate is actually named for: however many sources have
        # no established lineage, they may contribute **at most one** origin between them.
        evidence_ids = tuple(
            dict.fromkeys(
                eid
                for pivot in investigation.all_executed_pivots
                for eid in pivot.evidence_produced
            )
        )
        sources = await self._sources_of(evidence_ids)
        unknown = [source for source in sources if not source.has_known_lineage]
        origins = _origins(sources)
        known_clusters = {
            cluster
            for cluster in origins.clusters
            if cluster != SourceDescriptor.UNKNOWN_LINEAGE_CLUSTER
        }
        ceiling = len(known_clusters) + (1 if unknown else 0)
        if len(origins.clusters) > ceiling:
            findings.append(
                GateFinding(
                    gate=EpistemicGate.SOURCE_INDEPENDENCE,
                    detail=(
                        f"{len(unknown)} source(s) with no established lineage produced "
                        f"{len(origins.clusters)} independent origin(s) against a ceiling of "
                        f"{ceiling}; absence of a recorded upstream is not evidence of "
                        "independence"
                    ),
                )
            )
        # IDENTITY, as a fail-closed backstop over what the checkpoint will actually carry.
        # `_refs` has already filtered internal-class entities out, so reaching this is a leak path
        # somebody opened and must close at its source, not catch here.
        for entity_id in (await self._refs(investigation)).entity_refs:
            entity = await self._entities.get_entity(entity_id)
            if entity is None:
                continue
            if disclosure_of_entity(entity.entity_type) is not DisclosureClass.DELIVERABLE:
                findings.append(
                    GateFinding(
                        gate=EpistemicGate.IDENTITY,
                        detail=(
                            f"entity {entity_id} is "
                            f"{disclosure_of_entity(entity.entity_type).value} and reached a "
                            "checkpoint's references; a checkpoint is durable and projectable, and "
                            "internal-classified material does not travel (founder decision D1)"
                        ),
                    )
                )
                break

        return tuple(_deduplicate(findings))

    # -- scoring ---------------------------------------------------------------

    def _score(
        self,
        observation: StepObservation,
        measurement: TrajectoryMeasurement,
        parent: TrajectoryMeasurement | None,
    ) -> ScoreVector:
        before = parent or TrajectoryMeasurement()
        session = observation.session
        memory = observation.memory

        # Novelty and redundancy are counted over what the mediator ACCEPTED, not over what the
        # pilot proposed. An adversarial review found the difference paying: `novel_pivot_families`
        # read every proposal, including ones the mediator refused, and it is a tier-2 term that on
        # its own promotes a candidate. A pilot naming three pivot families it had never named
        # before — on an entity that does not exist, so all three are refused — scored three
        # novelties and got its checkpoint promoted for proposing nothing that ran. A search must
        # not be able to buy progress with a refusal.
        accepted: list[RunPivot] = [
            turn.move
            for turn in session.transcript
            if isinstance(turn.move, RunPivot) and turn.ruling.status is RulingStatus.ACCEPTED
        ]
        accepted_pivots = len(accepted)
        # A `record_belief` is where a model states a conclusion, and it appears in exactly one
        # term below — `moves_spent`, a cost. There is deliberately no term it can raise. This is
        # the line `test_model_confidence_cannot_raise_evolution_score` pins, and it is a property
        # of what this function reads rather than of anything the mediator refuses.
        families_before = (
            set(memory.exhausted_pivot_families)
            | {result.pivot_family for result in memory.failed_directions}
            | {entry.repeat_key.split(":", 1)[0] for entry in memory.high_value_pivot_families}
        )
        accepted_families = {pivot.pivot_type.value for pivot in accepted}
        redundant = sum(
            1 for pivot in accepted if memory.has_tried(pivot.pivot_type.value, pivot.entity_id)
        )

        return ScoreVector(
            origin_floor_gain=measurement.origin_floor - before.origin_floor,
            independent_origin_gain=(measurement.independent_origins - before.independent_origins),
            contradictions_resolved=max(
                0, before.open_contradictions - measurement.open_contradictions
            ),
            hypotheses_settled=measurement.settled_hypotheses - before.settled_hypotheses,
            uncertainty_reduction=max(
                0.0,
                before.total_hypothesis_uncertainty - measurement.total_hypothesis_uncertainty,
            ),
            evidence_backed_claim_gain=(
                measurement.evidence_backed_claims - before.evidence_backed_claims
            ),
            useful_entities_discovered=measurement.useful_entities - before.useful_entities,
            discriminating_relationships_gained=(
                measurement.discriminating_relationships - before.discriminating_relationships
            ),
            novel_pivot_families=len(accepted_families - families_before),
            pivots_spent=accepted_pivots,
            moves_spent=len(session.transcript),
            budget_spent=max(0.0, measurement.budget_spent - before.budget_spent),
            redundant_pivots=redundant,
            refused_moves=sum(1 for ruling in session.rulings if not ruling.accepted),
        )

    # -- reads -----------------------------------------------------------------

    async def _sources_of(self, evidence_ids: Sequence[str]) -> tuple[SourceDescriptor, ...]:
        found: list[SourceDescriptor] = []
        for evidence_id in evidence_ids:
            evidence = await self._evidence.get(evidence_id)
            if evidence is not None:
                found.append(evidence.provenance.source)
        return tuple(found)

    async def _claims_of(self, claim_ids: Sequence[str]) -> tuple[Claim, ...]:
        found: list[Claim] = []
        for claim_id in claim_ids:
            claim = await self._claims.get(claim_id)
            if claim is not None:
                found.append(claim)
        return tuple(found)

    async def _entities_of(self, entity_ids: Sequence[str]) -> tuple[Entity, ...]:
        found: list[Entity] = []
        for entity_id in entity_ids:
            entity = await self._entities.get_entity(entity_id)
            if entity is not None:
                found.append(entity)
        return tuple(found)

    async def _discriminating_edges(self, investigation: Investigation) -> int:
        """How many distinct, *resolvable* edges around the seed actually narrowed the field.

        Three conditions, and the third exists because of a defect this evaluator found in the
        plane below it.

        **Selective.** :class:`~nemesis.core.relationships.PivotSelectivity` decides, not this
        module. An uncounted population is not informative here for the reason it weighs zero in an
        edge: assuming a pivot was selective when nobody counted is how shared hosting becomes an
        adversary cluster.

        **Distinct by what it asserts, not by its identifier.** Re-executing an identical pivot
        mints a fresh claim — the assertion time differs — and materialization turns that into a
        second :class:`~nemesis.core.relationships.Relationship` with a new ``edge_id`` saying the
        same thing. Counting identifiers made *running the same pivot again* look like a discovery,
        which is a search rewarded for repeating itself.

        **Resolvable at both ends.** ``nemesis.pursuit.materialize`` mints entity identifiers and
        builds edges against them, and ``PursuitEngine._absorb`` then upserts the entities — which
        *merges* an entity that already exists and returns the canonical one — while adding the
        edges unchanged. So every edge touching an already-known entity references an identifier
        the graph does not hold. Measured on the reference fixtures: three executions of one
        registration pivot leave two entities in the store and six distinct endpoint identifiers on
        three edges, none of which resolve.

        That is a defect in the Pursuit plane and it is **not fixed here** — changing graph-write
        semantics is a separate change with its own blast radius, and it is reported rather than
        quietly patched from a plane that must not write the graph at all. What this method does is
        refuse to be *inflated* by it: an edge whose endpoints the graph cannot vouch for is not an
        edge this evaluator will pay for. The honest consequence is that the figure reads zero on
        the current fixtures, and a zero that is true beats a number that counts phantoms.
        """
        if not investigation.branches:
            return 0
        assertions: set[tuple[str, str, str, str, str]] = set()
        for branch in investigation.branches[:1]:
            subgraph = await self._entities.neighbourhood(
                GraphQuery(
                    entity_id=branch.focus_entity_id,
                    max_depth=NEIGHBOURHOOD_DEPTH,
                    exclude_shared_infrastructure=False,
                )
            )
            resolvable = {entity.entity_id for entity in subgraph.entities}
            for relationship in subgraph.relationships:
                selectivity = relationship.selectivity
                if selectivity is None or not selectivity.is_informative:
                    continue
                if relationship.source_id not in resolvable:
                    continue
                if relationship.target_id not in resolvable:
                    continue
                assertions.add(
                    (
                        relationship.source_id,
                        relationship.target_id,
                        relationship.relation.value,
                        relationship.pivot_method.value,
                        selectivity.attribute,
                    )
                )
        return len(assertions)


@dataclass(frozen=True)
class _Origins:
    clusters: tuple[str, ...]
    unplantable: tuple[str, ...]
    floor: int


def _origins(sources: Sequence[SourceDescriptor]) -> _Origins:
    """Group sources into provenance clusters and compute the counterfactual floor.

    The floor is ADR-0004's robustness margin, applied to origins rather than to a fused opinion:
    remove the single most load-bearing cluster an adversary could have authored, and count what is
    left. A *named* cluster survives removal if any source in it sits in a channel an adversary
    cannot write into — which, per :data:`~nemesis.core.provenance.UNPLANTABLE_SOURCE_CLASSES`, is
    a deliberately short list.

    **The unknown-lineage bucket never survives, whatever it contains.** That is a correction an
    adversarial review forced and the reasoning is the same one
    :meth:`~nemesis.core.provenance.SourceDescriptor.provenance_cluster` gives for the bucket
    existing at all. A named cluster is a set of sources known to share an origin, so one
    unplantable member vouches for the rest. ``lineage:unknown`` is the opposite: a bag of sources
    about which nothing is established, grouped *conservatively* rather than because they are
    related. Treating it as unplantable because one anonymous own-sensor artifact landed in it
    would launder nine anonymous planted ones into the robustness floor — the precise laundering
    the bucket was introduced to prevent, reintroduced one level up.

    This does **not** re-run :mod:`nemesis.core.fusion`. Fusion combines opinions about a stated
    proposition, and a trajectory is not a proposition; what is reused is the pair of primitives
    fusion itself rests on — the clustering and the plantability allowlist — so the two cannot
    drift apart on the question of what independence means.
    """
    clusters: dict[str, bool] = {}
    for source in sources:
        key = source.provenance_cluster()
        vouched = not source.is_adversary_influenceable
        if key == SourceDescriptor.UNKNOWN_LINEAGE_CLUSTER:
            vouched = False
        clusters[key] = clusters.get(key, False) or vouched
    unplantable = tuple(sorted(key for key, safe in clusters.items() if safe))
    plantable = [key for key, safe in clusters.items() if not safe]
    floor = max(0, len(clusters) - (1 if plantable else 0))
    return _Origins(tuple(sorted(clusters)), unplantable, floor)


def _open_contradictions(claims: Sequence[Claim]) -> int:
    """Contradiction pairs where both sides are present in this investigation.

    Both sides, deliberately. A claim naming a contradiction we do not hold is a lead, not a
    contradiction the investigation has to resolve, and counting it would make an investigation
    look conflicted for citing something it never collected.
    """
    known = {claim.claim_id for claim in claims}
    pairs = {
        frozenset((claim.claim_id, other))
        for claim in claims
        for other in claim.contradicted_by_claims
        if other in known
    }
    return len(pairs)


def _deduplicate(findings: Sequence[GateFinding]) -> list[GateFinding]:
    seen: set[tuple[str, str]] = set()
    unique: list[GateFinding] = []
    for finding in findings:
        key = (finding.gate.value, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


__all__ = ["NEIGHBOURHOOD_DEPTH", "PursuitEvaluator", "StepObservation"]
