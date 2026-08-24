"""The resurgence watch: finding candidate signals in the graph, and inventing none.

:mod:`nemesis.pursuit.resurgence` scores signals it is handed and deliberately holds no graph
handle — a scorer that can go looking for evidence will find the evidence that supports the
answer it is reaching. This is the other half: it walks the graph and produces the signals,
and it is where the restraint has to live.

**How a signal appears in a graph.** Continuity between an old operation and a new one shows up
as two entities attached to the same *bridge* node — two addresses presenting one certificate,
two wallets in one cluster, two samples in one family. So the walk is two hops of depth one:
out from each known entity to its bridges, then back from each bridge to whoever else touches
it. Depth one twice rather than a depth-two traversal, because the traversal has its own
policy about expanding through shared infrastructure and this walk wants to *see* those bridges
in order to score them at nothing rather than to miss them.

**The rule this module exists to hold: a population is never counted from our own graph.** We
know of two domains through this registrar; the registrar has forty thousand customers. A local
count is a lower bound on the world's, and a lower bound used as a population turns a
coincidence into the strongest signal in the assessment. So a bridge is either globally unique
by construction — a full certificate fingerprint, a full PGP fingerprint, a key — or it carries
no population at all and contributes exactly zero.

**What a graph alone cannot establish, and the consequence.** ``Relationship`` and ``Claim``
carry no :class:`~nemesis.core.provenance.SourceDescriptor`; provenance lives on the evidence in
the vault, reached through a claim. A caller holding only a graph handle therefore cannot show
that any fact came from a channel an adversary could not author, so the default descriptor here
is plantable and unjudgeable — the robustness margin then removes everything and the engine
reports a lead rather than a finding.

That is the correct output, not a limitation to be worked around. A confident resurgence claim
assembled from a graph whose provenance nobody checked is exactly what this platform exists to
refuse. A caller that *can* resolve provenance passes ``provenance_of`` and gets a stronger
answer honestly.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict

from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import ClaimId
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotSelectivity, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.ports.storage import GraphQuery, GraphStore
from nemesis.pursuit.investigation import (
    Investigation,
    InvestigationBranch,
    InvestigationState,
)
from nemesis.pursuit.resurgence import (
    ResurgenceAssessment,
    ResurgenceEngine,
    ResurgenceSignal,
    ResurgenceSignalKind,
)


class BridgeRule:
    """One way two entities can be shown to share something, and what that is worth."""

    __slots__ = ("bridge_types", "globally_unique", "kind", "relations")

    def __init__(
        self,
        *,
        kind: ResurgenceSignalKind,
        bridge_types: frozenset[EntityType],
        relations: frozenset[RelationType],
        globally_unique: bool,
    ) -> None:
        self.kind = kind
        self.bridge_types = bridge_types
        self.relations = relations
        self.globally_unique = globally_unique


BRIDGE_RULES: Final[tuple[BridgeRule, ...]] = (
    BridgeRule(
        kind=ResurgenceSignalKind.SHARED_PRIVATE_KEY,
        bridge_types=frozenset({EntityType.TLS_CERTIFICATE, EntityType.SSH_KEY}),
        relations=frozenset({RelationType.PRESENTS_CERTIFICATE, RelationType.SHARES_KEY}),
        # Serving TLS with a certificate requires its private key, so two hosts presenting one
        # certificate is control of key material rather than knowledge of a public value. The
        # caveat worth stating: a *stolen* key produces the same observation, which is why the
        # engine's ceiling for this kind is 0.90 and not higher.
        globally_unique=True,
    ),
    BridgeRule(
        kind=ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT,
        bridge_types=frozenset({EntityType.PGP_KEY}),
        relations=frozenset({RelationType.SIGNED_BY}),
        # A published fingerprint identifies by construction — but publishing one demonstrates
        # nothing about holding the key, which is the engine's reason for the lower ceiling.
        globally_unique=True,
    ),
    BridgeRule(
        kind=ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
        bridge_types=frozenset(
            {
                EntityType.MALWARE_FAMILY,
                EntityType.SOURCE_CODE_ARTIFACT,
                EntityType.PHISHING_KIT,
            }
        ),
        relations=frozenset(
            {
                RelationType.BELONGS_TO_FAMILY,
                RelationType.SHARES_CODE_WITH,
                RelationType.BUILT_WITH,
                RelationType.VARIANT_OF,
            }
        ),
        globally_unique=False,
    ),
    BridgeRule(
        kind=ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT,
        bridge_types=frozenset({EntityType.WALLET_CLUSTER}),
        relations=frozenset({RelationType.CLUSTERED_WITH, RelationType.TRANSACTS_WITH}),
        globally_unique=False,
    ),
    BridgeRule(
        kind=ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN,
        bridge_types=frozenset({EntityType.REGISTRAR, EntityType.HOSTING_PROVIDER, EntityType.ASN}),
        relations=frozenset(
            {
                RelationType.REGISTERED_THROUGH,
                RelationType.HOSTED_ON,
                RelationType.ANNOUNCED_BY,
            }
        ),
        globally_unique=False,
    ),
)
"""Bridge node types, the edges that reach them, and whether the bridge identifies by itself.

``globally_unique`` is asserted for exactly two rules and both earn it: a full certificate
fingerprint and a full PGP fingerprint identify by construction. Everything else — a malware
family, a wallet cluster, a registrar — is shared by an unknown number of parties, gets no
population, and therefore contributes nothing until somebody counts it against a named corpus.
"""


def _unresolved_provenance(_claims: tuple[ClaimId, ...]) -> SourceDescriptor:
    """The descriptor used when the caller cannot resolve provenance.

    Deliberately the weakest honest answer: an open-source class, which the plantability
    allowlist treats as adversary-writable, and a reliability of "cannot be judged". Both are
    true of a fact whose origin nobody looked up, and both push the assessment toward a lead.

    The alternative — guessing at ``OWN_SENSOR`` because the observation is in *our* graph —
    would mark every assembled fact unplantable and let the robustness margin pass anything.
    Ownership of the record is not authorship of the fact; the same confusion the source
    allowlist already refuses for honeypots.
    """
    return SourceDescriptor(
        source_class=SourceClass.OPEN_SOURCE,
        identifier="graph-traversal (provenance not resolved)",
        reliability=SourceReliability.CANNOT_BE_JUDGED,
    )


def _rule_for(bridge: Entity, relation: RelationType) -> BridgeRule | None:
    for rule in BRIDGE_RULES:
        if bridge.entity_type in rule.bridge_types and relation in rule.relations:
            return rule
    return None


async def _ends_of(graph: GraphStore, edge: Relationship) -> tuple[Entity, Entity] | None:
    """Both ends of an edge, resolved to the entities they now belong to.

    Resolved rather than compared by id, and this is not defensive coding. ``merge_entities``
    keeps the *stored* id when a node is observed again and records the pre-merge id in an alias
    map so old edges keep resolving — so an edge minted before a merge carries an id that
    ``find_entity`` no longer returns. Comparing ``edge.source_id`` against a canonical id then
    silently picks the wrong end of the edge.

    Measured, not imagined: the first version of this walk did exactly that and found nothing at
    all in the reference scenario, whose resurgence address genuinely does present the
    historical certificate.

    Identity here is the pair ``(type, natural key)`` — the codebase's own definition — because
    that is the thing a merge preserves and the surrogate id is the thing it does not.
    """
    source = await graph.get_entity(edge.source_id)
    target = await graph.get_entity(edge.target_id)
    if source is None or target is None:
        return None
    return source, target


async def _bridges_of(
    graph: GraphStore, entity: Entity
) -> list[tuple[Entity, RelationType, tuple[ClaimId, ...]]]:
    """The attribute nodes this entity is attached to, at depth one.

    ``exclude_shared_infrastructure`` is off on purpose. The traversal's default refusal to
    expand through a registrar is right for pursuit — following it discovers nothing — but this
    walk needs to *see* the registrar in order to record the resemblance and score it at zero.
    Missing it entirely would leave a reader unable to tell "we checked and it means nothing"
    from "nobody looked".
    """
    found: list[tuple[Entity, RelationType, tuple[ClaimId, ...]]] = []
    subgraph = await graph.neighbourhood(
        GraphQuery(entity_id=entity.entity_id, max_depth=1, exclude_shared_infrastructure=False)
    )
    for edge in subgraph.relationships:
        ends = await _ends_of(graph, edge)
        if ends is None:
            continue
        source, target = ends
        if source.identity() == entity.identity():
            other = target
        elif target.identity() == entity.identity():
            other = source
        else:
            continue
        if _rule_for(other, edge.relation) is not None:
            found.append((other, edge.relation, edge.supporting_claims))
    return found


async def assemble_resurgence_signals(
    graph: GraphStore,
    *,
    prior_entity_ids: Sequence[str],
    observed_at: datetime,
    provenance_of: Callable[[tuple[ClaimId, ...]], SourceDescriptor] = _unresolved_provenance,
) -> tuple[ResurgenceSignal, ...]:
    """Walk out from a known cluster and return what the graph offers as continuity.

    ``prior_entity_ids`` is the campaign as we already know it. Anything reachable through a
    bridge and *not* in that set is a candidate; anything inside it is last month rather than a
    return, which is the first thing a naive version gets wrong.

    Membership of that set is tested by identity — ``(type, natural key)`` — and not by
    surrogate id, for the same reason the edge walk resolves both ends: a caller holding an id
    from a closed case may be holding a pre-merge one.

    Returns at most one signal per (candidate, bridge) pair. Two known entities sharing one
    certificate with one new host is a single observation, and emitting it twice would show a
    human one fact as two in the contribution list — fusion would collapse them by fact key, so
    the score would be right and the explanation wrong.

    Ordinary control flow throughout: an entity id that resolves to nothing is skipped, because
    a caller passing a stale id from a closed case is expected rather than exceptional.
    """
    known_entities: list[Entity] = []
    for entity_id in dict.fromkeys(prior_entity_ids):
        resolved = await graph.get_entity(entity_id)
        if resolved is not None:
            known_entities.append(resolved)
    prior_identities = {entity.identity() for entity in known_entities}

    seen: set[tuple[tuple[EntityType, str], tuple[EntityType, str]]] = set()
    signals: list[ResurgenceSignal] = []

    for known in known_entities:
        for bridge, relation, bridge_claims in await _bridges_of(graph, known):
            rule = _rule_for(bridge, relation)
            if rule is None:  # pragma: no cover - _bridges_of already filtered
                continue

            neighbours = await graph.neighbourhood(
                GraphQuery(
                    entity_id=bridge.entity_id, max_depth=1, exclude_shared_infrastructure=False
                )
            )
            for edge in neighbours.relationships:
                if edge.relation not in rule.relations:
                    continue
                ends = await _ends_of(graph, edge)
                if ends is None:
                    continue
                source, target = ends
                if source.identity() == bridge.identity():
                    candidate = target
                elif target.identity() == bridge.identity():
                    candidate = source
                else:
                    continue
                if (
                    candidate.identity() in prior_identities
                    or candidate.identity() == bridge.identity()
                    or candidate.entity_type in rule.bridge_types
                ):
                    continue

                pair = (candidate.identity(), bridge.identity())
                if pair in seen:
                    continue
                seen.add(pair)

                attribute = f"{bridge.entity_type.value}:{bridge.natural_key}"
                cited = tuple(dict.fromkeys((*bridge_claims, *edge.supporting_claims)))
                signals.append(
                    ResurgenceSignal(
                        kind=rule.kind,
                        shared_attribute=attribute,
                        selectivity=PivotSelectivity(
                            attribute=attribute,
                            # No population unless the attribute identifies by construction.
                            # Counting this graph's neighbours would be counting what we happen
                            # to know, which is not what the field means.
                            is_globally_unique=rule.globally_unique,
                        ),
                        observed_by=provenance_of(cited),
                        new_entity_type=candidate.entity_type,
                        new_entity_key=candidate.natural_key,
                        prior_entity_key=known.natural_key,
                        extent=TemporalExtent.at(observed_at),
                        supporting_claims=cited,
                    )
                )

    return tuple(signals)


def signals_by_candidate(
    signals: Sequence[ResurgenceSignal],
) -> dict[tuple[EntityType, str], tuple[ResurgenceSignal, ...]]:
    """Group assembled signals by the entity each one is about.

    The assembler returns a flat sequence because a walk finds what it finds, but the engine's
    question is *per candidate*: "is **this** cluster the campaign returning". Fusing signals
    about six different addresses into one verdict answers a question nobody asked — it would
    read as one confident finding about a campaign rather than six separate judgements, and the
    six would prop each other up through a shared fact key.

    Caught by looking at real output rather than by a failing test: a blind walk of the
    reference graph produced six certificate signals about six distinct candidates, and fusing
    them together was silently answering the wrong question.
    """
    grouped: dict[tuple[EntityType, str], list[ResurgenceSignal]] = {}
    for signal in signals:
        grouped.setdefault((signal.new_entity_type, signal.new_entity_key), []).append(signal)
    return {key: tuple(members) for key, members in grouped.items()}


# ---------------------------------------------------------------------------
# Closing the loop
#
# `DETECT -> PURSUE -> ... -> DISRUPT -> WATCH -> REAPPEARANCE -> PURSUE`. Every piece of that
# existed separately and nothing joined the last two: an investigation entered
# MONITORING_RESURGENCE and stayed there, because the thing that would have noticed a return
# was never asked.
# ---------------------------------------------------------------------------


class ResurgenceFinding(BaseModel):
    """One candidate, scored. The unit is the candidate rather than the campaign."""

    model_config = ConfigDict(frozen=True)

    candidate_type: EntityType
    candidate_key: str
    assessment: ResurgenceAssessment


class WatchReport(BaseModel):
    """What one pass of the resurgence watch examined, and what it concluded.

    ``candidates_examined`` and ``not_watching_reason`` are both here because an empty
    ``findings`` tuple is ambiguous on its own, and the ambiguity is the dangerous kind: a
    control that quietly stopped running looks exactly like a control that ran and found
    nothing. One of these fields always says which happened.
    """

    model_config = ConfigDict(frozen=True)

    investigation_id: str
    campaign: str
    checked_at: datetime
    candidates_examined: int = 0
    findings: tuple[ResurgenceFinding, ...] = ()
    not_watching_reason: str | None = None

    @property
    def actionable(self) -> tuple[ResurgenceFinding, ...]:
        return tuple(f for f in self.findings if f.assessment.is_actionable)

    @property
    def resumes(self) -> bool:
        """Whether this pass justifies reopening the case.

        Leads do not reopen cases. With provenance unresolved every assembled signal is
        plantable and the margin removes it, so a watch that resumed on anything it found would
        spend the remaining budget on whatever coincidence the graph happened to contain — and
        an adversary who knows that can arrange coincidences cheaply.
        """
        return bool(self.actionable)

    def render(self) -> str:
        if self.not_watching_reason is not None:
            return (
                f"Resurgence watch did not run for {self.investigation_id}: "
                f"{self.not_watching_reason}"
            )
        lines = [
            f"Resurgence watch for {self.campaign} ({self.investigation_id}) at "
            f"{self.checked_at.isoformat()}",
            f"  {self.candidates_examined} candidate(s) examined, "
            f"{len(self.actionable)} actionable",
        ]
        for finding in self.findings:
            verdict = "RESUME" if finding.assessment.is_actionable else "lead"
            lines.append(
                f"  [{verdict}] {finding.candidate_type.value}:{finding.candidate_key} — "
                f"{finding.assessment.band.value}"
            )
        if not self.findings:
            lines.append("  nothing in the graph connects this cluster to anything new")
        return "\n".join(lines)


async def watch_for_resurgence(
    graph: GraphStore,
    investigation: Investigation,
    *,
    campaign: str,
    candidate_population: int,
    now: datetime,
    provenance_of: Callable[[tuple[ClaimId, ...]], SourceDescriptor] = _unresolved_provenance,
    engine: ResurgenceEngine | None = None,
) -> WatchReport:
    """Ask, for a case sitting in resurgence watch, whether the adversary has come back.

    **The state is the trigger.** A case that is still open is being pursued, and running the
    watch over it would score its own live infrastructure as its own return. Anything other than
    ``MONITORING_RESURGENCE`` is declined with the reason recorded rather than answered with an
    empty result.

    The cluster is taken from the investigation's own branch foci — the entities it actually
    worked on — so the watch inherits whatever the case established rather than needing a
    separately maintained list of what the campaign owns.

    One assessment per candidate. Fusing signals about several candidates into one verdict would
    answer a question nobody asked and let distinct candidates prop each other up through a
    shared fact key.
    """
    if investigation.state is not InvestigationState.MONITORING_RESURGENCE:
        return WatchReport(
            investigation_id=investigation.investigation_id,
            campaign=campaign,
            checked_at=now,
            not_watching_reason=(
                f"the investigation is {investigation.state.value}, not "
                f"{InvestigationState.MONITORING_RESURGENCE.value}; a case still being pursued "
                "would score its own live infrastructure as its own return"
            ),
        )

    signals = await assemble_resurgence_signals(
        graph,
        prior_entity_ids=[branch.focus_entity_id for branch in investigation.branches],
        observed_at=now,
        provenance_of=provenance_of,
    )
    scorer = engine or ResurgenceEngine()
    grouped = signals_by_candidate(signals)

    findings = tuple(
        ResurgenceFinding(
            candidate_type=entity_type,
            candidate_key=natural_key,
            assessment=scorer.assess(
                campaign=campaign,
                signals=members,
                candidate_population=candidate_population,
                assessed_at=now,
            ),
        )
        for (entity_type, natural_key), members in sorted(
            grouped.items(), key=lambda item: (item[0][0].value, item[0][1])
        )
    )
    return WatchReport(
        investigation_id=investigation.investigation_id,
        campaign=campaign,
        checked_at=now,
        candidates_examined=len(grouped),
        findings=findings,
    )


def resume_pursuit(
    investigation: Investigation,
    *,
    candidate_entity_id: str,
    candidate_key: str,
    reason: str,
    now: datetime,
    additional_budget: float,
) -> Investigation:
    """Reopen a watched case on a candidate that came back.

    Pure, like ``mark_monitoring_resurgence`` next to it: the state transition is a value, and
    recording it in the audit trail belongs to whoever has the sink. The resumption is also
    written into ``notes`` so it survives on the object itself rather than only in a log.

    **Everything already done survives.** Prior branches, hypotheses and the budget already
    spent are untouched, and the candidate arrives as a new branch. A case that reopened as a
    blank page would have thrown away the reason we recognised the return — destroying our
    investigative continuity along with the adversary's operational one, which is the trade §9
    exists to refuse.

    **The budget is added to, never reset.** A case that reopens with a fresh allowance every
    time is a tap an adversary controls: returning is cheap for them, and the budget is what
    bounds what it costs us. The increment is a required argument for the same reason the
    candidate population is — every value that could be defaulted is either the permissive one
    or the one that silently strangles a real resumption.
    """
    if additional_budget < 0:
        raise ValueError("a resumption cannot grant a negative budget increment")

    branch_id = f"B{len(investigation.branches)}"
    resumed = investigation.with_branch(
        InvestigationBranch(
            branch_id=branch_id,
            focus_entity_id=candidate_entity_id,
            focus_entity_key=candidate_key,
            depth=0,
            budget_allocated=additional_budget,
            created_at=now,
        )
    )
    return resumed.model_copy(
        update={
            "state": InvestigationState.OPEN,
            "total_budget": investigation.total_budget + additional_budget,
            "last_step_at": now,
            "notes": (
                *investigation.notes,
                f"resurgence resumed pursuit on {candidate_key} at {now.isoformat()}: {reason}",
            ),
        }
    )


__all__ = [
    "BRIDGE_RULES",
    "BridgeRule",
    "ResurgenceFinding",
    "WatchReport",
    "assemble_resurgence_signals",
    "resume_pursuit",
    "signals_by_candidate",
    "watch_for_resurgence",
]
