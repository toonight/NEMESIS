"""Following a claim back to whoever actually saw the thing.

The graph records that two hosts present one certificate. It does not record *who observed
that*, and it cannot: ``Relationship`` and ``Claim`` carry no
:class:`~nemesis.core.provenance.SourceDescriptor`. Provenance lives on the evidence in the
vault, one hop further back, on :attr:`~nemesis.core.provenance.ProvenanceChain.source`.

**Everything downstream depends on making that hop.** The robustness margin drops the most
load-bearing *plantable* fact and keeps a fact only when some attesting origin is a channel an
adversary cannot author into. A caller that cannot name the origin therefore has no unplantable
facts, the margin removes everything, and the honest output is a lead. Measured on the
reference run before this module existed: the resurgence watch scored 0.007 from the graph
against 0.811 from the same phase with provenance supplied by hand. The gap was this hop.

**Why it returns several sources rather than one.** One fact seen by two collectors is two
attestations. :func:`~nemesis.core.fusion.establish_fact` is what decides whether two origins
accumulate or fold together — it groups by ``provenance_cluster`` and needs both to do it.
Collapsing them here would make that decision silently, in the wrong place, and with less
information than the function that exists for it.

**Standing, not aboutness.** An origin is inherited only across a link a *procedure* made, never
across a link somebody *chose*. Nothing on :class:`~nemesis.core.evidence.EvidenceObject` names a
claim, an entity or a statement, so "is this artifact about this assertion" is not a question this
schema can ask, and the only instrument that could answer it is a model — which invariant 1 puts
outside the enforcement path by construction. What a claim can no longer do is borrow an
unplantable origin by pointing at an artifact. A relevance check is `PROPOSED`.

**What that is worth, stated at its true price.** The gate reads ``derivation``, which the claim's
own author writes. An adversary who can already write to the claim store defeats it by writing
``DIRECT_COLLECTION`` instead of ``HUMAN_ANALYST`` — one field — or by citing nothing at all and
naming a real observation as the premise of a ``DETERMINISTIC_RULE`` whose ``rule_name`` nothing
replays. Both were built and executed against this code. So this is **not** a control against an
adversary inside the graph, and the register must not be read as claiming one.

What it does close is the path that does not require an adversary at all: honest code, or a future
writer, recording a hypothesis next to an artifact and silently acquiring that artifact's
unplantable origin. That is the shape that reaches production by accident rather than by attack,
and it was open. Today neither writer that exists can produce the laundering shape —
``pilot/mediator`` hardcodes ``MODEL_ASSERTION`` and ``api/submission`` hardcodes
``EXTERNAL_REPORT``, both with no evidence field — so this is a control installed before the
writer that would need it, which is the only time it can be installed cheaply.

**What it will not do.** It does not guess. A claim it cannot find, evidence the vault does not
hold, and a claim a model authored all produce :data:`UNRESOLVED_SOURCE` — plantable and
unjudgeable — and are counted so a reader can see how much of the answer rests on nothing. An
empty source list would be worse than useless: downstream, "no adversary-influenceable origin"
is what an *unplantable* fact looks like, so returning nothing for a fact nobody checked would
invert the meaning.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Sequence
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.claims import Claim, DerivationKind
from nemesis.core.evidence import EvidenceObject
from nemesis.core.ids import ClaimId
from nemesis.core.provenance import (
    SourceClass,
    SourceDescriptor,
    SourceReliability,
    merge_source_records,
)
from nemesis.core.relationships import PivotSelectivity
from nemesis.ports.storage import ClaimStore


@runtime_checkable
class EvidenceReader(Protocol):
    """The one method this resolver needs from a vault.

    A deliberate narrowing, in the shape of ``PublicationRecorder`` next door: resolving
    provenance means reading metadata, and it has no business being handed something that can
    seal, retrieve artifacts or read the chain head. A caller can pass an
    :class:`~nemesis.ports.storage.EvidenceVault`, which satisfies this, without the resolver
    acquiring the ability to do anything else with it.
    """

    async def get(self, evidence_id: str) -> EvidenceObject | None: ...


UNRESOLVED_SOURCE: Final = SourceDescriptor(
    source_class=SourceClass.OPEN_SOURCE,
    identifier="unresolved provenance",
    reliability=SourceReliability.CANNOT_BE_JUDGED,
)
"""What stands in for an origin nobody established.

``OPEN_SOURCE`` because the plantability allowlist is exactly ``{OWN_SENSOR,
LAW_ENFORCEMENT}`` and everything else is adversary-writable by default — which is the correct
reading of a fact whose origin was never checked. ``CANNOT_BE_JUDGED`` for the same reason on
the other axis.

Deliberately *not* ``OWN_SENSOR`` on the grounds that the record is in our vault. Holding the
record is not having authored the observation, and the source allowlist already refuses that
confusion for honeypots: a honeypot is ours, and an adversary writing into it is the entire
point of deploying one.
"""

MAX_DERIVATION_DEPTH: Final = 6
"""How far up a derivation chain to walk looking for evidence-backed claims.

A bound rather than a full traversal: derivation chains in this platform are shallow, and an
unbounded walk over a store an adversary can grow is a way to make a watch pass take forever.
The ports' own ``derivation_chain`` is used where available, and this is the fallback's limit.
"""

COLLECTING_DERIVATIONS: Final = frozenset(
    {DerivationKind.DIRECT_COLLECTION, DerivationKind.AUTHORITATIVE_RECORD}
)
"""Derivations in which citing the artifact and collecting it are the same act.

The question this module has to answer is not how strong a claim is, it is **who chose the
pairing**. :func:`~nemesis.collect.base.build_observation` seals the bytes and mints the claim
from one record in one call, so the citation is a byproduct of collecting and nobody selected it.
An ``AUTHORITATIVE_RECORD`` is the same shape by definition: a registrar's own record of its own
registry *is* the assertion. Everywhere else the author had the whole vault to choose from, and
the pairing is itself an assertion.

Deliberately not ``ClaimKind``. ``kind`` is the writer's own choice, so a gate on it is bypassed
by claiming to be *more* certain: ``FACT``/``EXTERNAL_REPORT`` carries the joint-maximum
``EPISTEMIC_STRENGTH`` with no observer anywhere behind it, and it constructs today. The same gate
would refuse ``CORRELATION``/``DIRECT_COLLECTION``, which a collector really did record.
``EPISTEMIC_STRENGTH`` already prices how much may be concluded; this prices who saw it, and the
two must not be made to stand in for one another.
"""

INHERITING_DERIVATIONS: Final = frozenset({DerivationKind.DETERMINISTIC_RULE})
"""Derivations a walk may carry a parent's origin down through.

Applied at **every** hop, not only at the bottom. A guess that cites no evidence at all but names
a real observation as its parent is choosing which parent matters, which is the same act as
choosing which artifact to cite — and a bottom-only rule cannot see it, because the claim the walk
returns is a genuine observation and passes any check made there.

``DETERMINISTIC_RULE`` is the one derivation :class:`~nemesis.core.claims.Claim` already forces to
name its inputs and to name and version itself, so the inheritance is somebody's replayable
procedure rather than somebody's judgement. Nothing re-runs the rule, and that is stated rather
than hidden: a fabricated ``rule_name`` over honest parents inherits their origins, and that is
the cheapest way through this module — cheaper than the citation hole it closes, because it needs
only a claim id where the citation needed an evidence id. Refusing it would strip the two
succession inferences the reference run's resurgence finding rests on, so it is recorded as an
open finding rather than guessed at. `PROPOSED`: replay the rule and compare content addresses.
"""

ASSERTED_BACKING_PREFIX: Final = "asserted backing: "
"""Marks a demoted origin in output a human reads. Nothing branches on it."""


class BackingKind(StrEnum):
    """How a claim came to be standing next to an artifact."""

    COLLECTED = "collected"
    """The act that produced the artifact is the act that made the claim."""

    ASSERTED = "asserted"
    """Somebody with the vault in front of them chose this pairing."""


def asserted_backing(source: SourceDescriptor) -> SourceDescriptor:
    """The origin of an artifact somebody *chose* to cite, described honestly.

    Not the artifact's own descriptor, because the origin of the artifact is not the origin of
    the assertion — the reasoning :data:`UNRESOLVED_SOURCE` already applies when it refuses to
    call our own vault an ``OWN_SENSOR``. And not :data:`UNRESOLVED_SOURCE` either: "nobody
    established an origin" and "somebody asserted a link nothing can check" are different states
    with different fixes, and collapsing them leaves an on-call engineer hunting a retention sweep
    for what was actually an attempted laundering. The demotion has to survive to the analyst's
    page, and the only thing that survives there is the descriptor.

    **Exactly one axis moves, and it is the one the claim is wrong about.**

    - ``source_class`` becomes ``HUMAN_ANALYST`` — the taxonomy's own term for "a named person's
      assertion", which is what a chosen pairing is. It sits outside
      :data:`~nemesis.core.provenance.UNPLANTABLE_SOURCE_CLASSES`, so plantability follows from
      the unchanged allowlist rather than from a second opinion about plantability.
    - ``reliability`` becomes ``CANNOT_BE_JUDGED``, because the descriptor now names the
      *asserter* and nobody has judged them. Carrying the sensor's grade onto a ``HUMAN_ANALYST``
      descriptor would assert that this author is usually reliable, which nobody established. It
      is also what stops the demotion from paying: measured with the grade preserved, two demoted
      origins on two fact keys leave the robustness margin at ``survived`` and the finding at
      0.6030 ``likely`` — the margin removes one planted fact and the second carries the
      conclusion. Unjudgeable, the same pile-up reports 0.0075 at every count.
    - ``operator``, ``upstream_of_record`` and ``handling_restrictions`` are carried across.
      Dropping the lineage fields would put the demotion in a different provenance cluster from
      the artifact's honest twin, and the two would then accumulate as independent. Measured on
      one artifact cited once honestly and once by a guess: keeping them holds the fact at 0.6030
      with one independent source, exactly what the honest claim scores alone; dropping them
      *raises* it to 0.7519 with two. A correctly detected guess must not add belief to the
      finding beside it. Handling caveats travel with the material rather than with the assertion,
      so a citation cannot launder TLP off either.

    The trust discount must not be allowed to stand in for the plantability control, and the tests
    are written so that it cannot: ``unplantable_facts`` and ``rests_only_on_plantable_evidence``
    are computed straight from the allowlist and are unmoved by a grade.
    """
    return SourceDescriptor(
        source_class=SourceClass.HUMAN_ANALYST,
        identifier=f"{ASSERTED_BACKING_PREFIX}{source.identifier}"[:512],
        reliability=SourceReliability.CANNOT_BE_JUDGED,
        operator=source.operator,
        upstream_of_record=source.upstream_of_record,
        handling_restrictions=source.handling_restrictions,
    )


class EvidenceLineage(BaseModel):
    """Where a set of claims came from, and how much of that is actually known."""

    model_config = ConfigDict(frozen=True)

    sources: tuple[SourceDescriptor, ...]
    """Every distinct origin behind these claims, in the order first met.

    Never empty. A caller with nothing to say about provenance says
    :data:`UNRESOLVED_SOURCE`, because saying nothing at all reads downstream as the opposite.
    """

    resolved_claims: int = Field(default=0, ge=0)
    unresolved_claims: int = Field(default=0, ge=0)
    model_derived_claims: int = Field(default=0, ge=0)
    """Counted separately from unresolved, and refused rather than resolved.

    A model assertion has no observer. Letting it fall through to the unresolved descriptor
    would be nearly harmless; letting it pick up a source from another claim in the same call
    would not be, and separating the counts is what makes the refusal visible (invariant 1).
    """

    asserted_backing_claims: int = Field(default=0, ge=0)
    """Claims that pointed at material somebody chose for them.

    Counted apart from resolved and from unresolved for the reason ``model_derived_claims``
    already is: the refusal has to be visible. Resolved means an origin was established;
    unresolved means nobody could look; this means somebody asserted a link the platform has no
    instrument to check.
    """

    @property
    def is_unresolved(self) -> bool:
        """Whether nothing at all was established."""
        return self.resolved_claims == 0

    def render(self) -> str:
        lines = [
            f"Lineage: {self.resolved_claims} resolved, "
            f"{self.asserted_backing_claims} asserted-backing and demoted, "
            f"{self.unresolved_claims} unresolved, "
            f"{self.model_derived_claims} model-derived and refused"
        ]
        lines.extend(
            f"  {source.source_class.value}:{source.identifier} "
            f"({'plantable' if source.is_adversary_influenceable else 'unplantable'})"
            for source in self.sources
        )
        return "\n".join(lines)


def _backing_kind(claim: Claim, *, inherited: bool) -> BackingKind:
    """Whether this claim's citation is a record of collecting or a choice of what to point at.

    ``inherited`` is the status of the whole path walked to get here, not of this claim alone: one
    chosen hop anywhere above is enough to make the backing asserted, however honest the claim at
    the bottom is. That is the L2 case — a guess that cites nothing and names a real observation
    as its parent — and it is invisible to any check made only at the bottom, because the claim
    the walk returns is a genuine collected observation and passes.
    """
    if inherited and claim.derivation in COLLECTING_DERIVATIONS:
        return BackingKind.COLLECTED
    return BackingKind.ASSERTED


async def _backings(
    claims: ClaimStore, claim: Claim, *, depth: int
) -> tuple[tuple[Claim, BackingKind], ...]:
    """The claims at the bottom of this one's derivation that cite evidence, and on what terms.

    An inference cites no evidence of its own; its provenance is its inputs'. Without walking
    down to them every derived claim would report as unresolved, and most of what this platform
    concludes is derived.

    It **classifies rather than refuses**. "Nobody could establish an origin" and "somebody
    asserted a link nothing can check" are different states with different fixes, and
    :data:`UNRESOLVED_SOURCE` already means the first; making it mean the second as well would
    leave an analyst unable to tell an attempted laundering from a retention sweep.

    **Breadth-first, and that is load-bearing rather than a matter of taste.** This walk used to
    recurse depth-first with no record of where it had been, so a claim reachable by many routes
    was fetched once per *route*. :data:`MAX_DERIVATION_DEPTH` bounded the depth and nothing
    bounded the breadth: measured on a nineteen-claim lattice, resolving three claims cost 1,821
    store lookups, and against an I/O-backed store that is 1,821 round trips on a path
    :func:`resolve_sources` puts inside the resurgence watch. The bound's own docstring says it
    exists to stop a walk being a way to make a watch pass take forever; it was guarding one
    dimension of two.

    The obvious repair — a visited set on the recursion — is wrong, and worth saying why. The
    walk is depth-budgeted, so a node first reached by a long route would be marked seen while
    holding almost no budget, and never re-explored when a short route reached it with budget to
    spare. Evidence below it would vanish, silently and depending on dictionary order. Levelling
    the walk removes the trap instead of stepping around it: breadth-first reaches every claim at
    its *shallowest* depth, which is the largest budget any route could give it, so one visit per
    claim is not merely cheaper but strictly more complete than the recursion it replaces.

    A cycle in ``derived_from_claims`` also terminates here rather than burning the depth budget.
    Nothing forbids one — ``Claim`` refuses only self-contradiction — and content addressing makes
    one awkward to build, not impossible.

    **The visited key carries the path's standing, and it has to.** The obvious key is the claim
    id, and it is wrong here: one claim reachable both across a rule and across a chosen hop has
    two different honest answers, and a key that cannot tell them apart returns whichever route
    the store happened to yield first. Keying on ``(claim_id, inherited)`` keeps at most two
    visits per claim — still linear — and makes the walk's result independent of iteration order.
    """
    if claim.is_model_derived:
        # Invariant 1, stated in its own right rather than left to fall out of the two derivation
        # sets above, so that widening either of them cannot silently readmit a model's assertion.
        # Redundant today; that is the point of writing it down.
        return ()
    if claim.supported_by_evidence:
        return ((claim, _backing_kind(claim, inherited=True)),)

    found: list[tuple[Claim, BackingKind]] = []
    seen: set[tuple[ClaimId, bool]] = {(claim.claim_id, True)}
    frontier: list[tuple[Claim, bool]] = [(claim, True)]

    for _ in range(depth):
        next_frontier: list[tuple[Claim, bool]] = []
        for node, inherited in frontier:
            # One chosen hop poisons everything below it: a procedure that runs over a judgement
            # is still standing on a judgement.
            carries = inherited and node.derivation in INHERITING_DERIVATIONS
            for parent_id in node.derived_from_claims:
                if (parent_id, carries) in seen:
                    continue
                seen.add((parent_id, carries))
                parent = await claims.get(parent_id)
                if parent is None or parent.is_model_derived:
                    continue
                # An evidence-backed claim ends its branch: its own citation is the origin, and
                # walking past it would attribute its parents' sources to it as well.
                if parent.supported_by_evidence:
                    found.append((parent, _backing_kind(parent, inherited=carries)))
                else:
                    next_frontier.append((parent, carries))
        if not next_frontier:
            break
        frontier = next_frontier

    return tuple(found)


# A second conjunct was designed, implemented and measured here, and is deliberately absent.
#
# It asked whether the artifact's chain of custody named the party that wrote the claim —
# ``any(event.actor == claim.asserted_by for event in evidence.provenance.custody)`` — to catch
# a hand-written ``DIRECT_COLLECTION`` claim over somebody else's artifact. It reads like a
# control. It is a release-triggered outage, and the reason is worth keeping where the next
# person to propose it will find it:
#
#   - ``evidence_id`` is a content address over the artifact bytes alone, so the same bytes
#     collected twice are one object (``core/evidence.py``, and that collapsing is deliberate:
#     it stops one fact counting as two corroborating observations).
#   - ``FileSystemEvidenceVault.seal`` returns the *stored* object on a re-seal — the first
#     sealer's metadata wins, by design, so a re-seal cannot relabel material.
#   - ``CustodyEvent(`` is constructed at exactly one site in the whole tree,
#     ``collect/base.py``, inside ``build_observation``. Nothing ever appends a second one.
#
# So the tuple holds exactly one event, forever, naming the first party ever to seal those
# bytes, and the conjunct does not compute what it says. It computes "was this claim's author
# the first party ever to seal these bytes" — and ``connector_actor_id`` hashes a connector's
# name *and version*. Measured: bumping one connector's version over a durable vault demoted
# 34 of 34 honest collected observations, took every finding in the reference run to the base
# rate, and flipped ``resumes`` from True to False. Invariant 14 defeated by a point release,
# with no adversary present. A two-collector store reproduces it with no version change at all.
#
# `PROPOSED`, and blocked on the vault recording a custody event per seal rather than per first
# seal. Until then the check cannot distinguish an impostor from a colleague.


async def resolve_lineage(
    claims: ClaimStore,
    vault: EvidenceReader,
    claim_ids: Sequence[ClaimId],
) -> EvidenceLineage:
    """Resolve claims to the origins that observed the evidence behind them.

    Ordinary control flow for every miss. A claim the store does not hold, evidence the vault
    does not hold and a claim a model authored are each recorded as such and contribute
    :data:`UNRESOLVED_SOURCE`; none of them raises, because a caller assembling signals from a
    graph that outlived a retention sweep is expected rather than exceptional.

    A resolved claim does not vouch for an unresolved one. Both origins come back, and what
    that mixture is worth is :func:`~nemesis.core.fusion.establish_fact`'s decision to make.
    """
    ordered: dict[tuple[str, str, str | None], SourceDescriptor] = {}
    resolved = 0
    unresolved = 0
    model_derived = 0
    asserted = 0

    for claim_id in dict.fromkeys(claim_ids):
        claim = await claims.get(claim_id)
        if claim is None:
            unresolved += 1
            continue
        if claim.is_model_derived:
            # Invariant 1: a model assertion is a hypothesis about the world, never a record
            # of it, and it has no observer to name.
            model_derived += 1
            continue

        found_collected = False
        found_asserted = False
        for backed, backing in await _backings(claims, claim, depth=MAX_DERIVATION_DEPTH):
            for evidence_id in backed.supported_by_evidence:
                evidence = await vault.get(evidence_id)
                if evidence is None:
                    continue
                collected = backing is BackingKind.COLLECTED
                source = evidence.provenance.source
                if not collected:
                    source = asserted_backing(source)
                key = (source.source_class.value, source.identifier, source.operator)
                # Folded, not first-wins. `setdefault` discarded the other record's
                # `reliability`, `upstream_of_record` and `handling_restrictions`, so which
                # artifact the store yielded first decided them — order dependence, one screen
                # below a walk that was made breadth-first precisely to remove it, and
                # `reliability` reaches `fusion.trust_of_source`, so the order could move a
                # fused number. `merge_source_records` folds each field toward the value that
                # asserts least.
                previous = ordered.get(key)
                ordered[key] = (
                    source if previous is None else merge_source_records(previous, source)
                )
                if collected:
                    found_collected = True
                else:
                    found_asserted = True
        if found_collected:
            resolved += 1
        elif found_asserted:
            # Not counted toward the UNRESOLVED_SOURCE append below: a demoted origin already
            # contributes a plantable descriptor of its own, and adding a second would count one
            # refusal twice.
            asserted += 1
        else:
            unresolved += 1

    sources = tuple(ordered.values())
    if unresolved or model_derived or not sources:
        sources = (*sources, UNRESOLVED_SOURCE)

    return EvidenceLineage(
        sources=sources,
        resolved_claims=resolved,
        unresolved_claims=unresolved,
        model_derived_claims=model_derived,
        asserted_backing_claims=asserted,
    )


def resolve_sources(
    claims: ClaimStore, vault: EvidenceReader
) -> Callable[[tuple[ClaimId, ...]], Coroutine[Any, Any, tuple[SourceDescriptor, ...]]]:
    """Bind a store and a vault into the hook the resurgence watch takes.

    The watch's default resolver knows nothing and says so; this one knows what the vault
    holds. Handing it in is the difference between a watch that can only ever report leads and
    one that can report a finding when the evidence supports it.
    """

    async def hook(claim_ids: tuple[ClaimId, ...]) -> tuple[SourceDescriptor, ...]:
        lineage = await resolve_lineage(claims, vault, claim_ids)
        return lineage.sources

    return hook


async def resolve_stated_selectivity(
    claims: ClaimStore, claim_ids: Sequence[ClaimId]
) -> PivotSelectivity | None:
    """The count a connector wrote down, when one of them did.

    Separate from the edge because the edge legitimately drops it: ``Relationship`` refuses a
    selectivity on a ``DIRECT_OBSERVATION``, on the grounds that nothing was inferred from a
    shared attribute — which is true of the *edge* and says nothing about whether the connector
    measured the attribute's rarity. A gateway that captured a kit observed it directly and can
    still report that three kits in its corpus carry that build path.

    So the count is read from the claim, which is where the connector wrote it, rather than
    from the edge, which is where a validator about a different concern removed it.

    Only a count with a stated denominator is returned. ``PivotSelectivity`` refuses the other
    kind anyway, and a number with no corpus behind it cannot be interpreted or challenged.
    """
    for claim_id in dict.fromkeys(claim_ids):
        claim = await claims.get(claim_id)
        if claim is None or claim.is_model_derived:
            continue
        qualifiers = claim.statement.qualifiers
        attribute = qualifiers.get("shared_attribute")
        raw = qualifiers.get("population_size")
        corpus = qualifiers.get("population_measured_against")
        if attribute is None or raw is None or corpus is None:
            continue
        try:
            population = int(raw)
        except ValueError:
            continue
        return PivotSelectivity(
            attribute=attribute,
            population_size=population,
            population_measured_against=corpus,
            is_globally_unique=qualifiers.get("globally_unique") == "true",
        )
    return None


def resolve_selectivity(
    claims: ClaimStore,
) -> Callable[[tuple[ClaimId, ...]], Coroutine[Any, Any, PivotSelectivity | None]]:
    """Bind a claim store into the hook the resurgence walk takes."""

    async def hook(claim_ids: tuple[ClaimId, ...]) -> PivotSelectivity | None:
        return await resolve_stated_selectivity(claims, claim_ids)

    return hook


__all__ = [
    "ASSERTED_BACKING_PREFIX",
    "COLLECTING_DERIVATIONS",
    "INHERITING_DERIVATIONS",
    "MAX_DERIVATION_DEPTH",
    "UNRESOLVED_SOURCE",
    "BackingKind",
    "EvidenceLineage",
    "EvidenceReader",
    "asserted_backing",
    "resolve_lineage",
    "resolve_selectivity",
    "resolve_sources",
    "resolve_stated_selectivity",
]
