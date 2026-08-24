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

**What it will not do.** It does not guess. A claim it cannot find, evidence the vault does not
hold, and a claim a model authored all produce :data:`UNRESOLVED_SOURCE` — plantable and
unjudgeable — and are counted so a reader can see how much of the answer rests on nothing. An
empty source list would be worse than useless: downstream, "no adversary-influenceable origin"
is what an *unplantable* fact looks like, so returning nothing for a fact nobody checked would
invert the meaning.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Sequence
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.claims import Claim
from nemesis.core.evidence import EvidenceObject
from nemesis.core.ids import ClaimId
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
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

    @property
    def is_unresolved(self) -> bool:
        """Whether nothing at all was established."""
        return self.resolved_claims == 0

    def render(self) -> str:
        lines = [
            f"Lineage: {self.resolved_claims} resolved, {self.unresolved_claims} unresolved, "
            f"{self.model_derived_claims} model-derived and refused"
        ]
        lines.extend(
            f"  {source.source_class.value}:{source.identifier} "
            f"({'plantable' if source.is_adversary_influenceable else 'unplantable'})"
            for source in self.sources
        )
        return "\n".join(lines)


async def _evidence_backed(claims: ClaimStore, claim: Claim, *, depth: int) -> tuple[Claim, ...]:
    """The claims at the bottom of this one's derivation that actually cite evidence.

    An inference cites no evidence of its own; its provenance is its inputs'. Without walking
    down to them every derived claim would report as unresolved, and most of what this platform
    concludes is derived.
    """
    if claim.supported_by_evidence:
        return (claim,)
    if depth <= 0 or not claim.derived_from_claims:
        return ()
    found: list[Claim] = []
    for parent_id in claim.derived_from_claims:
        parent = await claims.get(parent_id)
        if parent is None or parent.is_model_derived:
            continue
        found.extend(await _evidence_backed(claims, parent, depth=depth - 1))
    return tuple(found)


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

        backing = await _evidence_backed(claims, claim, depth=MAX_DERIVATION_DEPTH)
        found_any = False
        for backed in backing:
            for evidence_id in backed.supported_by_evidence:
                evidence = await vault.get(evidence_id)
                if evidence is None:
                    continue
                source = evidence.provenance.source
                key = (source.source_class.value, source.identifier, source.operator)
                ordered.setdefault(key, source)
                found_any = True
        if found_any:
            resolved += 1
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


__all__ = [
    "MAX_DERIVATION_DEPTH",
    "UNRESOLVED_SOURCE",
    "EvidenceLineage",
    "EvidenceReader",
    "resolve_lineage",
    "resolve_sources",
]
