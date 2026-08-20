"""What NEMESIS already knew, before this investigation touched anything.

The brief calls the Global Adversary Graph "the long-term strategic asset" and says every
observation should potentially enrich future investigations. The graph delivers the first
half — `upsert_entity` merges on (type, natural key) and widens temporal extents, so a second
run genuinely accumulates rather than duplicating. It has never delivered the second half:
**nothing asked it what it already knew.** An adversarial audit put it plainly — no code path
queries prior knowledge to inform a new pursuit, so every investigation started blind against
an adversary the platform may have spent months mapping.

This module is that question. It is small on purpose: the primitive (`find_entity`) already
existed, and what was missing was the *discipline of asking*, plus one distinction that turns
out to carry the whole feature.

**The distinction: known-before versus just-written.** Once an investigation runs, the entity
it discovered is in the graph — so "is it in the graph?" answers yes for everything and means
nothing. Prior knowledge is what the graph held *before this investigation opened*, and the
bitemporal model already records it: ``extent.known_from`` is when the thing was first observed
to exist, independent of when we wrote it down. An entity whose ``known_from`` predates the
investigation's start is memory; one that does not is this run's own discovery wearing the same
shape. Getting this backwards would make every run report itself as corroborated by history.

**Why this is a security property and not only a feature.** Invariant 14 says a takedown is
followed by resurgence monitoring, and resurgence is meaningless without recall: recognising
that a new domain shares a certificate with infrastructure seized eight months ago is the entire
mechanism. It also cuts the other way, and the caution is the point — *recognition is not
corroboration*. Having seen an entity before raises no confidence in any claim about it. A
planted artifact observed twice is a planted artifact observed twice. So this module returns
facts about what was recorded and refuses to return a score.

Status: `IMPLEMENTED`. What is **not** here: recall does not yet run automatically inside the
pursuit engine, so it informs a caller that asks rather than steering a pivot. Wiring it into
pivot selection is a decision about letting history bias where an investigation looks, which is
a real risk (yesterday's error becomes today's prior) and is recorded as `PROPOSED` rather than
slipped in.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict

from nemesis.core.disclosure import DisclosureClass, disclosure_of_entity
from nemesis.core.entities import Entity, EntityType
from nemesis.ports.storage import GraphStore

LONG_ACQUAINTANCE: Final = timedelta(days=90)
"""Beyond this, an entity counts as long-known rather than recently seen.

A threshold, not a measurement — stated in code so it can be argued with. Ninety days is
roughly the point at which "we saw this during the incident" becomes "we have been watching
this", which is a different kind of claim about the same node.
"""


class RecallVerdict(StrEnum):
    """What the graph had on an entity before this investigation opened."""

    UNKNOWN = "unknown"
    """Never seen. The investigation is starting from nothing on this node, which is the
    honest default and the common case for a young graph."""

    FIRST_SEEN_IN_THIS_INVESTIGATION = "first_seen_in_this_investigation"
    """Present in the graph, but this run put it there. **Not** prior knowledge, and the
    distinction that stops a run from reporting itself as corroborated by history."""

    KNOWN_BEFORE = "known_before"
    """Observed before this investigation opened. Genuine recall."""

    LONG_KNOWN = "long_known"
    """Known for longer than :data:`LONG_ACQUAINTANCE`. A node the platform has been living
    with rather than one it met during an incident."""


class Recollection(BaseModel):
    """What was already on file about one entity. Facts, deliberately not a score."""

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    natural_key: str
    verdict: RecallVerdict

    entity_id: str | None = None
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    known_for: timedelta | None = None

    recorded_labels: tuple[str, ...] = ()
    recorded_attributes: tuple[str, ...] = ()
    """Attribute *names* only. The values can be anything a connector wrote, and a recall
    summary is read in contexts — a pilot briefing, an analyst list — where the point is what
    is on file rather than its contents."""

    is_shared_infrastructure: bool = False
    is_synthetic: bool = False

    caution: str = (
        "Recognition is not corroboration. Having seen this entity before raises no confidence "
        "in any claim about it: an artifact an adversary planted and we observed twice is an "
        "artifact an adversary planted."
    )

    @property
    def is_prior_knowledge(self) -> bool:
        return self.verdict in {RecallVerdict.KNOWN_BEFORE, RecallVerdict.LONG_KNOWN}

    def render(self) -> str:
        if self.verdict is RecallVerdict.UNKNOWN:
            return f"{self.natural_key}: never seen before"
        if self.verdict is RecallVerdict.FIRST_SEEN_IN_THIS_INVESTIGATION:
            return f"{self.natural_key}: discovered by this investigation, not prior knowledge"
        days = 0 if self.known_for is None else self.known_for.days
        shape = "long known" if self.verdict is RecallVerdict.LONG_KNOWN else "known before"
        return f"{self.natural_key}: {shape} — first observed {days} day(s) ago"


class RecallReport(BaseModel):
    """Recall across a set of entities: what this investigation is walking back into."""

    model_config = ConfigDict(frozen=True)

    investigation_opened_at: datetime
    recollections: tuple[Recollection, ...]

    @property
    def prior(self) -> tuple[Recollection, ...]:
        return tuple(item for item in self.recollections if item.is_prior_knowledge)

    @property
    def novel(self) -> tuple[Recollection, ...]:
        return tuple(item for item in self.recollections if not item.is_prior_knowledge)

    @property
    def graph_paid_off(self) -> bool:
        """Whether the accumulated graph contributed anything to this investigation at all.

        Worth exposing because the honest answer on a young deployment is False, and a
        platform whose central promise is persistent memory should be able to say so rather
        than implying value it has not yet accrued.
        """
        return bool(self.prior)

    def render(self) -> str:
        lines = [
            f"Recall against the Global Adversary Graph "
            f"({len(self.prior)} of {len(self.recollections)} already known):"
        ]
        lines.extend(f"  - {item.render()}" for item in self.recollections)
        if not self.graph_paid_off:
            lines.append(
                "  The graph contributed nothing to this investigation. That is the expected "
                "answer early on; it becomes a finding if it stays true."
            )
        return "\n".join(lines)


async def recall_entity(
    graph: GraphStore,
    entity_type: EntityType,
    natural_key: str,
    *,
    investigation_opened_at: datetime,
    now: datetime,
    long_acquaintance: timedelta = LONG_ACQUAINTANCE,
) -> Recollection:
    """Ask the graph what it already had on one entity.

    ``investigation_opened_at`` is required, with no default, because it is the whole
    distinction: without it this function can only answer "is it in the graph", which after the
    first pivot is yes for everything the run just wrote.
    """
    found = await graph.find_entity(entity_type, natural_key)
    if found is None:
        return Recollection(
            entity_type=entity_type, natural_key=natural_key, verdict=RecallVerdict.UNKNOWN
        )

    first = found.extent.known_from
    last = found.extent.known_until
    known_for = now - first

    if first >= investigation_opened_at:
        verdict = RecallVerdict.FIRST_SEEN_IN_THIS_INVESTIGATION
    elif known_for >= long_acquaintance:
        verdict = RecallVerdict.LONG_KNOWN
    else:
        verdict = RecallVerdict.KNOWN_BEFORE

    return Recollection(
        entity_type=entity_type,
        natural_key=natural_key,
        verdict=verdict,
        entity_id=found.entity_id,
        first_observed=first,
        last_observed=last,
        known_for=known_for,
        recorded_labels=found.labels,
        recorded_attributes=tuple(sorted(found.attributes)),
        is_shared_infrastructure=found.is_shared_infrastructure,
        is_synthetic=found.is_synthetic,
    )


async def recall(
    graph: GraphStore,
    entities: tuple[tuple[EntityType, str], ...],
    *,
    investigation_opened_at: datetime,
    now: datetime,
    deliverable_only: bool = False,
) -> RecallReport:
    """Recall across several entities at once.

    ``deliverable_only`` drops internal-class and RESTRICTED node types from the report. Set it
    whenever the result travels somewhere a briefing travels — a pilot, and therefore a hosted
    model vendor — because recall about a person is still material about a person, and the fact
    that it came from memory rather than from this run changes nothing about that.
    """
    results = []
    for entity_type, natural_key in entities:
        if (
            deliverable_only
            and disclosure_of_entity(entity_type) is not DisclosureClass.DELIVERABLE
        ):
            continue
        results.append(
            await recall_entity(
                graph,
                entity_type,
                natural_key,
                investigation_opened_at=investigation_opened_at,
                now=now,
            )
        )
    return RecallReport(
        investigation_opened_at=investigation_opened_at, recollections=tuple(results)
    )


def resurgence_candidates(report: RecallReport, *, entity: Entity | None = None) -> tuple[str, ...]:
    """Prior-known nodes worth treating as a possible return of an old adversary.

    Deliberately excludes shared infrastructure. A CDN address we have known for two years is
    prior knowledge and means nothing: recognising it would produce a resurgence signal on every
    investigation that touches a large provider, which is the failure mode the graph traversal
    already refuses to expand through.
    """
    del entity  # reserved for a future signature that scopes candidates to one focus
    return tuple(item.natural_key for item in report.prior if not item.is_shared_infrastructure)


__all__ = [
    "LONG_ACQUAINTANCE",
    "RecallReport",
    "RecallVerdict",
    "Recollection",
    "recall",
    "recall_entity",
    "resurgence_candidates",
]
