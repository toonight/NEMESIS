"""Which cases an adversary has appeared in — a projection, never a store.

Cross-run accumulation was already real before this module: :func:`~nemesis.graph.memory.
merge_entities` folds a node observed again into the one already held, ``widen_extent`` widens
its known window, and :mod:`nemesis.graph.journal` makes both durable. What was missing was the
*index*. No object in the Global Adversary Graph carries a case identifier — ``Entity``,
``Relationship`` and ``Claim`` each go without one — so nothing could answer "have we met this
before, and what did we conclude".

**That absence is deliberate and stays.** The same adversary appearing in many cases is the
entire point of the graph; stamping a ``case_id`` on a node would either pick one case
arbitrarily or turn one real-world thing back into several. The relation between a case and an
entity belongs on neither of them.

**So the index is derived from the audit trail**, which already records it: an
``investigation.start`` names the seed, every ``pivot.execute`` names both the investigation,
the entity it touched, and the typed natural keys it materialized, and a ``pilot.move`` that
requested an effect names the investigation and the target it was aimed at. Each makes an
appearance, because an entity admitted to the graph or acted against is an entity the case has
met — a projection that knew an actor was at the far end of an edge and not that the actor had
ever appeared was contradicting the graph it projected. That trail is append-only and
hash-chained, so the projection
inherits durability and tamper-evidence from a mechanism that already had them, and this module
adds no authoritative state. Deleting the index costs the time to replay the events and nothing
else — which is the test of whether something is a projection or a second database wearing the
word.

**What it can honestly answer**, and the list is deliberately short:

- which investigations touched this entity, and when;
- whether that is more than one — a *recurrence*, which is a finding, as opposed to a busy
  branch, which is a Tuesday;
- which pivots were run against it;
- what effects were attempted against it, and how each came out.

**What it cannot answer, and must not be read as answering.** "Which assets were replaced"
needs the ``SUCCEEDED_BY`` edges in the graph. "Which confidence levels moved" needs claim
versions. "Which hypotheses were disproved" needs the investigation objects, which the audit
trail summarises rather than carries. Those are the resurgence engine's questions, and pointing
this module at them would produce confident answers from evidence that cannot support them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from nemesis.ports.storage import AuditEvent

PIVOT_ACTION = "pivot.execute"
INVESTIGATION_ACTION = "investigation.start"
EFFECT_ACTION = "effect.execute"
PILOT_MOVE_ACTION = "pilot.move"

READ_ACTIONS = frozenset({PIVOT_ACTION, INVESTIGATION_ACTION, EFFECT_ACTION, PILOT_MOVE_ACTION})
"""The actions this projection interprets.

Everything else is skipped in silence rather than counted as unreadable. The distinction
matters: an action this module has never heard of is forward compatibility, while a
``pivot.execute`` it cannot parse is a hole in the memory. Reporting the first as a hole would
train a reader to ignore the count that exists to be alarming.
"""


class EntityAppearance(BaseModel):
    """One entity, in one investigation, with what was done to it there."""

    model_config = ConfigDict(frozen=True)

    entity_type: str
    natural_key: str
    investigation_id: str
    first_seen: datetime
    last_seen: datetime
    pivots: tuple[str, ...] = ()
    """Sorted and deduplicated: the question is which techniques were tried, not how often."""

    @property
    def key(self) -> tuple[str, str]:
        return self.entity_type, self.natural_key


class InvestigationRecord(BaseModel):
    """One case, as the trail describes it at its opening."""

    model_config = ConfigDict(frozen=True)

    investigation_id: str
    opened_at: datetime
    seed_type: str
    seed_key: str
    detected_by: str = ""


class EffectAttempt(BaseModel):
    """One effect aimed at a target, and how it came out."""

    model_config = ConfigDict(frozen=True)

    target: str
    outcome: str
    """The audit event's outcome verbatim.

    For an effect that is a composite line — the verdict, then the adapter, the contact flag,
    the artifacts and the adapter's whole detail paragraph. Kept whole because the trail is the
    record and truncating it here would mean the projection and the trail disagree about what
    happened; :attr:`verdict` is the part a reader wants first.
    """

    attempted_at: datetime

    @property
    def verdict(self) -> str:
        """The leading token: ``drafted``, ``simulated``, ``refused_unauthorized``, …

        A reader asking "what did we try last time" wants the outcome, not the paragraph
        explaining which steps the simulated adapter did not perform.
        """
        return self.outcome.split(" ", 1)[0]


class AdversaryMemory(BaseModel):
    """What the platform remembers about entities across cases.

    Frozen and comparable, because the property that makes a projection safe is that rebuilding
    it from the same events produces the same object. A test asserts exactly that; without it
    "rebuildable" is an adjective rather than a guarantee.
    """

    model_config = ConfigDict(frozen=True)

    appearances: tuple[EntityAppearance, ...] = ()
    investigations: tuple[InvestigationRecord, ...] = ()
    effects: tuple[EffectAttempt, ...] = ()

    unreadable: int = Field(default=0, ge=0)
    """Events this projection recognised the action of and could not interpret.

    Reported rather than dropped. A hole that presents itself as zero appearances is
    indistinguishable from an adversary we have never met, and the second is a much more
    comfortable thing to believe.
    """

    # -- questions -------------------------------------------------------------

    def appearances_of(self, entity_type: str, natural_key: str) -> tuple[EntityAppearance, ...]:
        return tuple(
            item
            for item in self.appearances
            if item.entity_type == entity_type and item.natural_key == natural_key
        )

    def cases_for(self, entity_type: str, natural_key: str) -> tuple[str, ...]:
        """Every investigation that touched this entity, oldest first."""
        return tuple(
            item.investigation_id for item in self.appearances_of(entity_type, natural_key)
        )

    def is_recurrence(self, entity_type: str, natural_key: str) -> bool:
        """Whether this entity has been seen in more than one case.

        The whole distinction this module exists for. Twenty pivots inside one investigation is
        one appearance; two investigations three months apart is an adversary who came back.
        """
        return len(self.cases_for(entity_type, natural_key)) > 1

    def entities_of(self, investigation_id: str) -> tuple[tuple[str, str], ...]:
        return tuple(
            item.key for item in self.appearances if item.investigation_id == investigation_id
        )

    def investigation(self, investigation_id: str) -> InvestigationRecord | None:
        return next(
            (r for r in self.investigations if r.investigation_id == investigation_id), None
        )

    def effects_against(self, target: str) -> tuple[str, ...]:
        """How every effect aimed at this target came out, oldest first.

        "What did we try last time, and what happened" is the question that stops a second
        futile takedown request against a provider that ignored the first.

        Verdicts rather than the whole recorded line: the trail's effect outcome carries the
        adapter's full detail paragraph after the verdict, and a caller joining those into one
        string produces a wall of text where a list of outcomes was wanted. The full line stays
        on :class:`EffectAttempt`.
        """
        return tuple(item.verdict for item in self.effects if item.target == target)

    def recurrences(self) -> tuple[tuple[str, str], ...]:
        """Every entity seen in more than one case, as ``(type, key)``."""
        return tuple(
            key
            for key in dict.fromkeys(item.key for item in self.appearances)
            if self.is_recurrence(*key)
        )

    def render(self) -> str:
        lines = [
            f"Adversary memory: {len(self.investigations)} investigation(s), "
            f"{len(self.appearances)} appearance(s)."
        ]
        if self.unreadable:
            lines.append(
                f"  ! {self.unreadable} audit event(s) could not be interpreted; this memory "
                "is incomplete by that much"
            )
        for entity_type, natural_key in self.recurrences():
            cases = self.cases_for(entity_type, natural_key)
            lines.append(f"  {entity_type}:{natural_key} — seen in {len(cases)} cases")
        return "\n".join(lines)


def _investigation_of(subject: str) -> str:
    """A pivot's subject is ``{investigation_id}/{branch_id}``; the case is the first half."""
    return subject.split("/", 1)[0]


def _materialized_entities(raw: str) -> tuple[tuple[str, str], ...] | None:
    """Decode the typed natural keys a pivot admitted to the graph.

    ``None`` is the malformed sentinel rather than the empty tuple: an empty result is an
    honest answer, while malformed JSON is a hole the projection must count. Older audit
    entries omit the field altogether and are handled by the caller as the old, narrower
    record they genuinely are.
    """
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(decoded, list):
        return None

    entities: list[tuple[str, str]] = []
    for item in decoded:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(value, str) and value for value in item)
        ):
            return None
        entity_type, natural_key = item
        entities.append((entity_type, natural_key))
    return tuple(entities)


@dataclass
class _Accumulator:
    """Mutable working state for one (type, key, investigation) triple.

    A dataclass rather than a dict of ``object`` because the alternative needed a
    ``type: ignore`` on every line that touched it, and a silenced type error in the middle of
    a projection is exactly where a wrong field would hide.
    """

    first: datetime
    last: datetime
    pivots: set[str] = dataclass_field(default_factory=set)


def rebuild(events: Iterable[AuditEvent]) -> AdversaryMemory:
    """Replay an audit trail into the memory it implies.

    Order-independent by construction: appearances are folded into a mapping keyed by
    ``(type, key, investigation)`` and the timestamps are taken as a min and a max, so a query
    that returns a window out of order produces the same answer as one that does not. A test
    asserts it, because "append-only" describes how the trail is written and not how a caller
    reads it back.
    """
    appearances: dict[tuple[str, str, str], _Accumulator] = {}
    investigations: dict[str, InvestigationRecord] = {}
    effects: list[EffectAttempt] = []
    unreadable = 0

    for event in events:
        if event.action not in READ_ACTIONS:
            continue

        if event.action == INVESTIGATION_ACTION:
            seed_key = event.inputs.get("seed_key")
            seed_type = event.inputs.get("seed_type")
            if not seed_key or not seed_type:
                unreadable += 1
                continue
            investigations[event.subject] = InvestigationRecord(
                investigation_id=event.subject,
                opened_at=event.occurred_at,
                seed_type=seed_type,
                seed_key=seed_key,
                detected_by=event.inputs.get("detected_by", ""),
            )
            continue

        if event.action == EFFECT_ACTION:
            effects.append(
                EffectAttempt(
                    target=event.subject, outcome=event.outcome, attempted_at=event.occurred_at
                )
            )
            continue

        if event.action == PILOT_MOVE_ACTION:
            # An effect the autonomous path requested. `record_effect`, which writes
            # `effect.execute`, is called only from the demonstration scenario — so keying this
            # index on that action alone made every effect a pilot ever asked for invisible to
            # "what did we try last time". Found by reading a real Codex-driven run back through
            # this projection, which is what a projection with a caller is for.
            if event.inputs.get("move_kind") != "request_effect":
                continue
            target = event.inputs.get("target_natural_key")
            outcome = event.inputs.get("effect_outcome")
            if not target or not outcome:
                # A pilot effect whose target or outcome the trail did not record. Counted, not
                # guessed at: runs predating `target_natural_key` land here and a memory that
                # silently dropped them would under-report what was tried.
                unreadable += 1
                continue
            effects.append(
                EffectAttempt(target=target, outcome=outcome, attempted_at=event.occurred_at)
            )
            # An entity we aimed an effect at is an entity we have met, and the memory used to
            # disagree with itself about that: `effects_against` named the target while
            # `cases_for` said it had never been seen, because an appearance was keyed only on
            # the entity a pivot ran *against*. A pilot that traverses to its approved target
            # and rehearses there — the shape of every run seeded away from the target — left
            # that target with no case history, so a recurrence check was blind to exactly the
            # assets an operator rebuilds: the ones we acted on last time.
            #
            # Effect targets are recorded even when no pivot materialized them. Pivot results
            # themselves are handled below from their typed natural-key list. A recurrence in
            # this projection means "filed in two cases", never common control: a co-hosted
            # lead can recur as a filing fact without becoming attribution evidence.
            target_type = event.inputs.get("target_entity_type")
            if not target_type:
                # Same rule as an untyped pivot: a persona and a domain can spell the same
                # string, so a target whose type the trail omits is counted rather than filed
                # under a type nobody observed. The effect above is still remembered — that
                # half the trail does support.
                unreadable += 1
                continue
            slot = appearances.setdefault(
                (target_type, target, event.subject),
                _Accumulator(first=event.occurred_at, last=event.occurred_at),
            )
            slot.first = min(slot.first, event.occurred_at)
            slot.last = max(slot.last, event.occurred_at)
            continue

        natural_key = event.inputs.get("entity")
        entity_type = event.inputs.get("entity_type")
        if not natural_key or not entity_type:
            # A pivot whose entity or type the trail did not record. Events written before the
            # type was recorded are genuinely ambiguous — a persona and a domain can spell the
            # same string — so they are counted rather than guessed at.
            unreadable += 1
            continue

        investigation_id = _investigation_of(event.subject)
        slot = appearances.setdefault(
            (entity_type, natural_key, investigation_id),
            _Accumulator(first=event.occurred_at, last=event.occurred_at),
        )
        slot.first = min(slot.first, event.occurred_at)
        slot.last = max(slot.last, event.occurred_at)
        pivot = event.inputs.get("pivot")
        if pivot:
            slot.pivots.add(pivot)

        raw_materialized = event.inputs.get("materialized_entities")
        if raw_materialized is None:
            # Backward compatibility: old entries genuinely did not preserve the result keys.
            # They still describe the entity pivoted on and are not malformed for predating
            # the wider audit contract.
            continue
        materialized = _materialized_entities(raw_materialized)
        if materialized is None:
            unreadable += 1
            continue
        for discovered_type, discovered_key in materialized:
            discovered = appearances.setdefault(
                (discovered_type, discovered_key, investigation_id),
                _Accumulator(first=event.occurred_at, last=event.occurred_at),
            )
            discovered.first = min(discovered.first, event.occurred_at)
            discovered.last = max(discovered.last, event.occurred_at)

    built = tuple(
        EntityAppearance(
            entity_type=entity_type,
            natural_key=natural_key,
            investigation_id=investigation_id,
            first_seen=slot.first,
            last_seen=slot.last,
            pivots=tuple(sorted(slot.pivots)),
        )
        for (entity_type, natural_key, investigation_id), slot in appearances.items()
    )
    return AdversaryMemory(
        # Sorted so the projection is a value rather than a record of iteration order: two
        # rebuilds from the same events must compare equal, and dict ordering is an accident of
        # how the trail happened to arrive.
        appearances=tuple(
            sorted(built, key=lambda a: (a.entity_type, a.natural_key, a.first_seen))
        ),
        investigations=tuple(sorted(investigations.values(), key=lambda r: r.opened_at)),
        effects=tuple(sorted(effects, key=lambda e: (e.attempted_at, e.target, e.outcome))),
        unreadable=unreadable,
    )


async def rebuild_from(sink: object, *, limit: int = 100_000) -> AdversaryMemory:
    """Rebuild from an audit sink, reading the whole trail rather than a page of it.

    ``AuditSink.query`` defaults to ``limit=100``, which is a sensible default for a human
    reading recent activity and silently wrong for a projection — a memory built from the last
    hundred events would report an adversary as never before seen because their case was the
    hundred-and-first. The limit is named here so the choice is visible.
    """
    query = getattr(sink, "query", None)
    if query is None:
        raise TypeError("an audit sink that cannot be queried cannot be projected")
    events: Sequence[AuditEvent] = await query(limit=limit)
    return rebuild(events)


__all__ = [
    "PILOT_MOVE_ACTION",
    "READ_ACTIONS",
    "AdversaryMemory",
    "EffectAttempt",
    "EntityAppearance",
    "InvestigationRecord",
    "rebuild",
    "rebuild_from",
]
