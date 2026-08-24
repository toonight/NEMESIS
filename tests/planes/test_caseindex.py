"""Which cases has this adversary appeared in, and what happened last time.

Cross-run accumulation was already real: ``merge_entities`` folds a node observed again into
the one already held, ``widen_extent`` widens its known window, and the journal makes both
durable. What was missing was the *index*. No object in the graph carries a case identifier —
deliberately, because the same adversary appearing in many cases is the entire point of the
graph — so nothing could answer "have we met this before, and what did we conclude".

The answer is a projection over the audit trail, which already links an investigation to every
entity it touched. It is rebuilt, never stored: there is no new authoritative state here, and
deleting the index costs nothing but the time to replay the events.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.core.ids import IdPrefix, new_id
from nemesis.graph.caseindex import AdversaryMemory, rebuild, rebuild_from
from nemesis.ports.storage import AuditEvent

T0 = datetime(2026, 1, 5, tzinfo=UTC)


def audit_id() -> str:
    return new_id(IdPrefix.AUDIT)


def opened(investigation: str, *, seed: str, seed_type: str = "domain", at: datetime) -> AuditEvent:
    return AuditEvent(
        audit_id=audit_id(),
        occurred_at=at,
        actor="nemesis.pursuit.engine",
        actor_kind="rule",
        action="investigation.start",
        subject=investigation,
        outcome="opened",
        inputs={"seed_type": seed_type, "seed_key": seed, "detected_by": "waf", "budget": "60"},
    )


def pivoted(
    investigation: str,
    *,
    entity: str,
    entity_type: str = "domain",
    pivot: str = "resolution_history",
    at: datetime,
    branch: str = "B1",
) -> AuditEvent:
    return AuditEvent(
        audit_id=audit_id(),
        occurred_at=at,
        actor=new_id(IdPrefix.ACTOR),
        actor_kind="rule",
        action="pivot.execute",
        subject=f"{investigation}/{branch}",
        outcome="succeeded",
        inputs={"pivot": pivot, "entity": entity, "entity_type": entity_type},
    )


def effected(*, target: str, outcome: str, at: datetime) -> AuditEvent:
    return AuditEvent(
        audit_id=audit_id(),
        occurred_at=at,
        actor=new_id(IdPrefix.ACTOR),
        actor_kind="agent",
        action="effect.execute",
        subject=target,
        outcome=outcome,
        inputs={"operation": "takedown_request_draft"},
    )


# -- the question the index exists to answer ---------------------------------------


def test_an_entity_seen_in_two_investigations_is_a_recurrence() -> None:
    inv_a, inv_b = new_id(IdPrefix.INVESTIGATION), new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv_a, seed="portal.example", at=T0),
            pivoted(inv_a, entity="portal.example", at=T0 + timedelta(minutes=1)),
            opened(inv_b, seed="other.example", at=T0 + timedelta(days=90)),
            pivoted(inv_b, entity="portal.example", at=T0 + timedelta(days=90, minutes=1)),
        ]
    )

    assert memory.is_recurrence("domain", "portal.example")
    assert memory.cases_for("domain", "portal.example") == (inv_a, inv_b)
    assert not memory.is_recurrence("domain", "other.example")


def test_an_entity_seen_many_times_in_one_investigation_is_not_a_recurrence() -> None:
    """Recurrence means *across cases*. Twenty pivots in one investigation is one appearance.

    The distinction is the whole value: an adversary that comes back is a finding, and a busy
    branch is a Tuesday.
    """
    inv = new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv, seed="portal.example", at=T0),
            *(
                pivoted(inv, entity="portal.example", at=T0 + timedelta(minutes=n))
                for n in range(20)
            ),
        ]
    )
    assert not memory.is_recurrence("domain", "portal.example")
    assert len(memory.cases_for("domain", "portal.example")) == 1


def test_the_same_key_under_two_types_is_two_entities() -> None:
    """A persona and a domain can spell the same string, and they are not the same thing.

    The audit event carries the type for exactly this reason. Keying the index on the natural
    key alone would merge them, and a merged node is the second way an attribution engine
    deceives itself — three weak links become an apparent cluster.
    """
    inv_a, inv_b = new_id(IdPrefix.INVESTIGATION), new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv_a, seed="anvil", at=T0),
            pivoted(inv_a, entity="anvil", entity_type="domain", at=T0),
            opened(inv_b, seed="anvil", at=T0 + timedelta(days=1)),
            pivoted(inv_b, entity="anvil", entity_type="persona", at=T0 + timedelta(days=1)),
        ]
    )
    assert not memory.is_recurrence("domain", "anvil")
    assert not memory.is_recurrence("persona", "anvil")
    assert memory.cases_for("domain", "anvil") == (inv_a,)
    assert memory.cases_for("persona", "anvil") == (inv_b,)


def test_an_appearance_carries_when_and_what_was_run() -> None:
    inv = new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv, seed="portal.example", at=T0),
            pivoted(inv, entity="portal.example", pivot="resolution_history", at=T0),
            pivoted(
                inv,
                entity="portal.example",
                pivot="registration_record",
                at=T0 + timedelta(hours=3),
            ),
        ]
    )
    appearance = memory.appearances_of("domain", "portal.example")[0]
    assert appearance.investigation_id == inv
    assert appearance.first_seen == T0
    assert appearance.last_seen == T0 + timedelta(hours=3)
    assert appearance.pivots == ("registration_record", "resolution_history")


def test_prior_effects_against_a_target_are_recalled() -> None:
    """ "What did we try last time" is the question that stops a second futile takedown."""
    inv = new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv, seed="portal.example", at=T0),
            pivoted(inv, entity="portal.example", at=T0),
            effected(target="portal.example", outcome="drafted", at=T0 + timedelta(hours=1)),
            effected(
                target="portal.example",
                outcome="refused_unauthorized",
                at=T0 + timedelta(hours=2),
            ),
        ]
    )
    assert memory.effects_against("portal.example") == ("drafted", "refused_unauthorized")


def test_an_investigation_records_its_seed_and_when_it_opened() -> None:
    inv = new_id(IdPrefix.INVESTIGATION)
    memory = rebuild([opened(inv, seed="portal.example", at=T0)])
    record = memory.investigation(inv)
    assert record is not None
    assert record.seed_key == "portal.example"
    assert record.seed_type == "domain"
    assert record.opened_at == T0


# -- it is a projection, and projections must be rebuildable -----------------------


def test_rebuilding_from_the_same_events_gives_the_same_memory() -> None:
    """The property that makes it safe to delete. A projection nobody can rebuild is a store."""
    inv = new_id(IdPrefix.INVESTIGATION)
    events = [
        opened(inv, seed="portal.example", at=T0),
        pivoted(inv, entity="portal.example", at=T0),
        effected(target="portal.example", outcome="drafted", at=T0 + timedelta(hours=1)),
    ]
    assert rebuild(events) == rebuild(events)


def test_event_order_does_not_change_the_answer() -> None:
    """An audit trail is append-only but a query may return any window in any order."""
    inv = new_id(IdPrefix.INVESTIGATION)
    events = [
        opened(inv, seed="portal.example", at=T0),
        pivoted(inv, entity="portal.example", at=T0 + timedelta(hours=2)),
        pivoted(inv, entity="portal.example", at=T0 + timedelta(hours=1)),
    ]
    assert rebuild(events) == rebuild(list(reversed(events)))


def test_an_empty_trail_is_an_empty_memory_not_an_error() -> None:
    memory = rebuild([])
    assert memory == AdversaryMemory()
    assert memory.cases_for("domain", "anything") == ()
    assert not memory.is_recurrence("domain", "anything")


# -- what it cannot read, it says it could not read --------------------------------


def test_a_pivot_event_with_no_entity_is_counted_not_dropped() -> None:
    """Unreadable is not absent.

    An event this projection cannot interpret is a hole in the memory, and a hole that reports
    itself as zero appearances is indistinguishable from an adversary we have never met.
    """
    inv = new_id(IdPrefix.INVESTIGATION)
    malformed = AuditEvent(
        audit_id=audit_id(),
        occurred_at=T0,
        actor="nemesis.pursuit.engine",
        actor_kind="rule",
        action="pivot.execute",
        subject=f"{inv}/B1",
        outcome="succeeded",
        inputs={"pivot": "resolution_history"},
    )
    memory = rebuild([opened(inv, seed="portal.example", at=T0), malformed])
    assert memory.unreadable == 1
    assert memory.appearances == ()


def test_actions_the_projection_does_not_model_are_ignored_without_complaint() -> None:
    """Forward compatibility. A new audit action must not make the memory report a hole."""
    inv = new_id(IdPrefix.INVESTIGATION)
    unrelated = AuditEvent(
        audit_id=audit_id(),
        occurred_at=T0,
        actor="nemesis.evidence.vault",
        actor_kind="rule",
        action="evidence.verify",
        subject="whatever",
        outcome="verified",
    )
    memory = rebuild([opened(inv, seed="p.example", at=T0), unrelated])
    assert memory.unreadable == 0


# -- the trail the platform actually writes ----------------------------------------


@pytest.mark.anyio
async def test_the_memory_survives_a_restart_of_the_process_that_wrote_it() -> None:
    """GAP-7: an adversary memory that a restart forgets is not a memory.

    Nothing here is held in the projection: the trail on disk is the state, and a second
    process reading the same file rebuilds the same answer. That is the property that makes it
    safe for the index to be deleted, moved or never written at all.
    """
    with tempfile.TemporaryDirectory() as workspace:
        path = Path(workspace) / "audit.jsonl"
        inv_a, inv_b = new_id(IdPrefix.INVESTIGATION), new_id(IdPrefix.INVESTIGATION)

        first = AppendOnlyAuditTrail(path)
        for event in (
            opened(inv_a, seed="portal.example", at=T0),
            pivoted(inv_a, entity="portal.example", at=T0),
        ):
            await first.record(event)

        # A different object over the same file: the restart.
        second = AppendOnlyAuditTrail(path)
        for event in (
            opened(inv_b, seed="other.example", at=T0 + timedelta(days=200)),
            pivoted(inv_b, entity="portal.example", at=T0 + timedelta(days=200)),
        ):
            await second.record(event)

        assert await second.verify_chain()

        third = AppendOnlyAuditTrail(path)
        memory = await rebuild_from(third)

    assert memory.is_recurrence("domain", "portal.example")
    assert memory.cases_for("domain", "portal.example") == (inv_a, inv_b)


@pytest.mark.anyio
async def test_a_real_pursuit_run_produces_a_readable_memory() -> None:
    """The projection against the trail the engine writes, not against handcrafted events.

    A test over fixtures of my own shape proves the parser and nothing about the platform. This
    one fails the day `pivot.execute` stops carrying what the index reads — which is exactly the
    coupling worth having a test for, since the two live in different planes.
    """
    from nemesis.slice.scenario import run_glass_anvil_scenario_async

    with tempfile.TemporaryDirectory() as workspace:
        result = await run_glass_anvil_scenario_async(workspace=Path(workspace))
        memory = await rebuild_from(result.stores.audit)

    assert memory.investigations, "no investigation was recorded"
    assert memory.appearances, "the trail recorded no entity the index could read"
    assert memory.unreadable == 0, (
        f"{memory.unreadable} pivot event(s) the index could not interpret"
    )
    seeded = memory.investigations[0]
    assert seeded.seed_key
    assert seeded.seed_type


def test_an_effect_outcome_is_reported_as_its_verdict_not_its_paragraph() -> None:
    """The trail's effect outcome is a composite line, not a word.

    ``effect.execute`` records ``"{verdict} adapter=... external_contact=... detail=..."``, and
    the detail is the adapter's whole explanation of which steps it did not perform. Reported
    whole, a list of two prior attempts becomes several hundred characters of prose where a
    reader wanted two words.
    """
    inv = new_id(IdPrefix.INVESTIGATION)
    composite = (
        "simulated adapter=simulation-effects-adapter external_contact=false artifacts=none "
        "detail=SIMULATED: rehearsed registrar_suspension against portal.example. Nothing left "
        "NEMESIS. Steps not performed: contact BulletproofReg — this plane has no network reach."
    )
    memory = rebuild(
        [
            opened(inv, seed="portal.example", at=T0),
            pivoted(inv, entity="portal.example", at=T0),
            effected(target="portal.example", outcome=composite, at=T0 + timedelta(hours=1)),
        ]
    )
    assert memory.effects_against("portal.example") == ("simulated",)
    assert memory.effects[0].outcome == composite, "the full line must survive on the record"


def test_a_pilot_driven_effect_is_remembered_too() -> None:
    """Found by reading a real Codex-driven run back through this projection.

    ``record_effect``, which writes ``effect.execute``, is called only from the demonstration
    scenario. A pilot's effect produces a ``pilot.move`` and nothing else — so keying this index
    on ``effect.execute`` alone made every effect the autonomous path ever requested invisible
    to "what did we try last time", which is the question the memory exists to answer.

    My defect, from the day the index was written: I keyed on an action without checking who
    writes it.
    """
    inv = new_id(IdPrefix.INVESTIGATION)
    pilot_effect = AuditEvent(
        audit_id=audit_id(),
        occurred_at=T0 + timedelta(hours=1),
        actor=new_id(IdPrefix.ACTOR),
        actor_kind="agent",
        action="pilot.move",
        subject=inv,
        outcome="accepted",
        inputs={
            "move_kind": "request_effect",
            "operation": "simulation",
            "effect_outcome": "simulated",
            "target_natural_key": "portal.example",
            "pilot": "codex-current-conversation",
        },
    )
    memory = rebuild(
        [
            opened(inv, seed="portal.example", at=T0),
            pivoted(inv, entity="portal.example", at=T0),
            pilot_effect,
        ]
    )
    assert memory.effects_against("portal.example") == ("simulated",)


def test_a_pilot_move_that_is_not_an_effect_is_not_remembered_as_one() -> None:
    """A pivot and a belief are moves too, and neither is something we tried against a target."""
    inv = new_id(IdPrefix.INVESTIGATION)
    belief = AuditEvent(
        audit_id=audit_id(),
        occurred_at=T0,
        actor=new_id(IdPrefix.ACTOR),
        actor_kind="agent",
        action="pilot.move",
        subject=inv,
        outcome="accepted",
        inputs={"move_kind": "record_belief", "pilot": "gpt-5-cyber"},
    )
    memory = rebuild([opened(inv, seed="portal.example", at=T0), belief])
    assert memory.effects == ()
    assert memory.unreadable == 0


def test_an_entity_we_ran_an_effect_against_has_a_case_history() -> None:
    """The projection must not know we acted against something and not know we ever saw it.

    Found by driving a live pilot from a seed the envelope did not approve: the run traversed to
    the approved target, rehearsed against it, and the memory then answered
    ``effects_against("initech-payments-secure.example") == ("simulated",)`` and
    ``cases_for("domain", "initech-payments-secure.example") == ()``. Two answers from one
    object, contradicting each other about whether the entity had ever been seen.

    An appearance was keyed only on the entity a pivot was *run against*, so every entity that a
    pivot merely *surfaced* was absent — including the one target the whole session existed to
    act on. A recurrence check over that index is blind to precisely the assets an operator
    rebuilds: the ones we took action against last time.

    Only effect targets are repaired here, not every discovered entity. Discovery is a weaker
    signal — a domain that shared an address once is a lead, and counting it as an appearance
    would report recurrences for anything that was ever co-hosted with anything. Something we
    aimed an effect at is not a lead, and the trail records it explicitly.
    """
    inv = new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv, seed="seed.example", at=T0),
            pivoted(inv, entity="seed.example", at=T0),
            AuditEvent(
                audit_id=audit_id(),
                occurred_at=T0 + timedelta(hours=1),
                actor=new_id(IdPrefix.ACTOR),
                actor_kind="agent",
                action="pilot.move",
                subject=inv,
                outcome="accepted",
                inputs={
                    "move_kind": "request_effect",
                    "operation": "simulation",
                    "effect_outcome": "simulated",
                    "target_natural_key": "target.example",
                    "target_entity_type": "domain",
                    "pilot": "claude-opus-5-current-conversation",
                },
            ),
        ]
    )
    assert memory.effects_against("target.example") == ("simulated",)
    assert memory.cases_for("domain", "target.example") == (inv,)


def test_an_effect_target_whose_type_the_trail_omits_is_counted_not_guessed() -> None:
    """A persona and a domain can spell the same string, so an untyped target is not an
    appearance. Runs written before the type was recorded land in ``unreadable`` rather than
    being filed under a type nobody observed — and the effect itself is still remembered, which
    is the half the trail *can* support.
    """
    inv = new_id(IdPrefix.INVESTIGATION)
    memory = rebuild(
        [
            opened(inv, seed="seed.example", at=T0),
            AuditEvent(
                audit_id=audit_id(),
                occurred_at=T0 + timedelta(hours=1),
                actor=new_id(IdPrefix.ACTOR),
                actor_kind="agent",
                action="pilot.move",
                subject=inv,
                outcome="accepted",
                inputs={
                    "move_kind": "request_effect",
                    "operation": "simulation",
                    "effect_outcome": "simulated",
                    "target_natural_key": "target.example",
                    "pilot": "legacy-run-without-a-recorded-type",
                },
            ),
        ]
    )
    assert memory.effects_against("target.example") == ("simulated",)
    assert memory.cases_for("domain", "target.example") == ()
    assert memory.unreadable == 1
