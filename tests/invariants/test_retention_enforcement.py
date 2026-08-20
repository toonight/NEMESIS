"""A retention policy that never erases anything is a document, not a control.

`core/retention.py` decides what should go and cannot act — core performs no I/O. These tests
are about the half that acts, and about the three ways enforcement is normally hollow:

- **It does not survive a restart.** The graph is journal-backed and replayed on open, so an
  erasure that is not journalled as its own operation is undone the next time the process
  starts. The upsert that created the node is still on disk. That is the load-bearing test
  here, and it is the one a reasonable implementation gets wrong.
- **It erases and forgets to say so.** An erasure that leaves no trace is indistinguishable
  from data loss (invariant 11 asks for auditable) — and a log that records the *value* it
  deleted has kept it.
- **It reports success it did not achieve.** A sweep that could not remove something must not
  report the graph as compliant.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nemesis.core.confidence import Opinion
from nemesis.core.entities import Entity, EntityType
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import PivotMethod, Relationship, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.graph.enforcement import enforce_retention
from nemesis.graph.journal import JournalBackedGraphStore
from nemesis.graph.memory import InMemoryGraphStore

pytestmark = pytest.mark.invariant

NOW = datetime(2026, 8, 17, tzinfo=UTC)
STALE = NOW - timedelta(days=400)  # past the 365-day human-identity period


def _entity(entity_type: EntityType, form: str, *, seen: datetime) -> Entity:
    return Entity.create(
        entity_id=new_id(IdPrefix.ENTITY),
        entity_type=entity_type,
        observed_form=form,
        extent=TemporalExtent.at(seen),
        is_synthetic=True,
    )


# --- The test a reasonable implementation gets wrong --------------------------


def test_an_erasure_survives_a_replay(tmp_path: Path) -> None:
    """THE TEST THIS FILE EXISTS FOR.

    The graph replays a mutation journal on open. Erase a node without journalling the
    erasure and the next replay brings it back — the upsert that created it is still on disk.
    A retention control that a restart undoes is not a control; it is a delay.
    """

    async def scenario() -> tuple[bool, bool]:
        store = await JournalBackedGraphStore.open(tmp_path)
        lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", seen=STALE)
        await store.upsert_entity(lead)

        report = await enforce_retention(store, [lead], now=NOW)
        assert len(report.erased) == 1, report.render()
        gone_now = await store.find_entity(EntityType.HUMAN_IDENTITY_LEAD, lead.natural_key)

        reopened = await JournalBackedGraphStore.open(tmp_path)
        gone_after = await reopened.find_entity(EntityType.HUMAN_IDENTITY_LEAD, lead.natural_key)
        return gone_now is None, gone_after is None

    erased, still_erased = asyncio.run(scenario())
    assert erased, "the node was not erased at all"
    assert still_erased, "the replay resurrected a node the platform undertook to forget"


def test_erasure_takes_the_edges_with_it() -> None:
    """Leaving the edges leaves dangling references to a node we undertook to forget, and a
    traversal still shows its shape — the same disclosure wearing a different form."""

    async def scenario() -> int:
        store = InMemoryGraphStore()
        lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", seen=STALE)
        domain = _entity(EntityType.DOMAIN, "kept.example", seen=NOW)
        await store.upsert_entity(lead)
        await store.upsert_entity(domain)
        await store.add_relationship(
            Relationship(
                edge_id=new_id(IdPrefix.EDGE),
                source_id=domain.entity_id,
                target_id=lead.entity_id,
                source_type=domain.entity_type,
                target_type=lead.entity_type,
                relation=RelationType.ASSOCIATED_WITH,
                extent=TemporalExtent.at(STALE),
                confidence=Opinion.vacuous(),
                pivot_method=PivotMethod.DIRECT_OBSERVATION,
            )
        )
        await enforce_retention(store, [lead, domain], now=NOW)
        return len(store._relationships)

    assert asyncio.run(scenario()) == 0, "an edge to an erased node survived"


# --- Recorded, without recording what was erased ------------------------------


def test_the_record_describes_the_shape_and_never_the_value() -> None:
    """A retention log that repeats what it deleted has kept it."""

    async def scenario() -> str:
        store = InMemoryGraphStore()
        lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "John Doe", seen=STALE)
        await store.upsert_entity(lead)
        report = await enforce_retention(store, [lead], now=NOW)
        return report.render() + str(report.model_dump())

    blob = asyncio.run(scenario()).lower()
    assert "human_identity_lead" in blob, "the record does not say what kind of thing went"
    assert "john" not in blob and "doe" not in blob, (
        "the retention record repeated the value it erased, which is keeping it"
    )


def test_a_dry_run_reports_identically_and_removes_nothing() -> None:
    """For personal data, reading what *would* go before it goes is the order those steps
    belong in — so the dry run must be the same report, not a weaker one."""

    async def scenario() -> tuple[int, bool]:
        store = InMemoryGraphStore()
        lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "A Person", seen=STALE)
        await store.upsert_entity(lead)
        report = await enforce_retention(store, [lead], now=NOW, dry_run=True)
        survived = await store.find_entity(EntityType.HUMAN_IDENTITY_LEAD, lead.natural_key)
        assert "would erase" in report.render()
        return len(report.erased), survived is not None

    counted, survived = asyncio.run(scenario())
    assert counted == 1 and survived, "the dry run erased something"


# --- Holds outrank the period, and are recorded too ---------------------------


def test_a_legal_hold_is_recorded_with_the_same_weight_as_an_erasure() -> None:
    """ "We kept it" is a decision somebody has to review. A sweep that logged only deletions
    would look complete while the interesting cases sat unexamined."""

    async def scenario() -> tuple[int, int, str]:
        store = InMemoryGraphStore()
        lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "A Person", seen=STALE)
        await store.upsert_entity(lead)
        report = await enforce_retention(
            store, [lead], now=NOW, legal_holds={lead.entity_id: "COURT-2026-77"}
        )
        survived = await store.find_entity(EntityType.HUMAN_IDENTITY_LEAD, lead.natural_key)
        assert survived is not None, "a node under a live court order was erased"
        return len(report.erased), len(report.held), report.render()

    erased, held, rendered = asyncio.run(scenario())
    assert (erased, held) == (0, 1)
    assert "COURT-2026-77" in rendered


def test_infrastructure_is_never_erased() -> None:
    """Persistent adversary memory is the strategic asset. Forgetting a domain harms nobody,
    and forgetting an organization would defeat the resurgence loop invariant 14 requires."""

    async def scenario() -> int:
        store = InMemoryGraphStore()
        old = [
            _entity(EntityType.DOMAIN, "ancient.example", seen=NOW - timedelta(days=4000)),
            _entity(EntityType.ORGANIZATION, "GLASS ANVIL", seen=NOW - timedelta(days=4000)),
        ]
        for node in old:
            await store.upsert_entity(node)
        report = await enforce_retention(store, old, now=NOW)
        return len(report.erased)

    assert asyncio.run(scenario()) == 0


# --- A sweep must not report success it did not achieve -----------------------


def test_a_failed_erasure_makes_the_report_non_compliant() -> None:
    """Enforcement, not a report. If a node could not be removed the graph is not clean, and
    saying otherwise is the defect class this project keeps finding in its own output."""

    async def scenario() -> tuple[bool, int]:
        store = InMemoryGraphStore()
        # Assessed but never inserted: erase_entity finds nothing to remove.
        lead = _entity(EntityType.HUMAN_IDENTITY_LEAD, "Absent Person", seen=STALE)
        report = await enforce_retention(store, [lead], now=NOW)
        return report.graph_is_compliant, len(report.failed)

    compliant, failures = asyncio.run(scenario())
    assert compliant is False
    assert failures == 1


def test_every_sweep_says_the_vault_is_not_covered() -> None:
    """A report saying "3 erased" while the vault still held the person's name would be worse
    than no report. The conflict between erasure and tamper-evidence is a founder decision and
    every sweep states it rather than implying the platform forgot."""

    async def scenario() -> str:
        return (await enforce_retention(InMemoryGraphStore(), [], now=NOW)).render()

    assert "RETENTION IN THE VAULT: NOT IMPLEMENTED" in asyncio.run(scenario())
