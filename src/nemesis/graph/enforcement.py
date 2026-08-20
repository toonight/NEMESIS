"""Retention enforced, not merely described.

:mod:`nemesis.core.retention` decides *what should go*, and deliberately cannot act:
:mod:`nemesis.core` performs no I/O, and separating the decision from the deletion is the
order those two steps belong in for personal data — an operator reads what *would* be erased
before anything is. This module is the second step.

**Erasure is the one mutation that loses information**, so three properties are structural
rather than optional:

**It is recorded.** An erasure that leaves no trace is indistinguishable from data loss, and
invariant 11 asks for auditable. What is recorded is the *shape* — entity type, category, the
period that expired, the sweep that ordered it — and never the value erased. A retention log
that repeats what it deleted has kept it.

**It survives a replay.** The graph is journal-backed and replayed on open, so an erasure that
is not journalled as its own operation is undone the next time the process starts: the upsert
that created the node is still on disk. That is why `GraphStore.erase_entity` exists on the
port with that requirement written into it, and why the journal carries `OP_ERASE`.

**A legal hold outranks it.** A node named by a live instrument is reported as held, never
erased, and the reference is recorded — so "we kept it" is as auditable as "we erased it".

**What this does not touch.** The evidence vault. Sealed evidence is append-only and
hash-chained, and removing an entry would break the chain that makes the vault worth having.
Reconciling erasure with tamper-evidence is a founder decision with three honest options
(crypto-erasure, never vaulting personal data, erasure as its own chained event) and until it
is settled every sweep says so out loud. A report that said "3 erased" while the vault still
held the person's name would be worse than no report.

Status: `IMPLEMENTED` for the graph. `REQUIRES` a founder decision for the vault.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from nemesis.core.entities import Entity, EntityCategory
from nemesis.core.retention import (
    VAULT_RETENTION_NOTICE,
    RetentionAssessment,
    RetentionClass,
    RetentionVerdict,
    sweep,
)
from nemesis.core.temporal import utcnow
from nemesis.ports.storage import GraphStore


class ErasureRecord(BaseModel):
    """One node erased, described by its shape and never by its value.

    A retention log that repeated what it deleted would have kept it, which is the whole
    point missed. Type and category are enough for an auditor to check that the policy was
    applied to the right population; the natural key is exactly what the obligation was to
    forget.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: str
    entity_type: str
    category: EntityCategory
    last_observed: datetime
    overdue_by_days: int
    erased_at: datetime
    policy_rationale: str

    def render(self) -> str:
        return (
            f"{self.entity_type} ({self.category.value}) erased — "
            f"{self.overdue_by_days} day(s) past its period"
        )


class HeldRecord(BaseModel):
    """A node past its period that was kept, and the instrument that keeps it.

    Recorded with the same weight as an erasure: "we kept it" is a decision somebody has to
    be able to review, and a sweep that only logged deletions would make retention look
    complete while the interesting cases sat unexamined.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: str
    entity_type: str
    legal_hold_reference: str
    overdue_by_days: int


class EnforcementReport(BaseModel):
    """What one sweep did, what it kept, and what it does not cover."""

    model_config = ConfigDict(frozen=True)

    ran_at: datetime
    assessed: int
    erased: tuple[ErasureRecord, ...]
    held: tuple[HeldRecord, ...]
    failed: tuple[str, ...] = ()
    dry_run: bool = False
    vault_notice: str = VAULT_RETENTION_NOTICE

    @property
    def graph_is_compliant(self) -> bool:
        """Whether every node past its period is now either gone or under a named hold.

        False whenever an erasure failed. A sweep that could not remove something must not
        report the graph as clean — that is the difference between enforcement and a report.
        """
        return not self.failed

    def render(self) -> str:
        head = "would erase" if self.dry_run else "erased"
        lines = [
            f"Retention sweep at {self.ran_at.isoformat(timespec='seconds')}"
            + (" — DRY RUN, nothing was removed" if self.dry_run else ""),
            f"  {self.assessed} node(s) assessed, {len(self.erased)} {head}, "
            f"{len(self.held)} held under a legal basis",
        ]
        lines += [f"    - {record.render()}" for record in self.erased]
        lines += [
            f"    = {record.entity_type} held under {record.legal_hold_reference}"
            for record in self.held
        ]
        if self.failed:
            lines.append(f"  {len(self.failed)} erasure(s) FAILED — the graph is not compliant:")
            lines += [f"    ! {reason}" for reason in self.failed]
        lines.append(f"  {self.vault_notice}")
        return "\n".join(lines)


async def enforce_retention(
    graph: GraphStore,
    entities: Sequence[Entity],
    *,
    now: datetime | None = None,
    legal_holds: dict[str, str] | None = None,
    policy: dict[EntityCategory, RetentionClass] | None = None,
    dry_run: bool = False,
    clock: Callable[[], datetime] = utcnow,
) -> EnforcementReport:
    """Assess a population, then erase what is past its period.

    ``dry_run`` produces the identical report without removing anything, and it is the
    intended first use: for personal data, reading what *would* go before it goes is the order
    those steps belong in.

    Takes the population as an argument rather than enumerating the graph itself. The
    ``GraphStore`` port has no "list everything" and deliberately so — a component that could
    walk the whole graph is a component that could exfiltrate it — so the caller names the
    nodes it is responsible for.
    """
    moment = now or clock()
    report = sweep(tuple(entities), now=moment, legal_holds=legal_holds, policy=policy)

    erased: list[ErasureRecord] = []
    held: list[HeldRecord] = []
    failed: list[str] = []

    for item in report.assessments:
        if item.verdict is RetentionVerdict.HELD_UNDER_LEGAL_BASIS:
            held.append(
                HeldRecord(
                    entity_id=item.entity_id,
                    entity_type=item.entity_type.value,
                    legal_hold_reference=item.legal_hold_reference or "unnamed",
                    overdue_by_days=_days(item),
                )
            )
            continue
        if not item.must_erase:
            continue

        record = ErasureRecord(
            entity_id=item.entity_id,
            entity_type=item.entity_type.value,
            category=item.category,
            last_observed=item.last_observed,
            overdue_by_days=_days(item),
            erased_at=moment,
            policy_rationale=item.rationale,
        )
        if dry_run:
            erased.append(record)
            continue
        try:
            removed = await graph.erase_entity(item.entity_id)
        except Exception as exc:
            # Reported rather than raised: a sweep that dies halfway has erased some nodes and
            # recorded none of it, which is the worst of both outcomes.
            failed.append(f"{item.entity_type.value} {item.entity_id}: {type(exc).__name__}")
            continue
        if removed:
            erased.append(record)
        else:
            failed.append(
                f"{item.entity_type.value} {item.entity_id}: not present in the graph, so the "
                "obligation to forget it cannot be discharged here"
            )

    return EnforcementReport(
        ran_at=moment,
        assessed=len(report.assessments),
        erased=tuple(erased),
        held=tuple(held),
        failed=tuple(failed),
        dry_run=dry_run,
    )


def _days(item: RetentionAssessment) -> int:
    return 0 if item.overdue_by is None else item.overdue_by.days


__all__ = ["EnforcementReport", "ErasureRecord", "HeldRecord", "enforce_retention"]
