"""Tamper and attribution tests for the append-only audit trail.

The four tamper modes are tested separately because they fail differently and a chain that
catches only in-place modification is the common useless variant — it is defeated by an
editor that drops a line. Insertion, interior deletion and reordering break the links;
tail truncation does not break anything at all and is visible only against a head
remembered outside the file. The last of those tests also states the limit: a file
truncated before this process ever opened it verifies clean, which is why invariant 10's
argument for an external anchor applies to actions as well as artifacts.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from nemesis.audit.trail import (
    MAX_RENDERED_RESULTS,
    ActorKind,
    AppendOnlyAuditTrail,
    AuditWriteError,
    UnattributedActionError,
    make_event,
    outcome_token,
    render_result_set,
)
from nemesis.core.authorization import AuthorizationDecision, OperationClass
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.relationships import PivotMethod, RelationType
from nemesis.ports.storage import AuditEvent

T0 = datetime(2026, 3, 2, 8, 14, tzinfo=UTC)
FINGERPRINT = "sha256:" + "1" * 64


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Drive one trail call to completion.

    The trail is ``async`` because the port declares it so; its critical section is
    synchronous file I/O guarded by a ``threading.Lock``, so a fresh loop per call is safe.
    """
    return asyncio.run(coroutine)


def _trail(tmp_path: Path) -> AppendOnlyAuditTrail:
    return AppendOnlyAuditTrail(tmp_path / "audit.jsonl")


def _record(trail: AppendOnlyAuditTrail, action: str, subject: str) -> AuditEvent:
    return run(
        trail.record(
            make_event(
                actor="analyst-1",
                actor_kind=ActorKind.HUMAN,
                action=action,
                subject=subject,
                outcome="opened the case",
                occurred_at=T0,
            )
        )
    )


def _three_entries(tmp_path: Path) -> tuple[AppendOnlyAuditTrail, list[str]]:
    trail = _trail(tmp_path)
    for index in range(3):
        _record(trail, action=f"case.step{index}", subject=f"domain:step{index}.example")
    lines = trail.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    return trail, lines


def _rewrite(trail: AppendOnlyAuditTrail, lines: list[str]) -> None:
    trail.path.write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")


# --- the four tamper modes ----------------------------------------------------


def test_modifying_a_sealed_entry_is_caught(tmp_path: Path) -> None:
    trail, lines = _three_entries(tmp_path)
    entry = json.loads(lines[1])
    entry["outcome"] = "permitted"
    lines[1] = json.dumps(entry)
    _rewrite(trail, lines)

    verification = run(trail.verify())

    assert not verification.intact
    assert verification.broken_at == 1
    assert verification.reason is not None
    assert "modified" in verification.reason


def test_inserting_an_entry_is_caught(tmp_path: Path) -> None:
    trail, lines = _three_entries(tmp_path)
    _rewrite(trail, [lines[0], lines[0], lines[1], lines[2]])

    verification = run(trail.verify())

    # The forged line is a genuine, correctly sealed entry — it just does not follow the
    # one before it. Only the link to the predecessor exposes that.
    assert not verification.intact
    assert verification.broken_at == 1
    assert verification.reason is not None
    assert "inserted, removed or reordered" in verification.reason


def test_deleting_an_interior_entry_is_caught(tmp_path: Path) -> None:
    trail, lines = _three_entries(tmp_path)
    _rewrite(trail, [lines[0], lines[2]])

    verification = run(trail.verify())

    assert not verification.intact
    assert verification.broken_at == 1


def test_reordering_entries_is_caught(tmp_path: Path) -> None:
    trail, lines = _three_entries(tmp_path)
    _rewrite(trail, [lines[0], lines[2], lines[1]])

    verification = run(trail.verify())

    # Every line is authentic and every hash recomputes; only the order is a lie.
    assert not verification.intact
    assert verification.broken_at == 1


def test_removing_the_tail_is_caught_only_against_a_head_held_outside_the_file(
    tmp_path: Path,
) -> None:
    trail, lines = _three_entries(tmp_path)
    _rewrite(trail, lines[:2])

    verification = run(trail.verify())

    assert not verification.intact
    assert verification.reason is not None
    assert "removed from the end" in verification.reason

    # Stated rather than hidden: a truncated chain links perfectly, so a process that never
    # saw the missing entries cannot tell. This is the gap an external anchor over head()
    # closes, and the reason the trail publishes one.
    reopened = AppendOnlyAuditTrail(trail.path)
    assert run(reopened.verify()).intact
    assert run(reopened.entry_count()) == 2


def test_the_trail_refuses_to_extend_a_file_that_changed_underneath_it(tmp_path: Path) -> None:
    trail, lines = _three_entries(tmp_path)
    _rewrite(trail, lines[:2])

    # Appending onto a head the file no longer carries would fork the chain and produce a
    # trail that verifies and is still wrong.
    with pytest.raises(AuditWriteError, match="changed on disk"):
        _record(trail, action="case.step3", subject="domain:step3.example")


def test_a_caller_may_not_choose_its_own_position_in_the_chain(tmp_path: Path) -> None:
    trail = _trail(tmp_path)
    event = make_event(
        actor="analyst-1",
        actor_kind=ActorKind.HUMAN,
        action="case.open",
        subject="case:glass-anvil",
        outcome="opened the case",
        occurred_at=T0,
    ).model_copy(update={"previous_hash": "sha256:" + "0" * 64})

    with pytest.raises(AuditWriteError, match="never accepts them from a caller"):
        run(trail.record(event))


# --- attribution ---------------------------------------------------------------


@pytest.mark.parametrize("actor", ["", "system", "Unknown", "n/a", "agent", "nobody", "analyst-1 "])
def test_an_action_with_no_attributable_actor_is_refused(tmp_path: Path, actor: str) -> None:
    trail = _trail(tmp_path)
    event = make_event(
        actor=actor,
        actor_kind=ActorKind.SYSTEM,
        action="pursuit.pivot",
        subject="domain:acme-invoice-portal.example",
        outcome="discovered 4",
        occurred_at=T0,
    )

    # A system action is still attributable — the actor is the component, not the word
    # "system". An unattributable entry is indistinguishable from one nobody would sign.
    with pytest.raises(UnattributedActionError):
        run(trail.record(event))
    assert not trail.path.exists()


def test_an_unclassifiable_actor_kind_is_refused(tmp_path: Path) -> None:
    trail = _trail(tmp_path)
    event = AuditEvent(
        audit_id=new_id(IdPrefix.AUDIT),
        occurred_at=T0,
        actor="pursuit-scheduler",
        actor_kind="daemon",
        action="pursuit.pivot",
        subject="domain:acme-invoice-portal.example",
        outcome="discovered 4",
    )

    with pytest.raises(UnattributedActionError, match="actor_kind"):
        run(trail.record(event))


def test_a_naive_timestamp_is_refused(tmp_path: Path) -> None:
    trail = _trail(tmp_path)
    event = make_event(
        actor="pursuit-scheduler",
        actor_kind=ActorKind.SYSTEM,
        action="pursuit.pivot",
        subject="domain:acme-invoice-portal.example",
        outcome="discovered 4",
        occurred_at=datetime(2026, 3, 2, 8, 14),  # noqa: DTZ001 — the defect under test
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        run(trail.record(event))


# --- denials carry the same weight as permissions --------------------------------


def _decision(*, permitted: bool, operation: OperationClass) -> AuthorizationDecision:
    return AuthorizationDecision(
        permitted=permitted,
        capability_id=new_id(IdPrefix.CAPABILITY),
        operation=operation,
        target_fingerprint=FINGERPRINT,
        evaluated_at=T0,
        denial_reasons=() if permitted else ("capability expired at 2026-03-02T08:00:00+00:00",),
    )


def test_a_denial_is_recorded_with_the_same_weight_as_a_permission(tmp_path: Path) -> None:
    trail = _trail(tmp_path)
    permitted = _decision(permitted=True, operation=OperationClass.SIMULATION)
    denied = _decision(permitted=False, operation=OperationClass.REGISTRAR_SUSPENSION)

    for decision in (permitted, denied):
        run(
            trail.record_authorization(
                actor="analyst-1",
                actor_kind=ActorKind.HUMAN,
                decision=decision,
                subject="domain:acme-invoice-portal.example",
            )
        )

    assert run(trail.entry_count()) == 2
    refusals = run(trail.query(outcome="denied"))
    assert len(refusals) == 1
    # A trail that keeps only the successes hides the pattern an investigator most wants:
    # repeated denied attempts against one target.
    recorded = refusals[0].authorization_decision
    assert recorded is not None
    assert recorded.denial_reasons == denied.denial_reasons
    assert refusals[0].inputs["capability_id"] == denied.capability_id
    assert run(trail.verify()).intact


def test_the_reporter_cannot_overwrite_the_facts_taken_from_the_decision(
    tmp_path: Path,
) -> None:
    trail = _trail(tmp_path)
    denied = _decision(permitted=False, operation=OperationClass.REGISTRAR_SUSPENSION)

    run(
        trail.record_authorization(
            actor="analyst-1",
            actor_kind=ActorKind.HUMAN,
            decision=denied,
            subject="domain:acme-invoice-portal.example",
            inputs={"operation": "simulation", "target_fingerprint": "sha256:" + "0" * 64},
        )
    )

    recorded = run(trail.query(action="authorization.decision"))[0]
    assert recorded.inputs["operation"] == OperationClass.REGISTRAR_SUSPENSION.value
    assert recorded.inputs["target_fingerprint"] == FINGERPRINT


# --- replayability ---------------------------------------------------------------


def test_a_pivot_records_what_would_be_needed_to_re_run_it(tmp_path: Path) -> None:
    trail = _trail(tmp_path)

    run(
        trail.record_pivot(
            actor="agent-pursuit-7",
            actor_kind=ActorKind.AGENT,
            connector="fixture-passive-dns",
            connector_version="1.4.0",
            method=PivotMethod.INFRASTRUCTURE_REUSE,
            relation=RelationType.RESOLVES_TO,
            from_entity="ip:198.51.100.23",
            query_parameters={"connector": "not-the-real-one", "address": "198.51.100.23"},
            discovered=["globex-invoice-portal.example", "acme-invoice-portal.example"],
            occurred_at=T0,
        )
    )

    recorded = run(trail.query(action="pursuit.pivot"))[0]
    # A pivot re-run against a different connector build is a different pivot; without the
    # version in the record, a replay that disagrees proves nothing.
    assert recorded.inputs["connector_version"] == "1.4.0"
    # A connector parameter must not be able to shadow the replay metadata and rewrite the
    # record of which tool was run.
    assert recorded.inputs["connector"] == "fixture-passive-dns"
    assert recorded.inputs["param.connector"] == "not-the-real-one"
    assert outcome_token(recorded.outcome) == "discovered"


def test_a_result_set_renders_the_same_however_it_is_ordered(tmp_path: Path) -> None:
    domains = [f"host{index:02d}.example" for index in range(MAX_RENDERED_RESULTS + 4)]

    forwards = render_result_set(domains)
    backwards = render_result_set([*reversed(domains), domains[0]])

    # A pivot returning the same domains in a different order is the same result. A replay
    # that reported a spurious difference would train people to ignore the comparison.
    assert forwards == backwards
    assert forwards.startswith(f"discovered {len(domains)} sha256:")
    # The demo's control case is a CDN address carrying 41,700 domains; the entry stays
    # readable and the digest still covers the whole set.
    assert forwards.endswith(",...]")
    assert domains[-1] not in forwards
