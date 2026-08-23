"""What a long-horizon run says out loud, and the two things it deliberately does not say.

Buzz — and any other collaboration backend — is a **projection surface**. NEMESIS remains the
source of truth: a checkpoint lives in the lineage, evidence lives in the vault, authority lives in
a signed capability, and none of those becomes any less authoritative or any more authoritative for
having been mentioned in a channel. This module builds the read-only, redacted, reference-carrying
view of an evolution event that humans are allowed to see, and nothing else.

Everything :mod:`nemesis.collaboration.events` enforces applies unchanged: DELIVERABLE class only,
bounded payloads, the internal-marker scan, content-addressed identifiers, references instead of
content. What is added here is two refusals specific to this plane.

**A hint is never echoed back.** :func:`hint_event` publishes that a suggestion arrived, who sent
it, how it was classified and whether it will reach the pilot — and not one character of what it
said. The text came from the channel; putting it back would amplify an adversary's message under
NEMESIS's own name, and a reader would see the platform apparently repeating an instruction. What
the record needs is that a hint was received and what was made of it, which is exactly what is
published.

**Progress is projected as counts, never as confidence.** A promoted checkpoint says the origin
count moved from three to four. It does not say the attribution got stronger, because the evaluator
never measured that and a channel is the last place to introduce a number nobody computed. Every
event here carries ``confidence=None`` with an ``uncertainty_note`` saying why, which is the
convention the collaboration plane already uses for a model assertion with no corroborating chain.

Status: `IMPLEMENTED`.
"""

from __future__ import annotations

import re
from datetime import datetime

from nemesis.collaboration.base import InboundSignal
from nemesis.collaboration.events import (
    CollaborationEvent,
    EpistemicStanding,
    Reference,
    ReferenceScheme,
)
from nemesis.core.disclosure import INTERNAL_MARKERS
from nemesis.core.identity import ActorKind
from nemesis.evolution.memory import MEMORY_CLASSIFICATION, MemoryEntry
from nemesis.evolution.models import (
    BranchStatus,
    EvolutionBranch,
    InvestigationCheckpoint,
    StopReason,
)
from nemesis.evolution.stagnation import StagnationAssessment
from nemesis.evolution.supervisor import IssuedDirective

EVOLUTION_ACTOR = "nemesis-evolution"
"""The display name every event here is published under.

The same convention :mod:`nemesis.collaboration.identities` uses: ``nemesis-pursuit`` for the
deterministic scheduler, ``nemesis-pilot`` for the model-driven seat. Evolution is a deterministic
component that *drives* a model, so its events are ``RULE``-kind — a reader must not mistake a
measurement for something a model said.
"""

SUPERVISOR_ACTOR = "nemesis-supervisor"
"""Directives are published under their own actor, because a directive is the one thing here that a
model may have produced. Keeping the two actors apart is what lets a reader tell a measured fact
from a recommendation without reading the standing field."""

MAX_PROJECTED_REFERENCES = 8
"""How many evidence or entity references one event carries. Small: a channel message is a pointer,
and an event listing sixty locators is a data export wearing a message's clothes."""

_MARKERS = re.compile("|".join(re.escape(marker) for marker in INTERNAL_MARKERS), re.IGNORECASE)


def _redact(text: str) -> str:
    """Neutralise NEMESIS's internal vocabulary in a field a stranger chose.

    Redaction rather than refusal, for the reason the mediator gives for a natural key: raising on
    a marker in adversary-controlled text converts a disclosure control into a denial of service
    the adversary fires. The events this plane publishes about a *hostile* message are exactly the
    ones that must not be suppressible by the hostile party.
    """
    return _MARKERS.sub("[redacted]", text)


NO_CONFIDENCE_NOTE = (
    "No confidence figure is published for a trajectory measurement. What was measured is how the "
    "investigation's structure changed, not how likely a conclusion is, and a number here would "
    "read as a finding."
)


def run_started_event(
    *,
    run_id: str,
    investigation_id: str,
    case_id: str,
    correlation_id: str,
    occurred_at: datetime,
    max_steps: int,
    moves_per_step: int,
) -> CollaborationEvent:
    """A run opened. Published so a channel can tell an autonomous run from a manual one."""
    return CollaborationEvent.for_publication(
        occurred_at=occurred_at,
        case_id=case_id,
        investigation_id=investigation_id,
        correlation_id=correlation_id,
        actor=EVOLUTION_ACTOR,
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.INFERENCE,
        event_type="evolution.run.started",
        summary=(
            f"A long-horizon evolution run opened over this investigation: at most {max_steps} "
            f"variation steps of at most {moves_per_step} pilot moves each. Every move is still "
            "proposed in the four-verb vocabulary and ruled on by the mediator."
        ),
        payload={
            "run_id": run_id,
            "max_steps": str(max_steps),
            "moves_per_step": str(moves_per_step),
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION, case_id=case_id, locator=investigation_id
            ),
        ),
        confidence=None,
        uncertainty_note=NO_CONFIDENCE_NOTE,
    )


def checkpoint_event(
    checkpoint: InvestigationCheckpoint,
    *,
    case_id: str,
    correlation_id: str,
    previous_origins: int = 0,
    previous_contradictions: int = 0,
) -> CollaborationEvent:
    """A checkpoint was promoted, with what moved and what it survives.

    The summary names the *robust* figure beside the raw one deliberately. "Independent origins 3 →
    4" and "survives removing a plantable artifact: yes" are different claims, and a channel that
    reported only the first would let a reader take a fragile finding for a corroborated one.
    """
    measurement = checkpoint.evaluation.measurement
    score = checkpoint.evaluation.score
    return CollaborationEvent.for_publication(
        occurred_at=checkpoint.created_at,
        case_id=case_id,
        investigation_id=checkpoint.investigation_id,
        correlation_id=correlation_id,
        actor=EVOLUTION_ACTOR,
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.INFERENCE,
        event_type="evolution.checkpoint.promoted",
        summary=(
            f"Checkpoint {checkpoint.step_index} promoted. Independent origins "
            f"{previous_origins} to {measurement.independent_origins}; origins surviving removal "
            f"of the most load-bearing plantable cluster: {measurement.origin_floor}. "
            f"Contradictions {previous_contradictions} to {measurement.open_contradictions}. "
            f"{score.useful_entities_discovered} new entity(ies) that are not shared "
            f"infrastructure, {score.discriminating_relationships_gained} new discriminating "
            "edge(s)."
        ),
        payload={
            "run_id": checkpoint.run_id,
            "checkpoint_id": checkpoint.checkpoint_id,
            "step": str(checkpoint.step_index),
            "independent_origins": str(measurement.independent_origins),
            "origin_floor": str(measurement.origin_floor),
            "open_contradictions": str(measurement.open_contradictions),
            "useful_entities": str(measurement.useful_entities),
            "shared_infrastructure_entities": str(measurement.shared_infrastructure_entities),
            "pivots_executed": str(measurement.pivots_executed),
            "directive_applied": checkpoint.directive_applied,
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION,
                case_id=case_id,
                locator=checkpoint.investigation_id,
            ),
            *(
                Reference(scheme=ReferenceScheme.EVIDENCE, case_id=case_id, locator=locator)
                for locator in checkpoint.evidence_refs[:MAX_PROJECTED_REFERENCES]
            ),
        ),
        confidence=None,
        uncertainty_note=NO_CONFIDENCE_NOTE,
    )


def plateau_event(
    assessment: StagnationAssessment,
    *,
    run_id: str,
    investigation_id: str,
    case_id: str,
    correlation_id: str,
    occurred_at: datetime,
) -> CollaborationEvent:
    """A plateau was detected, with the numbers that produced the verdict."""
    return CollaborationEvent.for_publication(
        occurred_at=occurred_at,
        case_id=case_id,
        investigation_id=investigation_id,
        correlation_id=correlation_id,
        actor=EVOLUTION_ACTOR,
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.INFERENCE,
        event_type="evolution.plateau.detected",
        summary=(
            f"Plateau over the last {assessment.window} step(s): "
            + "; ".join(assessment.reasons[:3])
        )[:2000],
        payload={
            "run_id": run_id,
            "window": str(assessment.window),
            "signals": ",".join(signal.value for signal in assessment.signals)[:500],
            **{key: value[:500] for key, value in assessment.metrics.items()},
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION, case_id=case_id, locator=investigation_id
            ),
        ),
        confidence=None,
        uncertainty_note=NO_CONFIDENCE_NOTE,
    )


def directive_event(
    issued: IssuedDirective,
    *,
    run_id: str,
    investigation_id: str,
    case_id: str,
    correlation_id: str,
) -> CollaborationEvent:
    """A supervisor directive. Published as a RECOMMENDATION, which is what it is.

    Not a DECISION and not an AUTHORIZED_ACTION: a directive changes what the next briefing
    emphasises, and the collaboration plane's own vocabulary already has the word for a proposed
    course of action that authorizes nothing by existing.
    """
    return CollaborationEvent.for_publication(
        occurred_at=issued.issued_at,
        case_id=case_id,
        investigation_id=investigation_id,
        correlation_id=correlation_id,
        actor=SUPERVISOR_ACTOR,
        actor_kind=ActorKind.AGENT,
        standing=EpistemicStanding.RECOMMENDATION,
        event_type="evolution.directive.issued",
        summary=(
            f"Directive {issued.directive.directive.value.upper()} "
            f"(focus: {issued.directive.focus.value}). {issued.directive.rationale} "
            "A directive changes what the next briefing emphasises. It runs nothing, authorizes "
            "nothing and widens no scope."
        )[:2000],
        payload={
            "run_id": run_id,
            "directive": issued.directive.directive.value,
            "focus": issued.directive.focus.value,
            "issued_by": issued.issued_by[:120],
            "supervisor_answered": str(issued.answered).lower(),
            "authorizes": "nothing",
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION, case_id=case_id, locator=investigation_id
            ),
        ),
        confidence=None,
        uncertainty_note=(
            "A directive is a proposed research posture, not a finding. Nothing about it is "
            "measured and nothing about it is authorized."
        ),
    )


def branch_event(
    branch: EvolutionBranch,
    *,
    investigation_id: str,
    case_id: str,
    correlation_id: str,
    occurred_at: datetime,
) -> CollaborationEvent:
    """A branch opened, promoted, plateaued or was pruned."""
    opened = branch.status is BranchStatus.ACTIVE and branch.closed_at is None
    return CollaborationEvent.for_publication(
        occurred_at=occurred_at,
        case_id=case_id,
        investigation_id=investigation_id,
        correlation_id=correlation_id,
        actor=EVOLUTION_ACTOR,
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.INFERENCE,
        event_type="evolution.branch.opened" if opened else "evolution.branch.closed",
        summary=(
            f"Branch {'opened' if opened else branch.status.value}: {branch.objective}. "
            f"{branch.step_allowance} step(s) of the run's shared allowance; branching divides a "
            "run's budget and never multiplies it."
            + (f" Reason: {branch.closure_reason}" if branch.closure_reason else "")
        )[:2000],
        payload={
            "run_id": branch.run_id,
            "branch_id": branch.branch_id,
            "status": branch.status.value,
            "step_allowance": str(branch.step_allowance),
            "steps_taken": str(branch.steps_taken),
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION, case_id=case_id, locator=investigation_id
            ),
        ),
        confidence=None,
        uncertainty_note=NO_CONFIDENCE_NOTE,
    )


def hint_event(
    entry: MemoryEntry,
    *,
    run_id: str,
    investigation_id: str,
    case_id: str,
    correlation_id: str,
) -> CollaborationEvent:
    """A research suggestion was received and classified. **Its text is not republished.**

    See the module docstring: echoing the hint would put an adversary's words back into the channel
    under NEMESIS's own actor. What is published is that one arrived, who sent it, what it was
    classified as, and whether it will be shown to the pilot.
    """
    return CollaborationEvent.for_publication(
        occurred_at=entry.created_at,
        case_id=case_id,
        investigation_id=investigation_id,
        correlation_id=correlation_id,
        actor=EVOLUTION_ACTOR,
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.INFERENCE,
        event_type=(
            "evolution.hint.quarantined" if entry.imperative else "evolution.hint.received"
        ),
        summary=(
            "A research suggestion was received from this channel and recorded as "
            f"{MEMORY_CLASSIFICATION}. It is not evidence, it authorizes nothing, and it cannot "
            "widen this investigation's scope or its capability envelope."
            + (
                " It reads as an instruction rather than a suggestion, so it was quarantined and "
                "will NOT be shown to the pilot."
                if entry.imperative
                else " It will be shown to the pilot as untrusted data, labelled as such."
            )
        ),
        payload={
            "run_id": run_id,
            "entry_id": entry.entry_id,
            "classification": MEMORY_CLASSIFICATION,
            # Redacted here as well as sanitized at ingestion, because this is the field a sender
            # chooses and `CollaborationEvent` RAISES on an internal marker. An adversarial review
            # showed the consequence: an author reference containing `same_operator_as` made the
            # quarantine notice unpublishable, so the one event that reports an injection attempt
            # was the event an attacker could suppress by choosing their own display name.
            "author": _redact(entry.created_by)[:120],
            "instruction_shapes": ",".join(entry.imperative)[:500],
            "shown_to_pilot": str(entry.projectable).lower(),
            "is_evidence": "false",
            "authorizes": "nothing",
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION, case_id=case_id, locator=investigation_id
            ),
        ),
        confidence=None,
        uncertainty_note=(
            "The text of the suggestion is deliberately not republished here. It arrived from "
            "this channel, and repeating it under NEMESIS's own actor would amplify whatever it "
            "said."
        ),
    )


def run_stopped_event(
    *,
    run_id: str,
    investigation_id: str,
    case_id: str,
    correlation_id: str,
    occurred_at: datetime,
    reason: StopReason,
    steps_taken: int,
    detail: str = "",
) -> CollaborationEvent:
    """A run ended, and why. Every stop reason is a deterministic condition, not a judgement."""
    return CollaborationEvent.for_publication(
        occurred_at=occurred_at,
        case_id=case_id,
        investigation_id=investigation_id,
        correlation_id=correlation_id,
        actor=EVOLUTION_ACTOR,
        actor_kind=ActorKind.RULE,
        standing=EpistemicStanding.INFERENCE,
        event_type="evolution.run.stopped",
        summary=(
            f"The evolution run stopped after {steps_taken} step(s): {reason.value}. "
            f"{detail} A stop is a deterministic condition on observable state — a budget, a "
            "ceiling, a conclusion — never a model's decision."
        )[:2000],
        payload={
            "run_id": run_id,
            "stop_reason": reason.value,
            "steps_taken": str(steps_taken),
        },
        references=(
            Reference(
                scheme=ReferenceScheme.INVESTIGATION, case_id=case_id, locator=investigation_id
            ),
        ),
        confidence=None,
        uncertainty_note=NO_CONFIDENCE_NOTE,
    )


def hint_text_of(signal: InboundSignal) -> str:
    """The suggestion inside a channel message, as untrusted text.

    Deliberately trivial, and deliberately here rather than in the controller. What it establishes
    is that reading a signal is a *conversion into data* with a name — the same reason
    :class:`~nemesis.collaboration.base.InboundSignal` is a different type from a
    :class:`~nemesis.collaboration.events.CollaborationEvent`. Nothing in the signal is followed:
    :attr:`~nemesis.collaboration.base.InboundSignal.references` names locators the sender wanted
    read, which is not the same as something NEMESIS should read, and this function does not touch
    them.
    """
    return signal.body


__all__ = [
    "EVOLUTION_ACTOR",
    "MAX_PROJECTED_REFERENCES",
    "NO_CONFIDENCE_NOTE",
    "SUPERVISOR_ACTOR",
    "branch_event",
    "checkpoint_event",
    "directive_event",
    "hint_event",
    "hint_text_of",
    "plateau_event",
    "run_started_event",
    "run_stopped_event",
]
