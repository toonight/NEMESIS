"""The course of the investigation, as a typed ledger the analyst view can draw.

Why this module exists, and why it is small.

:func:`nemesis.ui.investigation.render_investigation` takes the attribution result and the
stage *names* rather than the scenario, because handed everything, the obvious next commit
renders a stage "just to see it" and an internal lead leaves through a field nobody thought
about. The rail on the analyst view wants more than names — a reader should see that the
dark-web stage quarantined an injection attempt, that the effects stage made no external
contact, that a human rejected one option — and this module is the aperture through which
that crosses, made deliberately narrow:

- A mark carries **integers and booleans only**, under labels chosen in code from the closed
  registry in :mod:`nemesis.ui.rail`. There is no free-text field. A persona, a domain, a name
  or a fingerprint has nowhere to travel, and a test dumps every mark to JSON and looks.
- The scenario is read in one function, :func:`stage_ledger`, and nowhere else in
  ``nemesis.ui``. The renderer imports :mod:`nemesis.ui.rail`, not this module, so it cannot
  reach the scenario even by accident.

Status: `IMPLEMENTED` over the `SIMULATED` reference scenario.
"""

from __future__ import annotations

from nemesis.slice.scenario import (
    AttributionStage,
    AuthorizationStage,
    BlockchainStage,
    DarkWebStage,
    DetectionStage,
    DisruptionStage,
    EffectsStage,
    EvidenceStage,
    GraphStage,
    PursuitStage,
    ResolutionStage,
    ResurgenceStage,
    ScenarioResult,
)
from nemesis.ui.rail import (
    FACT_FORMS,
    FACT_LABELS,
    STAGE_META,
    StageFact,
    StageMark,
    StageMeta,
    meta_for,
)


def _fact(label: str, value: int | bool) -> StageFact:
    return StageFact(label=label, value=value)


def _mark(name: str, facts: list[StageFact], *, refusals: int = 0) -> StageMark:
    return StageMark(name=name, facts=tuple(facts), refusals=refusals)


def stage_ledger(result: ScenarioResult) -> tuple[StageMark, ...]:
    """Read the scenario once and return only counts and flags, one mark per stage.

    Every branch below chooses *which integer or boolean* leaves the stage. Nothing here
    forwards a string from the run. A stage type this function does not know is returned as a
    bare mark rather than skipped.
    """
    marks: list[StageMark] = []
    for name, stage in result.stages():
        if isinstance(stage, DetectionStage):
            marks.append(_mark(name, [_fact("sensors", len(stage.sensors))]))
        elif isinstance(stage, PursuitStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("autonomous pivots", stage.autonomous_pivots),
                        _fact("directed collections", len(stage.directed)),
                        _fact("pivots failed", len(stage.autonomous_failures)),
                    ],
                )
            )
        elif isinstance(stage, GraphStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("entities", stage.entity_count),
                        _fact("relationships", stage.relationship_count),
                        _fact(
                            "shared infrastructure excluded",
                            len(stage.excluded_shared_infrastructure),
                        ),
                    ],
                )
            )
        elif isinstance(stage, DarkWebStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("hostile claims", stage.hostile_content_claims),
                        _fact("injection attempts", 1),
                        _fact("injection acted on", bool(stage.prompt_injection.acted_on)),
                        _fact(
                            "identity lead withheld",
                            not stage.identity_lead.promoted_to_attribution,
                        ),
                    ],
                )
            )
        elif isinstance(stage, BlockchainStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("inbound payments", stage.inbound_payments),
                        _fact("dimensions withheld from", len(stage.withheld_from)),
                    ],
                )
            )
        elif isinstance(stage, ResolutionStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("signals used", len(stage.signals_used)),
                        _fact("signals unavailable", len(stage.signals_unavailable)),
                    ],
                    refusals=1,  # the human-identity refusal is a required field of the stage
                )
            )
        elif isinstance(stage, AttributionStage):
            refused = sum(
                1
                for item in stage.result.assessments
                if item.identity_gate is not None and not item.identity_gate.passed
            )
            marks.append(
                _mark(
                    name,
                    [
                        _fact("dimensions assessed", len(stage.result.assessments)),
                        _fact("dimensions refused", refused),
                        _fact("weak markers not scored", len(stage.weak_markers_not_scored)),
                    ],
                    refusals=refused,
                )
            )
        elif isinstance(stage, EvidenceStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("vault intact", stage.is_intact),
                        _fact("entries exported", stage.export_entries),
                        _fact("restricted entries withheld", stage.export_withheld_restricted),
                        _fact("anchor externally held", stage.anchor_is_externally_held),
                    ],
                )
            )
        elif isinstance(stage, DisruptionStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("levers executable now", len(stage.executable_now)),
                        _fact(
                            "levers needing legal authority", len(stage.requires_legal_authority)
                        ),
                        _fact(
                            "levers needing ownership confirmation",
                            len(stage.needs_ownership_confirmation),
                        ),
                    ],
                )
            )
        elif isinstance(stage, AuthorizationStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("approvals", len(stage.approvals)),
                        _fact("human rejections", 1),  # `rejection` is a required field
                        _fact("platform refusals", 1),  # `assurance_refusal` likewise
                        _fact("capability lifetime hours", round(stage.lifetime_hours)),
                    ],
                    refusals=2,
                )
            )
        elif isinstance(stage, EffectsStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("effects rehearsed", len(stage.results)),
                        _fact("external contact made", stage.external_contact_made),
                        _fact("separate process", stage.isolation.separate_process),
                        _fact("network denied", stage.isolation.network_denied),
                    ],
                )
            )
        elif isinstance(stage, ResurgenceStage):
            marks.append(
                _mark(
                    name,
                    [
                        _fact("candidates examined", stage.watch.candidates_examined),
                        _fact("reconnecting artifacts", len(stage.links)),
                        _fact("case reopened", stage.resumed is not None),
                    ],
                )
            )
        else:
            marks.append(StageMark(name=name))
    return tuple(marks)


__all__ = [
    "FACT_FORMS",
    "FACT_LABELS",
    "STAGE_META",
    "StageFact",
    "StageMark",
    "StageMeta",
    "meta_for",
    "stage_ledger",
]
