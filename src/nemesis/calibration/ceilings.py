"""How much the resurgence belief ceilings actually matter.

Seven numbers in :data:`~nemesis.pursuit.resurgence.BELIEF_CEILING` decide how much any one
kind of continuity may contribute, and **nothing validates them**. They were chosen by ordering
the kinds by how expensive each is to stage, which is an argument rather than a measurement, and
the module that holds them says so.

**This does not calibrate them, and cannot.** Calibration needs outcomes — cases where somebody
established whether two clusters really were one adversary — and this platform has none. A
corpus generated here would carry labels invented alongside the signals, so scoring against it
would measure agreement with the generator's assumptions, which are ours rather than the
world's. ``docs/calibration/PROTOCOL.md`` makes that refusal for the persona engine and it
applies here unchanged.

**What can be measured without outcomes is how much the numbers are load-bearing**, and that is
what this does. The claim standing in the repository is that *the ordering* is the defensible
part and the magnitudes are not. That claim is falsifiable: perturb the ceilings in ways that
preserve the ordering and in ways that destroy it, and count how many verdicts move.

- If verdicts survive large magnitude changes and break when the order is destroyed, the claim
  holds and the unvalidated magnitudes are a small liability.
- If verdicts move under a modest uniform scaling, the claim is wrong, the magnitudes are doing
  the work, and their being unvalidated is a serious problem that this report should say so.

The cases below are synthetic and exist to span the decision space, not to represent any
population. They carry no labels and nothing here scores accuracy: the only quantity reported
is *verdict stability under perturbation*, which is a property of the machinery rather than a
claim about the world.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from nemesis.core.ids import IdPrefix, content_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotSelectivity
from nemesis.core.temporal import TemporalExtent
from nemesis.pursuit.resurgence import (
    BELIEF_CEILING,
    ResurgenceEngine,
    ResurgenceSignal,
    ResurgenceSignalKind,
)

PROBE_AT: Final = datetime(2026, 6, 1, tzinfo=UTC)
PROBE_POPULATION: Final = 40
"""Tracked campaigns the probe cases are compared against. Fixed so the prior is constant and
the only thing varying between runs is the ceiling table."""


def _source(unplantable: bool, identifier: str) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=SourceClass.OWN_SENSOR if unplantable else SourceClass.OPEN_SOURCE,
        identifier=identifier,
        reliability=(
            SourceReliability.COMPLETELY_RELIABLE
            if unplantable
            else SourceReliability.USUALLY_RELIABLE
        ),
    )


def _signal(
    kind: ResurgenceSignalKind,
    *,
    attribute: str,
    unplantable: bool,
    population: int | None,
    unique: bool = False,
) -> ResurgenceSignal:
    from nemesis.core.entities import EntityType

    return ResurgenceSignal(
        kind=kind,
        shared_attribute=attribute,
        selectivity=PivotSelectivity(
            attribute=attribute,
            population_size=population,
            population_measured_against="probe corpus" if population is not None else None,
            is_globally_unique=unique,
        ),
        observed_by=_source(unplantable, f"probe-{attribute[:12]}"),
        new_entity_type=EntityType.DOMAIN,
        new_entity_key="returned.example",
        prior_entity_key="original.example",
        extent=TemporalExtent.at(PROBE_AT),
        supporting_claims=(content_id(IdPrefix.CLAIM, attribute.encode()),),
    )


@dataclass(frozen=True)
class ProbeCase:
    """One bundle of signals, and why it is in the set.

    Deliberately not labelled with an answer. A label would invite scoring accuracy against it,
    and the answer would be one this module invented.
    """

    name: str
    signals: tuple[ResurgenceSignal, ...]
    spans: str


def probe_cases() -> tuple[ProbeCase, ...]:
    """A set spanning the decision space, chosen to sit near the boundaries.

    Cases far from any threshold tell a sensitivity study nothing — they survive every
    perturbation and inflate the stability figure. These are picked to be movable.
    """
    return (
        ProbeCase(
            name="two unplantable facts, two groups",
            signals=(
                _signal(
                    ResurgenceSignalKind.SHARED_PRIVATE_KEY,
                    attribute="cert:aa",
                    unplantable=True,
                    population=None,
                    unique=True,
                ),
                _signal(
                    ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
                    attribute="build:bb",
                    unplantable=True,
                    population=3,
                ),
            ),
            spans="the case the loop closes on",
        ),
        ProbeCase(
            name="two weak unplantable facts, two groups",
            signals=(
                _signal(
                    ResurgenceSignalKind.NAMING_PATTERN,
                    attribute="pattern:cc",
                    unplantable=True,
                    population=40,
                ),
                _signal(
                    ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN,
                    attribute="registrar:dd",
                    unplantable=True,
                    population=40,
                ),
            ),
            spans="the weakest kinds, corroborated — should stay a lead",
        ),
        ProbeCase(
            name="one strong unplantable fact",
            signals=(
                _signal(
                    ResurgenceSignalKind.SHARED_PRIVATE_KEY,
                    attribute="cert:ee",
                    unplantable=True,
                    population=None,
                    unique=True,
                ),
            ),
            spans="single-origin veto, independent of any ceiling",
        ),
        ProbeCase(
            name="two strong plantable facts",
            signals=(
                _signal(
                    ResurgenceSignalKind.SHARED_PRIVATE_KEY,
                    attribute="cert:ff",
                    unplantable=False,
                    population=None,
                    unique=True,
                ),
                _signal(
                    ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT,
                    attribute="drop:gg",
                    unplantable=False,
                    population=2,
                ),
            ),
            spans="robustness margin, independent of any ceiling",
        ),
        ProbeCase(
            name="mid-strength pair near the floor",
            signals=(
                _signal(
                    ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
                    attribute="build:hh",
                    unplantable=True,
                    population=8,
                ),
                _signal(
                    ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT,
                    attribute="wallet:ii",
                    unplantable=True,
                    population=8,
                ),
            ),
            spans="closest to the actionable floor — the movable case",
        ),
        ProbeCase(
            name="fingerprint and exfil, corroborated",
            signals=(
                _signal(
                    ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT,
                    attribute="pgp:jj",
                    unplantable=True,
                    population=None,
                    unique=True,
                ),
                _signal(
                    ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT,
                    attribute="drop:kk",
                    unplantable=True,
                    population=2,
                ),
            ),
            spans="two mid-to-strong kinds in two groups",
        ),
    )


def _scaled(factor: float) -> dict[ResurgenceSignalKind, float]:
    """Every ceiling multiplied, order preserved, clamped into the unit interval."""
    return {kind: min(0.99, max(0.01, value * factor)) for kind, value in BELIEF_CEILING.items()}


def _flattened() -> dict[ResurgenceSignalKind, float]:
    """Every ceiling set to the mean. Magnitude preserved, ordering destroyed."""
    mean = sum(BELIEF_CEILING.values()) / len(BELIEF_CEILING)
    return dict.fromkeys(BELIEF_CEILING, mean)


def _inverted() -> dict[ResurgenceSignalKind, float]:
    """The ordering reversed: what is hardest to stage now counts for least."""
    ordered = sorted(BELIEF_CEILING.items(), key=lambda item: item[1])
    values = [value for _, value in reversed(ordered)]
    return {kind: values[index] for index, (kind, _) in enumerate(ordered)}


PERTURBATIONS: Final[tuple[tuple[str, str, dict[ResurgenceSignalKind, float]], ...]] = (
    ("scaled x0.6", "order preserved", _scaled(0.6)),
    ("scaled x0.8", "order preserved", _scaled(0.8)),
    ("scaled x1.25", "order preserved", _scaled(1.25)),
    ("flattened to the mean", "ORDER DESTROYED", _flattened()),
    ("ordering inverted", "ORDER DESTROYED", _inverted()),
)
"""The perturbations, split by whether they keep the ordering.

The split is the experiment. Magnitude changes are large — down to six tenths and up by a
quarter — because a sensitivity study that only nudges is a study designed to find stability.
"""


@dataclass(frozen=True)
class PerturbationResult:
    """What one perturbed ceiling table did to the verdicts."""

    name: str
    preserves_order: bool
    verdicts_changed: int
    cases: int

    @property
    def stable(self) -> bool:
        return self.verdicts_changed == 0

    def render(self) -> str:
        mark = "stable" if self.stable else f"{self.verdicts_changed}/{self.cases} MOVED"
        kind = "order kept " if self.preserves_order else "ORDER BROKEN"
        return f"  [{kind}] {self.name:24} {mark}"


@dataclass(frozen=True)
class CeilingSensitivity:
    """Whether the ordering or the magnitudes are doing the work.

    ``claim_holds`` is the repository's standing claim under test, not a pass/fail on the
    engine: verdicts unmoved by large magnitude changes and moved by destroying the order.
    """

    baseline: tuple[tuple[str, bool], ...]
    results: tuple[PerturbationResult, ...]

    @property
    def order_preserving_moves(self) -> int:
        return sum(r.verdicts_changed for r in self.results if r.preserves_order)

    @property
    def order_breaking_moves(self) -> int:
        return sum(r.verdicts_changed for r in self.results if not r.preserves_order)

    @property
    def claim_holds(self) -> bool:
        """Whether the ordering is load-bearing and the magnitudes are not."""
        return self.order_preserving_moves == 0 and self.order_breaking_moves > 0

    def render(self) -> str:
        lines = [
            "Resurgence ceiling sensitivity — how much the unvalidated numbers matter",
            "",
            "  This is NOT calibration. There are no outcomes to calibrate against, and a",
            "  synthetic corpus would carry labels invented beside the signals. What is",
            "  measured is verdict stability under perturbation, which is a property of the",
            "  machinery rather than a claim about the world.",
            "",
            f"  baseline: {sum(1 for _, a in self.baseline if a)}/{len(self.baseline)} "
            "probe cases actionable",
        ]
        lines.extend(result.render() for result in self.results)
        lines.append("")
        if self.claim_holds:
            lines.append(
                "  The standing claim holds on this probe set: verdicts survived every "
                "magnitude change and moved when the ordering was destroyed. The ordering is "
                "load-bearing; the exact ceilings are not."
            )
        elif self.order_preserving_moves:
            lines.append(
                "  The standing claim does NOT hold: a verdict moved under a change that kept "
                "the ordering. The magnitudes are doing work, and their being unvalidated is a "
                "liability rather than a footnote."
            )
        else:
            lines.append(
                "  Inconclusive on this probe set: nothing moved under any perturbation, so it "
                "does not discriminate. Read this as a defect in the probe cases rather than as "
                "evidence about the ceilings."
            )
        return "\n".join(lines)


def _verdicts(
    cases: Sequence[ProbeCase], ceilings: Mapping[ResurgenceSignalKind, float] | None
) -> tuple[tuple[str, bool], ...]:
    engine = ResurgenceEngine()
    original = dict(BELIEF_CEILING)
    if ceilings is not None:
        BELIEF_CEILING.update(ceilings)
    try:
        return tuple(
            (
                case.name,
                engine.assess(
                    campaign="probe",
                    signals=case.signals,
                    candidate_population=PROBE_POPULATION,
                    assessed_at=PROBE_AT,
                ).is_actionable,
            )
            for case in cases
        )
    finally:
        BELIEF_CEILING.clear()
        BELIEF_CEILING.update(original)


def measure_ceiling_sensitivity(
    cases: Sequence[ProbeCase] | None = None,
) -> CeilingSensitivity:
    """Run every perturbation over the probe set and count the verdicts that moved.

    The table is mutated in place and restored in a ``finally``, because it is read through a
    module-level name by code this function does not own. The restoration is asserted by a test:
    a sensitivity probe that left the shipped ceilings altered would be the worst possible
    bug in a module about not trusting them.
    """
    probes = tuple(cases) if cases is not None else probe_cases()
    baseline = _verdicts(probes, None)
    results = []
    for name, order, table in PERTURBATIONS:
        perturbed = _verdicts(probes, table)
        moved = sum(
            1
            for (_, before), (_, after) in zip(baseline, perturbed, strict=True)
            if before != after
        )
        results.append(
            PerturbationResult(
                name=name,
                preserves_order=order == "order preserved",
                verdicts_changed=moved,
                cases=len(probes),
            )
        )
    return CeilingSensitivity(baseline=baseline, results=tuple(results))


FLOOR_PERTURBATIONS: Final[tuple[float, ...]] = (0.45, 0.50, 0.60, 0.65)
"""Alternative actionable floors to probe.

Added after the first run of this module: the one verdict that moved under a magnitude change
crossed the floor by **0.001**, which says the threshold is at least as load-bearing as the
ceilings it is compared against. ``ACTIONABLE_FLOOR`` is 0.55, inherited from the disruption
plane's ownership floor, and PROJECT_STATE already records that no corpus validates *that*
either. It had not been under suspicion until this measurement put it there.
"""


@dataclass(frozen=True)
class FloorSensitivity:
    """How many verdicts the actionable threshold alone decides."""

    moves: tuple[tuple[float, int], ...]
    cases: int

    @property
    def total_moves(self) -> int:
        return sum(moved for _, moved in self.moves)

    def render(self) -> str:
        lines = ["  actionable floor, held against the shipped ceilings:"]
        lines.extend(
            f"    floor {floor:.2f}  {'stable' if moved == 0 else f'{moved}/{self.cases} MOVED'}"
            for floor, moved in self.moves
        )
        if self.total_moves == 0:
            lines.append(
                "    the threshold alone decides nothing here: every probe case is held by a "
                "veto or sits far from it"
            )
        return "\n".join(lines)


def _actionable_at(assessment: object, floor: float) -> bool:
    """The actionable verdict recomputed against an arbitrary floor.

    Recomputed rather than reached by mutating ``ACTIONABLE_FLOOR``, which is ``Final`` and
    should stay that way: a probe that rebinds a shipped constant is one bad ``finally`` away
    from leaving the platform running on a threshold nobody chose. Every component of the
    verdict is already exposed, so the parameterised form needs no mutation at all.
    """
    from nemesis.core.confidence import ConfidenceBand

    return (
        assessment.band is not ConfidenceBand.INSUFFICIENT_BASIS  # type: ignore[attr-defined]
        and assessment.opinion.projected_probability >= floor  # type: ignore[attr-defined]
        and not assessment.fusion.rests_only_on_plantable_evidence  # type: ignore[attr-defined]
        and not assessment.is_single_origin  # type: ignore[attr-defined]
    )


def measure_floor_sensitivity(cases: Sequence[ProbeCase] | None = None) -> FloorSensitivity:
    """Move the threshold, leave the ceilings alone, and count the verdicts that follow.

    Deliberately separate from the ceiling study rather than folded into it. They are two
    unvalidated numbers and a reader needs to know which one a verdict turned on; one figure
    covering both would hide exactly what the first run of this module found.
    """
    probes = tuple(cases) if cases is not None else probe_cases()
    engine = ResurgenceEngine()
    assessments = [
        engine.assess(
            campaign="probe",
            signals=case.signals,
            candidate_population=PROBE_POPULATION,
            assessed_at=PROBE_AT,
        )
        for case in probes
    ]
    baseline = [item.is_actionable for item in assessments]
    moves = tuple(
        (
            floor,
            sum(
                1
                for item, before in zip(assessments, baseline, strict=True)
                if _actionable_at(item, floor) != before
            ),
        )
        for floor in FLOOR_PERTURBATIONS
    )
    return FloorSensitivity(moves=moves, cases=len(probes))


__all__ = [
    "FLOOR_PERTURBATIONS",
    "PERTURBATIONS",
    "PROBE_POPULATION",
    "CeilingSensitivity",
    "FloorSensitivity",
    "PerturbationResult",
    "ProbeCase",
    "measure_ceiling_sensitivity",
    "measure_floor_sensitivity",
    "probe_cases",
]
