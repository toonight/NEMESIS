"""Synthetic cases with known answers, and an explicit statement of what that is worth.

The generator produces linkage cases where the truth is known **because we constructed
it**. That makes some measurements defensible and others circular, and the difference is
the most important thing in this package.

**Defensible.** Whether the system's confidence responds correctly to a perturbation *we
applied*. If we take one source and re-report it through five fronts, we know with
certainty that no new evidence entered. Any confidence increase is a defect, and the size
of the increase is a real measurement of a real failure. Ground truth here is not a guess
about the world; it is a fact about what we did.

**Circular.** Whether the system's absolute probabilities match reality. The generator
decides how often "same operator" is true and how strong each signal is. Score against that
and you have measured agreement with your own assumptions. The number will look like
calibration and will not be calibration.

Every assumption the generator makes is carried in :class:`GeneratorAssumptions` and printed
with any measurement conditioned on it, because a reader who is not shown the assumptions
cannot tell which of the two kinds of number they are looking at.

Nothing here uses a global random source. Every case is generated from an explicit seed, so
a reported figure can be reproduced exactly — a calibration report nobody can re-run is an
assertion.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import StrEnum

from nemesis.core.confidence import Opinion
from nemesis.core.fusion import SourcedOpinion
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability


class CaseKind(StrEnum):
    """What each generated case is designed to probe."""

    GENUINE_INDEPENDENT = "genuine_independent"
    """Several truly independent origins observed related facts. Confidence *should* rise."""

    LAUNDERED = "laundered"
    """One artifact, re-observed by several collectors whose lineage is missing. No new
    evidence exists. Confidence must not rise, and the truth is that the entities are
    unrelated."""

    RESOLD_FEEDS = "resold_feeds"
    """Several feeds resolving to one declared upstream. Lineage is *known*, so this probes
    the grouping rather than the unknown-lineage fallback."""

    CONFLICTED = "conflicted"
    """Credible origins that disagree. Conflict must surface rather than average away."""

    NO_EVIDENCE = "no_evidence"
    """Nobody looked. The honest output is a refusal to estimate."""

    ADVERSARY_ONLY = "adversary_only"
    """Every contributing source sits in a channel the adversary can write into."""


@dataclass(frozen=True)
class GeneratorAssumptions:
    """Everything the generator decides that the world would otherwise decide.

    Printed alongside any measurement conditioned on it. These are not tuning knobs to be
    optimized against — moving them moves the "truth" the system is scored on, which is
    precisely why absolute scores from this generator are not calibration.
    """

    prevalence: float = 0.5
    """How often the proposition is true. Real linkage prevalence on a large forum is
    orders of magnitude lower; 0.5 is chosen so both error directions are observable in a
    tractable number of cases, not because it is realistic."""

    true_signal_strength: float = 0.72
    """Probability that a source reports positively when the proposition is true."""

    false_signal_strength: float = 0.22
    """Probability that a source reports positively when it is false. The gap between this
    and ``true_signal_strength`` is the discriminating power we are *granting* the sources,
    and it is the single assumption that most inflates any resulting score."""

    evidence_weight: float = 6.0
    """Observation count behind each source's opinion. Larger means more confident sources."""

    def as_lines(self) -> tuple[str, ...]:
        return (
            f"prevalence                 {self.prevalence:.2f}  (real linkage prevalence is "
            "far lower; chosen for observability)",
            f"P(report + | true)         {self.true_signal_strength:.2f}",
            f"P(report + | false)        {self.false_signal_strength:.2f}  (the granted "
            "discriminating power — the assumption that most inflates any score)",
            f"evidence weight per source {self.evidence_weight:.1f}",
        )


@dataclass(frozen=True)
class SyntheticCase:
    """One case, with the answer and with how the answer was constructed."""

    case_id: str
    kind: CaseKind
    truth: bool
    sources: tuple[SourcedOpinion, ...]

    distinct_real_origins: int
    """How many genuinely independent facts underlie the sources. For a laundered case this
    is 1 however many sources there are, and that gap is the whole measurement."""

    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def source_count(self) -> int:
        return len(self.sources)


def _source(
    identifier: str,
    *,
    operator: str | None,
    upstream: str | None = None,
    source_class: SourceClass = SourceClass.INTERNET_SCAN,
    reliability: SourceReliability = SourceReliability.USUALLY_RELIABLE,
) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=source_class,
        identifier=identifier,
        operator=operator,
        upstream_of_record=upstream,
        reliability=reliability,
    )


def _opinion(reports_positive: bool, weight: float, base_rate: float) -> Opinion:
    supporting = weight if reports_positive else 0.0
    contradicting = 0.0 if reports_positive else weight
    return Opinion.from_evidence(
        supporting=supporting, contradicting=contradicting, base_rate=base_rate
    )


class CaseGenerator:
    """Deterministic generator. Same seed, same cases, always."""

    def __init__(self, assumptions: GeneratorAssumptions | None = None) -> None:
        self.assumptions = assumptions or GeneratorAssumptions()

    def generate(self, *, count: int, seed: int) -> tuple[SyntheticCase, ...]:
        rng = random.Random(seed)  # noqa: S311 - simulation, not security
        kinds = list(CaseKind)
        return tuple(
            self._case(f"case-{index:04d}", kinds[index % len(kinds)], rng)
            for index in range(count)
        )

    def generate_kind(self, kind: CaseKind, *, count: int, seed: int) -> tuple[SyntheticCase, ...]:
        rng = random.Random(seed)  # noqa: S311 - simulation, not security
        return tuple(self._case(f"{kind.value}-{index:04d}", kind, rng) for index in range(count))

    # -- case construction ----------------------------------------------------

    def _case(self, case_id: str, kind: CaseKind, rng: random.Random) -> SyntheticCase:
        assumptions = self.assumptions
        base = assumptions.prevalence

        match kind:
            case CaseKind.NO_EVIDENCE:
                # Nobody looked. Truth is drawn but unobservable, which is the point: the
                # system must not produce an estimate either way.
                return SyntheticCase(
                    case_id=case_id,
                    kind=kind,
                    truth=rng.random() < base,
                    sources=(),
                    distinct_real_origins=0,
                    notes=("No source contributed. The honest output is a refusal.",),
                )

            case CaseKind.LAUNDERED:
                # The attack that matters. One planted artifact; the proposition is FALSE;
                # several honest collectors observe descendants of it; lineage is missing.
                copies = rng.randint(3, 8)
                planted = _opinion(True, assumptions.evidence_weight, base)
                sources = tuple(
                    SourcedOpinion(
                        source=_source(f"collector-{index}", operator=None),
                        opinion=planted,
                        label=f"collector-{index}",
                        # One artifact. Every collector attests the SAME fact, which is what
                        # makes this laundering rather than corroboration.
                        fact_key=f"{case_id}:planted-artifact",
                    )
                    for index in range(copies)
                )
                return SyntheticCase(
                    case_id=case_id,
                    kind=kind,
                    truth=False,
                    sources=sources,
                    distinct_real_origins=1,
                    notes=(
                        f"{copies} honest reports of ONE planted artifact, lineage unknown. "
                        "No new evidence exists.",
                    ),
                )

            case CaseKind.RESOLD_FEEDS:
                copies = rng.randint(3, 6)
                truth = rng.random() < base
                positive = self._reports_positive(truth, rng)
                opinion = _opinion(positive, assumptions.evidence_weight, base)
                sources = tuple(
                    SourcedOpinion(
                        source=_source(
                            f"feed-{index}", operator=f"reseller-{index}", upstream="one-upstream"
                        ),
                        opinion=opinion,
                        label=f"feed-{index}",
                        fact_key=f"{case_id}:upstream-record",
                    )
                    for index in range(copies)
                )
                return SyntheticCase(
                    case_id=case_id,
                    kind=kind,
                    truth=truth,
                    sources=sources,
                    distinct_real_origins=1,
                    notes=(f"{copies} feeds, one declared upstream.",),
                )

            case CaseKind.CONFLICTED:
                truth = rng.random() < base
                sources = (
                    SourcedOpinion(
                        source=_source(
                            "own-sensor",
                            operator="us",
                            source_class=SourceClass.OWN_SENSOR,
                            reliability=SourceReliability.COMPLETELY_RELIABLE,
                        ),
                        opinion=_opinion(True, assumptions.evidence_weight * 1.5, base),
                        label="own-sensor",
                        fact_key=f"{case_id}:observation",
                    ),
                    SourcedOpinion(
                        source=_source(
                            "partner-feed",
                            operator="partner",
                            source_class=SourceClass.PARTNER,
                            reliability=SourceReliability.USUALLY_RELIABLE,
                        ),
                        opinion=_opinion(False, assumptions.evidence_weight * 1.5, base),
                        label="partner-feed",
                        fact_key=f"{case_id}:observation",
                    ),
                )
                return SyntheticCase(
                    case_id=case_id,
                    kind=kind,
                    truth=truth,
                    sources=sources,
                    distinct_real_origins=2,
                    notes=("Two credible, independent origins flatly disagree.",),
                )

            case CaseKind.ADVERSARY_ONLY:
                truth = rng.random() < base
                count = rng.randint(2, 4)
                sources = tuple(
                    SourcedOpinion(
                        source=_source(
                            f"forum-{index}",
                            operator=f"forum-{index}-op",
                            source_class=SourceClass.DARK_WEB,
                            reliability=SourceReliability.NOT_USUALLY_RELIABLE,
                        ),
                        opinion=_opinion(
                            self._reports_positive(truth, rng), assumptions.evidence_weight, base
                        ),
                        label=f"forum-{index}",
                        fact_key=f"{case_id}:post-{index}",
                    )
                    for index in range(count)
                )
                return SyntheticCase(
                    case_id=case_id,
                    kind=kind,
                    truth=truth,
                    sources=sources,
                    distinct_real_origins=count,
                    notes=("Every source sits in a channel the adversary can write into.",),
                )

            case CaseKind.GENUINE_INDEPENDENT:
                truth = rng.random() < base
                count = rng.randint(2, 5)
                sources = tuple(
                    SourcedOpinion(
                        source=_source(f"origin-{index}", operator=f"org-{index}"),
                        opinion=_opinion(
                            self._reports_positive(truth, rng), assumptions.evidence_weight, base
                        ),
                        label=f"origin-{index}",
                        # Distinct origins observed distinct things. Giving them one fact key
                        # would model them as re-reporting a single artifact, which is the
                        # laundered case, not this one.
                        fact_key=f"{case_id}:fact-{index}",
                    )
                    for index in range(count)
                )
                return SyntheticCase(
                    case_id=case_id,
                    kind=kind,
                    truth=truth,
                    sources=sources,
                    distinct_real_origins=count,
                    notes=(f"{count} genuinely distinct origins.",),
                )

    def _reports_positive(self, truth: bool, rng: random.Random) -> bool:
        threshold = (
            self.assumptions.true_signal_strength
            if truth
            else self.assumptions.false_signal_strength
        )
        return rng.random() < threshold
