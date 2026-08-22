"""The harness: what can be proved, what can only be measured, and what neither can settle.

Two kinds of output, kept apart because they are worth very different amounts.

**Properties** are assertions about the system's response to a perturbation *we applied*.
Re-report one source through six fronts and no new evidence exists — that is a fact about
what we did, not a belief about the world. If confidence rises, the size of the rise is a
real measurement of a real defect. These results stand on their own.

**Measurements** are scored against outcomes the generator invented. They describe
agreement with our own assumptions. They are useful for comparing two configurations under
identical assumptions and for catching gross miscalibration in a known direction, and they
are not calibration. The report says so, at the top, before the numbers.

What neither can settle is whether the fusion operator is the right one. A harness over our
own generator rewards whichever assumptions were coded into the generator; that requires
blind cases with injected false flags and independently adjudicated subclaims. ADR-0003
records this, and the report repeats it rather than letting a reader infer otherwise from a
page of confident figures.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nemesis.calibration.coherence import check_coherence
from nemesis.calibration.freeze import MeasurementProvenance, measurement_provenance
from nemesis.calibration.generator import (
    CaseGenerator,
    CaseKind,
    GeneratorAssumptions,
    SyntheticCase,
)
from nemesis.calibration.scoring import (
    BrierDecomposition,
    brier_decomposition,
    discrimination_auc,
)
from nemesis.core.confidence import ConfidenceBand, band_of
from nemesis.core.fusion import FusionResult, fuse
from nemesis.core.proposition import PropositionClass

LINKAGE_PROPOSITION = PropositionClass.ACTOR_ATTRIBUTION
"""What the harness's cases are about: whether two entities share an operator.

Declared here rather than per call so the headline false-match number measures the
proposition the attack targets. Scoring the attack as an OBSERVATION would report a 0%
false-match rate by asking a different question."""

ACTIONABLE_BANDS: frozenset[ConfidenceBand] = frozenset(
    {ConfidenceBand.LIKELY, ConfidenceBand.VERY_LIKELY, ConfidenceBand.ALMOST_CERTAIN}
)
"""Bands at which an analyst might act. The threshold for counting a false match.

Set at LIKELY rather than higher on purpose: the question a false-match rate answers is
"how often would this have started something", and an investigation starts well below
certainty.
"""


@dataclass(frozen=True)
class PropertyResult:
    """A property that either holds or does not, with the number that decides it."""

    name: str
    holds: bool
    measured: str
    why_it_matters: str

    def render(self) -> str:
        mark = "PASS" if self.holds else "FAIL"
        return f"  [{mark}] {self.name}\n         {self.measured}"


@dataclass(frozen=True)
class ConditionalMeasurement:
    """A number that is only meaningful given the generator's assumptions."""

    name: str
    value: float | None
    detail: str

    def render(self) -> str:
        shown = "n/a" if self.value is None else f"{self.value:.4f}"
        return f"  {self.name:<38} {shown:>8}   {self.detail}"


@dataclass(frozen=True)
class CalibrationReport:
    """Everything the harness found, ordered so the caveats are read first."""

    assumptions: GeneratorAssumptions
    seed: int
    case_count: int
    provenance: MeasurementProvenance
    """What this run was measured under: the three freeze digests and the environment.

    `docs/calibration/PROTOCOL.md` §6 ends "every figure is reported with ... the freeze digest
    it was measured under. A number without those four is not a result." This report printed a
    Brier decomposition, an AUC and two false-match rates and carried none of them. The freeze
    exists so a measurement can be tied to a configuration, and the one thing that produces
    measurements did not record the configuration.
    """

    properties: tuple[PropertyResult, ...]
    measurements: tuple[ConditionalMeasurement, ...]
    brier: BrierDecomposition | None
    laundering_false_match_rate: float
    laundering_inflation: float
    single_source_false_match_rate: float
    """How often ONE planted source, with no amplification at all, already reaches an
    actionable band. The number that says whether the anti-laundering defence addresses
    the attack or only its amplification."""

    per_kind_brier: tuple[tuple[str, float, int], ...] = ()

    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def properties_hold(self) -> bool:
        return all(item.holds for item in self.properties)

    def render(self) -> str:
        lines: list[str] = []
        lines.append("=" * 78)
        lines.append("CALIBRATION HARNESS")
        lines.append("=" * 78)
        lines.append("")
        lines.append("WHAT THIS CANNOT TELL YOU")
        lines.append("  Nothing here is calibration. Outcomes come from a generator whose")
        lines.append("  assumptions we chose, so scores measure agreement with those assumptions,")
        lines.append("  not with the world. This harness cannot settle whether the fusion operator")
        lines.append("  is the right one: it will reward whichever assumptions were coded into the")
        lines.append("  generator. Settling that needs blind cases with injected false flags and")
        lines.append("  independently adjudicated subclaims. See ADR-0003.")
        lines.append("")
        lines.append("MEASURED UNDER")
        lines.extend(self.provenance.render())
        lines.append("")
        lines.append("GENERATOR ASSUMPTIONS (every conditional number below rests on these)")
        lines.extend(f"  {line}" for line in self.assumptions.as_lines())
        lines.append(f"  seed {self.seed}, {self.case_count} cases — rerun to reproduce exactly")
        lines.append("")
        lines.append("-" * 78)
        lines.append("PROPERTIES — these stand on their own")
        lines.append("-" * 78)
        lines.append("  Each perturbs the input in a way we control, so the ground truth is a fact")
        lines.append("  about what we did rather than a belief about the world.")
        lines.append("")
        lines.extend(item.render() for item in self.properties)
        lines.append("")
        lines.append("-" * 78)
        lines.append("CONDITIONAL MEASUREMENTS — only meaningful given the assumptions above")
        lines.append("-" * 78)
        lines.extend(item.render() for item in self.measurements)
        if self.brier is not None:
            lines.append("")
            lines.extend(f"  {line}" for line in self.brier.render().splitlines())
        if self.per_kind_brier:
            lines.append("")
            lines.append("  Brier by case kind — the aggregate above mixes cases where")
            lines.append("  discrimination is possible with cases where refusing is CORRECT,")
            lines.append("  so the aggregate is not a verdict on the system:")
            for kind, score, count in self.per_kind_brier:
                lines.append(f"    {kind:<24} {score:.4f}  (n={count})")
        lines.append("")
        lines.append("-" * 78)
        lines.append("HEADLINE")
        lines.append("-" * 78)
        lines.append(
            f"  False-match rate under provenance laundering: "
            f"{self.laundering_false_match_rate:.1%}"
        )
        lines.append("    How often several honest reports of ONE planted artifact, with lineage")
        lines.append("    missing, produce a band an analyst would act on — when the truth is that")
        lines.append("    the entities are unrelated. This number is defensible: we planted it.")
        lines.append(f"  Confidence inflation from laundering: {self.laundering_inflation:+.4f}")
        lines.append("    Change in projected probability from re-reporting one source through")
        lines.append("    several fronts. Anything above zero is evidence appearing from nowhere.")
        lines.append("")
        lines.append(
            f"  Same rate from ONE planted source, no amplification: "
            f"{self.single_source_false_match_rate:.1%}"
        )
        lines.append("    If this matches the figure above, the anti-laundering defence is working")
        lines.append(
            "    and is beside the point: the attack does not need amplification, because a"
        )
        lines.append("    single well-constructed planted artifact from a reliable-looking source")
        lines.append("    already clears the bar an analyst would act on.")
        lines.extend(f"\n  ! {note}" for note in self.notes)
        return "\n".join(lines)


def _forecast(result: FusionResult) -> float:
    return result.opinion.projected_probability


def run_calibration(
    *, cases: int = 600, seed: int = 20260815, assumptions: GeneratorAssumptions | None = None
) -> CalibrationReport:
    """Run the harness and return a report that leads with its own limits."""
    generator = CaseGenerator(assumptions)
    settings = generator.assumptions

    properties = [
        _property_laundering_adds_nothing(generator, seed),
        _property_resold_feeds_collapse(generator, seed),
        _property_genuine_corroboration_counts(generator, seed),
        _property_no_evidence_refuses(generator, seed),
        _property_conflict_surfaces(generator, seed),
        _property_adversary_only_is_flagged(generator, seed),
        _property_the_engine_does_not_contradict_itself(generator, seed),
    ]

    laundered = generator.generate_kind(CaseKind.LAUNDERED, count=200, seed=seed + 1)
    false_matches = 0
    for case in laundered:
        result = fuse(case.sources, proposition=LINKAGE_PROPOSITION)
        if band_of(result.opinion) in ACTIONABLE_BANDS:
            false_matches += 1
    false_match_rate = false_matches / len(laundered)

    inflation = _measure_laundering_inflation(generator, seed)
    single_source_rate = _measure_single_source_false_match(generator, seed)

    scored = [
        case
        for case in generator.generate(count=cases, seed=seed)
        if case.kind is not CaseKind.NO_EVIDENCE
    ]
    forecasts = [_forecast(fuse(case.sources, proposition=LINKAGE_PROPOSITION)) for case in scored]
    outcomes = [case.truth for case in scored]

    brier = brier_decomposition(forecasts, outcomes) if scored else None
    auc = discrimination_auc(forecasts, outcomes) if scored else None

    measurements = (
        ConditionalMeasurement(
            name="discrimination (AUC)",
            value=auc,
            detail="0.5 = no better than chance under these assumptions",
        ),
        ConditionalMeasurement(
            name="mean forecast",
            value=sum(forecasts) / len(forecasts) if forecasts else None,
            detail=f"against a generated prevalence of {settings.prevalence:.2f}",
        ),
    )

    notes: list[str] = []
    if brier is not None and brier.binning_discrepancy > 0.05:
        notes.append(
            f"Binning discrepancy {brier.binning_discrepancy:.3f} is large relative to the "
            f"score ({brier.brier_score:.3f}); the reliability and resolution split is coarse "
            "at this bin width. Not an error — bin more finely to sharpen it."
        )
    if false_match_rate > 0.0:
        notes.append(
            f"{false_matches} of {len(laundered)} laundered cases reached an actionable band. "
            "Each is an investigation that would have started against an unrelated party."
        )

    return CalibrationReport(
        assumptions=settings,
        provenance=measurement_provenance(),
        seed=seed,
        case_count=len(scored),
        properties=tuple(properties),
        measurements=measurements,
        brier=brier,
        laundering_false_match_rate=false_match_rate,
        laundering_inflation=inflation,
        single_source_false_match_rate=single_source_rate,
        per_kind_brier=_per_kind_brier(generator, seed, cases),
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


def _one_source(case: SyntheticCase) -> tuple[object, ...]:
    return (case.sources[0],)


def _measure_single_source_false_match(generator: CaseGenerator, seed: int) -> float:
    """How often a lone planted source already reaches an actionable band.

    Read against the laundering false-match rate. If the two are equal, the grouping
    defence is intact and irrelevant to the outcome, because the adversary never needed
    to amplify anything.
    """
    cases = generator.generate_kind(CaseKind.LAUNDERED, count=200, seed=seed + 1)
    reached = sum(
        1
        for case in cases
        if band_of(fuse(case.sources[:1], proposition=LINKAGE_PROPOSITION).opinion)
        in ACTIONABLE_BANDS
    )
    return reached / len(cases)


def _per_kind_brier(
    generator: CaseGenerator, seed: int, cases: int
) -> tuple[tuple[str, float, int], ...]:
    """Brier per case kind, so a refusal-heavy mix does not read as a poor forecaster."""
    out: list[tuple[str, float, int]] = []
    for kind in CaseKind:
        if kind is CaseKind.NO_EVIDENCE:
            continue
        sample = generator.generate_kind(kind, count=max(40, cases // 12), seed=seed + 11)
        forecasts = [
            _forecast(fuse(case.sources, proposition=LINKAGE_PROPOSITION)) for case in sample
        ]
        outcomes = [case.truth for case in sample]
        score = sum(
            (f - (1.0 if o else 0.0)) ** 2 for f, o in zip(forecasts, outcomes, strict=True)
        ) / len(sample)
        out.append((kind.value, score, len(sample)))
    return tuple(out)


def _measure_laundering_inflation(generator: CaseGenerator, seed: int) -> float:
    """Worst confidence gain from re-reporting one source through several fronts."""
    worst = 0.0
    for case in generator.generate_kind(CaseKind.LAUNDERED, count=100, seed=seed + 2):
        many = _forecast(fuse(case.sources, proposition=LINKAGE_PROPOSITION))
        one = _forecast(fuse(case.sources[:1], proposition=LINKAGE_PROPOSITION))
        worst = max(worst, many - one)
    return worst


def _property_laundering_adds_nothing(generator: CaseGenerator, seed: int) -> PropertyResult:
    worst = _measure_laundering_inflation(generator, seed)
    return PropertyResult(
        name="Re-reporting one source through several fronts adds no confidence",
        holds=worst <= 1e-9,
        measured=(
            f"worst projected-probability gain across 100 laundered cases: {worst:+.6f} (must be 0)"
        ),
        why_it_matters=(
            "One planted artifact observed honestly by many collectors is the attack that "
            "produces confident, wrong attribution without anybody lying."
        ),
    )


def _property_resold_feeds_collapse(generator: CaseGenerator, seed: int) -> PropertyResult:
    worst = 0.0
    for case in generator.generate_kind(CaseKind.RESOLD_FEEDS, count=100, seed=seed + 3):
        many = fuse(case.sources, proposition=LINKAGE_PROPOSITION)
        one = fuse(case.sources[:1], proposition=LINKAGE_PROPOSITION)
        worst = max(worst, _forecast(many) - _forecast(one))
    return PropertyResult(
        name="Feeds resolving to one declared upstream are counted once",
        holds=worst <= 1e-9,
        measured=f"worst gain across 100 resold-feed cases: {worst:+.6f} (must be 0)",
        why_it_matters="Five feeds reselling one upstream are one source, not five.",
    )


def _property_genuine_corroboration_counts(generator: CaseGenerator, seed: int) -> PropertyResult:
    """The counterpart. A system so defensive that real agreement changes nothing is useless."""
    improved = 0
    total = 0
    for case in generator.generate_kind(CaseKind.GENUINE_INDEPENDENT, count=100, seed=seed + 4):
        if case.source_count < 2:
            continue
        total += 1
        many = fuse(case.sources, proposition=LINKAGE_PROPOSITION)
        one = fuse(case.sources[:1], proposition=LINKAGE_PROPOSITION)
        if many.opinion.uncertainty < one.opinion.uncertainty - 1e-9:
            improved += 1
    rate = improved / total if total else 0.0
    return PropertyResult(
        name="Genuinely independent origins do reduce uncertainty",
        holds=rate > 0.95,
        measured=f"uncertainty fell in {improved}/{total} multi-origin cases ({rate:.1%})",
        why_it_matters=(
            "The defence against laundering must not be bought by making real corroboration "
            "worthless."
        ),
    )


def _property_no_evidence_refuses(generator: CaseGenerator, seed: int) -> PropertyResult:
    cases = generator.generate_kind(CaseKind.NO_EVIDENCE, count=50, seed=seed + 5)
    refused = sum(
        1
        for case in cases
        if band_of(fuse(case.sources, proposition=LINKAGE_PROPOSITION).opinion)
        is ConfidenceBand.INSUFFICIENT_BASIS
    )
    return PropertyResult(
        name="No evidence produces a refusal, not a probability",
        holds=refused == len(cases),
        measured=f"{refused}/{len(cases)} returned INSUFFICIENT_BASIS",
        why_it_matters="A prior presented as a finding is the failure invariant 4 exists for.",
    )


def _property_conflict_surfaces(generator: CaseGenerator, seed: int) -> PropertyResult:
    cases = generator.generate_kind(CaseKind.CONFLICTED, count=50, seed=seed + 6)
    flagged = sum(
        1 for case in cases if fuse(case.sources, proposition=LINKAGE_PROPOSITION).conflicting_pairs
    )
    return PropertyResult(
        name="Credible sources that disagree raise conflict",
        holds=flagged == len(cases),
        measured=f"{flagged}/{len(cases)} reported a conflicting pair",
        why_it_matters=(
            "Conflict between credible origins should stop an operation, and averaging it "
            "away makes it invisible."
        ),
    )


def _property_adversary_only_is_flagged(generator: CaseGenerator, seed: int) -> PropertyResult:
    cases = generator.generate_kind(CaseKind.ADVERSARY_ONLY, count=50, seed=seed + 7)
    flagged = sum(
        1
        for case in cases
        if any(
            "deception hypothesis" in warning
            for warning in fuse(case.sources, proposition=LINKAGE_PROPOSITION).warnings
        )
    )
    return PropertyResult(
        name="Evidence drawn only from adversary-writable channels is flagged",
        holds=flagged == len(cases),
        measured=f"{flagged}/{len(cases)} raised a deception hypothesis",
        why_it_matters="A finding an adversary could have staged end to end is a hypothesis.",
    )


def _property_the_engine_does_not_contradict_itself(
    generator: CaseGenerator, seed: int
) -> PropertyResult:
    """Coherence over the same population the Brier scoring uses.

    The only quantitative property in this harness that stands without ground truth. Every
    score above is measured against a generator whose assumptions are ours rather than the
    world's; "does this system contradict itself" needs nothing external, because a forecaster
    reporting more confidence from strictly less evidence is broken whatever the world says.

    Scored on the same cases as the Brier decomposition on purpose: a system can be
    well-calibrated against a generator and still contradict itself, and the two questions
    deserve the same inputs rather than a friendlier population for the harder one.
    """
    cases = generator.generate(count=200, seed=seed + 7)
    report = check_coherence(
        [case.sources for case in cases], proposition=PropositionClass.SHARED_ORIGIN
    )
    worst = report.worst
    return PropertyResult(
        name="No output of the engine contradicts another",
        holds=report.coherent,
        measured=(
            f"{report.checked} law check(s) over {len(cases)} cases, "
            f"{len(report.violations)} violation(s)"
            + (f"; worst gap {worst.magnitude:.4f} on {worst.law}" if worst else "")
        ),
        why_it_matters=(
            "Unlike every score in this report, this needs no ground truth: a violation means "
            "two outputs cannot both be true, so at least one is wrong regardless of the "
            "world. It is the one quantitative claim this platform can honestly make today."
        ),
    )
