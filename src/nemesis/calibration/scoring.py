"""Proper scoring, and the decomposition that stops a good score from being reassuring.

A Brier score alone is close to useless for judging this system, for a reason worth stating
plainly: **NEMESIS could achieve an excellent Brier score by refusing to say anything.**
A forecaster that always predicts the base rate is perfectly calibrated and completely
uninformative, and a platform whose defining behaviour is declining to over-claim is exactly
the kind of system that can hide inside that number.

Murphy's decomposition separates the two questions (Murphy, *A New Vector Partition of the
Probability Score*, J. Appl. Meteorol. 12, 1973):

    BS  =  reliability  -  resolution  +  uncertainty

- **Reliability** — when we say 70%, does it happen 70% of the time? Lower is better. This
  is calibration, and it is the part a cautious system gets for free.
- **Resolution** — do our forecasts vary with the outcome at all, or do we always say the
  same thing? Higher is better. This is the part refusing to answer destroys.
- **Uncertainty** — the base rate's own variance. Irreducible; a property of the problem,
  not of us.

The identity is exact for discrete forecasts and approximate for binned continuous ones;
:attr:`BrierDecomposition.binning_discrepancy` reports the gap, and it is a statement about
bin width rather than about correctness.

Reporting reliability without resolution would let this platform mistake caution for
accuracy. Both are always reported together here, and the report says which is which.

**What every number in this module is conditional on.** Outcomes come from a generator whose
assumptions we chose. Reliability and resolution measured against it describe agreement with
those assumptions, not agreement with the world. They are useful for *comparing* two
configurations under identical assumptions and for detecting gross miscalibration in a known
direction. They are not calibration. See ADR-0003.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from nemesis.core.confidence import BAND_RANGES

DEFAULT_BINS: tuple[float, ...] = (0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0001)
"""Deciles. Conventional, and *not* what the calibration protocol grades on."""

PUBLISHED_BAND_BINS: tuple[float, ...] = (
    *sorted({edge for low, high in BAND_RANGES.values() for edge in (low, high)})[:-1],
    1.0001,
)
"""The edges of the seven bands this platform actually publishes.

Derived from `BAND_RANGES` and required by `docs/calibration/PROTOCOL.md`, because calibration
should be measured on **what a reader is told**, not on an arbitrary decile grid. Nobody acts on
0.83; they act on "very likely", and a model can be well calibrated across deciles while
systematically misplacing the band boundary that decides the word.

Kept beside `DEFAULT_BINS` rather than replacing it: deciles remain useful for a finer-grained
diagnostic, and a protocol that forbids looking at the data another way is a protocol that gets
ignored. The distinction is which one a *reported* figure uses.
"""

MIN_BIN_COUNT: int = 20
"""Below this, a bin's observed frequency is noise. The protocol requires such bins to be
reported **with their count** and excluded from summary statistics — never silently merged into
a neighbour, which would hide exactly where the evidence ran out."""


@dataclass(frozen=True)
class ReliabilityBin:
    """One bucket of the reliability diagram."""

    lower: float
    upper: float
    count: int
    mean_forecast: float
    observed_frequency: float

    @property
    def gap(self) -> float:
        """Forecast minus outcome. Positive means over-confident in this bucket."""
        return self.mean_forecast - self.observed_frequency

    @property
    def underpowered(self) -> bool:
        """Too few cases for the observed frequency to mean anything.

        Reported rather than dropped. A bin of three cases that all came out true reads as
        perfect calibration at whatever band it sits in, and silently merging it into a
        neighbour would hide precisely where the evidence ran out.
        """
        return self.count < MIN_BIN_COUNT


@dataclass(frozen=True)
class BrierDecomposition:
    """The score, split into the parts that answer different questions."""

    brier_score: float
    reliability: float
    resolution: float
    uncertainty: float
    base_rate: float
    sample_size: int
    bins: tuple[ReliabilityBin, ...]

    @property
    def skill_against_base_rate(self) -> float:
        """Brier skill score against always predicting the base rate.

        Zero means the forecasts are worth exactly as much as a constant. Negative means
        they are worse than saying nothing, which is a result worth reporting loudly rather
        than burying inside a decomposition.
        """
        if self.uncertainty <= 0:
            return 0.0
        return 1.0 - (self.brier_score / self.uncertainty)

    @property
    def underpowered_bins(self) -> tuple[ReliabilityBin, ...]:
        """Bins below `MIN_BIN_COUNT`, kept visible and excluded from the reported figure."""
        return tuple(b for b in self.bins if b.underpowered)

    @property
    def reported_reliability(self) -> float | None:
        """Reliability over adequately populated bins only — the protocol's reported figure.

        `reliability` itself stays over the whole sample, because the Murphy identity is only
        exact that way and a score that quietly drops its inconvenient cases is not a score.
        This is the separate number the protocol grades on, and it comes with
        `cases_excluded_as_underpowered` attached so nobody can read it without the count.

        ``None`` when every bin is underpowered: no reportable calibration figure exists at that
        sample size, and returning 0.0 there would look like perfect calibration.
        """
        powered = [b for b in self.bins if not b.underpowered]
        cases = sum(b.count for b in powered)
        if not cases:
            return None
        return sum(b.count * b.gap**2 for b in powered) / cases

    @property
    def cases_excluded_as_underpowered(self) -> int:
        """How many cases sit in bins too thin to report. Always shown beside the figure."""
        return sum(b.count for b in self.underpowered_bins)

    @property
    def binning_discrepancy(self) -> float:
        """How far ``BS - (REL - RES + UNC)`` is from zero.

        **Not an error term.** Murphy's three-part identity is exact only when forecasts
        take finitely many distinct values and each bin isolates one of them; measured on
        this implementation, discrete forecasts give a residual of 2.8e-17. Grouping
        *continuous* forecasts into ranges introduces a discrepancy, because the forecasts
        inside a bin are no longer identical.

        NEMESIS produces continuous forecasts, so this is always non-zero in practice. It
        is a measure of how coarse the bins are relative to the spread of the forecasts —
        useful for deciding whether to bin more finely, useless as an alarm. An earlier
        version of this docstring called a non-zero value evidence that every number here
        was wrong, which would have fired on every real run.
        """
        return abs(self.brier_score - (self.reliability - self.resolution + self.uncertainty))

    def render(self) -> str:
        lines = [
            f"Brier score      {self.brier_score:.4f}   (lower is better; n={self.sample_size})",
            f"  reliability    {self.reliability:.4f}   calibration — lower is better",
            f"  resolution     {self.resolution:.4f}   informativeness — HIGHER is better",
            f"  uncertainty    {self.uncertainty:.4f}   the problem's own variance, irreducible",
            f"skill vs base    {self.skill_against_base_rate:+.4f}   "
            f"(0 = no better than always saying {self.base_rate:.2f})",
        ]
        thin = self.underpowered_bins
        if thin:
            reported = self.reported_reliability
            shown = "none — every bin is underpowered" if reported is None else f"{reported:.4f}"
            lines.append(
                f"  reported rel.  {shown}   over {len(self.bins) - len(thin)} of "
                f"{len(self.bins)} bins; {self.cases_excluded_as_underpowered} case(s) in "
                f"{len(thin)} bin(s) below n={MIN_BIN_COUNT} are excluded, not merged"
            )
        if self.resolution < 0.01:
            lines.append(
                "  ! resolution is near zero: these forecasts barely vary with the outcome. "
                "A good reliability figure here means caution, not accuracy."
            )
        return "\n".join(lines)


def brier_decomposition(
    forecasts: list[float], outcomes: list[bool], *, bins: tuple[float, ...] = DEFAULT_BINS
) -> BrierDecomposition:
    """Decompose the Brier score over binned forecasts.

    ``forecasts`` are probabilities in [0, 1]; ``outcomes`` the realised truth values.
    """
    if len(forecasts) != len(outcomes):
        raise ValueError("forecasts and outcomes must be the same length")
    if not forecasts:
        raise ValueError("cannot score an empty sample")

    size = len(forecasts)
    base_rate = sum(1.0 for outcome in outcomes if outcome) / size
    score = sum((f - (1.0 if o else 0.0)) ** 2 for f, o in zip(forecasts, outcomes, strict=True))
    score /= size

    reliability = 0.0
    resolution = 0.0
    buckets: list[ReliabilityBin] = []

    for lower, upper in pairwise(bins):
        members = [(f, o) for f, o in zip(forecasts, outcomes, strict=True) if lower <= f < upper]
        if not members:
            continue
        count = len(members)
        mean_forecast = sum(f for f, _ in members) / count
        observed = sum(1.0 for _, o in members if o) / count

        reliability += count * (mean_forecast - observed) ** 2
        resolution += count * (observed - base_rate) ** 2
        buckets.append(
            ReliabilityBin(
                lower=lower,
                upper=min(upper, 1.0),
                count=count,
                mean_forecast=mean_forecast,
                observed_frequency=observed,
            )
        )

    return BrierDecomposition(
        brier_score=score,
        reliability=reliability / size,
        resolution=resolution / size,
        uncertainty=base_rate * (1.0 - base_rate),
        base_rate=base_rate,
        sample_size=size,
        bins=tuple(buckets),
    )


def discrimination_auc(forecasts: list[float], outcomes: list[bool]) -> float | None:
    """Area under the ROC curve, by the Mann-Whitney formulation.

    Ties count a half, which matters here: a system that refuses to estimate produces many
    identical forecasts, and counting those as wins would flatter it.

    Returns ``None`` when one class is absent — an AUC over a single class is not a number,
    and returning 0.5 there would look like a measurement.
    """
    positives = [f for f, o in zip(forecasts, outcomes, strict=True) if o]
    negatives = [f for f, o in zip(forecasts, outcomes, strict=True) if not o]
    if not positives or not negatives:
        return None

    wins = 0.0
    for positive in positives:
        for negative in negatives:
            if positive > negative:
                wins += 1.0
            elif positive == negative:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def published_band_decomposition(
    forecasts: list[float], outcomes: list[bool]
) -> BrierDecomposition:
    """The decomposition the calibration protocol reports, binned on the published bands.

    `brier_decomposition` defaults to deciles, which are conventional and are **not** what
    `docs/calibration/PROTOCOL.md` grades on. The protocol and the implementation disagreed on
    this from the day the protocol was written — a reviewer found it — and the disagreement was
    the ordinary doc-versus-code defect, not a subtlety: a metric frozen in prose while a
    contradicting implementation already existed.

    The bands are what a reader is told. Nobody acts on 0.83; they act on "very likely", and a
    model can be well calibrated across deciles while systematically misplacing the boundary
    that decides the word.
    """
    return brier_decomposition(forecasts, outcomes, bins=PUBLISHED_BAND_BINS)
