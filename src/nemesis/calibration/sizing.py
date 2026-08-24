"""How many controlled operations milestone 3 would actually need.

Milestone 3 is the only path to ground truth this project has: run infrastructure *we own* —
honeypot ranges, operations across hosts and identities under our control — so the linkage is
known because we created it. The protocol ends its description with a sentence worth repeating,
because it decides what this module is: **"This is the milestone that needs a decision about
infrastructure and cost. It is not code."**

So this is not milestone 3, and nothing here produces ground truth. It computes the *size* of
the experiment, which is the input the cost decision is missing. Somebody has to decide whether
to fund renting hosts and registering domains for months; they cannot decide it against "a
corpus" and they can decide it against a number of operations, a duration, and what that number
buys in precision.

**Where the numbers come from, and how far they can be trusted.** Two are arithmetic and stand
on their own: the sample size to estimate a proportion to a stated precision, and the correction
for the fact that most case pairs cannot discriminate between candidate ceiling tables. The
second uses the discriminating fraction measured by :mod:`nemesis.calibration.ceilings` over its
swept grid — a real measurement of this engine, and an assumption about the world, because it
presumes real operations would resemble that grid in how often they land near a threshold. They
would not, exactly. The figure is an order of magnitude, and the report says so.

Nothing here is frozen as a dial: these are derivations from measured inputs, and if the grid or
the engine changes the answer should change with them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

from nemesis.calibration.ceilings import measure_ceiling_sensitivity, swept_cases

Z_95: Final = 1.959_963_984_540_054
"""Two-sided normal quantile at 95%. Written out rather than rounded to 1.96 because it is
multiplied by itself and then by a few hundred."""

TARGET_MARGINS: Final[tuple[float, ...]] = (0.10, 0.05, 0.02)
"""Margins of error worth costing.

0.10 tells you whether a rate is closer to 10% or 30% — enough to catch a ceiling that is
badly wrong. 0.05 is where two candidate tables start to be distinguishable. 0.02 is what
"calibrated" would ordinarily mean, and it is here mainly to show what it costs.
"""

ASSUMED_RATE: Final = 0.5
"""The proportion assumed when sizing. Deliberately the worst case.

``p(1-p)`` is maximised at a half, so this gives the largest requirement and therefore the
honest one to plan against. Sizing at an optimistic rate produces a corpus that turns out too
small precisely when the answer is interesting.
"""


def sample_size_for_margin(margin: float, *, rate: float = ASSUMED_RATE) -> int:
    """Labelled pairs needed to estimate a proportion to ``margin`` at 95% confidence.

    The ordinary normal approximation, ``n = z² p(1-p) / e²``. It assumes independent cases,
    which controlled operations would only approximately be — operations sharing a tenant, a
    provider or a week are correlated, and the true requirement is therefore higher than this.
    """
    if not 0.0 < margin < 1.0:
        raise ValueError("a margin of error is a proportion strictly between 0 and 1")
    return math.ceil((Z_95**2) * rate * (1.0 - rate) / (margin**2))


@dataclass(frozen=True)
class CorpusRequirement:
    """What one target precision costs, in labelled pairs and in operations."""

    margin: float
    discriminating_pairs: int
    total_pairs: int
    operations: int

    def render(self) -> str:
        return (
            f"  +/-{self.margin:.0%}  {self.discriminating_pairs:>6} discriminating pairs  "
            f"-> {self.total_pairs:>7} pairs total  -> ~{self.operations:>4} operations"
        )


@dataclass(frozen=True)
class SizingReport:
    """The experiment's size, and the assumptions it rests on."""

    discriminating_fraction: float
    movable: int
    grid_cases: int
    requirements: tuple[CorpusRequirement, ...]

    def render(self) -> str:
        lines = [
            "Milestone 3 sizing — what controlled operations would cost, in operations",
            "",
            "  NOT milestone 3, and not ground truth. Milestone 3 is running infrastructure we",
            "  own so the linkage is known because we created it; the protocol says it is a",
            "  decision about cost and not code. This computes the size that decision needed.",
            "",
            "  DECIDED 2026-08-24: not funded (ADR-0012). So the ceilings and the actionable",
            "  floor stay unvalidated, and the consequence is not a footnote:",
            "  NEMESIS's confidence bands are ORDINAL, NOT PROBABILISTIC. 'Likely' means this",
            "  engine ranked something above what it calls 'unlikely', under eight constants",
            "  nobody has checked against outcomes. It does not mean 70%.",
            "",
            "  The figures below are kept because a decision not to fund is revisitable and the",
            "  numbers are what a revisit would start from.",
            "",
            f"  discriminating fraction: {self.movable}/{self.grid_cases} "
            f"({self.discriminating_fraction:.1%}) of swept cases can move under a ceiling",
            "  perturbation at all. Pairs that cannot move tell a calibration nothing, so the",
            "  corpus must be larger than the precision arithmetic alone suggests.",
            "",
        ]
        lines.extend(item.render() for item in self.requirements)
        lines.extend(
            [
                "",
                "  Pairs per operation is taken as 2: an operation contributes a linkable pair",
                "  with its own predecessor and roughly one not-linkable pair against somebody",
                "  else's. A design running more identities per operation would do better, and",
                "  that is a design question rather than an arithmetic one.",
                "",
                "  Read these as an order of magnitude. The discriminating fraction is measured",
                "  against a grid whose shape is a choice, and it assumes real operations would",
                "  land near the decision boundary about as often — which they would not,",
                "  exactly. The sizing arithmetic also assumes independent cases, and operations",
                "  sharing a provider or a week are not, so the true requirement is higher.",
            ]
        )
        return "\n".join(lines)


def size_milestone_three(*, pairs_per_operation: int = 2) -> SizingReport:
    """Derive the corpus size from the measured discriminating fraction.

    ``pairs_per_operation`` is the one frank guess in the chain and is a parameter for that
    reason: how many usable labelled pairs one controlled operation yields depends entirely on
    how the experiment is laid out, and pretending otherwise would bury a design decision inside
    a constant.
    """
    if pairs_per_operation < 1:
        raise ValueError("an operation that yields no pairs is not a case")

    sensitivity = measure_ceiling_sensitivity(swept_cases())
    grid = len(sensitivity.baseline)
    fraction = sensitivity.movable / grid if grid else 0.0

    requirements = []
    for margin in TARGET_MARGINS:
        discriminating = sample_size_for_margin(margin)
        total = math.ceil(discriminating / fraction) if fraction else 0
        requirements.append(
            CorpusRequirement(
                margin=margin,
                discriminating_pairs=discriminating,
                total_pairs=total,
                operations=math.ceil(total / pairs_per_operation),
            )
        )

    return SizingReport(
        discriminating_fraction=fraction,
        movable=sensitivity.movable,
        grid_cases=grid,
        requirements=tuple(requirements),
    )


__all__ = [
    "ASSUMED_RATE",
    "TARGET_MARGINS",
    "Z_95",
    "CorpusRequirement",
    "SizingReport",
    "sample_size_for_margin",
    "size_milestone_three",
]
