"""Coherence: the one quantitative property this platform can honestly establish today.

The calibration milestone named three things the harness could do without lying —
"coherentization, Brier decomposition, and false-match-rate under lineage laundering". Two
were built. This is the third, and it was left last despite being the *only* one that stands
on its own, which is worth stating plainly:

**Calibration needs ground truth. Coherence does not.**

"Are these numbers right?" cannot be answered here: attribution rarely has resolved cases, no
corpus exists, and every Brier score in this harness is scored against a generator whose
assumptions are ours rather than the world's. That limitation is risk #1 in `PROJECT_STATE.md`
and no amount of better mathematics touches it.

"Do these numbers contradict each other?" needs nothing external at all. A forecaster that
reports *more* confidence from strictly less evidence is broken, and you can prove it without
knowing a single true answer. So coherence is the honest quantitative claim: not that NEMESIS
is right, but that it does not disagree with itself.

Four laws are checked, each chosen because the platform already claims it somewhere in prose
and nothing had ever measured it:

**Monotonicity under corroboration.** Adding an independent source that agrees must not lower
belief. A fusion rule that punishes corroboration is one an adversary exploits by *adding*
supporting noise.

**Monotonicity under removal.** Removing a supporting source must not *raise* belief. This is
the law the robustness margin depends on: the margin recomputes without a plantable fact and
compares, and if removal could raise the figure the comparison is meaningless.

**Band agreement.** The verbal band must contain the numeric probability it summarises. An
analyst reading "likely" and an analyst reading 0.62 must be reading the same finding —
otherwise the band is decoration and the number is buried.

**Dependence discipline.** Fusing *n* copies of one origin must not exceed fusing that origin
once. This is provenance laundering expressed as a coherence law, and it is the one an
adversary actually attacks.

A violation is not a poor score. It is a **defect**: it means two outputs of this system
cannot both be true, so at least one is wrong regardless of what the world says. That is why
`nemesis calibrate` exits non-zero on a structural failure and merely reports a bad Brier.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from pydantic import BaseModel, ConfigDict

from nemesis.core.confidence import BAND_RANGES, ConfidenceBand, Opinion, band_of
from nemesis.core.fusion import SourcedOpinion, fuse
from nemesis.core.proposition import PropositionClass

TOLERANCE: Final = 1e-9
"""Floating-point slack. Deliberately tiny: these are exact laws, not statistical trends, and
a generous tolerance would hide a real violation as rounding."""


class CoherenceViolation(BaseModel):
    """Two outputs that cannot both be true, with enough to reproduce the pair."""

    model_config = ConfigDict(frozen=True)

    law: str
    detail: str
    left: float
    right: float

    @property
    def magnitude(self) -> float:
        return abs(self.left - self.right)

    def render(self) -> str:
        return f"{self.law}: {self.detail} ({self.left:.4f} vs {self.right:.4f})"


class CoherenceReport(BaseModel):
    """What the laws found. Coherent is a real verdict here; calibrated is not."""

    model_config = ConfigDict(frozen=True)

    checked: int
    violations: tuple[CoherenceViolation, ...]

    @property
    def coherent(self) -> bool:
        return not self.violations

    @property
    def worst(self) -> CoherenceViolation | None:
        return max(self.violations, key=lambda v: v.magnitude, default=None)

    def render(self) -> str:
        lines = [
            f"Coherence: {self.checked} law check(s), {len(self.violations)} violation(s)",
        ]
        if self.coherent:
            lines.append(
                "  No output of this system contradicts another. That is a claim about "
                "self-consistency, NOT about correctness — coherence needs no ground truth, "
                "and correctness cannot be established without a corpus that does not exist."
            )
        else:
            lines.append(
                "  A violation is a defect, not a poor score: two outputs cannot both be "
                "true, so at least one is wrong whatever the world says."
            )
            lines += [f"    ! {item.render()}" for item in self.violations]
        return "\n".join(lines)


def _projected(sourced: Sequence[SourcedOpinion], proposition: PropositionClass) -> float:
    return fuse(list(sourced), proposition=proposition).opinion.projected_probability


def check_monotonic_under_corroboration(
    base: Sequence[SourcedOpinion],
    added: SourcedOpinion,
    proposition: PropositionClass,
) -> CoherenceViolation | None:
    """A *supporting* source, at least as confident as the current estimate, must not lower it.

    A rule that punishes corroboration is one an adversary exploits by *adding* supporting
    noise until the figure falls — the opposite of how anyone expects an attribution engine to
    behave, and therefore the opposite of what anyone tests.

    Both guards are load-bearing rather than softening, and both were found by measuring:
    the unguarded law fired 64 times on the real engine and was wrong every time. See the
    comment in the body for what each one excludes and why.
    """
    before = _projected(base, proposition)

    # Two guards, and both were added after the unguarded law fired 64 times on the real
    # engine and every one of those was the law being wrong rather than the engine.
    #
    # **The source must actually support the proposition.** 2 of the 64 were sources with
    # belief exactly 0 and high disbelief — evidence *against*, whose projected probability is
    # only `base_rate x uncertainty` and can look high. Adding another dissenting source
    # correctly strengthens disbelief and lowers the projection: two sources saying "no" make
    # "no" stronger. Calling that a corroboration failure was a category error, and the
    # removal law two functions down already guarded on support while this one did not.
    #
    # **It must be at least as confident as the current estimate.** The other 62 were weaker
    # sources attesting the same fact; within a dependence group the engine averages, so
    # pulling an estimate toward a less-certain observation is correct rather than a
    # contradiction.
    #
    # Measured, diagnosed, then narrowed — twice. Shipping the first version would have
    # reported 64 defects in an engine that had none.
    opinion = added.opinion
    if opinion.belief <= opinion.disbelief:
        return None
    if opinion.projected_probability + TOLERANCE < before:
        return None

    after = _projected([*base, added], proposition)
    if after + TOLERANCE < before:
        return CoherenceViolation(
            law="monotonic under corroboration",
            detail="adding an agreeing independent source lowered belief",
            left=before,
            right=after,
        )
    return None


def check_monotonic_under_removal(
    full: Sequence[SourcedOpinion],
    index: int,
    proposition: PropositionClass,
) -> CoherenceViolation | None:
    """Removing a supporting source must not raise belief.

    The law the robustness margin rests on. The margin recomputes a conclusion without a
    plantable fact and compares the two; if removal could *raise* the figure, that comparison
    says nothing and the margin is theatre.
    """
    if not 0 <= index < len(full):
        return None
    reduced = [*full[:index], *full[index + 1 :]]
    if not reduced:
        return None
    before = _projected(full, proposition)
    after = _projected(reduced, proposition)
    supports = full[index].opinion.projected_probability >= 0.5
    if supports and after > before + TOLERANCE:
        return CoherenceViolation(
            law="monotonic under removal",
            detail="removing a supporting source raised belief",
            left=before,
            right=after,
        )
    return None


def check_band_agreement(opinion: Opinion) -> CoherenceViolation | None:
    """The verbal band must contain the number it summarises.

    An analyst reading "likely" and an analyst reading 0.62 have to be reading the same
    finding. Where they are not, the band is decoration and the number is buried in it.
    """
    band = band_of(opinion)
    if band is ConfidenceBand.INSUFFICIENT_BASIS:
        return None
    low, high = BAND_RANGES[band]
    probability = opinion.projected_probability
    if not (low - TOLERANCE <= probability < high + TOLERANCE):
        return CoherenceViolation(
            law="band agreement",
            detail=f"band {band.value} does not contain its own probability",
            left=probability,
            right=low,
        )
    return None


def check_dependence_discipline(
    single: SourcedOpinion,
    copies: int,
    proposition: PropositionClass,
) -> CoherenceViolation | None:
    """Fusing *n* copies of one origin must not exceed fusing it once.

    Provenance laundering stated as a coherence law. It is the one an adversary actually
    attacks — republish a claim through five aggregators and let the count do the work — and
    it is checkable with no ground truth at all, because the *same* origin cannot corroborate
    itself however many hats it wears.
    """
    once = _projected([single], proposition)
    many = _projected([single] * max(copies, 1), proposition)
    if many > once + TOLERANCE:
        return CoherenceViolation(
            law="dependence discipline",
            detail=f"{copies} copies of one origin outscored that origin once",
            left=once,
            right=many,
        )
    return None


def check_coherence(
    cases: Sequence[Sequence[SourcedOpinion]],
    *,
    proposition: PropositionClass,
    laundering_copies: int = 5,
) -> CoherenceReport:
    """Run every law over every case and report what contradicts what.

    Takes cases rather than generating them, so the same populations the Brier scoring uses
    can be checked for coherence — a system can be well-calibrated on a generator and still
    contradict itself, and the two questions deserve the same inputs.
    """
    violations: list[CoherenceViolation] = []
    checked = 0

    for case in cases:
        if not case:
            continue
        result = fuse(list(case), proposition=proposition)

        checked += 1
        if (found := check_band_agreement(result.opinion)) is not None:
            violations.append(found)

        checked += 1
        if (
            found := check_dependence_discipline(case[0], laundering_copies, proposition)
        ) is not None:
            violations.append(found)

        if len(case) >= 2:
            checked += 1
            if (found := check_monotonic_under_removal(case, 0, proposition)) is not None:
                violations.append(found)

            checked += 1
            if (
                found := check_monotonic_under_corroboration(case[:-1], case[-1], proposition)
            ) is not None:
                violations.append(found)

    return CoherenceReport(checked=checked, violations=tuple(violations))


__all__ = [
    "TOLERANCE",
    "CoherenceReport",
    "CoherenceViolation",
    "check_band_agreement",
    "check_coherence",
    "check_dependence_discipline",
    "check_monotonic_under_corroboration",
    "check_monotonic_under_removal",
]
