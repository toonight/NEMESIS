"""Confidence representation.

Invariant 4 requires that confidence and uncertainty be explicit. A single float cannot
do that, because it cannot distinguish the two situations that matter most in an
investigation:

- **We have no evidence.** Nobody has looked. The honest answer is the prior.
- **We have conflicting evidence.** Two credible sources disagree. Something is wrong,
  and an analyst needs to see it.

Both land on 0.5 in a scalar model, and the second one — the one that should stop an
operation — becomes invisible. So confidence here is a *subjective-logic opinion*:
a four-tuple ``(belief, disbelief, uncertainty, base_rate)`` with ``b + d + u = 1``.
No evidence is ``u = 1``. Conflict is ``b ≈ d`` with low ``u``. They are not the same
number and never collapse into one.

This module holds the **representation only**. Fusion operators — how two opinions
combine — live in :mod:`nemesis.core.fusion`, because choosing them is a separate and
much harder decision that depends on whether the sources are independent.

Reference: A. Jøsang, *Subjective Logic: A Formalism for Reasoning Under Uncertainty*,
Springer, 2016. See ADR-0002 for why this formalism was chosen and what was rejected.
"""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.provenance import InformationCredibility, SourceReliability

Unit = Annotated[float, Field(ge=0.0, le=1.0)]

_TOLERANCE = 1e-9


class Opinion(BaseModel):
    """A subjective-logic opinion about a binary proposition.

    ``belief + disbelief + uncertainty == 1``. The ``base_rate`` is the prior probability
    assigned in the absence of evidence — what you would guess knowing nothing.

    The base rate is where most of the honesty lives. For a proposition like *"this
    persona is the same operator as that one"*, the prior is very low: given two randomly
    chosen personas on a large forum, they are almost certainly different people. Setting
    that base rate to 0.5 out of apparent neutrality silently builds in the assumption
    that any two personas are as likely the same as not, which is how base-rate neglect
    produces confident false identification at scale.
    """

    model_config = ConfigDict(frozen=True)

    belief: Unit
    disbelief: Unit
    uncertainty: Unit
    base_rate: Unit = 0.5

    @model_validator(mode="after")
    def _check_additivity(self) -> Self:
        total = self.belief + self.disbelief + self.uncertainty
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(
                f"belief + disbelief + uncertainty must equal 1, got {total:.6f} "
                f"(b={self.belief}, d={self.disbelief}, u={self.uncertainty})"
            )
        return self

    # -- constructors ---------------------------------------------------------

    @classmethod
    def vacuous(cls, base_rate: float = 0.5) -> Opinion:
        """Total ignorance: nobody has looked. Distinct from "evenly balanced"."""
        return cls(belief=0.0, disbelief=0.0, uncertainty=1.0, base_rate=base_rate)

    @classmethod
    def from_evidence(
        cls,
        *,
        supporting: float,
        contradicting: float,
        base_rate: float = 0.5,
        prior_weight: float = 2.0,
    ) -> Opinion:
        """Map counted evidence onto an opinion via the Beta mapping.

        With ``r`` supporting and ``s`` contradicting observations and non-informative
        prior weight ``W``:

            b = r / (r + s + W),  d = s / (r + s + W),  u = W / (r + s + W)

        Uncertainty shrinks as evidence accumulates but never reaches zero, which is the
        property we want: no finite amount of evidence should produce certainty about an
        adversary who is actively trying to mislead us.
        """
        if supporting < 0 or contradicting < 0:
            raise ValueError("evidence counts must be non-negative")
        if prior_weight <= 0:
            raise ValueError("prior_weight must be positive")
        total = supporting + contradicting + prior_weight
        return cls(
            belief=supporting / total,
            disbelief=contradicting / total,
            uncertainty=prior_weight / total,
            base_rate=base_rate,
        )

    @classmethod
    def from_admiralty(
        cls,
        reliability: SourceReliability,
        credibility: InformationCredibility,
        *,
        base_rate: float = 0.5,
    ) -> Opinion:
        """Translate a NATO Admiralty grading into an opinion.

        The two axes map to different things, which is the point of the code: credibility
        drives the belief/disbelief split, reliability drives how much uncertainty remains.
        An "A" source reporting a "4" (doubtful) yields low belief with low uncertainty —
        we are fairly sure the thing is doubtful. An "E" source reporting a "1"
        (confirmed) yields high uncertainty — we cannot tell.

        The numeric weights below are a **calibration choice, not a derivation**. They are
        a defensible starting point, not a measured mapping; see ADR-0002. They must be
        recalibrated against outcomes once real cases exist.
        """
        credibility_belief = {
            InformationCredibility.CONFIRMED: 0.95,
            InformationCredibility.PROBABLY_TRUE: 0.75,
            InformationCredibility.POSSIBLY_TRUE: 0.55,
            InformationCredibility.DOUBTFUL: 0.30,
            InformationCredibility.IMPROBABLE: 0.10,
            InformationCredibility.CANNOT_BE_JUDGED: 0.50,
        }[credibility]

        # How much of the opinion is evidence-bearing at all.
        reliability_weight = {
            SourceReliability.COMPLETELY_RELIABLE: 0.95,
            SourceReliability.USUALLY_RELIABLE: 0.80,
            SourceReliability.FAIRLY_RELIABLE: 0.60,
            SourceReliability.NOT_USUALLY_RELIABLE: 0.35,
            SourceReliability.UNRELIABLE: 0.10,
            SourceReliability.CANNOT_BE_JUDGED: 0.20,
        }[reliability]

        # "Cannot be judged" on either axis must not masquerade as a real signal.
        if credibility is InformationCredibility.CANNOT_BE_JUDGED:
            reliability_weight = min(reliability_weight, 0.20)

        uncertainty = 1.0 - reliability_weight
        belief = credibility_belief * reliability_weight
        disbelief = (1.0 - credibility_belief) * reliability_weight
        return cls(belief=belief, disbelief=disbelief, uncertainty=uncertainty, base_rate=base_rate)

    # -- projections ----------------------------------------------------------

    @property
    def projected_probability(self) -> float:
        """The point estimate: ``P = b + a·u``.

        Use it to rank and threshold. Never display it alone — it is exactly the scalar
        that discards the distinction this class exists to preserve.
        """
        return self.belief + self.base_rate * self.uncertainty

    @property
    def is_vacuous(self) -> bool:
        """No evidence at all."""
        return self.uncertainty >= 1.0 - _TOLERANCE

    @property
    def is_dogmatic(self) -> bool:
        """Zero uncertainty. Almost always a modelling error in this domain: it asserts
        that no future evidence could change the conclusion."""
        return self.uncertainty <= _TOLERANCE

    @property
    def indecisiveness(self) -> float:
        """How evenly this opinion is split between belief and disbelief, in [0, 1].

        Deliberately **not** called "conflict". A single opinion cannot express conflict:
        an opinion of ``b=0.29, d=0.67`` is not two sources disagreeing, it is one source
        saying "probably not". Reading indecisiveness as conflict manufactures a warning
        on every middling credibility rating, and a warning that fires constantly is a
        warning nobody reads.

        Real conflict is a property of *fusion* — two sources that each looked and reached
        opposite conclusions — and is diagnosed in :mod:`nemesis.core.fusion`, which can
        see the inputs. Here, this value is only interpretable once you know how many
        independent sources produced the opinion.
        """
        return 2.0 * min(self.belief, self.disbelief)

    def dominant(self) -> str:
        """Coarse verbal direction. Says nothing about how the opinion was formed."""
        if self.is_vacuous:
            return "unknown"
        if self.belief > self.disbelief:
            return "supported"
        if self.disbelief > self.belief:
            return "refuted"
        return "balanced"


class ConfidenceBand(StrEnum):
    """Verbal probability bands.

    Words like "likely" mean wildly different numeric ranges to different readers, which
    is why intelligence communities standardise them. Every NEMESIS output that shows a
    band must show its numeric range alongside, never the word alone.

    Bands follow the structure used by ICD 203 (US IC analytic standards). The exact
    boundaries below are NEMESIS's own and are stated explicitly so a reader can disagree
    with them rather than having to guess.
    """

    ALMOST_NO_CHANCE = "almost_no_chance"
    VERY_UNLIKELY = "very_unlikely"
    UNLIKELY = "unlikely"
    ROUGHLY_EVEN = "roughly_even"
    LIKELY = "likely"
    VERY_LIKELY = "very_likely"
    ALMOST_CERTAIN = "almost_certain"
    INSUFFICIENT_BASIS = "insufficient_basis"
    """Not a probability. The evidence does not support any estimate — reported as such
    rather than as "roughly even", which would falsely imply that we looked and found
    balance."""


BAND_RANGES: dict[ConfidenceBand, tuple[float, float]] = {
    ConfidenceBand.ALMOST_NO_CHANCE: (0.00, 0.05),
    ConfidenceBand.VERY_UNLIKELY: (0.05, 0.20),
    ConfidenceBand.UNLIKELY: (0.20, 0.45),
    ConfidenceBand.ROUGHLY_EVEN: (0.45, 0.55),
    ConfidenceBand.LIKELY: (0.55, 0.80),
    ConfidenceBand.VERY_LIKELY: (0.80, 0.95),
    ConfidenceBand.ALMOST_CERTAIN: (0.95, 1.00),
}

VACUITY_THRESHOLD = 0.70
"""Above this uncertainty, no probability band is reported.

An opinion resting on almost nothing produces a projected probability equal to its prior.
Dressing that up as "unlikely" presents an assumption as a finding.
"""


def band_of(opinion: Opinion) -> ConfidenceBand:
    """Assign a verbal band, refusing to do so when the basis is too thin."""
    if opinion.uncertainty >= VACUITY_THRESHOLD:
        return ConfidenceBand.INSUFFICIENT_BASIS
    probability = opinion.projected_probability
    for band, (low, high) in BAND_RANGES.items():
        if low <= probability < high:
            return band
    return ConfidenceBand.ALMOST_CERTAIN


def describe(opinion: Opinion) -> str:
    """One line an analyst can read without knowing subjective logic."""
    band = band_of(opinion)
    if band is ConfidenceBand.INSUFFICIENT_BASIS:
        return (
            f"insufficient basis (uncertainty {opinion.uncertainty:.2f}) — "
            "not enough evidence to estimate"
        )
    low, high = BAND_RANGES[band]
    return (
        f"{band.value.replace('_', ' ')} ({low:.0%} to {high:.0%}), "
        f"point estimate {opinion.projected_probability:.0%}, "
        f"uncertainty {opinion.uncertainty:.2f}"
    )
