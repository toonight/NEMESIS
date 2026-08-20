"""The robustness margin: a conclusion must survive losing a plantable fact.

The defect these tests pin was measured, not theorised. Before the margin, one planted
source from a reliable-looking origin reached LIKELY on its own, and the calibration
harness reported a 100% false-match rate under provenance laundering — identical whether
the artifact was re-reported through eight collectors or one.

The counterpart matters as much. A fix that suppressed legitimate findings would have
traded one failure for a worse one, so half of what is asserted here is that the system
still concludes things.
"""

from __future__ import annotations

import pytest

from nemesis.core.confidence import ConfidenceBand, Opinion, band_of
from nemesis.core.fusion import SourcedOpinion, establish_fact, fuse
from nemesis.core.proposition import ROBUSTNESS_MARGIN, MarginOutcome, PropositionClass
from nemesis.core.provenance import (
    UNPLANTABLE_SOURCE_CLASSES,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
)

pytestmark = pytest.mark.invariant

CONFIDENT = Opinion.from_evidence(supporting=6, contradicting=0, base_rate=0.5)


def _sourced(
    index: int,
    *,
    operator: str | None = None,
    source_class: SourceClass = SourceClass.INTERNET_SCAN,
    reliability: SourceReliability = SourceReliability.USUALLY_RELIABLE,
    fact: str = "one-fact",
    opinion: Opinion = CONFIDENT,
) -> SourcedOpinion:
    return SourcedOpinion(
        source=SourceDescriptor(
            source_class=source_class,
            identifier=f"source-{index}",
            operator=operator,
            reliability=reliability,
        ),
        opinion=opinion,
        fact_key=fact,
    )


# --- The attack --------------------------------------------------------------


@pytest.mark.parametrize("collectors", [1, 3, 8])
def test_one_planted_fact_is_refused_however_many_collectors_report_it(
    collectors: int,
) -> None:
    """The measured attack. Honest collectors, one planted artifact, no lineage."""
    result = fuse(
        [_sourced(i) for i in range(collectors)],
        proposition=PropositionClass.ACTOR_ATTRIBUTION,
    )
    assert band_of(result.opinion) is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.margin_outcome is MarginOutcome.EVERY_FACT_REMOVED


def test_declared_operators_and_top_reliability_do_not_rescue_one_fact() -> None:
    """Strength is the axis an adversary can move, so the margin does not look at it.

    Eight distinct declared operators, all graded completely reliable, all attesting one
    fact: the evidence alone reads as near-certainty and the report is a refusal.
    """
    result = fuse(
        [
            _sourced(i, operator=f"org-{i}", reliability=SourceReliability.COMPLETELY_RELIABLE)
            for i in range(8)
        ],
        proposition=PropositionClass.ACTOR_ATTRIBUTION,
    )
    assert result.evidential_opinion is not None
    assert result.evidential_opinion.projected_probability > 0.95
    assert band_of(result.opinion) is ConfidenceBand.INSUFFICIENT_BASIS


# --- The counterpart: the product must survive the fix -----------------------


def test_distinct_facts_still_accumulate() -> None:
    """report(n) equals what the evidence alone gave at n-1. Corroboration still counts."""
    reported = []
    for count in range(1, 6):
        result = fuse(
            [_sourced(i, operator=f"org-{i}", fact=f"fact-{i}") for i in range(count)],
            proposition=PropositionClass.ACTOR_ATTRIBUTION,
        )
        reported.append(result.opinion.projected_probability)

    assert (
        band_of(
            fuse(
                [_sourced(0, operator="org-0", fact="fact-0")],
                proposition=PropositionClass.ACTOR_ATTRIBUTION,
            ).opinion
        )
        is ConfidenceBand.INSUFFICIENT_BASIS
    )
    assert reported[1] == pytest.approx(0.781, abs=1e-3)
    assert reported[2] == pytest.approx(0.860, abs=1e-3)
    assert reported == sorted(reported), "more distinct facts must never report less"


def test_an_unplantable_attestation_is_untouched() -> None:
    """A fact an adversary cannot author is not removable, so the margin takes nothing.

    This is what stops the margin from being a blanket suppression: evidence from a channel
    the adversary cannot write into keeps its full weight at n=1.
    """
    for count in (1, 2, 3):
        margined = fuse(
            [
                _sourced(i, operator=f"org-{i}", source_class=SourceClass.OWN_SENSOR)
                for i in range(count)
            ],
            proposition=PropositionClass.ACTOR_ATTRIBUTION,
        )
        plain = establish_fact(
            [
                _sourced(i, operator=f"org-{i}", source_class=SourceClass.OWN_SENSOR)
                for i in range(count)
            ]
        )
        assert margined.opinion.projected_probability == pytest.approx(
            plain.opinion.projected_probability, abs=1e-12
        )
        assert margined.margin_outcome is MarginOutcome.NO_REMOVABLE_FACT


def test_observations_are_bit_identical_to_the_unmargined_path() -> None:
    """Planting does not change whether a domain resolved where it resolved.

    An observation carries margin 0, so a single reliable observer remains sufficient. A
    fix that suppressed this would have broken the platform for no gain.
    """
    sources = [_sourced(0, operator="org-0")]
    assert fuse(
        sources, proposition=PropositionClass.OBSERVATION
    ).opinion.projected_probability == pytest.approx(
        establish_fact(sources).opinion.projected_probability, abs=1e-12
    )


# --- Guards ------------------------------------------------------------------


def test_a_conclusion_that_does_not_accuse_is_never_margined() -> None:
    """Guard against margining exculpation, and against zeroing deception alternatives.

    Removing support from a finding that already fails to accuse pushes it further from
    accusing, which is not a safety property. It would also silently flatten every planting
    hypothesis, which is single-source by construction — invariant 13 would go inert.
    """
    against = Opinion.from_evidence(supporting=0, contradicting=6, base_rate=0.5)
    result = fuse(
        [_sourced(0, operator="org-0", opinion=against)],
        proposition=PropositionClass.ACTOR_ATTRIBUTION,
    )
    assert result.margin_outcome is MarginOutcome.NOT_AN_ACCUSATION
    assert result.opinion.projected_probability < 0.5


def test_the_evidential_opinion_is_always_carried() -> None:
    """The margin removes support deliberately; hiding how much would be its own defect."""
    result = fuse([_sourced(i) for i in range(3)], proposition=PropositionClass.ACTOR_ATTRIBUTION)
    assert result.evidential_opinion is not None
    assert result.evidential_opinion.projected_probability > result.opinion.projected_probability
    assert result.removed_fact is not None


# --- The stipulated constants ------------------------------------------------


def test_the_margin_is_one_plantable_fact_and_zero_for_observations() -> None:
    """A tripwire on the only stipulated number in the mechanism."""
    assert ROBUSTNESS_MARGIN[PropositionClass.OBSERVATION] == 0
    assert ROBUSTNESS_MARGIN[PropositionClass.SHARED_ORIGIN] == 1
    assert ROBUSTNESS_MARGIN[PropositionClass.ACTOR_ATTRIBUTION] == 1


def test_plantability_is_an_allowlist_and_it_is_short() -> None:
    """A blocklist read a commercial feed, a partner and a model as unplantable, and one
    artifact laundered through any of them reached VERY_LIKELY. Adding a class here weakens
    every control that depends on plantability."""
    assert {SourceClass.OWN_SENSOR, SourceClass.LAW_ENFORCEMENT} == UNPLANTABLE_SOURCE_CLASSES
    for plantable in (
        SourceClass.COMMERCIAL_FEED,
        SourceClass.PARTNER,
        SourceClass.HONEYPOT,
        SourceClass.BLOCKCHAIN,
        SourceClass.MODEL_INFERENCE,
        SourceClass.HUMAN_ANALYST,
    ):
        assert SourceDescriptor(source_class=plantable, identifier="x").is_adversary_influenceable


def test_fuse_requires_a_proposition() -> None:
    """No default, for the same reason persona resolution requires a candidate population:
    every value that could be defaulted is either the permissive one that reproduces the
    defect or a strict one that suppresses legitimate observations."""
    with pytest.raises(TypeError, match="proposition"):
        fuse([_sourced(0)])  # type: ignore[call-arg]
