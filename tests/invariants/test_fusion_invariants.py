"""Invariant 4 and invariant 13: fusion must not be steerable by an adversary.

Every test here encodes a specific attack on the confidence machinery. The threat model is
that the adversary knows how NEMESIS fuses evidence and will shape the inputs accordingly:
stand up feeds, re-report the same data through fronts, contradict true findings, or make
an unknown source assert something loudly.

The numbers in these tests are not arbitrary. They were measured against the primary
sources during the design of :mod:`nemesis.core.fusion`; see ADR-0002.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nemesis.core.confidence import Opinion
from nemesis.core.fusion import (
    CONFLICT_ALERT_THRESHOLD,
    DependenceHandling,
    SourcedOpinion,
    cumulative_belief_fusion,
    degree_of_conflict,
    discount,
    fuse,
    trust_of_source,
    weighted_belief_fusion,
)
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotMethod, Relationship

pytestmark = pytest.mark.invariant


def _source(
    identifier: str,
    *,
    operator: str | None = None,
    upstream: str | None = None,
    source_class: SourceClass = SourceClass.COMMERCIAL_FEED,
    reliability: SourceReliability = SourceReliability.USUALLY_RELIABLE,
) -> SourceDescriptor:
    return SourceDescriptor(
        source_class=source_class,
        identifier=identifier,
        operator=operator or f"{identifier}-corp",
        upstream_of_record=upstream,
        reliability=reliability,
    )


STRONG = Opinion.from_evidence(supporting=8, contradicting=1)
VACUOUS = Opinion.vacuous()


# --- Attack: denial of confidence by standing up empty sources ---------------


def test_vacuous_sources_cannot_move_a_weighted_fusion() -> None:
    """An adversary who registers feeds that say nothing must not be able to move us.

    This is why weighted belief fusion was chosen over averaging belief fusion, which is
    the operator the literature nominates for dependent sources. Under averaging, nine
    empty sources drag a real source from P=0.66 to P=0.43 and inflate uncertainty from
    0.20 to 0.71 — a denial-of-confidence attack that costs the adversary no evidence.
    """
    real = Opinion(belief=0.60, disbelief=0.20, uncertainty=0.20, base_rate=0.30)
    alone = weighted_belief_fusion([real])
    swamped = weighted_belief_fusion([real, *([VACUOUS] * 9)])

    assert swamped.projected_probability == pytest.approx(alone.projected_probability, abs=1e-9)
    assert swamped.uncertainty == pytest.approx(alone.uncertainty, abs=1e-9)


def test_vacuous_sources_cannot_move_the_top_level_fusion() -> None:
    real = SourcedOpinion(source=_source("real"), opinion=STRONG)
    noise = [SourcedOpinion(source=_source(f"noise{i}"), opinion=VACUOUS) for i in range(9)]
    alone = fuse([real], proposition=PropositionClass.OBSERVATION)
    swamped = fuse([real, *noise], proposition=PropositionClass.OBSERVATION)
    assert swamped.opinion.projected_probability == pytest.approx(
        alone.opinion.projected_probability, abs=1e-9
    )


# --- Attack: confidence inflation by re-reporting through fronts -------------


def test_weighted_fusion_is_idempotent() -> None:
    """The same source, repeated, must change nothing."""
    once = weighted_belief_fusion([STRONG])
    five_times = weighted_belief_fusion([STRONG] * 5)
    assert five_times.projected_probability == pytest.approx(once.projected_probability)
    assert five_times.uncertainty == pytest.approx(once.uncertainty)


def test_cumulative_fusion_is_not_idempotent_which_is_why_grouping_exists() -> None:
    """Documents the hazard the grouping step defends against.

    Cumulative fusion is evidence summation, so feeding it the same source repeatedly
    inflates confidence with no new information. That behaviour is *correct* for genuinely
    independent sources and catastrophic otherwise, which is why fuse() groups by origin
    before it ever reaches this operator.
    """
    once = cumulative_belief_fusion([STRONG])
    five_times = cumulative_belief_fusion([STRONG] * 5)
    assert five_times.uncertainty < once.uncertainty / 3


def test_feeds_sharing_an_upstream_are_counted_once() -> None:
    """Three resold feeds are one source. Agreement between them is not corroboration."""
    resold = [
        SourcedOpinion(
            source=_source(name, operator=f"{name}-corp", upstream="farsight-dnsdb"),
            opinion=STRONG,
        )
        for name in ("feed-x", "feed-y", "feed-z")
    ]
    result = fuse(resold, proposition=PropositionClass.OBSERVATION)

    assert result.total_sources == 3
    assert result.independent_source_count == 1
    assert result.dependence_handling is DependenceHandling.DEPENDENT_COLLAPSED
    assert any("not corroboration" in warning for warning in result.warnings)

    single = fuse([resold[0]], proposition=PropositionClass.OBSERVATION)
    assert result.opinion.uncertainty == pytest.approx(single.opinion.uncertainty, abs=1e-9)


def test_genuinely_independent_sources_do_reduce_uncertainty() -> None:
    """The counterpart: real corroboration must still count for something.

    A system so defensive that independent agreement changes nothing is useless.
    """
    independent = [
        SourcedOpinion(source=_source(name), opinion=STRONG)
        for name in ("censys", "ripe", "abusech")
    ]
    many = fuse(independent, proposition=PropositionClass.OBSERVATION)
    one = fuse([independent[0]], proposition=PropositionClass.OBSERVATION)

    assert many.independent_source_count == 3
    assert many.opinion.uncertainty < one.opinion.uncertainty
    assert many.dependence_handling is DependenceHandling.INDEPENDENT_ACCUMULATED


# --- Attack: an unknown source asserting loudly ------------------------------


def test_an_unknown_source_teaches_us_nothing() -> None:
    """A brand-new source asserting with total certainty must leave us where we were.

    The base-rate-sensitive discounting operator would give this claim a derived belief of
    0.99. The uncertainty-favouring operator returns a vacuous opinion, which is the honest
    answer: we have no reason to believe a stranger.
    """
    result = fuse(
        [
            SourcedOpinion(
                source=_source("brand-new", reliability=SourceReliability.CANNOT_BE_JUDGED),
                opinion=Opinion(belief=1.0, disbelief=0.0, uncertainty=0.0),
            )
        ],
        proposition=PropositionClass.OBSERVATION,
    )
    assert result.opinion.is_vacuous


def test_a_distrusted_source_does_not_refute_a_claim_by_asserting_it() -> None:
    """Distrust must convert to uncertainty, not to disbelief.

    Otherwise an adversary refutes a true claim simply by having a known-bad source assert
    it — cheap, and a documented attack on reputation systems.
    """
    unreliable = trust_of_source(_source("known-bad", reliability=SourceReliability.UNRELIABLE))
    asserted = Opinion(belief=1.0, disbelief=0.0, uncertainty=0.0)
    discounted = discount(unreliable, asserted)

    assert discounted.disbelief == pytest.approx(0.0, abs=1e-9)
    assert discounted.uncertainty > 0.9


# --- Order independence ------------------------------------------------------


def test_fusion_does_not_depend_on_source_ordering() -> None:
    """A confidence score that changes with arrival order is not a confidence score.

    Weighted and averaging fusion are not associative: folding a list two at a time gives
    different answers for different bracketings (measured: 0.3207 N-ary vs 0.3322 and
    0.3723 for the two pairwise orders). fuse() must therefore be N-ary throughout.
    """
    opinions = [
        Opinion(belief=0.6, disbelief=0.2, uncertainty=0.2, base_rate=0.3),
        Opinion(belief=0.1, disbelief=0.8, uncertainty=0.1, base_rate=0.5),
        Opinion(belief=0.4, disbelief=0.1, uncertainty=0.5, base_rate=0.2),
    ]
    forward = weighted_belief_fusion(opinions)
    reverse = weighted_belief_fusion(list(reversed(opinions)))
    assert forward.projected_probability == pytest.approx(reverse.projected_probability)


def test_pairwise_folding_would_disagree_with_the_n_ary_answer() -> None:
    """Pins the hazard: this is what the API refuses to let callers do."""
    opinions = [
        Opinion(belief=0.6, disbelief=0.2, uncertainty=0.2, base_rate=0.3),
        Opinion(belief=0.1, disbelief=0.8, uncertainty=0.1, base_rate=0.5),
        Opinion(belief=0.4, disbelief=0.1, uncertainty=0.5, base_rate=0.2),
    ]
    n_ary = weighted_belief_fusion(opinions)
    left = weighted_belief_fusion([weighted_belief_fusion(opinions[:2]), opinions[2]])
    assert n_ary.projected_probability != pytest.approx(left.projected_probability, abs=0.005)


# --- Conflict must surface ---------------------------------------------------


def test_two_confident_sources_that_disagree_raise_conflict() -> None:
    result = fuse(
        [
            SourcedOpinion(
                source=_source(
                    "own-sensor",
                    source_class=SourceClass.OWN_SENSOR,
                    reliability=SourceReliability.COMPLETELY_RELIABLE,
                ),
                opinion=Opinion.from_evidence(supporting=8, contradicting=1),
            ),
            SourcedOpinion(
                source=_source("dark-forum", source_class=SourceClass.DARK_WEB),
                opinion=Opinion.from_evidence(supporting=1, contradicting=9),
            ),
        ],
        proposition=PropositionClass.OBSERVATION,
    )
    assert result.max_conflict >= CONFLICT_ALERT_THRESHOLD
    assert result.conflicting_pairs
    assert any("disagree" in warning for warning in result.warnings)


def test_max_conflict_reports_the_real_maximum_not_only_alerting_pairs() -> None:
    """Regression: max_conflict was taken over the alerting subset, so genuine
    disagreement just below the threshold was reported as 0.0 — "no disagreement at all".
    """
    mild = fuse(
        [
            SourcedOpinion(
                source=_source("a"), opinion=Opinion.from_evidence(supporting=5, contradicting=2)
            ),
            SourcedOpinion(
                source=_source("b"), opinion=Opinion.from_evidence(supporting=3, contradicting=4)
            ),
        ],
        proposition=PropositionClass.OBSERVATION,
    )
    assert mild.max_conflict > 0.0


def test_two_ignorant_sources_are_not_in_conflict() -> None:
    """Conflict is weighted by certainty. Two sources that know nothing do not disagree,
    however far apart their priors sit — otherwise the alarm fires constantly.
    """
    assert degree_of_conflict(Opinion.vacuous(0.1), Opinion.vacuous(0.9)) == pytest.approx(0.0)


# --- Deception surfacing -----------------------------------------------------


def test_all_adversary_influenceable_sources_raises_a_deception_warning() -> None:
    result = fuse(
        [
            SourcedOpinion(source=_source(name, source_class=SourceClass.DARK_WEB), opinion=STRONG)
            for name in ("forum-a", "market-b")
        ],
        proposition=PropositionClass.OBSERVATION,
    )
    assert result.adversary_influenceable_sources == 2
    assert any("deception hypothesis" in warning for warning in result.warnings)


def test_no_sources_yields_a_prior_not_a_finding() -> None:
    result = fuse([], proposition=PropositionClass.OBSERVATION)
    assert result.opinion.is_vacuous
    assert result.dependence_handling is DependenceHandling.NO_SOURCES
    assert any("prior, not a finding" in warning for warning in result.warnings)


# --- Algebraic properties ----------------------------------------------------

_opinions = st.builds(
    lambda b, d, a: Opinion(
        belief=b / (b + d + 1e-9 + 1),
        disbelief=d / (b + d + 1e-9 + 1),
        uncertainty=1 - (b + d) / (b + d + 1e-9 + 1),
        base_rate=a,
    ),
    b=st.floats(min_value=0.0, max_value=10.0, allow_nan=False),
    d=st.floats(min_value=0.0, max_value=10.0, allow_nan=False),
    a=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
)


@given(opinions=st.lists(_opinions, min_size=1, max_size=6))
@settings(max_examples=200, deadline=None)
def test_weighted_fusion_always_yields_a_valid_opinion(opinions: list[Opinion]) -> None:
    """Additivity must hold for every input. A fused opinion that does not sum to 1 is not
    an opinion, and every downstream probability derived from it is meaningless."""
    fused = weighted_belief_fusion(opinions)
    assert fused.belief + fused.disbelief + fused.uncertainty == pytest.approx(1.0, abs=1e-6)


@given(opinions=st.lists(_opinions, min_size=1, max_size=6))
@settings(max_examples=200, deadline=None)
def test_cumulative_fusion_always_yields_a_valid_opinion(opinions: list[Opinion]) -> None:
    fused = cumulative_belief_fusion(opinions)
    assert fused.belief + fused.disbelief + fused.uncertainty == pytest.approx(1.0, abs=1e-6)


@given(opinions=st.lists(_opinions, min_size=2, max_size=5))
@settings(max_examples=200, deadline=None)
def test_weighted_fusion_is_order_independent(opinions: list[Opinion]) -> None:
    forward = weighted_belief_fusion(opinions)
    backward = weighted_belief_fusion(list(reversed(opinions)))
    assert forward.belief == pytest.approx(backward.belief, abs=1e-9)
    assert forward.uncertainty == pytest.approx(backward.uncertainty, abs=1e-9)


@given(trust=_opinions, claim=_opinions)
@settings(max_examples=200, deadline=None)
def test_discounting_never_increases_belief(trust: Opinion, claim: Opinion) -> None:
    """Trust can only weaken a claim, never strengthen it. A source we half-believe cannot
    make us more certain than the source itself was."""
    discounted = discount(trust, claim)
    assert discounted.belief <= claim.belief + 1e-9
    assert discounted.uncertainty >= claim.uncertainty - 1e-9


# --- Method reliability is not the same question as selectivity --------------


def _clustered_edge(method: PivotMethod, *, population: int, unique: bool = False) -> Relationship:
    from datetime import UTC, datetime

    from nemesis.core.entities import EntityType
    from nemesis.core.ids import IdPrefix, content_id, new_id
    from nemesis.core.relationships import PivotSelectivity, RelationType
    from nemesis.core.temporal import TemporalExtent

    selectivity = PivotSelectivity(
        attribute="shared attribute",
        population_size=population,
        population_measured_against="synthetic corpus, 2026-08",
        is_globally_unique=unique,
    )
    return Relationship(
        edge_id=new_id(IdPrefix.EDGE),
        source_id=new_id(IdPrefix.ENTITY),
        target_id=new_id(IdPrefix.ENTITY),
        source_type=EntityType.CRYPTO_ADDRESS,
        target_type=EntityType.CRYPTO_ADDRESS,
        relation=RelationType.CLUSTERED_WITH,
        extent=TemporalExtent.between(
            datetime(2026, 3, 1, tzinfo=UTC), datetime(2026, 5, 1, tzinfo=UTC)
        ),
        confidence=Opinion.from_evidence(supporting=5, contradicting=0),
        pivot_method=method,
        selectivity=selectivity,
        supporting_claims=(content_id(IdPrefix.CLAIM, b"c"),),
    )


def test_a_fallible_method_caps_a_perfectly_selective_attribute() -> None:
    """The case this control exists for.

    Multi-input wallet clustering on exactly two addresses is maximally selective — a
    population of two cannot be narrowed further — yet the heuristic is defeated by
    CoinJoin and mixers by design. Selectivity alone would present a fallible inference
    as a near-certainty.
    """
    edge = _clustered_edge(PivotMethod.TRANSACTION_GRAPH, population=2)
    assert edge.selectivity is not None
    assert edge.selectivity.evidential_weight() == pytest.approx(0.95)
    assert edge.evidential_weight() == pytest.approx(0.60)
    assert edge.is_method_capped


def test_cryptographic_identity_is_not_capped() -> None:
    """A private key is not shared by accident, and nothing should discount that."""
    edge = _clustered_edge(PivotMethod.CRYPTOGRAPHIC_IDENTITY, population=2, unique=True)
    assert edge.evidential_weight() == pytest.approx(1.0)
    assert not edge.is_method_capped


def test_stylometry_is_capped_hardest_and_says_why() -> None:
    """Adversarial stylometry degrades authorship attribution severely, and open-world
    accuracy is far below the closed-world figures usually quoted."""
    edge = _clustered_edge(PivotMethod.LINGUISTIC_SIMILARITY, population=2)
    assert edge.evidential_weight() == pytest.approx(0.30)
    caveats = " ".join(edge.explain().caveats)
    assert "different kind of evidence" in caveats


def test_a_weak_attribute_still_wins_over_a_reliable_method() -> None:
    """The cap is a ceiling, not a floor. A direct observation of a worthless pivot is
    still worthless — otherwise the ceiling would launder bad evidence upwards."""
    edge = _clustered_edge(PivotMethod.SHARED_ATTRIBUTE, population=40_000)
    assert edge.evidential_weight() < 0.1
    assert not edge.is_method_capped


# --- Provenance laundering: the attack the design was NOT originally built for


def test_unknown_lineage_does_not_become_asserted_independence() -> None:
    """Sources with no recorded lineage must not accumulate as independent corroboration.

    This is the failure an external review found, and it is worse than the vacuous-feed
    attack the module was first designed against. One adversary-planted artifact is observed
    honestly by several genuinely different collectors; by the time the reports reach
    fusion, lineage is incomplete. Nobody lies, no source is unreliable, no conflict fires.
    If missing provenance is read as independence, cumulative fusion counts each honest
    observation as fresh support for an actor.
    """
    planted = Opinion(belief=0.90, disbelief=0.02, uncertainty=0.08, base_rate=0.30)
    reports = [
        SourcedOpinion(
            source=SourceDescriptor(
                source_class=SourceClass.INTERNET_SCAN,
                identifier=f"scanner-{index}",
                reliability=SourceReliability.USUALLY_RELIABLE,
            ),
            opinion=planted,
        )
        for index in range(10)
    ]
    result = fuse(reports, proposition=PropositionClass.OBSERVATION)

    assert result.independent_source_count == 1, (
        "ten collectors with no recorded lineage were counted as ten independent origins; "
        "that is provenance laundering and it reaches P=0.97 on one planted fact"
    )
    alone = fuse([reports[0]], proposition=PropositionClass.OBSERVATION)
    assert result.opinion.projected_probability == pytest.approx(
        alone.opinion.projected_probability, abs=1e-9
    )


def test_known_distinct_lineage_still_accumulates() -> None:
    """The counterpart: the conservative default must not make real corroboration worthless."""
    planted = Opinion(belief=0.90, disbelief=0.02, uncertainty=0.08, base_rate=0.30)
    reports = [
        SourcedOpinion(
            source=SourceDescriptor(
                source_class=SourceClass.INTERNET_SCAN,
                identifier=f"scanner-{index}",
                operator=f"org-{index}",
                reliability=SourceReliability.USUALLY_RELIABLE,
            ),
            opinion=planted,
        )
        for index in range(3)
    ]
    result = fuse(reports, proposition=PropositionClass.OBSERVATION)
    assert result.independent_source_count == 3
    assert (
        result.opinion.uncertainty
        < fuse([reports[0]], proposition=PropositionClass.OBSERVATION).opinion.uncertainty
    )


def test_provenance_cluster_semantics_are_asymmetric() -> None:
    """Same cluster proves dependence. Different clusters prove nothing about independence."""
    unknown_a = SourceDescriptor(source_class=SourceClass.OPEN_SOURCE, identifier="a")
    unknown_b = SourceDescriptor(source_class=SourceClass.COMMERCIAL_FEED, identifier="b")
    assert not unknown_a.has_known_lineage
    assert unknown_a.provenance_cluster() == unknown_b.provenance_cluster()

    known = SourceDescriptor(
        source_class=SourceClass.OPEN_SOURCE, identifier="c", operator="some-org"
    )
    assert known.has_known_lineage
    assert known.provenance_cluster() != unknown_a.provenance_cluster()


def test_weighted_fusion_idempotence_does_not_survive_a_differing_input() -> None:
    """Pins a limit that was overclaimed: WBF resists exact duplicates, not near-clones.

    An adversary who can produce slightly different copies of the side they want believed
    still gains multiplicity leverage. Provenance grouping has to catch that; the operator
    does not.
    """
    a = Opinion(belief=0.6, disbelief=0.2, uncertainty=0.2, base_rate=0.5)
    b = Opinion(belief=0.2, disbelief=0.6, uncertainty=0.2, base_rate=0.5)

    assert weighted_belief_fusion([a, b]).projected_probability == pytest.approx(0.500)
    assert weighted_belief_fusion([a, a, b]).projected_probability == pytest.approx(
        0.5667, abs=1e-3
    )


def test_discounting_and_fusion_do_not_commute() -> None:
    """Pins an ordering the design must specify rather than leave to the caller.

    Discounting each source then fusing is not the same as fusing then discounting. This
    module discounts first, per source, which is the only order under which a per-source
    trust judgement means anything.
    """
    opinion = Opinion(belief=0.6, disbelief=0.2, uncertainty=0.2, base_rate=0.3)
    trust = Opinion(belief=0.5, disbelief=0.0, uncertainty=0.5, base_rate=0.5)

    discount_first = cumulative_belief_fusion([discount(trust, opinion)] * 2)
    fuse_first = discount(trust, cumulative_belief_fusion([opinion, opinion]))

    assert discount_first.projected_probability != pytest.approx(
        fuse_first.projected_probability, abs=1e-3
    )
