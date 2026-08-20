"""Plane 5 — persona resolution.

Every test here is an attack on the engine rather than a demonstration of it. The threat
model is the one from GLASS ANVIL: the adversary publishes what we will read, can register
as many personas as it likes, and knows how the linkage is scored. The three ways this
engine could be made to produce confident nonsense are a neutral prior, correlated signals
counted as corroboration, and stylometry allowed to decide — so those are what is tested,
each in the form "remove the control and this test fails".

The numeric expectations are derived from the ceilings in :mod:`nemesis.resolve.signals`
and the discounting table in :mod:`nemesis.core.fusion`. Where a test pins an exact figure
it is to catch a silent change in those tables, not because the figure is calibrated
against anything real; NEMESIS has no ground-truth corpus and cannot claim calibration.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nemesis.core.confidence import ConfidenceBand, Opinion, band_of
from nemesis.core.entities import EntityType, NormalizationError
from nemesis.core.fusion import SourcedOpinion, establish_fact
from nemesis.core.ids import IdPrefix, content_id
from nemesis.core.proposition import MarginOutcome
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotSelectivity
from nemesis.resolve.engine import (
    BASE_RATE_CEILING,
    HUMAN_IDENTIFICATION_IS_NOT_A_THRESHOLD,
    PROPOSITION_TEMPLATE,
    HumanIdentityRefusal,
    PersonaLinkageAssessment,
    PersonaResolutionEngine,
    base_rate_for_population,
)
from nemesis.resolve.signals import (
    BELIEF_CEILING,
    CONTRADICTION_BELIEF_CEILING,
    CorrelationGroup,
    LinkageSignal,
    LinkageSignalKind,
    SignalDirection,
    activity_hour_overlap,
    alias_similarity,
    infrastructure_reuse,
    least_reliable,
    shared_contact_handle,
    shared_cryptographic_identity,
    shared_wallet_cluster,
    writing_style_similarity,
)

# Synthetic throughout. The fingerprint is 40 hex characters — a full 160-bit PGP
# fingerprint — because the model refuses anything shorter.
FINGERPRINT = "9f2c4e1a" * 5


def _evidential(result: PersonaLinkageAssessment) -> Opinion:
    """What the evidence gives before the robustness margin removes a plantable fact.

    Every signal in this module arrives through a dark-web archive, which is a channel an
    adversary can author, so a linkage resting on one fact is now reported as no basis
    however strong that fact looked. That is the margin working, and it is tested on its own
    below.

    The arithmetic tests are about a different question — what a fingerprint is worth, whether
    correlated signals collapse, whether the prior does the work — and they read this figure,
    which `fuse` carries precisely so both remain visible. Reading the margined number here
    would conflate "the evidence is weak" with "the evidence could have been planted", and
    those need different fixes from an analyst.
    """
    return result.fusion.evidential_opinion or result.opinion


def _evidential_band(result: PersonaLinkageAssessment) -> ConfidenceBand:
    return band_of(_evidential(result))


CORPUS = "DarkBazaar persona corpus, 2026-08 snapshot"
FORUM_POPULATION = 40_000

ARCHIVE = SourceDescriptor(
    source_class=SourceClass.DARK_WEB,
    identifier="darkbazaar-listing-archive",
    reliability=SourceReliability.USUALLY_RELIABLE,
    operator="nemesis-darkweb-archive",
)
LEDGER = SourceDescriptor(
    source_class=SourceClass.BLOCKCHAIN,
    identifier="chain-observer",
    reliability=SourceReliability.USUALLY_RELIABLE,
    operator="nemesis-chain",
)


def _claim(text: str) -> str:
    return content_id(IdPrefix.CLAIM, text.encode())


def _pgp(*, demonstrated_key_control: bool = False) -> LinkageSignal:
    return shared_cryptographic_identity(
        fingerprint=FINGERPRINT,
        observed_by=ARCHIVE,
        demonstrated_key_control=demonstrated_key_control,
        supporting_claims=(_claim("pgp"),),
    )


def _alias(*, alias_b: str = "AnvilWorks", stem_population_size: int = 300) -> LinkageSignal:
    return alias_similarity(
        alias_a="GlassAnvil",
        alias_b=alias_b,
        observed_by=ARCHIVE,
        stem_population_size=stem_population_size,
        population_corpus=CORPUS,
        supporting_claims=(_claim("alias"),),
    )


def _handle(*, population_size: int | None = 2) -> LinkageSignal:
    return shared_contact_handle(
        handle="@glassanvil",
        platform="telegram",
        observed_by=ARCHIVE,
        population_size=population_size,
        population_corpus=CORPUS if population_size is not None else None,
        supporting_claims=(_claim("handle"),),
    )


def _wallet() -> LinkageSignal:
    return shared_wallet_cluster(
        cluster_identifier="bc1qglassanvil-cluster",
        heuristic="multi-input co-spend",
        heuristic_reliability=0.8,
        known_failure_modes=("CoinJoin", "custodial co-spend"),
        observed_by=LEDGER,
        population_size=2,
        population_corpus="synthetic ledger snapshot 2026-08",
        supporting_claims=(_claim("wallet"),),
    )


def _hours(*, disjoint: bool = False) -> LinkageSignal:
    # 60 posts a side, so the sample is above MIN_POSTS_FOR_A_ROUTINE and the comparison
    # describes a routine rather than when the collector happened to look.
    window = list(range(0, 3)) * 20 if disjoint else list(range(6, 16)) * 10
    return activity_hour_overlap(
        hours_a=list(range(6, 16)) * 10,
        hours_b=window,
        observed_by=ARCHIVE,
        population_size=40,
        population_corpus=CORPUS,
        supporting_claims=(_claim("hours"),),
    )


def _stylometry(*, open_world: bool = False, score: float = 1.0) -> LinkageSignal:
    """Deliberately the most flattering stylometry available: a perfect score, a
    closed world, two candidates, no obfuscation. Every discount in the extractor is
    turned off, so what remains is the ceiling and the engine's guard."""
    return writing_style_similarity(
        score=score,
        method="character-ngram-svm",
        candidate_set_size=2,
        population_corpus=CORPUS,
        observed_by=ARCHIVE,
        open_world=open_world,
        supporting_claims=(_claim("stylometry"),),
    )


ENGINE = PersonaResolutionEngine()


def _assess(
    signals: list[LinkageSignal], *, population: int = FORUM_POPULATION
) -> PersonaLinkageAssessment:
    return ENGINE.assess(
        "GlassAnvil",
        "AnvilWorks",
        signals,
        population,
        population_measured_against=CORPUS,
    )


# --- The strong case: a full fingerprint carries it --------------------------


def test_a_shared_full_fingerprint_drives_the_answer() -> None:
    """The one signal in this domain that is worth something on its own.

    It must reach a band from a single observation, or the engine is useless. It must also
    stay short of certainty: what was observed is that both personas *published* the same
    string, and publication is not possession.
    """
    result = _assess([_pgp()])

    assert _evidential_band(result) is ConfidenceBand.LIKELY
    assert _evidential(result).projected_probability > 0.55
    assert _evidential(result).belief < 0.95
    assert result.contributions[0].delta_projected > 0.5

    # And then the margin removes it, because one published string in a channel the
    # adversary writes into is exactly one plantable fact. Both halves are the finding: the
    # evidence is worth something, and it is not worth acting on alone.
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.fusion.margin_outcome is MarginOutcome.EVERY_FACT_REMOVED
    assert any(
        alternative.name == "reputation transfer by a third party"
        for alternative in result.alternatives
    )


def test_demonstrated_key_control_outranks_a_published_fingerprint() -> None:
    """Signing beats publishing, and lands in a different correlation group.

    A published fingerprint is a string in a listing the actor wrote, correlated with every
    other string in that listing. A signature is not reproducible by reading, so it is the
    one cryptographic signal that accumulates with the self-presentation evidence rather
    than being averaged into it.
    """
    published = _assess([_pgp(), _alias(), _handle()])
    signed = _assess([_pgp(demonstrated_key_control=True), _alias(), _handle()])

    assert published.fusion.independent_source_count == 1
    assert signed.fusion.independent_source_count == 2
    assert _evidential(signed).uncertainty < _evidential(published).uncertainty
    assert _evidential(signed).projected_probability > _evidential(published).projected_probability


# --- Alias similarity alone is not evidence of an operator -------------------


def test_alias_similarity_alone_cannot_reach_a_band() -> None:
    """ "Anvil" in both names is what an impersonator produces on purpose."""
    result = _assess([_alias()])

    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.opinion.projected_probability < 0.05
    assert result.opinion.uncertainty > 0.9


def test_an_identical_alias_shared_by_only_two_personas_still_reaches_no_band() -> None:
    """The strongest alias evidence that can exist: byte-identical, and unique in the corpus.

    It must still fail to produce a band. Inheriting an established vendor's name is a
    routine practice in these markets and costs a registration form, so no alias ceiling
    that permits a band here is defensible. This test fails if
    ``BELIEF_CEILING[ALIAS_SIMILARITY]`` is raised past roughly 0.42.
    """
    result = _assess([_alias(alias_b="GlassAnvil", stem_population_size=2)])

    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.opinion.uncertainty > 0.70


# --- Correlated signals must not accumulate ----------------------------------


def test_correlated_self_presentation_signals_are_counted_once() -> None:
    """Alias, handle and published fingerprint are one decision, not three findings.

    This is the module's central control. All three are things the actor chose to put in one
    listing; an impersonator copies all three in one afternoon. Fusing them as independent
    sources turns one decision into apparent corroboration.
    """
    signals = [_pgp(), _alias(), _handle()]
    result = _assess(signals)

    assert result.fusion.total_sources == 3
    assert result.fusion.independent_source_count == 1
    assert len(result.collapsed_groups) == 1
    collapsed = result.collapsed_groups[0]
    assert collapsed.group is CorrelationGroup.SELF_PRESENTATION
    assert len(collapsed.signals) == 3

    # Adding two correlated signals to the fingerprint must not raise the answer.
    fingerprint_alone = _assess([_pgp()])
    assert (
        _evidential(result).projected_probability
        <= _evidential(fingerprint_alone).projected_probability
    )

    # The weak correlated signals are in the record and not in the conclusion.
    negligible = {c.kind for c in result.contributions if c.is_negligible}
    assert LinkageSignalKind.ALIAS_SIMILARITY in negligible


def test_pretending_the_same_signals_were_independent_inflates_the_answer() -> None:
    """Pins what the grouping is defending against, by removing it.

    The same three opinions, from the same sources, differing only in the independence key
    they were stamped with. Cumulative fusion accumulates them and the answer moves — which
    is correct for genuinely independent origins and is exactly the inflation the
    correlation grouping exists to prevent.
    """
    signals = [_pgp(), _alias(), _handle()]
    base_rate = base_rate_for_population(FORUM_POPULATION)
    grouped = _assess(signals)

    ungrouped = establish_fact(
        [
            SourcedOpinion(
                source=signal.observed_by.model_copy(
                    update={"upstream_of_record": f"pretend-independent-{index}"}
                ),
                opinion=signal.to_opinion(base_rate=base_rate),
                label=signal.kind.value,
            )
            for index, signal in enumerate(signals)
        ],
    )

    assert ungrouped.independent_source_count == 3
    assert ungrouped.opinion.projected_probability > grouped.opinion.projected_probability + 0.1
    assert ungrouped.opinion.uncertainty < grouped.opinion.uncertainty


def test_signals_from_different_generating_processes_do_accumulate() -> None:
    """The counterpart: an engine so defensive that nothing ever corroborates is useless.

    A ledger cluster and a signed key are not two versions of one self-description, and
    their agreement must reduce uncertainty.
    """
    one = _assess([_pgp(demonstrated_key_control=True)])
    two = _assess([_pgp(demonstrated_key_control=True), _wallet()])

    assert two.fusion.independent_source_count == 2
    assert two.opinion.uncertainty < one.opinion.uncertainty


# --- The base rate -----------------------------------------------------------


def test_a_neutral_prior_would_turn_a_moderate_signal_into_a_confident_answer() -> None:
    """Why the prior is derived from the population rather than set to 0.5.

    One shared Telegram handle, advertised by only these two personas in the corpus. Under
    the real prior that is roughly even. Under a neutral 0.5 the identical belief and
    uncertainty read as *likely* — a confident answer manufactured by the prior alone, on
    every pair in the corpus that shares a handle.
    """
    result = _assess([_handle()])

    evidential = _evidential(result)
    neutral = Opinion(
        belief=evidential.belief,
        disbelief=evidential.disbelief,
        uncertainty=evidential.uncertainty,
        base_rate=0.5,
    )

    assert band_of(neutral) is ConfidenceBand.LIKELY
    assert _evidential_band(result) is ConfidenceBand.ROUGHLY_EVEN
    assert neutral.projected_probability > evidential.projected_probability + 0.2


def test_a_larger_candidate_population_weakens_the_same_evidence() -> None:
    """The same signals, drawn from a bigger pool, must mean less."""
    small = _assess([_handle(), _hours()], population=50)
    large = _assess([_handle(), _hours()], population=500_000)

    assert small.base_rate > large.base_rate
    assert small.opinion.projected_probability > large.opinion.projected_probability
    assert small.opinion.belief == pytest.approx(large.opinion.belief, abs=1e-9)


def test_the_prior_is_capped_and_floored() -> None:
    """A shortlist of two must not buy a near-certain prior, and no prior is ever zero."""
    assert base_rate_for_population(2) == BASE_RATE_CEILING
    assert base_rate_for_population(10_000_000) > 0.0
    assert base_rate_for_population(40_000) < 0.001

    with pytest.raises(ValueError, match="corpus"):
        base_rate_for_population(1)


def test_no_signals_yields_the_prior_rather_than_even_odds() -> None:
    """The empty case must not leak fusion's neutral 0.5.

    ``fuse([])`` returns a vacuous opinion carrying base rate 0.5, because it cannot know
    this proposition's prior. Reported unchanged, an assessment with no evidence at all
    would project even odds that two arbitrary forum accounts are one operator.
    """
    result = _assess([])

    assert result.opinion.is_vacuous
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.opinion.projected_probability < 0.001
    assert result.opinion.base_rate == base_rate_for_population(FORUM_POPULATION)


def test_a_single_signal_contribution_is_measured_against_the_prior() -> None:
    """Leave-one-out on the only signal must fall back to the prior, not to even odds.

    Falling back to ``fuse([])`` would score the removal at 0.5 and report a genuine
    positive signal as having *lowered* the estimate.
    """
    result = _assess([_handle()])
    (contribution,) = result.contributions

    assert contribution.delta_projected > 0.0
    assert contribution.delta_projected == pytest.approx(
        _evidential(result).projected_probability - result.base_rate
    )


# --- Stylometry --------------------------------------------------------------


def test_stylometry_alone_reaches_no_band_even_at_a_perfect_score() -> None:
    result = _assess([_stylometry()])

    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.ceiling.attainable_projected_probability < 0.2
    assert any("obfuscation" in warning for warning in result.warnings)


def test_raising_the_stylometry_ceiling_does_not_make_stylometry_decisive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The numeric cap is a dictionary entry; the guard is what survives someone editing it.

    With the ceiling raised to 0.95 the arithmetic reaches *likely* on a stylometric match
    alone. The engine must still refuse to report a band, because open-world authorship
    attribution against an adversary who can obfuscate does not support one at any score.
    """
    monkeypatch.setitem(BELIEF_CEILING, LinkageSignalKind.WRITING_STYLE_SIMILARITY, 0.95)
    result = _assess([_stylometry()])

    assert _evidential_band(result) is ConfidenceBand.LIKELY
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert any("only support" in warning for warning in result.warnings)


def test_stylometry_alongside_a_real_signal_does_not_suppress_the_band() -> None:
    """The guard must be narrow. It refuses stylometry as the *sole* support; a band that
    the fingerprint earned is still reported when a stylometric match happens to agree."""
    result = _assess([_pgp(), _stylometry()])

    # Read on the evidential figure: with both signals plantable the margin refuses the
    # linkage anyway, and this test is about the stylometry guard being narrow rather than
    # about what survives losing a fact.
    assert _evidential_band(result) is not ConfidenceBand.INSUFFICIENT_BASIS
    assert not any("only support" in warning for warning in result.warnings)


# --- Contradiction is weaker than it feels -----------------------------------


def test_disjoint_posting_hours_cannot_refute_a_linkage() -> None:
    """Two personas that never post at the same time may be one operator on two shifts.

    Negative behavioural evidence is capped so it cannot become a refutation, and the
    contradicting signal is recorded as such rather than folded into support.
    """
    result = _assess([_hours(disjoint=True)])

    assert result.opinion.disbelief < CONTRADICTION_BELIEF_CEILING
    assert result.opinion.dominant() == "refuted"
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.contradicting_claims
    assert not result.supporting_claims


# --- The ceiling -------------------------------------------------------------


def test_the_ceiling_bounds_what_this_evidence_could_ever_reach() -> None:
    """A weak evidence set must say how far it could go even if collection were perfect,
    so an analyst can tell "we need better evidence" from "we need more of this evidence"."""
    weak = _assess([_alias(), _hours()])
    strong = _assess([_pgp(demonstrated_key_control=True), _wallet()])

    assert weak.opinion.projected_probability <= weak.ceiling.attainable_projected_probability
    assert weak.ceiling.attainable_projected_probability < 0.6
    assert strong.ceiling.attainable_projected_probability > 0.75
    # Even perfect evidence of this kind stops short of certainty: keys are shared, sold and
    # stolen, and the ceiling has to leave room for that.
    assert strong.ceiling.attainable_projected_probability < 0.95


def test_adding_a_weak_correlated_signal_does_not_lower_the_ceiling() -> None:
    """A ceiling that falls when evidence is added is not a ceiling.

    Within a correlation group the weaker members are averaged against the strong one by
    weighted fusion, so counting them all would make the alias drag the fingerprint's
    ceiling down.
    """
    alone = _assess([_pgp()])
    with_alias = _assess([_pgp(), _alias()])

    assert with_alias.ceiling.attainable_projected_probability == pytest.approx(
        alone.ceiling.attainable_projected_probability
    )


# --- The hard ceiling: no human identity, ever -------------------------------


def _every_signal_at_maximum() -> list[LinkageSignal]:
    """The most linked two personas could possibly be: a signed key, a unique handle, a
    two-member wallet cluster, an identical alias, matching routines, matching prose."""
    return [
        _pgp(demonstrated_key_control=True),
        _handle(),
        _wallet(),
        _alias(alias_b="GlassAnvil", stem_population_size=2),
        _hours(),
        _stylometry(),
        infrastructure_reuse(
            attribute="3f8a1c" * 10,
            infrastructure_type=EntityType.TLS_CERTIFICATE,
            observed_by=ARCHIVE,
            population_size=2,
            population_corpus=CORPUS,
            supporting_claims=(_claim("cert"),),
        ),
    ]


def test_the_engine_refuses_a_human_identity_with_every_signal_at_maximum() -> None:
    """The acceptance criterion of the whole platform, at this plane.

    The linkage itself lands high — that is the engine working. The identification does not
    land at all, and not because the evidence fell short of a threshold: there is no
    threshold. A refusal implemented as a very high number would concede the shape of the
    argument to an adversary who only has to manufacture agreement to cross it.
    """
    maximal = _every_signal_at_maximum()
    linkage = _assess(maximal)

    assert linkage.band in {ConfidenceBand.VERY_LIKELY, ConfidenceBand.LIKELY}

    refusal = ENGINE.refuse_human_identity(
        "GlassAnvil",
        offered_signals=maximal,
        asserted_identities=("John Doe",),
    )

    assert refusal.refused is True
    assert refusal.signals_offered == len(maximal)
    assert refusal.identity_assertions_offered == 1
    assert refusal.reason == HUMAN_IDENTIFICATION_IS_NOT_A_THRESHOLD
    assert "legal determination" in refusal.reason


def test_a_refused_identity_does_not_retain_the_name_it_was_offered() -> None:
    """The refusal must not become the record that names the person.

    Storing it would create personal data about someone the platform has just declined to
    accuse — in GLASS ANVIL, someone the adversary planted precisely so it would be
    repeated.
    """
    refusal = ENGINE.refuse_human_identity("GlassAnvil", asserted_identities=("John Doe", "S. Doe"))

    assert refusal.identity_assertions_offered == 2
    assert "Doe" not in refusal.model_dump_json()
    assert refusal.retained_identity_material is False


def test_a_refusal_cannot_be_constructed_as_an_identification() -> None:
    """There is no instance of this type that represents a granted identification."""
    with pytest.raises(ValidationError):
        HumanIdentityRefusal(
            refused=False,
            persona="GlassAnvil",
            signals_offered=7,
            reason="everything matched",
        )


def test_an_assessment_cannot_be_repurposed_to_carry_a_name() -> None:
    """The assessment type carries exactly one proposition, about two personas.

    Without this check the class is a convenient envelope for any sentence a caller likes —
    arriving with a fused opinion and a confidence band attached to lend it weight.
    """
    valid = _assess([_pgp()]).model_dump()
    valid["proposition"] = "persona GlassAnvil is operated by John Doe of Minsk"

    with pytest.raises(ValidationError, match="exactly one proposition"):
        PersonaLinkageAssessment.model_validate(valid)


def test_every_assessment_carries_the_ceiling_it_was_produced_under() -> None:
    result = _assess([_pgp()])

    assert result.ceiling.produces_human_identity_attribution is False
    assert result.proposition == PROPOSITION_TEMPLATE.format(
        persona_a="GlassAnvil", persona_b="AnvilWorks"
    )
    assert any("natural person" in excluded for excluded in result.ceiling.excluded_conclusions)
    assert "same person or people" in result.render()


def test_a_persona_cannot_be_assessed_against_itself() -> None:
    with pytest.raises(ValueError, match="itself"):
        ENGINE.assess("GlassAnvil", "GlassAnvil", [_pgp()], FORUM_POPULATION)


# --- Signal-level controls the engine depends on -----------------------------
#
# These live in nemesis.resolve.signals, but the engine's guarantees rest on them, so they
# are exercised here rather than assumed.


def test_an_uncounted_attribute_contributes_nothing_and_says_so() -> None:
    """Nobody counted how many personas advertise the handle, so it narrows nothing.

    The dangerous alternative is to treat an uncounted attribute as selective, which is how
    a shared-hosting artifact becomes an adversary cluster.
    """
    signal = _handle(population_size=None)
    assert signal.evidential_weight == 0.0

    result = _assess([signal])
    assert result.opinion.is_vacuous
    assert any("nobody counted" in warning for warning in result.warnings)
    assert any("A count" in evidence.description for evidence in result.settling_evidence)


def test_a_short_pgp_key_id_cannot_establish_identity() -> None:
    """32-bit key ids collide on a laptop; accepting one would hand an adversary a way to
    manufacture identity between any two personas it chose."""
    with pytest.raises(NormalizationError, match="full 160-bit"):
        shared_cryptographic_identity(fingerprint="9f2c4e1a", observed_by=ARCHIVE)


def test_only_a_cryptographic_fingerprint_may_claim_global_uniqueness() -> None:
    """A copyable string must never be decisive by construction."""
    with pytest.raises(ValidationError, match="globally unique"):
        LinkageSignal(
            kind=LinkageSignalKind.ALIAS_SIMILARITY,
            observed_by=ARCHIVE,
            shared_attribute="stem:anvil",
            selectivity=PivotSelectivity(attribute="alias stem", is_globally_unique=True),
        )


def test_the_absence_of_a_shared_attribute_is_not_evidence_of_different_people() -> None:
    """An operator who compartmentalises has no shared key by design. Reading that as
    disbelief would reward good tradecraft with a "different people" finding."""
    with pytest.raises(ValidationError, match="cannot contradict"):
        LinkageSignal(
            kind=LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY,
            observed_by=ARCHIVE,
            shared_attribute="pgp_key:absent",
            selectivity=PivotSelectivity(attribute="pgp fingerprint"),
            direction=SignalDirection.CONTRADICTS,
        )


def test_open_world_and_obfuscation_discounts_compound() -> None:
    """The real case for a criminal forum: both discounts apply at once."""
    closed = _stylometry(open_world=False)
    open_world = _stylometry(open_world=True)
    obfuscated = writing_style_similarity(
        score=1.0,
        method="character-ngram-svm",
        candidate_set_size=2,
        population_corpus=CORPUS,
        observed_by=ARCHIVE,
        obfuscation_indicators=("register shift after takedown",),
    )

    assert open_world.match_strength < closed.match_strength
    assert obfuscated.match_strength < open_world.match_strength


def test_linking_through_shared_infrastructure_requires_a_justification() -> None:
    """Every tenant of a bulletproof host would otherwise become the same operator."""
    with pytest.raises(ValueError, match="justification"):
        infrastructure_reuse(
            attribute="AS64512",
            infrastructure_type=EntityType.ASN,
            observed_by=ARCHIVE,
            population_size=2,
            population_corpus=CORPUS,
        )


def test_a_match_is_worth_no_more_than_its_weaker_half() -> None:
    """A fingerprint seen by a trusted archive on one side and an unvetted scrape on the
    other is an unvetted-scrape finding."""
    scrape = SourceDescriptor(
        source_class=SourceClass.OPEN_SOURCE,
        identifier="pastebin-mirror",
        reliability=SourceReliability.CANNOT_BE_JUDGED,
    )
    assert least_reliable(ARCHIVE, scrape) is scrape

    unvetted = shared_cryptographic_identity(fingerprint=FINGERPRINT, observed_by=scrape)
    result = _assess([unvetted])

    # Trust discounting on an unjudgeable source is uncertainty-favouring: we learn nothing
    # from a stranger, rather than half-believing it.
    assert result.opinion.is_vacuous
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS


# --- The robustness margin, now that this plane has fact keys -----------------


def test_two_distinct_shared_attributes_are_two_facts() -> None:
    """The fact key is the specific shared attribute, not the signal's kind or its channel.

    A fingerprint and a contact handle are two different things an adversary would have had
    to arrange. That is the question the margin asks, and it is a different question from
    "were these produced by one choice of the actor's?" — which is what the independence key
    answers, and which still collapses both into one self-presentation group.
    """
    result = _assess([_pgp(), _handle()])

    assert result.fusion.facts_established == 2
    assert result.fusion.independent_source_count == 1, "still one correlated decision"


def test_the_same_attribute_seen_twice_is_one_fact() -> None:
    """Two collectors reporting the same fingerprint have not doubled the evidence.

    They are two accounts of one fact and accumulate as such. If this counted as two facts,
    an adversary could defeat the margin by planting once and waiting to be found twice.
    """
    second_archive = ARCHIVE.model_copy(update={"identifier": "a-different-archive"})
    result = _assess([_pgp(), _pgp().model_copy(update={"observed_by": second_archive})])

    assert result.fusion.facts_established == 1
    assert result.fusion.margin_outcome is MarginOutcome.EVERY_FACT_REMOVED
    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS


def test_a_linkage_on_one_plantable_fact_is_refused() -> None:
    """The gap PROJECT_STATE recorded as the largest one left in the anti-planting mechanism.

    A shared fingerprint published on a criminal forum is one copyable string in a channel
    the adversary writes into. Before fact keys reached this plane it produced *likely*; a
    planted string was enough to link two personas.
    """
    result = _assess([_pgp()])

    assert result.band is ConfidenceBand.INSUFFICIENT_BASIS
    assert result.opinion.is_vacuous
    assert result.fusion.unplantable_facts == 0
    assert any("could have been planted" in warning for warning in result.warnings)

    # And the evidential figure is carried, not discarded: an analyst must see the size of
    # the reduction, or the refusal looks like the evidence was weak rather than removable.
    assert _evidential(result).projected_probability > 0.55


def test_a_fact_attested_by_a_channel_the_adversary_cannot_author_survives() -> None:
    """The margin must not refuse everything, or it is an outage rather than a control.

    An own-sensor observation is not something an adversary can arrange by publishing, so
    the fact it attests is unremovable and the linkage stands.
    """
    own_sensor = SourceDescriptor(
        source_class=SourceClass.OWN_SENSOR,
        identifier="nemesis-collector",
        reliability=SourceReliability.COMPLETELY_RELIABLE,
        operator="nemesis",
    )
    result = _assess([_pgp().model_copy(update={"observed_by": own_sensor})])

    assert result.fusion.unplantable_facts == 1
    assert result.fusion.margin_outcome is MarginOutcome.NO_REMOVABLE_FACT
    assert result.band is not ConfidenceBand.INSUFFICIENT_BASIS


def test_two_plantable_facts_survive_losing_one() -> None:
    """The margin costs one fact. A linkage resting on two independent things stands.

    Both signals must be genuinely different attributes: two selective ones, so that what
    remains after dropping the stronger is still worth something.
    """
    result = _assess([_pgp(), _handle(population_size=3)])

    assert result.fusion.facts_established == 2
    assert result.fusion.margin_outcome is MarginOutcome.SURVIVED
    assert result.opinion.projected_probability > result.base_rate
