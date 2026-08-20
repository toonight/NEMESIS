"""Freeze before evaluate, enforced rather than promised.

The largest declared weakness of this project is that no confidence figure it produces has ever
been scored against a known-correct answer. Closing that needs a corpus of resolved cases, and
a corpus is worth nothing if the engine can be adjusted while it is being graded: a score
obtained by tuning against the cases that measure you is a score of your tuning.

Every calibration constant here is a documented *choice*, which makes the temptation concrete —
each is a dial, and each moves a number somebody is about to grade. These tests are what stops
"we froze first" from being a claim in a protocol document that nobody can check.
"""

from __future__ import annotations

import ast
import importlib
import os
import py_compile
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import pytest

import nemesis.attribute.engine as attribution_engine
from nemesis.attribute.dimensions import AttributionDimension
from nemesis.attribute.engine import (
    AttributionEngine,
    AttributionEvidence,
    AttributionRequest,
    DimensionInput,
    _is_cheaply_plantable,
)
from nemesis.calibration.freeze import (
    CALIBRATION_CONSTANTS,
    CONSTANT_DIGESTS,
    FROZEN_DIGEST,
    MODULE_DIGESTS,
    SELF,
    _digest_of,
    canonical,
    constants_drifted,
    discovered_constants,
    drifted,
    engine_digest,
    engine_drifted,
    freeze_digest,
    frozen_modules,
    module_digests,
    normalised_source,
    observed_values,
)
from nemesis.calibration.scoring import (
    MIN_BIN_COUNT,
    PUBLISHED_BAND_BINS,
    published_band_decomposition,
)
from nemesis.core.claims import Claim, ClaimKind, DeceptionAssessment, DerivationKind, Statement
from nemesis.core.confidence import (
    ADMIRALTY_RELIABILITY_WEIGHT,
    BAND_RANGES,
    ConfidenceBand,
    Opinion,
    band_of,
)
from nemesis.core.entities import EntityType
from nemesis.core.fusion import cumulative_belief_fusion, weighted_belief_fusion
from nemesis.core.ids import IdPrefix, content_id, new_id
from nemesis.core.proposition import ROBUSTNESS_MARGIN, PropositionClass
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import METHOD_RELIABILITY_CEILING, PivotMethod
from nemesis.core.temporal import TemporalExtent
from nemesis.resolve.engine import PersonaLinkageAssessment, PersonaResolutionEngine
from nemesis.resolve.signals import (
    LinkageSignal,
    alias_similarity,
    infrastructure_reuse,
    shared_cryptographic_identity,
    writing_style_similarity,
)

pytestmark = pytest.mark.invariant

ASSESSED_AT = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
CAMPAIGN_WINDOW = TemporalExtent.between(
    datetime(2026, 2, 18, tzinfo=UTC), datetime(2026, 3, 10, tzinfo=UTC)
)
ANALYST = new_id(IdPrefix.ACTOR)
SRC = Path(__file__).resolve().parents[2] / "src"
"""The tree under test. Tampering is always done on a copy read from here, never in place."""


# --- The constants -----------------------------------------------------------


def test_no_calibration_constant_has_moved_since_the_freeze() -> None:
    """THE ONE THIS FILE EXISTS FOR.

    A mismatch is not a bug in the code. It means a dial moved, and it forces the question that
    matters: did that happen *before* an evaluation or *during* one? Constants should change
    when there is a reason — what must not happen is that they change quietly, which is exactly
    what a promise in a document permits.

    Updating `FROZEN_DIGEST` is the deliberate act: one line, in its own commit, with the
    reason. That is the whole mechanism.
    """
    assert freeze_digest() == FROZEN_DIGEST, (
        "a calibration constant changed. If that was deliberate, update FROZEN_DIGEST in its "
        "own commit and say why; if it was not, this is the drift the freeze exists to catch"
    )
    assert drifted() == ()


def test_a_constant_that_appears_is_reported_as_loudly_as_one_that_moves(
    tmp_path: Path,
) -> None:
    """What replaced the scanner — and the second attempt at proving it.

    There used to be a second scope, `scoring_engines()`, over which a scan flagged numeric
    constants nobody had registered. It was the last enumeration in this file: a list of modules
    feeding a list of excuses. It is redundant because a **new** constant has no entry in the
    frozen table, so `constants_drifted()` names it — derived instead of listed, and over 103
    modules instead of fourteen.

    The first version of this test asserted nothing. It parsed a tampered *string*, checked that
    `ast` had found the name in it, then called `constants_drifted()` on the real, untouched
    tree and asserted `()` — the opposite of the claim, dressed as a confirmation. A reviewer
    caught it. It is the exact defect this file exists to catch, committed inside the file that
    exists to catch it, and the mechanism it was meant to prove is the one that has now been
    wrong nine times.

    So the freeze takes a `tree` argument now. The fix is to make the mechanism testable rather
    than to test around it: the injection goes into a real copy of the package, and the
    assertion is the exact name, not a truthy shrug.
    """
    package = tmp_path / "nemesis"
    shutil.copytree(SRC / "nemesis", package)

    confidence = package / "core/confidence.py"
    source = confidence.read_text(encoding="utf-8")
    assert "_TOLERANCE = 1e-9" in source
    confidence.write_text(
        source.replace("_TOLERANCE = 1e-9", "_TOLERANCE = 1e-9\nA_NEW_DIAL = 0.42", 1),
        encoding="utf-8",
    )

    # The copy is byte-identical apart from the injection, so anything else reported here would
    # mean the freeze reads something other than what it claims to.
    assert constants_drifted(tree=package) == ("nemesis.core.confidence:A_NEW_DIAL",)
    # And the syntax digest sees the same edit from its own direction.
    assert engine_drifted(tree=package) == ("nemesis/core/confidence.py",)

    # The untouched copy is clean, which is what makes the assertion above mean anything: if a
    # copied tree drifted by construction, the test would pass whatever it was handed.
    pristine = tmp_path / "pristine"
    shutil.copytree(SRC / "nemesis", pristine / "nemesis")
    assert constants_drifted(tree=pristine / "nemesis") == ()
    assert engine_drifted(tree=pristine / "nemesis") == ()


def test_the_registry_reads_the_real_modules() -> None:
    """Imported, not parsed. A constant that was renamed or moved must fail loudly here rather
    than being read from a stale copy of the source and silently frozen at the wrong value."""
    values = observed_values()

    assert len(values) == len(CALIBRATION_CONSTANTS)
    # Scalars *and* tables. The registry originally held only scalars, which is precisely why
    # `BAND_RANGES` could move without breaking anything: a dict is not a lesser dial.
    assert any(isinstance(value, dict) for value in values.values())
    # Tuples too, since the metric bin edges joined the registry: freezing what the platform
    # believes while leaving the ruler that measures it free to move closes nothing.
    # A `timedelta` too: how long a hole in the evidence may be before it is reported as a
    # discontinuity is a claim about how sparsely we collect, and it changes what an analyst
    # is told. A dial is a dial whatever type it happens to wear.
    assert all(
        isinstance(value, int | float | dict | tuple | timedelta | frozenset | StrEnum)
        for value in values.values()
    )
    assert any(isinstance(value, tuple) for value in values.values())
    assert any(isinstance(value, timedelta) for value in values.values())
    # A bare enum member is a dial too — `LINKAGE_PROPOSITION` alone decides which proposition
    # the harness scores, and scoring the attack as an OBSERVATION reports a 0% false-match
    # rate by answering a different question. It contains no digits at all.
    assert any(isinstance(value, StrEnum) for value in values.values())
    assert any(isinstance(value, frozenset) for value in values.values())
    # Spot-check two that carry very different meanings, so a wholesale rewiring of the
    # registry to a single module could not pass this.
    assert values["nemesis.resolve.signals:STYLOMETRY_BELIEF_CEILING"] == 0.15
    assert values["nemesis.attribute.engine:DECEPTION_BASE_RATE"] == 0.25


# --- The behaviour -----------------------------------------------------------


def test_the_fusion_operators_still_answer_the_same() -> None:
    """Golden vectors: fixed inputs, fixed outputs.

    Hashing the source of the fusion operators would have been easier and worse. Not because a
    byte hash misses a changed sign — it breaks on any edit, that one included — but because it
    breaks on a reworded comment too, and a check that cannot tell those apart is one somebody
    switches off. The syntax digests elsewhere in this file draw that distinction; these vectors
    make a different guarantee again: the code may be rewritten wholesale and still has to
    **answer the same**.

    These numbers were **read off the engine**, not predicted. The first draft of this test
    guessed them and would have frozen four wrong assertions — which is the failure a golden
    vector exists to prevent, committed inside the mechanism meant to prevent it. If one moves
    later, the engine's behaviour changed, and any measurement taken before that point
    describes a different system.
    """
    weak = Opinion(belief=0.2, disbelief=0.1, uncertainty=0.7, base_rate=0.5)
    strong = Opinion(belief=0.7, disbelief=0.1, uncertainty=0.2, base_rate=0.5)
    against = Opinion(belief=0.1, disbelief=0.6, uncertainty=0.3, base_rate=0.5)

    # Two independent origins agreeing: cumulative fusion should reduce uncertainty below
    # either input, which is the whole reason independence is worth establishing.
    agreed = cumulative_belief_fusion((weak, strong))
    assert round(agreed.belief, 6) == 0.697368
    assert round(agreed.uncertainty, 6) == 0.184211
    assert agreed.uncertainty < min(weak.uncertainty, strong.uncertainty)

    # The same two, treated as one dependence group: averaging, not accumulating. A weaker
    # answer than the above, and deliberately so — sources that may share an origin must not
    # compound.
    averaged = weighted_belief_fusion((weak, strong))
    assert round(averaged.belief, 6) == 0.651613
    assert round(averaged.uncertainty, 6) == 0.248387
    assert averaged.uncertainty > agreed.uncertainty  # averaging never compounds

    # Disagreement must not average away into a confident middle.
    conflicted = cumulative_belief_fusion((strong, against))
    assert round(conflicted.belief, 6) == 0.522727
    assert round(conflicted.disbelief, 6) == 0.340909
    assert round(conflicted.uncertainty, 6) == 0.136364


def test_a_vacuous_opinion_stays_vacuous_through_fusion() -> None:
    """The property that keeps "we do not know" from becoming "we mildly believe" by being
    fused with other things that also do not know. Pinned at the freeze because it is the
    behaviour an evaluation would most easily flatter."""
    nothing = Opinion(belief=0.0, disbelief=0.0, uncertainty=1.0, base_rate=0.5)

    assert cumulative_belief_fusion((nothing, nothing)).uncertainty == 1.0
    assert weighted_belief_fusion((nothing, nothing)).uncertainty == 1.0


# --- End to end: what a reader actually sees ---------------------------------


def test_the_published_confidence_bands_have_not_moved() -> None:
    """The gap a reviewer walked through: the fusion vectors froze fusion and nothing else.

    Changing `BAND_RANGES` alone moved a published figure from *likely* to *almost certain*
    while the digest and the scanner both stayed green — because the scanner matched only
    `NAME = <digit>` and a band table is a dict.

    A table is not a lesser dial than a scalar. `BAND_RANGES` decides the **word** a reader
    sees, which is the only output most consumers of this platform will ever read: nobody acts
    on 0.83, they act on "very likely".
    """

    def at(probability: float, uncertainty: float = 0.1) -> Opinion:
        belief = max(0.0, min(1.0 - uncertainty, probability - 0.5 * uncertainty))
        return Opinion(
            belief=belief,
            disbelief=1.0 - uncertainty - belief,
            uncertainty=uncertainty,
            base_rate=0.5,
        )

    assert band_of(at(0.50)) is ConfidenceBand.ROUGHLY_EVEN
    assert band_of(at(0.70)) is ConfidenceBand.LIKELY
    assert band_of(at(0.88)) is ConfidenceBand.VERY_LIKELY
    assert band_of(at(0.95)) is ConfidenceBand.ALMOST_CERTAIN


def test_the_refusal_threshold_has_not_moved() -> None:
    """Correct refusals are a graded outcome in the protocol, so the line that produces them is
    frozen too. A system that cannot be graded on refusing will be tuned to stop refusing, and
    the cheapest way to improve every other metric is to quietly lower this."""
    thin = Opinion(belief=0.2, disbelief=0.05, uncertainty=0.75, base_rate=0.5)
    at_the_line = Opinion(belief=0.25, disbelief=0.05, uncertainty=0.70, base_rate=0.5)

    assert band_of(thin) is ConfidenceBand.INSUFFICIENT_BASIS
    # The threshold is inclusive: exactly at the line still refuses. An off-by-one here would
    # be invisible in every aggregate and would change which cases get answered at all.
    assert band_of(at_the_line) is ConfidenceBand.INSUFFICIENT_BASIS


def test_the_robustness_margin_and_method_ceilings_have_not_moved() -> None:
    """Two tables that decide as much as any scalar, in modules the first scan never opened.

    The margin is what makes a conclusion survive losing a plantable fact; the ceilings are
    what stop a fallible technique from becoming decisive. Both are exactly the dials an
    evaluation would reward loosening.
    """
    assert ROBUSTNESS_MARGIN[PropositionClass.OBSERVATION] == 0
    assert ROBUSTNESS_MARGIN[PropositionClass.SHARED_ORIGIN] == 1
    assert ROBUSTNESS_MARGIN[PropositionClass.ACTOR_ATTRIBUTION] == 1

    assert METHOD_RELIABILITY_CEILING[PivotMethod.CRYPTOGRAPHIC_IDENTITY] == 1.0
    assert METHOD_RELIABILITY_CEILING[PivotMethod.LINGUISTIC_SIMILARITY] == 0.3
    assert METHOD_RELIABILITY_CEILING[PivotMethod.BEHAVIORAL_PATTERN] == 0.45
    # Stylometry must stay far below anything that could carry a conclusion alone.
    assert METHOD_RELIABILITY_CEILING[PivotMethod.LINGUISTIC_SIMILARITY] < 0.5


# --- The engines, not their tables -------------------------------------------


def test_the_modules_have_not_changed_shape() -> None:
    """The backstop, and the reason enumeration was always going to lose.

    Three rounds of review found three things the constant registry could not see: tables,
    modules the list did not name, and — the one that settled it — a **categorical** table
    holding no numbers. Moving `ALIAS_SIMILARITY` between correlation groups changed a
    published band from *unlikely* to *roughly even*, because that table decides whether two
    signals compound as independent evidence or average as one dependence group. A numeric scan
    was structurally incapable of noticing.

    A registry answers "which dial moved". It cannot answer "did anything move", because it
    only knows the dials somebody listed. This does, at the cost of naming nothing.

    Verified in both directions when it was built: moving one entry of `CORRELATION_GROUP_OF`
    breaks it, and rewording a docstring does not — which required stripping *attribute*
    docstrings, not just leading ones, because this codebase documents constants with bare
    strings after the assignment and the first version produced a false positive on prose.
    """
    assert engine_drifted() == (), (
        "these modules' syntax changed. If deliberate, run scripts/refreeze_calibration.py in "
        "its own commit with the reason; any measurement taken before this point describes a "
        "different system"
    )


def test_the_metric_bins_are_derived_from_the_published_bands() -> None:
    """The protocol and the implementation disagreed, and a reviewer found it.

    The protocol required binning on the seven published bands; `scoring.py` used ten deciles,
    kept every bin however small, and the two documents contradicted each other from the day
    the protocol was written. Freezing a metric definition in prose while a contradicting
    implementation already exists is the same defect as any other doc-versus-code drift.

    The edges are now derived from `BAND_RANGES` rather than copied, so they cannot drift
    again — and the frozen `BAND_RANGES` above is what pins them.
    """
    edges = sorted({edge for low, high in BAND_RANGES.values() for edge in (low, high)})

    assert PUBLISHED_BAND_BINS[:-1] == tuple(edges[:-1])
    assert PUBLISHED_BAND_BINS[-1] > 1.0  # the top bin is closed, so 1.0 lands somewhere
    assert len(PUBLISHED_BAND_BINS) - 1 == len(BAND_RANGES)
    assert MIN_BIN_COUNT == 20


# --- Input to published result, through the engines themselves ---------------
#
# The gap a third review named: every vector above pins a *table*. None of them ran an input
# through `PersonaResolutionEngine` or `AttributionEngine`, so any change to how the engines
# *use* those tables — the order of discounting, where the margin applies, which side an
# inverted signal lands on — was unpinned. The engine digest catches a syntax change; only
# these catch a behavioural one, and only these describe what a reader is actually shown.
#
# Every figure below was **read off the engine**, never predicted. The first draft of the fusion
# vectors above guessed four numbers and got all four wrong — inside the mechanism built to stop
# exactly that — so these were measured first and written down second.

FINGERPRINT = "9f2c4e1a" * 5
"""A full 160-bit PGP fingerprint. Shorter is refused, because a 32-bit key id can be collided
on a laptop and would hand an adversary identity between any two personas it chose."""

ARCHIVE = SourceDescriptor(
    source_class=SourceClass.COMMERCIAL_FEED,
    identifier="darkbazaar-archive",
    reliability=SourceReliability.USUALLY_RELIABLE,
    operator="DarkArchiveCo",
)
SENSOR = SourceDescriptor(
    source_class=SourceClass.OWN_SENSOR,
    identifier="own-sensor",
    reliability=SourceReliability.COMPLETELY_RELIABLE,
    operator="own-sensor",
)

DARK_BAZAAR_POPULATION = 40_000
"""Accounts on the forum the pair was drawn from — not the size of the shortlist resemblance
produced. The engine requires it, because every value that could be assumed is either the
neutral 0.5 this platform exists to refuse or a number the caller had to measure anyway."""


def _resolve(signals: tuple[LinkageSignal, ...]) -> PersonaLinkageAssessment:
    return PersonaResolutionEngine().assess(
        "vendor_atlas",
        "helpful_anon",
        signals,
        DARK_BAZAAR_POPULATION,
        population_measured_against="DarkBazaar 2026-08 snapshot",
    )


def test_resolution_end_to_end_two_personas_one_key() -> None:
    """Signals in, published band out — the whole path, not the tables it reads.

    Three inputs, and the third pair of assertions is the one worth having: **one cryptographic
    fingerprint, alone, does not publish a linkage.** The evidence says *likely*; what a reader
    is shown is *insufficient basis*, because the robustness margin removes the single
    plantable fact and asks what survives. Nothing does.

    Add one genuinely independent observation from our own sensor and the published answer
    moves — to *roughly even*, not to certainty. That gap between 0.7793 evidential and 0.5130
    published is the margin doing its job, and it is invisible in any test that reads a table.
    """
    weak = (
        alias_similarity(alias_a="vendor_atlas", alias_b="vendorat1as", observed_by=ARCHIVE),
        writing_style_similarity(
            score=0.91,
            method="stylometry-v2",
            candidate_set_size=DARK_BAZAAR_POPULATION,
            population_corpus="DarkBazaar 2026-08 snapshot",
            observed_by=ARCHIVE,
        ),
    )
    one_key = (
        shared_cryptographic_identity(
            fingerprint=FINGERPRINT, observed_by=ARCHIVE, demonstrated_key_control=True
        ),
    )
    key_and_sensor = (
        *one_key,
        infrastructure_reuse(
            attribute="203.0.113.77",
            infrastructure_type=EntityType.IP_ADDRESS,
            observed_by=SENSOR,
            population_size=2,
            population_corpus="hosting tenants seen on this address",
        ),
    )

    # A near-miss alias and a 0.91 stylometry score against forty thousand candidates: the
    # combination that would convict an innocent vendor in any system that added them up.
    resembling = _resolve(weak)
    assert band_of(resembling.opinion) is ConfidenceBand.INSUFFICIENT_BASIS
    assert resembling.fusion.evidential_opinion is not None
    assert round(resembling.fusion.evidential_opinion.belief, 6) == 0.003348

    # One fingerprint, key control demonstrated: strong evidence, published as nothing.
    keyed = _resolve(one_key)
    assert keyed.is_single_origin
    assert band_of(keyed.fusion.evidential_opinion or keyed.opinion) is ConfidenceBand.LIKELY
    assert round((keyed.fusion.evidential_opinion or keyed.opinion).belief, 6) == 0.712500
    assert band_of(keyed.opinion) is ConfidenceBand.INSUFFICIENT_BASIS

    # Plus one independent observation we made ourselves.
    corroborated = _resolve(key_and_sensor)
    assert not corroborated.is_single_origin
    assert round(corroborated.opinion.belief, 6) == 0.513000
    assert round(corroborated.opinion.uncertainty, 6) == 0.487000
    assert band_of(corroborated.opinion) is ConfidenceBand.ROUGHLY_EVEN
    assert round((corroborated.fusion.evidential_opinion or corroborated.opinion).belief, 6) == (
        0.779330
    )


def test_attribution_end_to_end_a_planted_name_lands_on_the_other_side() -> None:
    """The inversion, measured at the output rather than asserted about the code.

    A group name embedded in a loader is offered here as **supporting** evidence, the way an
    analyst would offer it and the way an adversary intends it to be read. What comes out is
    disbelief 0.30 on the organization dimension: the engine files it as contradicting, because
    a string in a binary is written by whoever built the binary and costs nothing to fake.

    Pinned because it is reversible in one edit and the reversal is invisible in aggregate. An
    engine that stopped inverting cheaply plantable signals would still produce five dimensions,
    still refuse human identity, still render — and would attribute the operation to whoever
    the adversary chose.

    The four assertions cover the four things a reader sees: the honest dimension keeps its
    figure, the planted one lands negative, the human dimension is refused *structurally*
    rather than scored low, and both warnings are surfaced.
    """
    plantable = DeceptionAssessment(
        adversary_could_plant=True,
        planting_cost="trivial",
        reasoning="a string in a binary is written by whoever built the binary",
    )

    def claim(subject: str, predicate: str, obj: str, text: str, **kwargs: object) -> Claim:
        return Claim.create(
            kind=ClaimKind.OBSERVATION,
            statement=Statement(
                subject=subject, predicate=predicate, obj=obj, natural_language=text
            ),
            derivation=DerivationKind.DIRECT_COLLECTION,
            asserted_by=ANALYST,
            asserted_at=ASSESSED_AT,
            valid_extent=CAMPAIGN_WINDOW,
            supported_by_evidence=(
                content_id(IdPrefix.EVIDENCE, f"{subject}|{predicate}|{obj}".encode()),
            ),
            **kwargs,  # type: ignore[arg-type]  # heterogeneous by construction; Claim validates
        )

    def offered(
        claim_: Claim, source: SourceDescriptor, belief: float, label: str
    ) -> AttributionEvidence:
        return AttributionEvidence(
            claim=claim_,
            source=source,
            opinion=Opinion(belief=belief, disbelief=0.0, uncertainty=1.0 - belief),
            label=label,
        )

    request = AttributionRequest(
        subject="Operation GLASS ANVIL",
        dimensions=(
            DimensionInput(
                dimension=AttributionDimension.INFRASTRUCTURE,
                hypothesis="The four domains are one operation.",
                evidence=(
                    offered(
                        claim("cluster", "resolves_to", "203.0.113.77", "four domains, one host"),
                        SENSOR,
                        0.80,
                        "shared hosting address",
                    ),
                    offered(
                        claim("kit", "matches", "loader-v3", "same loader build artefacts"),
                        SENSOR,
                        0.70,
                        "loader build artefacts",
                    ),
                ),
            ),
            DimensionInput(
                dimension=AttributionDimension.ORGANIZATION,
                hypothesis="RedOctober Team ran Operation GLASS ANVIL.",
                evidence=(
                    offered(
                        claim(
                            "binary",
                            "contains_string",
                            "RedOctober Team",
                            "a group name embedded in the loader",
                            deception=plantable,
                        ),
                        ARCHIVE,
                        0.75,
                        "embedded group name",
                    ),
                ),
            ),
        ),
    )

    result = AttributionEngine(assessed_by=ANALYST).assess(request, assessed_at=ASSESSED_AT)

    infrastructure = result.for_dimension(AttributionDimension.INFRASTRUCTURE)
    assert infrastructure.band is ConfidenceBand.LIKELY
    assert round(infrastructure.opinion.belief, 6) == 0.684146

    # Offered as support; recorded against. This is the whole test.
    organization = result.for_dimension(AttributionDimension.ORGANIZATION)
    assert round(organization.opinion.disbelief, 6) == 0.300000
    assert organization.opinion.belief == 0.0
    assert organization.band is ConfidenceBand.INSUFFICIENT_BASIS

    # Refused at the structural gate, before scoring — not scored and found wanting.
    human = result.for_dimension(AttributionDimension.HUMAN_IDENTITY)
    assert human.is_refused
    assert not result.names_a_person

    assert len(result.warnings) == 2


# --- The instrument ----------------------------------------------------------


def test_the_reported_metric_bins_on_the_published_bands_and_excludes_thin_ones() -> None:
    """The ruler, exercised — not merely declared in a protocol document.

    Two behaviours the protocol demands and the implementation did not have: bin on the seven
    published bands rather than ten deciles, and keep an underpowered bin **visible while
    excluding it from the reported figure**. Both are checked here on a sample built so that
    the difference is decidable rather than plausible.

    The thin bin here is three cases that all came out true, sitting in the *almost certain*
    band. Folded into a summary it reads as perfect calibration at the top of the scale, which
    is exactly the shape of noise a small corpus produces and exactly the shape a reader would
    over-trust.
    """
    forecasts = [0.30] * 40 + [0.70] * 40 + [0.97] * 3
    outcomes = [i < 12 for i in range(40)] + [i < 28 for i in range(40)] + [True] * 3

    report = published_band_decomposition(forecasts, outcomes)

    # Seven bands, not ten deciles: three populated here, and each at its own band.
    assert len(report.bins) == 3
    assert [b.lower for b in report.bins] == [0.20, 0.55, 0.95]

    thin = report.underpowered_bins
    assert len(thin) == 1
    assert thin[0].count == 3 and thin[0].lower == 0.95
    assert report.cases_excluded_as_underpowered == 3

    # The forecaster is exactly calibrated on the two real bands, so the reported figure is
    # zero — and it is zero only because the flattering three-case bin was left out of it.
    reported = report.reported_reliability
    assert reported is not None
    assert round(reported, 12) == 0.0
    assert report.reliability > reported  # the whole-sample figure still carries the thin bin

    # Visible, with its count, in what a human reads. Never merged into a neighbour.
    rendered = report.render()
    assert "3 case(s) in 1 bin(s)" in rendered
    assert f"n={MIN_BIN_COUNT}" in rendered

    # And no reportable figure at all when nothing is adequately populated: returning 0.0 there
    # would read as perfect calibration on the strength of five cases.
    starved = published_band_decomposition([0.9] * 5, [True] * 5)
    assert starved.reported_reliability is None
    assert "every bin is underpowered" in starved.render()


def test_every_dial_in_the_tree_is_covered_without_being_listed() -> None:
    """Five reviews, five bypasses, all the same defect. This is the answer to the class.

    The scanner had been moved to a derived module set while `engine_digest` still hashed a
    hand-written list, so the two disagreed about scope and a reviewer walked through the gap:
    `LINKAGE_PROPOSITION` in `calibration/harness.py` is *discovered* by one and *hashed* by
    neither. Flipping it from `ACTOR_ATTRIBUTION` to `OBSERVATION` took both reported
    false-match rates from 0.0 to 1.0 with every check green — the harness scores the attack as
    a different proposition, so it stops measuring the attack.

    Deriving the set from "modules that import the confidence machinery" does not fix it either:
    `core/provenance.py` imports none of it and holds `UNPLANTABLE_SOURCE_CLASSES`, the table
    that decides which evidence gets inverted.

    So the scope is now the whole tree and there is nothing to list. A dial is any module-level
    constant that is not pure text; it does not have to contain a digit, which is the assumption
    that failed four times.
    """
    assert not constants_drifted(), (
        "a dial moved, appeared or vanished somewhere in src/nemesis. If deliberate, regenerate "
        "CONSTANT_DIGESTS in its own commit with the reason"
    )

    covered = discovered_constants()

    # The three the reviewer named, plus the two of the same shape found alongside them.
    for reference in (
        "nemesis.calibration.harness:LINKAGE_PROPOSITION",
        "nemesis.calibration.harness:ACTIONABLE_BANDS",
        "nemesis.core.provenance:UNPLANTABLE_SOURCE_CLASSES",
        "nemesis.attribute.engine:DIMENSION_PROPOSITION",
        "nemesis.core.relationships:IDENTITY_ASSERTING_RELATIONS",
    ):
        assert reference in covered, f"{reference} escaped the freeze once already"
        assert reference in CALIBRATION_CONSTANTS, f"{reference} has no named diagnostic"

    # Coverage has to reach every plane, or the restructuring is theatre. These four modules
    # decide security properties rather than confidence figures, and each is a table of plain
    # strings — the shape that was waved through as prose until a review counted them.
    for reference in (
        "nemesis.collect.worker:FORBIDDEN_PREFIXES",
        "nemesis.effects.isolation:CREDENTIAL_PATHS",
        "nemesis.core.disclosure:INTERNAL_MARKERS",
        "nemesis.resolve.engine:EXCLUDED_CONCLUSIONS",
    ):
        assert reference in covered, f"{reference} is a dial, whatever its values are made of"

    assert len(frozen_modules()) == len(MODULE_DIGESTS)
    assert set(covered) == set(CONSTANT_DIGESTS)


def test_the_reported_bypass_is_closed() -> None:
    """The reviewer's reproduction, run as a test rather than trusted as a report.

    Flipping the harness's proposition class is the cheapest possible attack on this
    platform's headline number, and it left no trace anywhere. It leaves one now.
    """
    import nemesis.calibration.harness as harness

    original = harness.LINKAGE_PROPOSITION
    try:
        harness.LINKAGE_PROPOSITION = PropositionClass.OBSERVATION
        assert drifted() == ("nemesis.calibration.harness:LINKAGE_PROPOSITION",)
    finally:
        harness.LINKAGE_PROPOSITION = original

    # And the syntactic half, which catches an edit to the source rather than to the object.
    source = Path(harness.__file__).read_text(encoding="utf-8")
    tampered = source.replace(
        "LINKAGE_PROPOSITION = PropositionClass.ACTOR_ATTRIBUTION",
        "LINKAGE_PROPOSITION = PropositionClass.OBSERVATION",
    )
    assert tampered != source, "the reproduction no longer matches the source it attacks"
    assert (
        _dial_digest(tampered, "LINKAGE_PROPOSITION")
        != CONSTANT_DIGESTS["nemesis.calibration.harness:LINKAGE_PROPOSITION"]
    )

    assert drifted() == ()
    assert constants_drifted() == ()


def test_the_freeze_names_the_one_constant_that_moved() -> None:
    """A diagnostic that cannot tell one from thirty-seven is not a diagnostic.

    `drifted()` used to compare only the aggregate digest and, on failure, return **every**
    registered name. Technically documented; in practice a report a reader takes as thirty-seven
    constants having changed when one had — and the first question after a red freeze is always
    "which dial, and was it deliberate".
    """
    original = ADMIRALTY_RELIABILITY_WEIGHT[SourceReliability.USUALLY_RELIABLE]
    try:
        ADMIRALTY_RELIABILITY_WEIGHT[SourceReliability.USUALLY_RELIABLE] = 0.81
        assert drifted() == ("nemesis.core.confidence:ADMIRALTY_RELIABILITY_WEIGHT",)
    finally:
        ADMIRALTY_RELIABILITY_WEIGHT[SourceReliability.USUALLY_RELIABLE] = original

    assert drifted() == ()


def _dial_digest(source: str, name: str) -> str:
    """The digest `discovered_constants` would produce for one dial, from source text.

    Lets a test tamper with a *copy* of a module and check the freeze notices, without editing
    the tree or reloading anything.
    """
    import hashlib

    for node in ast.parse(source).body:
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            target, value = node.targets[0].id, node.value
        if target != name or value is None:
            continue
        dump = ast.dump(value, annotate_fields=True, include_attributes=False)
        return hashlib.sha256(f"nemesis.calibration.harness:{name}={dump}".encode()).hexdigest()[
            :16
        ]
    raise AssertionError(f"{name} not found in the source under test")


def test_the_freeze_is_the_same_number_in_every_process() -> None:
    """A freeze that fails at random is worse than no freeze at all.

    The values were folded with `repr()`, and a `frozenset` of enum members reprs in hash order
    — which CPython randomises per process. Registering the first categorical dials
    (`UNPLANTABLE_SOURCE_CLASSES`, `ACTIONABLE_BANDS`) therefore made the digest
    non-deterministic: measured across five seeds, five different digests. CI would have gone
    red for no reason roughly whenever it ran, and the lesson a reader takes from an
    intermittently red tripwire is that a red tripwire means nothing.

    Sets are canonicalised by sorting because their order carries no meaning; sequences are not,
    because theirs does.
    """
    seeds = ("0", "1", "12345")
    digests = {
        subprocess.run(
            [
                sys.executable,
                "-c",
                "from nemesis.calibration.freeze import freeze_digest;print(freeze_digest())",
            ],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
        ).stdout.strip()
        for seed in seeds
    }

    assert len(digests) == 1, (
        f"the freeze digest varies with the interpreter's hash seed: {digests}"
    )
    assert digests == {FROZEN_DIGEST}

    # And the property that makes it so, checked directly rather than only through the digest.
    scrambled = canonical(frozenset({"delta", "alpha", "charlie"}))
    assert scrambled == canonical(frozenset({"charlie", "delta", "alpha"}))
    assert scrambled.index("alpha") < scrambled.index("charlie") < scrambled.index("delta")
    # Sequences keep their order: reversing a tuple of bin edges is a real change.
    assert canonical((0.1, 0.2)) != canonical((0.2, 0.1))


def test_no_constant_is_classified_out_of_the_freeze() -> None:
    """The sixth instance, and the two attempts it took to stop classifying at all.

    First rule: skip a constant whose literals are all strings, because such a thing is a
    message. It let `LOW_PLANTING_COSTS` through — the table `_is_cheaply_plantable` reads, so
    deleting one word stops the attribution engine inverting cheaply plantable evidence, and the
    vector above asserting a planted group name lands at disbelief 0.30 would have started
    reporting *support* for whoever the adversary named.

    Second rule, narrower: a value that *constructs or looks up* is a table however much of it
    is text. A review then found that still excluded `FORBIDDEN_PREFIXES`, `CREDENTIAL_PATHS`,
    `INTERNAL_MARKERS` and `EXCLUDED_CONCLUSIONS` — four security tables of plain strings. Never
    a bypass, because the module digest covers them; but the claim that every dial was *named*
    was false, and a freeze that overstates its own reach is the defect this project rejects.

    There is no rule now. Every module-level upper-case assignment is a dial, and the cost of
    including the genuine prose is nothing: rewording a message already moves that module's
    syntax digest, so naming it too introduces no failure mode that did not exist.
    """
    covered = discovered_constants()

    for reference in (
        "nemesis.attribute.engine:LOW_PLANTING_COSTS",
        "nemesis.core.authorization:UNSIGNED_FIELDS",
        "nemesis.pilot.mediator:OBSERVABLE_STOP_CONDITIONS",
        "nemesis.evidence.vault:_EVIDENCE_ID_RE",
        "nemesis.audit.trail:_UNATTRIBUTABLE_ACTORS",
    ):
        assert reference in covered, f"{reference} is a table of strings, not a sentence"

    # Including the plain messages, which no longer need a judgement call about what they are.
    assert "nemesis.resolve.engine:PROPOSITION_TEMPLATE" in covered
    assert len(covered) == len(CONSTANT_DIGESTS)

    # Load-bearing: drop one word and the planted-evidence inversion stops firing.
    plantable = DeceptionAssessment(
        adversary_could_plant=True,
        planting_cost="trivial",
        reasoning="a string in a binary is written by whoever built the binary",
    )
    assert _is_cheaply_plantable(plantable)

    original = attribution_engine.LOW_PLANTING_COSTS
    try:
        attribution_engine.LOW_PLANTING_COSTS = frozenset({"low"})
        assert not _is_cheaply_plantable(plantable), (
            "removing 'trivial' no longer disables the inversion; this test is measuring "
            "the wrong table"
        )
        assert drifted() == ("nemesis.attribute.engine:LOW_PLANTING_COSTS",)
    finally:
        attribution_engine.LOW_PLANTING_COSTS = original

    assert drifted() == ()


# --- The whole class, replayed -----------------------------------------------

HISTORICAL_BYPASSES: tuple[tuple[str, str, object], ...] = (
    (
        "nemesis.core.confidence:BAND_RANGES",
        "a table, when the scanner only understood scalars",
        {**BAND_RANGES, ConfidenceBand.LIKELY: (0.60, 0.80)},
    ),
    (
        "nemesis.core.relationships:METHOD_RELIABILITY_CEILING",
        "a table in a module the hand-written list did not name",
        {**METHOD_RELIABILITY_CEILING, PivotMethod.LINGUISTIC_SIMILARITY: 0.9},
    ),
    (
        "nemesis.resolve.signals:CORRELATION_GROUP_OF",
        "categorical: no digits at all, and it decides whether signals compound",
        None,  # filled in below; needs the module's own enums
    ),
    (
        "nemesis.slice.scenario:DARK_BAZAAR_PERSONA_POPULATION",
        "the base-rate denominator, in a module reachable by no import rule",
        400,
    ),
    (
        "nemesis.calibration.harness:LINKAGE_PROPOSITION",
        "discovered by the scanner, hashed by neither digest",
        PropositionClass.OBSERVATION,
    ),
    (
        "nemesis.attribute.engine:LOW_PLANTING_COSTS",
        "a lookup table of strings, waved through as prose",
        frozenset({"low"}),
    ),
)
"""Every bypass ever found here, with the value that demonstrated it.

Kept as data rather than prose because a list of past failures in a document is a story, and a
list of past failures in a parametrised test is a regression suite.
"""


@pytest.mark.parametrize(("reference", "why", "replacement"), HISTORICAL_BYPASSES)
def test_every_bypass_ever_found_here_is_named_now(
    reference: str, why: str, replacement: object
) -> None:
    """Six bypasses, six different shapes, one defect. This is the assertion that they are shut.

    Each of these once moved a published confidence figure with every check green. Each is
    replayed against the live registry, and the freeze must not merely go red — it must **name
    the constant**, because "something moved" sends a reader to read thirty-seven diffs and
    "`LOW_PLANTING_COSTS` moved" sends them to the one that matters.
    """
    module_name, _, attribute = reference.partition(":")
    module = importlib.import_module(module_name)
    original = getattr(module, attribute)

    if replacement is None:
        # The categorical case, built from the module's own enums rather than hard-coded: move
        # the first signal into some *other* correlation group. Which one does not matter — what
        # matters is that a signal stops compounding as independent evidence and starts
        # averaging inside a dependence group, which changed a published band once.
        moved = dict(original)
        first = next(iter(moved))
        moved[first] = next(group for group in moved.values() if group != moved[first])
        replacement = moved

    assert replacement != original, f"the replacement for {reference} changes nothing"

    try:
        setattr(module, attribute, replacement)
        assert drifted() == (reference,), (
            f"{reference} moved and the freeze did not name it — {why}"
        )
    finally:
        setattr(module, attribute, original)

    assert drifted() == ()


SYNTACTIC_BYPASSES: tuple[tuple[str, str, str, str], ...] = (
    (
        "an inline evidence weight, in a function body",
        "nemesis/pursuit/materialize.py",
        "supporting = 6.0 if claim.kind",
        "supporting = 20.0 if claim.kind",
    ),
    (
        "the selectivity-to-evidence multiplier, in the same body",
        "nemesis/pursuit/materialize.py",
        "supporting=weight * 10.0",
        "supporting=weight * 12.0",
    ),
    (
        "pure logic: publishing the pre-margin opinion externally",
        "nemesis/attribute/disclosure.py",
        "opinion=assessment.opinion,",
        "opinion=assessment.evidential_opinion or assessment.opinion,",
    ),
    (
        "a dataclass field default, which is a class attribute and not a constant",
        "nemesis/calibration/generator.py",
        "true_signal_strength: float = 0.72",
        "true_signal_strength: float = 0.98",
    ),
    (
        "case-shape logic in the generator, touching no value the report prints",
        "nemesis/calibration/generator.py",
        "rng.randint(2, 5)",
        "rng.randint(3, 9)",
    ),
)
"""Bypasses that no digest of *values* can catch, however complete that digest is.

Each was demonstrated end to end before it was closed. The first moves the GLASS ANVIL
attribution's ORGANIZATION dimension from *unlikely* (0.4470) to *likely* (0.5873) — the
direction reverses — while all four checks stayed clean and all 913 tests passed. The third
touches no constant at all and moves the band on the **external deliverable**, the artefact
handed to a provider or a regulator.
"""


@pytest.mark.parametrize(("why", "relative", "before", "after"), SYNTACTIC_BYPASSES)
def test_a_value_digest_is_not_enough_and_the_tree_digest_covers_the_rest(
    why: str, relative: str, before: str, after: str
) -> None:
    """Instances 7 and 8: the scope was complete over modules and not over *places in* them.

    Every mechanism up to this point read module-level assignments. A bare `6.0` inside a
    function body is not one, a dataclass field default is not one, and a two-line change that
    publishes a different attribute is not a value at all. `engine_digest` was narrowed to
    fourteen modules on the argument that hashing all logic everywhere would fire too often to
    stay armed — and an adversarial sweep went through that argument twice within the hour.

    Seven bypasses, seven narrowings. The scope is now the whole tree, and the churn is the
    price rather than a thing to be optimised away.

    Tampering happens on a **copy** of the source through the same `normalised_source` the
    digest uses; a test that reimplemented the normalisation could agree with itself while
    disagreeing with the code.
    """
    source = (SRC / relative).read_text(encoding="utf-8")
    assert before in source, f"the reproduction no longer matches {relative}"

    tampered = _digest_of(normalised_source(source.replace(before, after, 1)))

    assert tampered != MODULE_DIGESTS[relative], f"the freeze does not see {why}"


def test_rewording_prose_does_not_break_the_tree_digest() -> None:
    """The other half, and the half that decides whether the tripwire stays armed.

    A digest that fired on every reworded docstring would be updated as a reflex within a week,
    and a reflex update is indistinguishable from waving through a real drift. This is why the
    digest is over a normalised syntax tree and not over the bytes.
    """
    relative = "nemesis/pursuit/materialize.py"
    source = (SRC / relative).read_text(encoding="utf-8")
    original = "Build entities and relationships from connector output."
    assert original in source

    reworded = source.replace(original, "Build the entities and edges from connector output.", 1)

    assert _digest_of(normalised_source(reworded)) == MODULE_DIGESTS[relative]


def test_the_refreeze_cannot_read_a_stale_bytecode_cache(tmp_path: Path) -> None:
    """A refreeze that appears to work and does not is worse than one that fails.

    CPython validates a `.pyc` against the source's **size and mtime truncated to whole
    seconds**. Every rewrite the freeze performs swaps one 64-character digest for another, so
    the size never changes, and a regeneration landing in the same second as the previous one is
    silently ignored. Observed once on this repository: the source read `d8ee5a…`, the imported
    module read `cd7eb0…`, and a test failed against a value present in no file.

    Dropping `freeze.py`'s own cache was the first fix and was not enough — a review pointed out
    that `observed_values()` imports **every other module** in the registry, each with a cache of
    its own. Demonstrated on the real tree before this was written: with a poisoned cache, an
    ordinary interpreter reported `DECEPTION_BASE_RATE` as 0.25 while the source said 0.99, and
    the freeze would have frozen the stale value.

    Reproduced here on a throwaway module rather than the real one, so the test cannot corrupt
    the tree it is protecting.
    """
    module = tmp_path / "a_dial.py"
    module.write_text("DIAL = 0.25\n", encoding="utf-8")
    py_compile.compile(str(module), doraise=True)
    before = module.stat()

    module.write_text("DIAL = 0.99\n", encoding="utf-8")  # same length, so size cannot betray it
    os.utime(module, (before.st_atime, before.st_mtime))

    read = "import a_dial; print(a_dial.DIAL)"
    environment = {"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}

    stale = subprocess.run(  # noqa: S603  (this interpreter, a literal snippet, no shell)
        [sys.executable, "-c", read],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
    ).stdout.strip()
    assert stale == "0.25", (
        "the stale-cache hazard did not reproduce; if CPython's invalidation changed, this test "
        "is no longer measuring anything and the isolation below is untested rather than proven"
    )

    isolated = subprocess.run(  # noqa: S603  (same, with the cache relocated)
        [sys.executable, "-c", read],
        capture_output=True,
        text=True,
        check=True,
        env={**environment, "PYTHONPYCACHEPREFIX": str(tmp_path / "fresh-cache")},
    ).stdout.strip()
    assert isolated == "0.99"

    # And the regeneration script is the thing that must set it.
    script = (SRC.parent / "scripts/refreeze_calibration.py").read_text(encoding="utf-8")
    assert "PYTHONPYCACHEPREFIX" in script
    assert "TemporaryDirectory" in script


def test_a_module_that_did_not_exist_before_is_enumerated(tmp_path: Path) -> None:
    """The ninth instance, and the second time this exact function was wrong.

    `frozen_modules()` took a `tree` argument and **ignored it**, still globbing the real
    package and still excluding this module by absolute path. Everything downstream then read
    the *copy* at those real relative paths, so tampering with an existing file worked — which
    is the only thing the tests did — while a module that exists only in the copy was never
    enumerated at all:

        new module enumerated: False
        constant drift: ()
        module drift: ()

    The edit meant to introduce the parameter had silently failed to match, and nothing caught
    it, because the case exercising the control coincided with the case it got wrong. That is
    the shape of every defect in this file's history.

    Adding a whole module is also the cheapest way to smuggle in a dial — no diff to any
    existing file — so this is worth a test on its own merits and not only as a regression.
    """
    package = tmp_path / "nemesis"
    shutil.copytree(SRC / "nemesis", package)
    (package / "new_module.py").write_text("A_SMUGGLED_DIAL = 0.99\n", encoding="utf-8")

    assert "nemesis/new_module.py" in frozen_modules(tree=package)
    assert constants_drifted(tree=package) == ("nemesis.new_module:A_SMUGGLED_DIAL",)
    assert engine_drifted(tree=package) == ("nemesis/new_module.py",)

    # `SELF` is excluded by *relative* path, as its docstring claims. By absolute path the
    # copy's own `freeze.py` would be included, and every test against a copied tree would
    # drown in several hundred spurious constants.
    assert SELF not in frozen_modules(tree=package)
    assert SELF in {f"nemesis/{p.relative_to(package).as_posix()}" for p in package.rglob("*.py")}


def test_every_scoped_function_actually_reads_the_tree_it_is_handed(tmp_path: Path) -> None:
    """The root cause, checked directly: a parameter accepted and then ignored.

    `frozen_modules` was not special. Six functions take `tree`, each threads it to the next,
    and any one of them silently dropping it leaves the others reading a mixture of two trees —
    which is precisely how the bug above stayed invisible, since the mixture agrees with itself
    for every file that exists in both.

    So each is handed a copy containing exactly one thing the real tree does not, and must
    report it. Cheaper than trusting six call sites to keep threading an argument nobody checks.
    """
    package = tmp_path / "nemesis"
    shutil.copytree(SRC / "nemesis", package)
    (package / "smuggled.py").write_text("SMUGGLED = 1.0\n", encoding="utf-8")

    assert "nemesis/smuggled.py" in frozen_modules(tree=package)
    assert "nemesis.smuggled:SMUGGLED" in discovered_constants(tree=package)
    assert "nemesis/smuggled.py" in module_digests(tree=package)
    assert constants_drifted(tree=package) == ("nemesis.smuggled:SMUGGLED",)
    assert engine_drifted(tree=package) == ("nemesis/smuggled.py",)
    assert engine_digest(tree=package) != engine_digest()

    # And the real tree is untouched by any of it, which is the whole point of taking a copy.
    assert constants_drifted() == ()
    assert engine_drifted() == ()


def test_no_function_here_accepts_a_tree_and_ignores_it() -> None:
    """The general form of the ninth instance, checked statically.

    The test above catches the six functions that are threaded together today. It would not
    catch a *seventh* added later that takes `tree`, forgets to use it, and quietly falls back
    to the real package — which is exactly what happened, and stayed invisible because a tree
    read half from a copy and half from the original agrees with itself for every file present
    in both.

    An argument that exists and is never read is a promise in a signature. This asks the syntax
    tree of this module the one question that catches it, whatever the function does.
    """
    source = (SRC / "nemesis/calibration/freeze.py").read_text(encoding="utf-8")

    ignored = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.FunctionDef):
            continue
        parameters = {argument.arg for argument in node.args.args + node.args.kwonlyargs}
        if "tree" not in parameters:
            continue
        body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
        if "id='tree'" not in body:
            ignored.append(node.name)

    assert ignored == [], (
        f"{ignored} take a `tree` argument and never read it, so they silently fall back to the "
        "real package while their callers believe they are looking at a copy"
    )
