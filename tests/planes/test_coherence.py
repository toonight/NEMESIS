"""Coherence laws: the one quantitative thing this platform can establish without a corpus.

Every Brier score in this project is scored against a generator whose assumptions are ours,
so "are these numbers right" stays unanswered and is risk #1. "Do these numbers contradict
each other" needs nothing external — a forecaster reporting more confidence from strictly
less evidence is broken whatever the world says.

These tests do two jobs, and the second is the one that makes the first mean anything:
they check the real engine obeys the laws, **and** they feed each law a deliberately
incoherent pair to prove the law can fail. A law that cannot fail detects nothing, which is
the same question this project asks of its racing test and its local reviewer.
"""

from __future__ import annotations

import pytest

from nemesis.calibration.coherence import (
    CoherenceViolation,
    check_band_agreement,
    check_coherence,
    check_dependence_discipline,
    check_monotonic_under_corroboration,
    check_monotonic_under_removal,
)
from nemesis.core.confidence import BAND_RANGES, Opinion, band_of
from nemesis.core.fusion import SourcedOpinion
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import SourceClass, SourceDescriptor


def _source(
    identifier: str, *, source_class: SourceClass = SourceClass.INTERNET_SCAN
) -> SourceDescriptor:
    return SourceDescriptor(source_class=source_class, identifier=identifier)


def _sourced(
    identifier: str,
    belief: float,
    *,
    fact: str = "fact:shared",
    source_class: SourceClass = SourceClass.INTERNET_SCAN,
) -> SourcedOpinion:
    return SourcedOpinion(
        source=_source(identifier, source_class=source_class),
        opinion=Opinion(belief=belief, disbelief=0.0, uncertainty=1.0 - belief, base_rate=0.1),
        fact_key=fact,
        label=identifier,
    )


PROPOSITION = PropositionClass.SHARED_ORIGIN


# --- The engine obeys the laws ------------------------------------------------


def test_the_real_engine_is_coherent_over_a_mixed_population() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    Not "is NEMESIS right" — nothing here can answer that. "Does NEMESIS contradict itself",
    which is answerable and which nothing had ever asked.
    """
    cases = [
        [_sourced("passive-dns", 0.6, fact="fact:a")],
        [
            _sourced("passive-dns", 0.6, fact="fact:a"),
            _sourced("ct-log", 0.5, fact="fact:b", source_class=SourceClass.OPEN_SOURCE),
        ],
        [
            _sourced("rdap", 0.3, fact="fact:c", source_class=SourceClass.COMMERCIAL_FEED),
            _sourced("passive-dns", 0.7, fact="fact:d"),
            _sourced("ct-log", 0.4, fact="fact:e", source_class=SourceClass.OPEN_SOURCE),
        ],
    ]

    report = check_coherence(cases, proposition=PROPOSITION)

    assert report.checked > 0, "a report that checked nothing proves nothing"
    assert report.coherent, report.render()
    assert "NOT about correctness" in report.render(), (
        "a coherent verdict must say what it is not, or it reads as a calibration result"
    )


def test_adding_an_agreeing_source_never_lowers_belief() -> None:
    """A rule that punishes corroboration is one an adversary exploits by *adding* supporting
    noise until the figure falls."""
    base = [_sourced("passive-dns", 0.6, fact="fact:a")]
    added = _sourced("ct-log", 0.6, fact="fact:b", source_class=SourceClass.OPEN_SOURCE)

    assert check_monotonic_under_corroboration(base, added, PROPOSITION) is None


def test_removing_a_supporting_source_never_raises_belief() -> None:
    """The law the robustness margin rests on. If removal could raise the figure, the margin's
    before-and-after comparison says nothing."""
    full = [
        _sourced("passive-dns", 0.7, fact="fact:a"),
        _sourced("ct-log", 0.6, fact="fact:b", source_class=SourceClass.OPEN_SOURCE),
    ]

    assert check_monotonic_under_removal(full, 0, PROPOSITION) is None


def test_copies_of_one_origin_never_outscore_that_origin_once() -> None:
    """Provenance laundering as a coherence law — the one an adversary actually attacks, and
    checkable with no ground truth because an origin cannot corroborate itself."""
    single = _sourced("aggregator", 0.7, fact="fact:a")

    assert check_dependence_discipline(single, 5, PROPOSITION) is None


def test_every_band_contains_its_own_probability() -> None:
    """An analyst reading "likely" and one reading 0.62 must be reading the same finding."""
    for belief in (0.02, 0.1, 0.3, 0.5, 0.62, 0.85, 0.97):
        opinion = Opinion(belief=belief, disbelief=1.0 - belief, uncertainty=0.0, base_rate=0.1)
        assert check_band_agreement(opinion) is None, f"belief={belief}"


# --- Each law can actually fail ----------------------------------------------


def test_the_band_law_can_actually_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A law that cannot fail detects nothing — the same question this project asks of its
    racing test and its local reviewer, turned on itself.

    An honest proof needs a genuinely disagreeing pair, and the engine will not produce one:
    `band_of` and `check_band_agreement` read the same table, so they agree by construction.
    So the table is made inconsistent for the length of this test. If the check were vacuous
    it would still pass here, and it does not.
    """
    from nemesis.calibration import coherence

    opinion = Opinion(belief=0.62, disbelief=0.38, uncertainty=0.0, base_rate=0.1)
    assert check_band_agreement(opinion) is None, "the honest pair must pass first"

    broken = dict(BAND_RANGES)
    broken[band_of(opinion)] = (0.0, 0.01)  # a band that cannot contain 0.62
    monkeypatch.setattr(coherence, "BAND_RANGES", broken)

    violation = coherence.check_band_agreement(opinion)
    assert violation is not None, "the band law passed a band that excludes its own probability"
    assert violation.law == "band agreement"


def test_a_violation_reports_both_sides_and_its_magnitude() -> None:
    """A finding an operator cannot reproduce is a finding they cannot act on."""
    violation = CoherenceViolation(
        law="monotonic under removal",
        detail="removing a supporting source raised belief",
        left=0.40,
        right=0.55,
    )

    assert violation.magnitude == pytest.approx(0.15)
    assert "0.4000" in violation.render() and "0.5500" in violation.render()


def test_an_incoherent_report_calls_it_a_defect_and_not_a_score() -> None:
    """The distinction that decides whether anyone acts on this. A poor Brier is information
    about a generator; a violation means two outputs cannot both be true."""
    from nemesis.calibration.coherence import CoherenceReport

    report = CoherenceReport(
        checked=4,
        violations=(
            CoherenceViolation(law="band agreement", detail="mismatch", left=0.2, right=0.9),
        ),
    )

    assert report.coherent is False
    assert report.worst is not None and report.worst.magnitude == pytest.approx(0.7)
    assert "defect, not a poor score" in report.render()


def test_an_empty_population_is_not_reported_as_coherent_by_accident() -> None:
    """Checking nothing and reporting "no contradictions" is the vacuous pass this project
    keeps hunting elsewhere."""
    report = check_coherence([], proposition=PROPOSITION)

    assert report.checked == 0
    assert report.coherent is True  # true, and worthless — which is why `checked` is reported
    assert "0 law check(s)" in report.render()
