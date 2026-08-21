"""The corpus apparatus, attacked rather than demonstrated.

A blind corpus is worth exactly as much as its blindness. Every test here is an attempt to see
an answer without unsealing it, or to produce a good score without answering — because the
failure this guards against is not dishonesty. It is that somebody who knows the answers
unconsciously builds cases the engine happens to handle, and the corpus quietly becomes a mirror
that reports the mirror's own shape as a result.

None of this makes the figures calibration. The cases are synthetic and the label says so. What
these tests pin is that the apparatus cannot cheat, which is the part worth having before
milestone 3 spends anything on infrastructure.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from nemesis.calibration.corpus import (
    CaseCategory,
    CaseLabel,
    Corpus,
    CorpusError,
    PopulationClaim,
    Prediction,
    build_corpus,
    score,
)
from nemesis.calibration.generator import CaseKind
from nemesis.core.confidence import ConfidenceBand, band_of
from nemesis.core.fusion import fuse
from nemesis.core.proposition import PropositionClass

pytestmark = pytest.mark.invariant

AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

POPULATION = PopulationClaim(
    describes="synthetic persona-linkage cases probing six evidence constructions",
    excludes="real adversary tradecraft, real infrastructure, and any real population",
    ground_truth_rule="the generator recorded what it built; no human adjudicated anything",
    generated_by="nemesis.calibration.generator",
)


def _corpus(seed: int = 20260821, per_kind: int = 20) -> Corpus:
    return build_corpus(population=POPULATION, seed=seed, per_kind=per_kind)


def _honest_predictions(corpus: Corpus) -> list[Prediction]:
    """An evaluator that sees `CaseInput` and nothing else, as the type demands."""
    predictions = []
    for item in corpus.inputs:
        result = fuse(item.sources, proposition=PropositionClass.SHARED_ORIGIN)
        band = band_of(result.opinion)
        refused = band is ConfidenceBand.INSUFFICIENT_BASIS
        predictions.append(
            Prediction(
                case_id=item.case_id,
                probability=None if refused else result.opinion.projected_probability,
                band=band,
            )
        )
    return predictions


# --- The blindness -----------------------------------------------------------


def test_the_evaluator_is_handed_nothing_that_carries_an_answer() -> None:
    """Structural, not a promise. There is no argument through which a label could arrive.

    A protocol that asked people to look away would be worth nothing. `CaseInput` carries the
    evidence and the population it was drawn from — what a real investigation would also have —
    and carries the truth, the category and the construction nowhere.
    """
    corpus = _corpus()
    exposed = {field.name for field in dataclasses.fields(corpus.inputs[0])}

    assert exposed == {"case_id", "sources", "candidate_population"}
    for forbidden in ("truth", "category", "attack_class", "distinct_real_origins", "kind"):
        assert forbidden not in exposed
        assert not hasattr(corpus.inputs[0], forbidden)


def test_neither_the_identifier_nor_the_order_says_anything() -> None:
    """The cheapest way to fake a good score, closed by shuffling before naming.

    An identifier of `laundered-0007` would hand the evaluator the attack class in the one field
    it is allowed to read, and grouping the categories would do the same through position. So an
    evaluator that uses *only* the identifier and the ordering is run here, and has to land at
    chance.

    Checked against the categories rather than the constructions because that is what an attacker
    would want: knowing a case is linkable is worth more than knowing how it was built.
    """
    corpus = _corpus()
    labels = corpus.sealed.unseal(actor="test", reason="verify the leak is closed", at=AT)

    assert all(item.case_id == f"case-{index:05d}" for index, item in enumerate(corpus.inputs))

    # A cheat that guesses from position: "the first half is linkable".
    half = len(corpus.inputs) // 2
    from_position = sum(
        (index < half) is (labels[item.case_id].category is CaseCategory.LINKABLE)
        for index, item in enumerate(corpus.inputs)
    ) / len(corpus.inputs)

    # A cheat that guesses from the identifier's digits.
    from_identifier = sum(
        (int(item.case_id.rsplit("-", 1)[1]) % 2 == 0)
        is (labels[item.case_id].category is CaseCategory.LINKABLE)
        for item in corpus.inputs
    ) / len(corpus.inputs)

    for name, hit_rate in (("position", from_position), ("identifier", from_identifier)):
        assert 0.35 < hit_rate < 0.65, (
            f"guessing the category from the {name} alone scored {hit_rate:.2f}; the corpus is "
            "leaking through the one field the evaluator is allowed to read"
        )


def test_construction_facts_stay_in_the_label() -> None:
    """`distinct_real_origins` is the difference between laundering and honest corroboration.

    A laundered case has one real origin behind many sources; an honest one has many. An
    evaluator that could read it would score perfectly while knowing nothing about evidence, so
    it lives in the sealed label and the input does not carry it in any form.
    """
    corpus = _corpus()
    labels = corpus.sealed.unseal(actor="test", reason="confirm the field exists there", at=AT)

    origins: dict[CaseKind, set[int]] = {}
    for label in labels.values():
        origins.setdefault(label.attack_class, set()).add(label.distinct_real_origins)

    # The three that carry the whole meaning of the field.
    assert origins[CaseKind.LAUNDERED] == {1}, "one artifact behind however many sources"
    assert origins[CaseKind.NO_EVIDENCE] == {0}, "nobody looked, so nothing underlies it"
    assert min(origins[CaseKind.GENUINE_INDEPENDENT]) > 1, "several facts, genuinely separate"

    assert not any(hasattr(item, "distinct_real_origins") for item in corpus.inputs)


# --- The seal ----------------------------------------------------------------


def test_opening_the_answers_is_counted_and_attributed() -> None:
    """§5: the number of times it has been opened is reported alongside any score from it.

    The moment a sealed set informs a change it stops being a test set and becomes a training
    set with a misleading name. Nothing here prevents that. What it does is make the count
    impossible to leave out of the report.
    """
    corpus = _corpus()
    assert corpus.sealed.opened_count == 0

    corpus.sealed.unseal(actor="analyst-a", reason="first evaluation", at=AT)
    corpus.sealed.unseal(actor="analyst-b", reason="second look after a change", at=AT)

    assert corpus.sealed.opened_count == 2
    assert [record.actor for record in corpus.sealed.unseal_log] == ["analyst-a", "analyst-b"]
    assert corpus.sealed.unseal_log[1].reason == "second look after a change"

    evaluation = score(
        corpus, _honest_predictions(corpus), actor="analyst-c", reason="scoring", at=AT
    )
    assert evaluation.labels_opened == 3
    assert "seal opened    3x" in evaluation.render()
    assert "every figure below is suspect" in evaluation.render()


def test_unsealing_without_a_reason_is_refused() -> None:
    """An unattributed opening is an opening nobody can weigh afterwards."""
    corpus = _corpus()

    with pytest.raises(CorpusError, match="named actor and a stated reason"):
        corpus.sealed.unseal(actor="  ", reason="because", at=AT)
    with pytest.raises(CorpusError, match="named actor and a stated reason"):
        corpus.sealed.unseal(actor="analyst", reason="", at=AT)

    assert corpus.sealed.opened_count == 0


def test_the_digest_identifies_the_answers_without_revealing_them() -> None:
    """What §5 rests on when it says a change after opening invalidates every figure."""
    first = _corpus(seed=1)
    same = _corpus(seed=1)
    other = _corpus(seed=2)

    assert first.sealed.digest == same.sealed.digest
    assert first.digest == same.digest
    assert first.sealed.digest != other.sealed.digest

    # And it moves when an answer moves, which is the only property that matters.
    labels = dict(first.sealed.unseal(actor="test", reason="tamper with a copy", at=AT))
    victim = next(
        case_id for case_id, label in labels.items() if label.category is CaseCategory.LINKABLE
    )
    before = first.sealed.digest
    labels[victim] = dataclasses.replace(labels[victim], truth=not labels[victim].truth)
    tampered = type(first.sealed)(_labels=labels)

    assert tampered.digest != before


# --- The grading -------------------------------------------------------------


def test_an_ambiguous_case_cannot_carry_a_true_answer() -> None:
    """The category most corpora omit, and the reason this one has refusal machinery.

    Giving it a truth value would let it back into discrimination, where scoring a case with no
    true answer as a failure rewards guessing.
    """
    with pytest.raises(CorpusError, match="ambiguous"):
        CaseLabel(
            case_id="case-00000",
            category=CaseCategory.AMBIGUOUS,
            attack_class=CaseKind.NO_EVIDENCE,
            truth=True,
            distinct_real_origins=1,
        )

    with pytest.raises(CorpusError, match="needs a truth value"):
        CaseLabel(
            case_id="case-00001",
            category=CaseCategory.LINKABLE,
            attack_class=CaseKind.GENUINE_INDEPENDENT,
            truth=None,
            distinct_real_origins=3,
        )


def test_a_partial_prediction_set_is_refused() -> None:
    """Dropping the hard cases is the cheapest way to a good score and the hardest to see."""
    corpus = _corpus()
    predictions = _honest_predictions(corpus)

    with pytest.raises(CorpusError, match="missing"):
        score(corpus, predictions[:-5], actor="a", reason="r", at=AT)

    with pytest.raises(CorpusError, match="two predictions for one case"):
        score(corpus, [*predictions, predictions[0]], actor="a", reason="r", at=AT)


def test_declining_is_never_counted_as_being_wrong() -> None:
    """THE ONE THIS FILE EXISTS FOR, and it was wrong first.

    The first version of the robustness table returned a single accuracy per attack class and
    counted a decline on a decidable case as incorrect. It scored `laundered` at **0.0000**, and
    the truth was the opposite: the engine declined on all forty and reached an actionable band
    on none, which is the anti-laundering defence working exactly as designed. Anyone reading
    that report would have concluded the defence was broken.

    Conflating "declined" with "wrong" is a strange thing to do anywhere; in a platform whose
    thesis is that declining is a correct answer it is self-refuting. Three columns, and the
    third is the only one that means the engine was actually wrong.
    """
    corpus = _corpus(per_kind=20)
    evaluation = score(corpus, _honest_predictions(corpus), actor="a", reason="r", at=AT)

    by_class = {row.attack_class: row for row in evaluation.outcomes_by_attack_class}
    assert set(by_class) == set(CaseKind)
    assert all(row.count == 20 for row in by_class.values())

    laundered = by_class[CaseKind.LAUNDERED]
    assert laundered.declined == 20, "the engine no longer declines on every laundered case"
    assert laundered.wrong == 0
    assert laundered.correct == 0

    # And the refusal on a genuinely undecidable case is a *correct* answer, not a decline.
    nothing_to_go_on = by_class[CaseKind.NO_EVIDENCE]
    assert nothing_to_go_on.correct == 20
    assert nothing_to_go_on.wrong == 0

    rendered = evaluation.render()
    assert "correct / declined / wrong" in rendered
    assert "Declining is not being wrong" in rendered


def test_both_halves_of_the_refusal_rate_are_reported_together() -> None:
    """Either alone rewards a system that never answers, or one that never declines."""
    corpus = _corpus()
    evaluation = score(corpus, _honest_predictions(corpus), actor="a", reason="r", at=AT)

    assert evaluation.refusal_recall == 1.0, "it no longer declines on every ambiguous case"
    assert evaluation.refusal_precision is not None
    assert evaluation.refusal_precision < 1.0

    # The precision figure counts every decline outside `ambiguous` as imprecise, which is the
    # protocol's formula and is misleading on its own: most of those declines land on
    # adversarially linked cases, where declining is the defensible answer. The breakdown is
    # reported beside it so the number can be read rather than believed.
    landed = dict(evaluation.refusals_by_category)
    assert landed[CaseCategory.AMBIGUOUS] > 0
    assert landed[CaseCategory.ADVERSARIALLY_LINKED] > 0
    assert "declining on an adversarially linked case is defensible" in evaluation.render()


def test_the_ambiguous_class_is_excluded_from_discrimination() -> None:
    """Scoring a case with no true answer as a discrimination failure rewards guessing."""
    corpus = _corpus()
    evaluation = score(corpus, _honest_predictions(corpus), actor="a", reason="r", at=AT)

    assert evaluation.discrimination_auc is not None
    assert 0.0 <= evaluation.discrimination_auc <= 1.0

    labels = corpus.sealed.unseal(actor="test", reason="count the classes", at=AT)
    scoreable = sum(
        1 for case_id, label in labels.items() if label.category is not CaseCategory.AMBIGUOUS
    )
    assert evaluation.reliability is not None
    assert evaluation.reliability.sample_size <= scoreable


def test_a_population_claim_must_say_what_it_does_not_cover() -> None:
    """The half every corpus author drops.

    Anyone can describe what they built. Almost nobody writes down what it says nothing about,
    and a score presented without that is a number wearing a suit.
    """
    for missing in ("describes", "excludes", "ground_truth_rule", "generated_by"):
        fields = {
            "describes": "x",
            "excludes": "y",
            "ground_truth_rule": "z",
            "generated_by": "w",
        }
        fields[missing] = "   "
        with pytest.raises(CorpusError, match=missing):
            PopulationClaim(**fields)


def test_the_report_refuses_to_call_itself_calibration() -> None:
    """The label this project would most easily over-claim, pinned in the output itself."""
    corpus = _corpus()
    rendered = score(corpus, _honest_predictions(corpus), actor="a", reason="r", at=AT).render()

    assert "WHAT THIS IS NOT" in rendered
    assert "Not calibration" in rendered
    assert "REQUIRES_EXTERNAL_DATA" in rendered
    # The four things §6 says a result cannot be without.
    assert "POPULATION" in rendered
    assert "ground truth" in rendered
    assert "corpus " in rendered
    assert "seal opened" in rendered
