"""A blind corpus: the protocol's §2, §4 and §5 made mechanical, before §3 costs anything.

WHAT THIS IS, AND WHAT IT IS NOT

`docs/calibration/PROTOCOL.md` describes six milestones. Three of them — separate roles for
generation, labelling and evaluation; a sealed test set; written-down categories and a
ground-truth rule — are *process*, and process can be proven wrong long before anybody rents a
host. This module proves the process.

It does **not** produce calibration, and no label here says otherwise. The cases are synthetic:
outcomes come from a generator whose assumptions we chose, so a score against them measures
agreement with those assumptions. Real calibration needs milestone 3 — controlled operations on
infrastructure we own — and stays `REQUIRES_EXTERNAL_DATA`. What is `IMPLEMENTED` is the
apparatus a real corpus would be poured into, and the guarantee that the apparatus cannot cheat.

THE ONE PROPERTY THAT MATTERS

**The evaluator cannot see the answers**, and not because it promises not to. `CaseInput` does
not carry the truth, the category, or how the case was built; `Corpus.inputs` is the only thing
an evaluator is handed, and the labels sit behind :class:`SealedLabels`, which yields them only
through `unseal()` — an act that is counted and logged. A protocol that asked people to look
away would be worth nothing, because the failure it guards against is not dishonesty. It is that
somebody who knows the answer unconsciously builds cases the engine happens to handle, and the
corpus quietly becomes a mirror.

Three leaks were closed deliberately, because each would have made the blindness decorative:

- **Ordering.** Cases are shuffled before identifiers are assigned, so position carries nothing.
- **Identifiers.** They are sequential and opaque. A `case_id` of `laundered-0007` would hand
  the evaluator the attack class in the one field it is allowed to read.
- **Construction facts.** `distinct_real_origins` — how many genuinely independent facts underlie
  a case — is the difference between a laundered case and an honest one. It lives in the label,
  never in the input. An evaluator that could read it would score perfectly while knowing
  nothing.

WHAT SEALING MEANS HERE, PRECISELY

`SealedLabels` is tamper-*evident*, not encrypted, and it is not wired to the platform's audit
trail — that plane is asynchronous and lives behind a different boundary. It holds a digest of
the labels, counts every unsealing, and keeps an append-only record of who opened it and why.
That satisfies what §5 asks for: opening is an event, and the count is reported beside any score
drawn from the set. It does not stop somebody determined to read the object in a debugger. Both
of those sentences are the honest description; the second is the reason this is a proof of
concept and not a control.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final

from nemesis.calibration.generator import CaseGenerator, CaseKind, GeneratorAssumptions
from nemesis.calibration.scoring import (
    MIN_BIN_COUNT,
    BrierDecomposition,
    discrimination_auc,
    published_band_decomposition,
)
from nemesis.core.confidence import ConfidenceBand
from nemesis.core.fusion import SourcedOpinion

__all__ = [
    "AMBIGUOUS_HAS_NO_TRUE_ANSWER",
    "CaseCategory",
    "CaseInput",
    "CaseLabel",
    "ClassOutcome",
    "Corpus",
    "CorpusError",
    "CorpusEvaluation",
    "PopulationClaim",
    "Prediction",
    "SealedLabels",
    "UnsealRecord",
    "build_corpus",
    "score",
]


class CorpusError(RuntimeError):
    """A corpus was built, read or scored in a way that would invalidate its figures."""


AMBIGUOUS_HAS_NO_TRUE_ANSWER: Final = (
    "An ambiguous case has no true answer, so it is excluded from discrimination and graded "
    "only on whether the engine declined. Scoring it as a discrimination failure would reward "
    "guessing, which is the behaviour this platform exists to refuse."
)


class CaseCategory(StrEnum):
    """What is true about a case — the axis a label records.

    Distinct from :class:`~nemesis.calibration.generator.CaseKind`, which records how the
    evidence was *constructed*. The protocol needs both and grades them differently: AUC runs
    over categories, robustness runs per construction, and conflating them would hide the class
    an adversary would choose behind an average.
    """

    LINKABLE = "linkable"
    """The entities really are one operation, and the evidence can show it."""

    NOT_LINKABLE = "not_linkable"
    """Independent operations that superficially resemble each other. The expensive mistake."""

    ADVERSARIALLY_LINKED = "adversarially_linked"
    """A planted artifact designed to create a false link. Truth: not linked."""

    AMBIGUOUS = "ambiguous"
    """Genuinely undecidable with the evidence available.

    The category most corpora omit and the one this platform's refusal machinery exists for. A
    system that cannot be graded on correct refusals will be tuned to stop refusing.
    """


@dataclass(frozen=True)
class PopulationClaim:
    """What the corpus claims to represent — and what it does not.

    `excludes` is required rather than optional. A score presented without its population is a
    number wearing a suit, and the exclusion is the half that gets dropped: every corpus author
    can describe what they built, and almost none writes down what it says nothing about.
    """

    describes: str
    excludes: str
    ground_truth_rule: str
    generated_by: str

    def __post_init__(self) -> None:
        for name in ("describes", "excludes", "ground_truth_rule", "generated_by"):
            if not getattr(self, name).strip():
                raise CorpusError(
                    f"a corpus needs a non-empty {name}; §2 of the protocol makes all four "
                    "unfalsifiable once results exist, which is why they are written first"
                )

    def render(self) -> list[str]:
        return [
            f"  describes      {self.describes}",
            f"  does NOT cover {self.excludes}",
            f"  ground truth   {self.ground_truth_rule}",
            f"  generated by   {self.generated_by}",
        ]


@dataclass(frozen=True)
class CaseInput:
    """Everything the evaluator is allowed to see. Deliberately thin.

    No truth, no category, no construction. Adding a field here is how the blindness would be
    lost, so anything added must be something a real investigation would also have.
    """

    case_id: str
    sources: tuple[SourcedOpinion, ...]
    candidate_population: int

    @property
    def source_count(self) -> int:
        return len(self.sources)


@dataclass(frozen=True)
class CaseLabel:
    """The answer, and how the case was built. Sealed."""

    case_id: str
    category: CaseCategory
    attack_class: CaseKind
    truth: bool | None
    distinct_real_origins: int

    def __post_init__(self) -> None:
        if self.category is CaseCategory.AMBIGUOUS:
            if self.truth is not None:
                raise CorpusError(
                    f"{self.case_id} is labelled ambiguous and carries a truth value. "
                    + AMBIGUOUS_HAS_NO_TRUE_ANSWER
                )
        elif self.truth is None:
            raise CorpusError(f"{self.case_id} is {self.category.value} and needs a truth value")


@dataclass(frozen=True)
class UnsealRecord:
    """One opening of the seal. Append-only."""

    at: datetime
    actor: str
    reason: str


@dataclass
class SealedLabels:
    """The answers, behind an act that is counted.

    Tamper-evident, not encrypted, and not wired to the platform audit trail — see this module's
    docstring for why that sentence is here rather than omitted.
    """

    _labels: Mapping[str, CaseLabel]
    _unseals: list[UnsealRecord] = field(default_factory=list)

    @property
    def digest(self) -> str:
        """A digest of the answers, publishable without revealing them.

        Lets a later reader confirm that the set scored is the set sealed, which is the claim
        §5 rests on when it says a change after opening invalidates every figure produced.
        """
        folded = hashlib.sha256()
        for case_id in sorted(self._labels):
            label = self._labels[case_id]
            folded.update(
                f"{case_id}|{label.category.value}|{label.attack_class.value}|"
                f"{label.truth}|{label.distinct_real_origins}".encode()
            )
            folded.update(b"\x00")
        return folded.hexdigest()

    @property
    def opened_count(self) -> int:
        """How many times the answers have been read. Reported beside every score from them."""
        return len(self._unseals)

    @property
    def unseal_log(self) -> tuple[UnsealRecord, ...]:
        return tuple(self._unseals)

    def unseal(self, *, actor: str, reason: str, at: datetime) -> Mapping[str, CaseLabel]:
        """Read the answers, and record that it happened.

        The moment a sealed set informs a change it stops being a test set and becomes a
        training set with a misleading name. Nothing here can prevent that; what it can do is
        make the count impossible to omit from the report.
        """
        if not actor.strip() or not reason.strip():
            raise CorpusError("unsealing needs a named actor and a stated reason")
        self._unseals.append(UnsealRecord(at=at, actor=actor.strip(), reason=reason.strip()))
        return self._labels


@dataclass(frozen=True)
class Corpus:
    """Inputs anyone may read, answers nobody reads by accident."""

    population: PopulationClaim
    inputs: tuple[CaseInput, ...]
    sealed: SealedLabels
    seed: int

    @property
    def case_count(self) -> int:
        return len(self.inputs)

    @property
    def digest(self) -> str:
        """Identifies the corpus without opening it."""
        folded = hashlib.sha256()
        for item in self.inputs:
            folded.update(
                f"{item.case_id}|{item.source_count}|{item.candidate_population}".encode()
            )
            folded.update(b"\x00")
        folded.update(self.sealed.digest.encode())
        return folded.hexdigest()


_CATEGORY_OF: Final[Mapping[CaseKind, CaseCategory]] = {
    CaseKind.GENUINE_INDEPENDENT: CaseCategory.LINKABLE,
    CaseKind.RESOLD_FEEDS: CaseCategory.LINKABLE,
    CaseKind.LAUNDERED: CaseCategory.ADVERSARIALLY_LINKED,
    CaseKind.ADVERSARY_ONLY: CaseCategory.ADVERSARIALLY_LINKED,
    CaseKind.CONFLICTED: CaseCategory.NOT_LINKABLE,
    CaseKind.NO_EVIDENCE: CaseCategory.AMBIGUOUS,
}
"""How a construction maps onto a truth category.

A generated case knows both, and they are not interchangeable: `LAUNDERED` and `ADVERSARY_ONLY`
are different attacks with the same truth, and grading them together would hide whichever one
the engine handles worse.
"""


def build_corpus(
    *,
    population: PopulationClaim,
    seed: int,
    per_kind: int = 40,
    candidate_population: int = 40_000,
    assumptions: GeneratorAssumptions | None = None,
) -> Corpus:
    """Generate a corpus whose answers are sealed and whose inputs leak nothing.

    Every category is populated, including `AMBIGUOUS`: a corpus without it cannot grade a
    refusal, and a system that cannot be graded on refusing will be tuned to stop refusing.
    """
    if per_kind < 1:
        raise CorpusError("a corpus needs at least one case per construction")

    generator = CaseGenerator(assumptions)
    generated = [
        (kind, case)
        for kind in CaseKind
        for case in generator.generate_kind(kind, count=per_kind, seed=seed)
    ]

    # Shuffled *before* identifiers are assigned, so neither the order nor the id says anything
    # about the category. Both were leaks worth closing: an evaluator reading `case-0003` must
    # learn nothing it could not learn from the evidence.
    random.Random(seed).shuffle(generated)  # noqa: S311  (reproducibility, not secrecy)

    inputs: list[CaseInput] = []
    labels: dict[str, CaseLabel] = {}
    for index, (kind, case) in enumerate(generated):
        case_id = f"case-{index:05d}"
        inputs.append(
            CaseInput(
                case_id=case_id,
                sources=case.sources,
                candidate_population=candidate_population,
            )
        )
        category = _CATEGORY_OF[kind]
        labels[case_id] = CaseLabel(
            case_id=case_id,
            category=category,
            attack_class=kind,
            truth=None if category is CaseCategory.AMBIGUOUS else case.truth,
            distinct_real_origins=case.distinct_real_origins,
        )

    return Corpus(
        population=population,
        inputs=tuple(inputs),
        sealed=SealedLabels(_labels=labels),
        seed=seed,
    )


@dataclass(frozen=True)
class Prediction:
    """What an evaluator returned for one case.

    `probability` is `None` when the engine declined to estimate. A refusal is an answer here,
    graded on its own terms rather than counted as a miss.
    """

    case_id: str
    probability: float | None
    band: ConfidenceBand

    @property
    def refused(self) -> bool:
        return self.probability is None


@dataclass(frozen=True)
class ClassOutcome:
    """How one attack class came out, split three ways rather than averaged into one."""

    attack_class: CaseKind
    correct: int
    declined: int
    wrong: int

    @property
    def count(self) -> int:
        return self.correct + self.declined + self.wrong


@dataclass(frozen=True)
class CorpusEvaluation:
    """A score, and the four things without which the protocol says it is not a result."""

    population: PopulationClaim
    corpus_digest: str
    labels_digest: str
    labels_opened: int
    case_count: int

    reliability: BrierDecomposition | None
    discrimination_auc: float | None
    refusal_precision: float | None
    refusal_recall: float | None
    outcomes_by_attack_class: tuple[ClassOutcome, ...]
    refusals_by_category: tuple[tuple[CaseCategory, int], ...]

    def render(self) -> str:
        lines = [
            "=" * 78,
            "BLIND CORPUS EVALUATION",
            "=" * 78,
            "",
            "WHAT THIS IS NOT",
            "  Not calibration. The cases are synthetic, so these figures measure agreement",
            "  with a generator's assumptions rather than with the world. Milestone 3 —",
            "  controlled operations on infrastructure we own — is what would change that,",
            "  and it is REQUIRES_EXTERNAL_DATA. What is demonstrated here is the apparatus:",
            "  roles separated, answers sealed, every category graded on its own terms.",
            "",
            "POPULATION",
            *self.population.render(),
            "",
            "PROVENANCE",
            f"  corpus         {self.corpus_digest[:16]}  ({self.case_count} cases)",
            f"  answers        {self.labels_digest[:16]}",
            f"  seal opened    {self.labels_opened}x"
            + ("" if self.labels_opened <= 1 else "   <- every figure below is suspect"),
            "",
            "-" * 78,
            "CALIBRATION — on the bands a reader is actually shown",
            "-" * 78,
        ]
        if self.reliability is None:
            lines.append("  no scoreable case: every prediction was a refusal or a bare estimate")
        else:
            lines.extend(f"  {line}" for line in self.reliability.render().splitlines())
            thin = self.reliability.underpowered_bins
            if thin:
                lines.append(
                    f"  {len(thin)} bin(s) below n={MIN_BIN_COUNT} are shown with their count "
                    "and excluded from the reported figure"
                )

        lines.extend(["", "-" * 78, "DISCRIMINATION", "-" * 78])
        if self.discrimination_auc is None:
            lines.append("  not computable: one of the two classes is absent")
        else:
            lines.append(f"  AUC (linkable vs not linkable)  {self.discrimination_auc:.4f}")
        lines.append(f"  {AMBIGUOUS_HAS_NO_TRUE_ANSWER}")

        lines.extend(["", "-" * 78, "CORRECT REFUSALS — both halves, always", "-" * 78])
        precision = "n/a" if self.refusal_precision is None else f"{self.refusal_precision:.4f}"
        recall = "n/a" if self.refusal_recall is None else f"{self.refusal_recall:.4f}"
        lines.append(
            f"  precision  {precision}   of everything it declined, how much was ambiguous"
        )
        lines.append(f"  recall     {recall}   of everything ambiguous, how much it declined")
        lines.append("  Either alone rewards a system that never answers, or one that never")
        lines.append("  declines. They are reported together or not at all.")

        lines.extend(["", "-" * 78, "ROBUSTNESS — per attack class, never averaged", "-" * 78])
        lines.append("  correct / declined / wrong. Declining is not being wrong, and the third")
        lines.append("  column is the only one that means the engine got it *actually* wrong.")
        lines.append("")
        lines.append(f"  {'class':<22} {'correct':>8} {'declined':>9} {'wrong':>7}   n")
        for outcome in self.outcomes_by_attack_class:
            lines.append(
                f"  {outcome.attack_class.value:<22} {outcome.correct:>8} "
                f"{outcome.declined:>9} {outcome.wrong:>7}   {outcome.count}"
            )
        lines.append("")
        lines.append("  An average across these would hide the class an adversary will choose,")
        lines.append("  which is the only class that matters. Collapsing the three columns into")
        lines.append("  one accuracy would do something worse: the first version of this report")
        lines.append("  scored `laundered` at 0.0000 because the engine declined on all forty,")
        lines.append("  which is the anti-laundering defence working perfectly. A reader would")
        lines.append("  have concluded the opposite of the truth.")

        lines.extend(["", "  What it declined on, by category:"])
        for category, count in self.refusals_by_category:
            lines.append(f"    {category.value:<24} {count}")
        lines.append("  Refusal precision above counts every decline outside `ambiguous` as")
        lines.append("  imprecise, which is the protocol's formula and is worth reading beside")
        lines.append("  this table: declining on an adversarially linked case is defensible, and")
        lines.append("  the formula cannot tell that from declining on an easy one.")
        return "\n".join(lines)


def score(
    corpus: Corpus,
    predictions: Sequence[Prediction],
    *,
    actor: str,
    reason: str,
    at: datetime,
) -> CorpusEvaluation:
    """Open the seal once, and grade every category on its own terms.

    Refuses a prediction set that does not match the corpus exactly. A partial set would let an
    evaluator drop the cases it found hard, which is the cheapest way to produce a good score
    and the hardest to see afterwards.
    """
    predicted = {item.case_id: item for item in predictions}
    if len(predicted) != len(predictions):
        raise CorpusError("two predictions for one case")
    expected = {item.case_id for item in corpus.inputs}
    if predicted.keys() != expected:
        missing = sorted(expected - predicted.keys())
        extra = sorted(predicted.keys() - expected)
        raise CorpusError(
            f"predictions do not match the corpus: {len(missing)} missing, {len(extra)} unknown. "
            "A partial set lets the hard cases disappear."
        )

    labels = corpus.sealed.unseal(actor=actor, reason=reason, at=at)

    decidable = [
        (predicted[case_id], label)
        for case_id, label in labels.items()
        if label.category is not CaseCategory.AMBIGUOUS
    ]
    answered = [(p, label) for p, label in decidable if not p.refused]

    reliability: BrierDecomposition | None = None
    auc: float | None = None
    if answered:
        forecasts = [p.probability for p, _ in answered if p.probability is not None]
        outcomes = [bool(label.truth) for _, label in answered]
        reliability = published_band_decomposition(forecasts, outcomes)
        auc = discrimination_auc(forecasts, outcomes)

    refusals = [p for p in predictions if p.refused]
    ambiguous = [label for label in labels.values() if label.category is CaseCategory.AMBIGUOUS]
    correct_refusals = sum(
        1 for p in refusals if labels[p.case_id].category is CaseCategory.AMBIGUOUS
    )
    precision = correct_refusals / len(refusals) if refusals else None
    recall = correct_refusals / len(ambiguous) if ambiguous else None

    return CorpusEvaluation(
        population=corpus.population,
        corpus_digest=corpus.digest,
        labels_digest=corpus.sealed.digest,
        labels_opened=corpus.sealed.opened_count,
        case_count=corpus.case_count,
        reliability=reliability,
        discrimination_auc=auc,
        refusal_precision=precision,
        refusal_recall=recall,
        outcomes_by_attack_class=_outcomes_by_attack_class(labels, predicted),
        refusals_by_category=_refusals_by_category(labels, refusals),
    )


def _outcomes_by_attack_class(
    labels: Mapping[str, CaseLabel], predicted: Mapping[str, Prediction]
) -> tuple[ClassOutcome, ...]:
    """Correct, declined and wrong — three counts, never one accuracy.

    The first version returned a single accuracy and counted a decline on a decidable case as
    incorrect. It scored `laundered` at 0.0000, and the truth was the opposite: the engine had
    declined on all forty, reaching an actionable band on none, which is the anti-laundering
    defence doing exactly its job. A reader would have concluded the defence was broken.

    Conflating "declined" with "wrong" is a strange thing to do in a platform whose thesis is
    that declining is a correct answer, and it is the shape of mistake that produces an alarming
    number nobody can act on.
    """
    tallies: dict[CaseKind, list[str]] = {}
    for case_id, label in labels.items():
        prediction = predicted[case_id]
        if label.category is CaseCategory.AMBIGUOUS:
            verdict = "correct" if prediction.refused else "wrong"
        elif prediction.refused:
            verdict = "declined"
        else:
            assert prediction.probability is not None
            verdict = "correct" if (prediction.probability >= 0.5) is bool(label.truth) else "wrong"
        tallies.setdefault(label.attack_class, []).append(verdict)

    return tuple(
        ClassOutcome(
            attack_class=kind,
            correct=verdicts.count("correct"),
            declined=verdicts.count("declined"),
            wrong=verdicts.count("wrong"),
        )
        for kind, verdicts in sorted(tallies.items(), key=lambda item: item[0].value)
    )


def _refusals_by_category(
    labels: Mapping[str, CaseLabel], refusals: Sequence[Prediction]
) -> tuple[tuple[CaseCategory, int], ...]:
    """Where the declines landed, so refusal precision can be read rather than believed."""
    counts: dict[CaseCategory, int] = {}
    for prediction in refusals:
        category = labels[prediction.case_id].category
        counts[category] = counts.get(category, 0) + 1
    return tuple(sorted(counts.items(), key=lambda item: item[0].value))


BlindEvaluator = Callable[[Sequence[CaseInput]], Sequence[Prediction]]
"""The shape of a role that never sees an answer.

Stated as a type because that is the enforcement. An evaluator receives `CaseInput` objects and
nothing else; there is no argument through which a label could arrive, and no promise anybody
has to keep.
"""
