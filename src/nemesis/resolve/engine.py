"""The persona resolution engine: are these two personas one operator?

One question, asked once, with a ceiling nailed to it. The engine links personas to
personas. It does not produce, and cannot be made to produce, an assertion about a natural
person — see :meth:`PersonaResolutionEngine.refuse_human_identity`.

Three things carry the honesty of this module, and each is a control against a specific way
persona linkage produces confident nonsense.

**The prior comes from the candidate population.** Given one persona on a forty-thousand
account forum, the chance that a *particular* other account is the same operator is about
one in forty thousand. At a neutral prior of 0.5 the same arithmetic reads very
differently: a signal that leaves belief at 0.30 with uncertainty 0.50 projects to 0.55 —
"likely" — on evidence that narrowed nothing at all. Applied across every pair in a corpus,
that neutrality manufactures a confident false identification for every pair that happens
to resemble. So :func:`base_rate_for_population` derives the prior from the population the
pair was drawn from, and a caller who cannot state that population cannot get an answer.

**Correlated signals are collapsed, not accumulated.** An alias, a published key
fingerprint and an advertised contact handle are one act of self-presentation, published in
one listing, copied — when copied — in one afternoon. :meth:`LinkageSignal.independence_key`
stamps them into one group and :func:`nemesis.core.fusion.fuse` fuses within a group with
the idempotent weighted operator, so three traces of one decision count once. Nothing here
multiplies confidences by hand; every combination goes through ``fuse``.

**Stylometry can never be decisive.** Its ceiling lives in
:data:`~nemesis.resolve.signals.STYLOMETRY_BELIEF_CEILING`, and this module adds a second,
structural guard: when writing-style similarity is the only thing supporting a linkage, no
probability band is reported whatever the arithmetic says. The numeric cap can be raised by
anyone editing a dictionary; the guard survives that, which is why both exist.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.confidence import ConfidenceBand, Opinion, band_of, describe
from nemesis.core.fusion import (
    FusionResult,
    SourcedOpinion,
    establish_fact,
    fuse,
    trust_of_source,
)
from nemesis.core.ids import ClaimId
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import SourceDescriptor
from nemesis.resolve.signals import (
    IRREDUCIBLE_UNCERTAINTY,
    CorrelationGroup,
    LinkageSignal,
    LinkageSignalKind,
    SignalDirection,
)

PROPOSITION_TEMPLATE = (
    "personas {persona_a} and {persona_b} are operated by the same person or people"
)
"""The only proposition this engine assesses, kept as a template so the assessment can
check that it was not repurposed to carry a claim about someone's name."""

ASSUMED_PERSONAS_PER_OPERATOR = 2.0
"""How many personas one operator runs, on average, in a criminal-market corpus.

A modelling assumption, not a measurement, and the only free parameter in the prior. It is
deliberately generous: a larger figure raises the prior and therefore every assessment, so
setting it low would flatter the engine's own conclusions.
"""

BASE_RATE_FLOOR = 1e-6
"""The prior is never exactly zero.

A zero prior asserts before any evidence that the two personas cannot be one operator, and
it silently deletes the base-rate term from every projection — which erases the difference
between "we have no evidence" and "we ruled it out".
"""

BASE_RATE_CEILING = 0.5
"""The prior is never above even odds, whatever population the caller passes.

The failure this prevents: a caller who passes the size of a shortlist rather than the size
of the corpus it was drawn from would buy a near-certain prior for free — and that
shortlist was built by the very resemblance the prior exists to weigh.
"""

NEGLIGIBLE_CONTRIBUTION = 0.01
"""Below one percentage point of movement, a signal is in the record and not in the
conclusion. Reported rather than hidden, so "the fingerprint carried this and the alias
added nothing" is a statement the assessment makes itself."""

STYLOMETRY_ONLY_REFUSAL = (
    "Writing-style similarity is the only support for this linkage. Adversarial-stylometry "
    "results show deliberate obfuscation degrades authorship attribution towards chance, and "
    "open-world accuracy is far below the closed-world figures usually quoted; a criminal "
    "forum is an open world whose participants are motivated to obfuscate. No band is "
    "reported on this basis alone."
)

HUMAN_IDENTIFICATION_IS_NOT_A_THRESHOLD = (
    "Naming the natural person behind a persona is a legal determination, not a confidence "
    "level. It rests on process this platform does not have and is not authorized to "
    "simulate: compelled subscriber disclosure, lawful interception, a judicial finding. No "
    "quantity of linkage signals substitutes for that process, so this refusal is not a "
    "threshold that stronger evidence could clear — there is no number on the other side of "
    "it. The engine links personas to personas and stops there."
)

EXCLUDED_CONCLUSIONS: tuple[str, ...] = (
    "the natural person operating either persona",
    "the nationality, residence or location of the operator",
    "membership of a named organization or state service",
    "the operator's role, seniority or motive",
)
"""Conclusions this engine will not reach, carried in every assessment.

Each is a claim persona linkage is routinely stretched to support: a shared working window
becomes a timezone becomes a nationality, a Russian source comment becomes a nationality
becomes an affiliation. None of them follows from "these two accounts are the same
operator", and listing them in the product is cheaper than arguing about it downstream.
"""


def base_rate_for_population(
    candidate_population: int,
    *,
    personas_per_operator: float = ASSUMED_PERSONAS_PER_OPERATOR,
) -> float:
    """The prior that two personas drawn from this population share an operator.

    Given one persona, the chance that a *particular* other persona in the corpus is run by
    the same operator is ``(k - 1) / (N - 1)``, with ``k`` the average number of personas
    per operator. That is one in forty thousand on a large forum, and it is the number that
    keeps a moderate resemblance from reading as a finding.
    """
    if candidate_population < 2:
        raise ValueError(
            "a candidate population below two personas contains no pair to assess; pass the "
            "size of the corpus the pair was drawn from, not the size of the pair"
        )
    if personas_per_operator < 1.0:
        raise ValueError("an operator runs at least one persona")
    raw = (personas_per_operator - 1.0) / (candidate_population - 1.0)
    return min(BASE_RATE_CEILING, max(BASE_RATE_FLOOR, raw))


class EvidenceAvailability(StrEnum):
    """Whether the evidence that would settle this can in fact be obtained.

    Uses the boundary labels from CLAUDE.md so that "we did not look" and "we are not
    permitted to look" stay distinguishable in an export. Duplicated from the attribution
    plane rather than imported: the two planes are siblings and may not import each other.
    """

    COLLECTABLE = "collectable"
    REQUIRES_EXTERNAL_DATA = "requires_external_data"
    REQUIRES_LEGAL_AUTHORITY = "requires_legal_authority"
    UNOBTAINABLE = "unobtainable"


class SettlingEvidence(BaseModel):
    """Something that would move this assessment, named concretely enough to go and get.

    "More corroboration" is not an entry. The test is whether a reader could turn the
    description into a collection task without asking what was meant.
    """

    model_config = ConfigDict(frozen=True)

    description: Annotated[str, Field(min_length=1, max_length=1000)]
    would_settle: Annotated[str, Field(min_length=1, max_length=1000)]
    availability: EvidenceAvailability


class AlternativeExplanation(BaseModel):
    """Another way the observed resemblance could have arisen.

    ``discriminator`` is required and is the useful half: an alternative recorded without
    saying what observation would separate it from the linkage hypothesis is an alternative
    that was listed rather than considered.
    """

    model_config = ConfigDict(frozen=True)

    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: Annotated[str, Field(min_length=1, max_length=2000)]

    adversary_cost: Annotated[str, Field(min_length=1, max_length=40)]
    """Rough effort to stage this deliberately, in the vocabulary of
    :class:`~nemesis.core.claims.DeceptionAssessment`: trivial, moderate, high, implausible.
    A resemblance that is cheap to manufacture is worth what it costs to manufacture."""

    discriminator: Annotated[str, Field(min_length=1, max_length=2000)]


class CollapsedSignalGroup(BaseModel):
    """Signals that were counted once because they are traces of one generating process."""

    model_config = ConfigDict(frozen=True)

    group: CorrelationGroup
    independence_key: Annotated[str, Field(min_length=1)]
    signals: tuple[str, ...]
    """Labels of the signals collapsed into this group, in the order supplied."""


class SignalContribution(BaseModel):
    """How much one signal moved the assessment, measured by removing it.

    Leave-one-out rather than a declared weight, because fusion is not a weighted sum: a
    signal that is dependent on a stronger one contributes almost nothing however impressive
    it looks in isolation, and only re-running the fusion without it shows that.
    """

    model_config = ConfigDict(frozen=True)

    label: Annotated[str, Field(min_length=1)]
    kind: LinkageSignalKind
    correlation_group: CorrelationGroup
    delta_projected: float
    """Projected probability with this signal, minus the projection without it."""

    @property
    def is_negligible(self) -> bool:
        return abs(self.delta_projected) < NEGLIGIBLE_CONTRIBUTION


class ResolutionCeiling(BaseModel):
    """What this engine is permitted to conclude, carried inside the product.

    Stated as data rather than as prose in a docstring because an export drops prose. A
    reader who sees a high band needs the ceiling in the same object, or the band will be
    read as a stronger kind of claim than the one that was assessed.
    """

    model_config = ConfigDict(frozen=True)

    strongest_supportable_claim: Annotated[str, Field(min_length=1)]
    attainable_projected_probability: Annotated[float, Field(ge=0.0, le=1.0)]
    """Where this signal set would land if every match were perfect and every shared
    attribute maximally selective, with the sources graded as they actually are. The gap
    between this and the reported figure is what better collection could still buy; when it
    is small, more of the same evidence will not help."""

    excluded_conclusions: tuple[str, ...] = EXCLUDED_CONCLUSIONS
    produces_human_identity_attribution: Literal[False] = False


class HumanIdentityRefusal(BaseModel):
    """The record of a refusal to name a natural person.

    A returned object rather than a raised exception, because the refusal is an analytic
    product in its own right: it must survive into the audit trail and the case file, where
    it answers "did anyone ask?" as well as "what was the answer?".

    ``refused`` is ``Literal[True]``. There is no instance of this class that represents a
    granted identification, so no caller can construct one and no downstream reader has to
    check a boolean before trusting the type.
    """

    model_config = ConfigDict(frozen=True)

    refused: Literal[True] = True
    persona: Annotated[str, Field(min_length=1, max_length=512)]
    signals_offered: Annotated[int, Field(ge=0)]

    identity_assertions_offered: Annotated[int, Field(ge=0)] = 0
    """How many name assertions were passed in. The names themselves are counted and
    discarded: retaining them here would create a record of personal data about someone the
    platform has just declined to accuse, and a stored name is repeated eventually."""

    retained_identity_material: Literal[False] = False
    reason: Annotated[str, Field(min_length=1)]


class PersonaLinkageAssessment(BaseModel):
    """The answer, with everything needed to argue with it.

    Every field is required. A caller who omits alternatives or settling evidence produces
    an assessment that looks complete and is not, and the omission is invisible at the point
    of reading.
    """

    model_config = ConfigDict(frozen=True)

    persona_a: Annotated[str, Field(min_length=1, max_length=512)]
    persona_b: Annotated[str, Field(min_length=1, max_length=512)]
    proposition: Annotated[str, Field(min_length=1, max_length=2000)]

    opinion: Opinion
    band: ConfidenceBand
    """May be weaker than :func:`~nemesis.core.confidence.band_of` of the opinion, never
    stronger: the guards in this module can refuse a band the arithmetic would allow. It is
    therefore *not* validated against the opinion — doing so would forbid exactly the
    refusals the guards exist to make."""

    base_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    candidate_population: Annotated[int, Field(ge=2)]
    population_measured_against: str | None

    fusion: FusionResult
    contributions: tuple[SignalContribution, ...]
    collapsed_groups: tuple[CollapsedSignalGroup, ...]
    alternatives: tuple[AlternativeExplanation, ...]
    settling_evidence: tuple[SettlingEvidence, ...]
    ceiling: ResolutionCeiling

    supporting_claims: tuple[ClaimId, ...]
    contradicting_claims: tuple[ClaimId, ...]
    warnings: tuple[str, ...]

    @model_validator(mode="after")
    def _check_assessment_rules(self) -> Self:
        if self.persona_a == self.persona_b:
            raise ValueError("a persona is trivially the same operator as itself")

        # The proposition is rebuilt rather than trusted. Without this, the class is a
        # convenient carrier for any sentence a caller likes — including one naming a
        # person, arriving with a fused opinion and a band attached to lend it weight.
        expected = PROPOSITION_TEMPLATE.format(persona_a=self.persona_a, persona_b=self.persona_b)
        if self.proposition != expected:
            raise ValueError(
                "a persona linkage assessment carries exactly one proposition, about two "
                f"personas: expected {expected!r}"
            )

        if self.band is not ConfidenceBand.INSUFFICIENT_BASIS:
            arithmetic = band_of(self.opinion)
            if arithmetic is ConfidenceBand.INSUFFICIENT_BASIS:
                raise ValueError(
                    "the opinion is too uncertain for any band, but a band was reported"
                )

        overlap = set(self.supporting_claims) & set(self.contradicting_claims)
        if overlap:
            raise ValueError(
                f"claim(s) {sorted(overlap)} are cited as both supporting and contradicting"
            )
        return self

    @property
    def is_single_origin(self) -> bool:
        return self.fusion.is_single_sourced

    @property
    def decisive_signals(self) -> tuple[SignalContribution, ...]:
        """Signals that actually moved the answer. Often one, and often not the longest
        part of the evidence list."""
        return tuple(c for c in self.contributions if not c.is_negligible)

    def render(self) -> str:
        """Plain text for an analyst or a report."""
        lines = [
            self.proposition,
            f"  Confidence: {describe(self.opinion)} [{self.band.value}]",
            f"  Prior: {self.base_rate:.2g} from a candidate population of "
            f"{self.candidate_population}"
            + (
                f" ({self.population_measured_against})" if self.population_measured_against else ""
            ),
            f"  Sources: {self.fusion.independent_source_count} independent of "
            f"{self.fusion.total_sources} signal(s); "
            f"{self.fusion.adversary_influenceable_sources} adversary-influenceable",
            f"  Ceiling: this evidence set could not exceed "
            f"{self.ceiling.attainable_projected_probability:.0%}; "
            f"{self.ceiling.strongest_supportable_claim}",
        ]
        for group in self.collapsed_groups:
            lines.append(
                f"  Collapsed — {group.group.value}: {', '.join(group.signals)} counted once"
            )
        for contribution in self.contributions:
            movement = (
                "no movement"
                if contribution.is_negligible
                else f"{contribution.delta_projected:+.3f}"
            )
            lines.append(f"  Signal — {contribution.label}: {movement}")
        for alternative in self.alternatives:
            lines.append(
                f"  Alternative — {alternative.name} (cost to stage: "
                f"{alternative.adversary_cost}): {alternative.discriminator}"
            )
        for missing in self.settling_evidence:
            lines.append(
                f"  Would settle — {missing.description} ({missing.availability.value}): "
                f"{missing.would_settle}"
            )
        lines.extend(f"  ! {warning}" for warning in self.warnings)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Alternative explanations
#
# Each is keyed to the generating process that produced the signal, because that is what
# decides how an innocent or staged explanation would look. They are generated rather than
# written by a caller so that the awkward ones cannot be quietly left out of a strong
# assessment.
# ---------------------------------------------------------------------------

_ALTERNATIVE_BY_GROUP: dict[CorrelationGroup, AlternativeExplanation] = {
    CorrelationGroup.SELF_PRESENTATION: AlternativeExplanation(
        name="reputation transfer by a third party",
        description=(
            "A different actor copied the alias, the advertised handle and the published key "
            "fingerprint from one public listing in order to inherit an established vendor's "
            "reputation. Every one of those values is a string the original actor published; "
            "reproducing them demonstrates reading, not identity."
        ),
        adversary_cost="trivial",
        discriminator=(
            "Material signed with the private key by both personas, or activity outside the "
            "listing — ledger structure, posting routine — that the copier could not have "
            "reproduced from what was published."
        ),
    ),
    CorrelationGroup.CRYPTOGRAPHIC_KEY_CONTROL: AlternativeExplanation(
        name="one key, more than one holder",
        description=(
            "Both personas demonstrably used one private key, and that key was shared inside "
            "a crew, sold with the shop, or stolen. Key control establishes common access to "
            "a secret, which is weaker than common identity."
        ),
        adversary_cost="moderate",
        discriminator=(
            "Whether use of the key is continuous across the handover or shows two "
            "overlapping tempos, and whether a revocation or transfer was ever announced."
        ),
    ),
    CorrelationGroup.FINANCIAL_LEDGER: AlternativeExplanation(
        name="clustering heuristic failure",
        description=(
            "Multi-input clustering infers wallet software, not ownership. Custodial "
            "services, mixers and CoinJoin co-spend on behalf of unrelated customers, which "
            "is exactly the tooling a paid criminal vendor uses."
        ),
        adversary_cost="moderate",
        discriminator=(
            "Whether the cluster's addresses ever co-spent through a known custodial or "
            "mixing service, and the heuristic's own stated failure rate on that corpus."
        ),
    ),
    CorrelationGroup.BEHAVIOURAL_ROUTINE: AlternativeExplanation(
        name="a shared working day, or a deliberate imitation of one",
        description=(
            "Roughly a twelfth of the internet shares any given posting window, and prose "
            "register is downstream of the same locale and schooling as thousands of other "
            "people. A successor persona that wants to be mistaken for its predecessor "
            "produces both of these on purpose."
        ),
        adversary_cost="trivial",
        discriminator=(
            "A longer posting sample, and whether the text carries indicators of deliberate "
            "obfuscation or deliberate imitation."
        ),
    ),
    CorrelationGroup.OPERATIONAL_INFRASTRUCTURE: AlternativeExplanation(
        name="co-tenancy on shared infrastructure",
        description=(
            "A bulletproof host, a proxy pool or a netblock serves many unrelated criminal "
            "tenants. Co-location on one is a property of the provider's customer list, not "
            "of the operator."
        ),
        adversary_cost="trivial",
        discriminator=(
            "How many other entities share the same host, certificate or netblock in the "
            "corpus the count was measured against."
        ),
    ),
}

_COINCIDENCE_ALTERNATIVE = AlternativeExplanation(
    name="two different operators, and the resemblance is coincidence",
    description=(
        "The null hypothesis, and the one the prior is about. In a corpus of this size, some "
        "pairs of unrelated personas resemble each other on any attribute nobody counted; "
        "the number of such pairs grows with the square of the population."
    ),
    adversary_cost="implausible",
    discriminator=(
        "A count of how many personas in the corpus share each matched attribute. An "
        "uncounted attribute cannot distinguish this alternative from the linkage."
    ),
)


def _alternatives_for(signals: Sequence[LinkageSignal]) -> tuple[AlternativeExplanation, ...]:
    groups = {signal.correlation_group for signal in signals}
    ordered = [_ALTERNATIVE_BY_GROUP[group] for group in CorrelationGroup if group in groups]
    return (*ordered, _COINCIDENCE_ALTERNATIVE)


# ---------------------------------------------------------------------------
# Evidence that would settle it
# ---------------------------------------------------------------------------


def _settling_evidence(
    signals: Sequence[LinkageSignal], result: FusionResult
) -> tuple[SettlingEvidence, ...]:
    """What would actually move this assessment, given what is already present.

    Nothing here proposes contacting a persona. A challenge-response — asking each account
    to sign a nonce — would settle key control outright and is the obvious suggestion; it is
    also engagement with a criminal persona, which this repository prohibits outright. The
    collectable form of the same evidence is material both personas already signed.
    """
    settling: list[SettlingEvidence] = []
    groups = {signal.correlation_group for signal in signals}

    if CorrelationGroup.CRYPTOGRAPHIC_KEY_CONTROL not in groups:
        settling.append(
            SettlingEvidence(
                description=(
                    "Archived messages or listings already signed by each persona with the "
                    "key whose fingerprint they publish."
                ),
                would_settle=(
                    "Whether the shared fingerprint reflects possession of the private key or "
                    "only the ability to copy a published string, which is the difference "
                    "between the linkage and the impersonation alternative."
                ),
                availability=EvidenceAvailability.COLLECTABLE,
            )
        )

    uncounted = [
        signal
        for signal in signals
        if not signal.selectivity.is_globally_unique and signal.selectivity.population_size is None
    ]
    if uncounted:
        attributes = ", ".join(sorted({signal.selectivity.attribute for signal in uncounted}))
        settling.append(
            SettlingEvidence(
                description=(
                    f"A count, against a named corpus and date, of how many personas share: "
                    f"{attributes}."
                ),
                would_settle=(
                    "How much each of those attributes narrows the field. Uncounted, they "
                    "contribute nothing to this assessment by construction."
                ),
                availability=EvidenceAvailability.COLLECTABLE,
            )
        )

    if result.is_single_sourced and signals:
        settling.append(
            SettlingEvidence(
                description=(
                    "The same match observed by an origin independent of the one that "
                    "reported it — a second archive, a ledger, our own telemetry."
                ),
                would_settle=(
                    "Whether this is corroboration or one origin repeated. Agreement inside a "
                    "single origin is not evidence about the world."
                ),
                availability=EvidenceAvailability.REQUIRES_EXTERNAL_DATA,
            )
        )

    return tuple(settling)


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------


def _grouped_source(signal: LinkageSignal) -> SourceDescriptor:
    """The descriptor fusion will group on.

    Mirrors :meth:`LinkageSignal.to_sourced_opinion` exactly. The ceiling computation below
    must stamp signals the same way, or it would report a ceiling that fusion could never
    reach — a target that flatters the evidence by pretending its correlated parts would
    accumulate.
    """
    return signal.observed_by.model_copy(update={"upstream_of_record": signal.independence_key()})


def _projected(sourced: Sequence[SourcedOpinion], base_rate: float) -> float:
    """Projected probability of a fused set, with the empty set held at the prior.

    :func:`fuse` returns a vacuous opinion carrying base rate 0.5 when handed nothing,
    because it has no way to know the proposition's prior. Using that here would score the
    removal of the only signal as landing on even odds, and a genuine positive signal would
    then be reported as having *lowered* the estimate.
    """
    if not sourced:
        return base_rate
    return establish_fact(sourced).opinion.projected_probability


# Persona resolution is margined, and the fact keys that make that meaningful come from
# LinkageSignal.fact_key(): one specific shared attribute — this fingerprint, this handle,
# this cluster — is one fact. It was not always so. This plane called `establish_fact`
# directly, on the reasoning that its output is an internal lead the D1 wall keeps inside the
# platform and that BELIEF_CEILING did a narrower version of the same job, and PROJECT_STATE
# recorded it as the largest remaining gap in the anti-planting mechanism. It was: a linkage
# resting on one copyable string, published in a channel the adversary writes into, is
# precisely the shape the margin exists to refuse, and "it never leaves the platform" is an
# argument about blast radius rather than about whether the finding is sound.
class PersonaResolutionEngine:
    """Fuses linkage signals into one assessment about two personas.

    Stateless apart from the prior's one assumption, so an assessment is reproducible from
    its inputs: the same signals, population and assumption always give the same answer.
    """

    def __init__(self, *, personas_per_operator: float = ASSUMED_PERSONAS_PER_OPERATOR) -> None:
        if personas_per_operator < 1.0:
            raise ValueError("an operator runs at least one persona")
        self._personas_per_operator = personas_per_operator

    @property
    def personas_per_operator(self) -> float:
        return self._personas_per_operator

    def assess(
        self,
        persona_a: str,
        persona_b: str,
        signals: Sequence[LinkageSignal],
        candidate_population: int,
        *,
        population_measured_against: str | None = None,
    ) -> PersonaLinkageAssessment:
        """Assess whether two personas are one operator.

        ``candidate_population`` is the number of personas the pair was drawn from — the
        forum's account count, not the size of the shortlist that resemblance produced. It
        is a required argument because there is no defensible default: every value of it
        that could be assumed is either the neutral 0.5 this module exists to refuse, or a
        number the caller would have had to measure anyway.
        """
        if persona_a.strip() == persona_b.strip():
            raise ValueError("a persona is trivially the same operator as itself")

        base_rate = base_rate_for_population(
            candidate_population, personas_per_operator=self._personas_per_operator
        )
        sourced = [signal.to_sourced_opinion(base_rate=base_rate) for signal in signals]

        # revise_on_conflict stays off. It penalises the minority account, which is right
        # against noise and wrong against a coordinated false majority — and a persona
        # linkage is assessed largely on channels where an adversary can create the majority.
        #
        # SHARED_ORIGIN rather than ACTOR_ATTRIBUTION: this asserts that two identities have
        # one origin, which is what the class names. Both carry a margin of one, so the
        # practical effect is the same and the label is the honest one.
        result = fuse(sourced, proposition=PropositionClass.SHARED_ORIGIN)

        if not signals:
            # fuse() cannot know this proposition's prior, so its empty-set opinion carries
            # 0.5 — the neutral prior that produces confident false identification at scale.
            result = result.model_copy(update={"opinion": Opinion.vacuous(base_rate)})

        warnings = list(result.warnings)
        band = band_of(result.opinion)

        supporting = [s for s in signals if s.direction is SignalDirection.SUPPORTS]
        if supporting and all(
            signal.kind is LinkageSignalKind.WRITING_STYLE_SIMILARITY for signal in supporting
        ):
            # Structural, not numeric: the belief ceiling is a dictionary entry anyone can
            # raise, and this guard is what makes stylometry non-decisive even then.
            band = ConfidenceBand.INSUFFICIENT_BASIS
            warnings.append(STYLOMETRY_ONLY_REFUSAL)

        contributions = self._contributions(signals, sourced, result, base_rate)
        collapsed = self._collapsed_groups(signals)
        if collapsed:
            warnings.append(
                "Signals sharing a generating process were counted once: "
                + "; ".join(
                    f"{group.group.value} ({', '.join(group.signals)})" for group in collapsed
                )
                + ". Correlated traces of one decision are not corroboration."
            )

        uncounted = sum(
            1
            for signal in signals
            if not signal.selectivity.is_globally_unique
            and signal.selectivity.population_size is None
        )
        if uncounted:
            warnings.append(
                f"{uncounted} signal(s) rest on an attribute nobody counted and contribute "
                "nothing; see the settling evidence."
            )

        ceiling = ResolutionCeiling(
            strongest_supportable_claim=PROPOSITION_TEMPLATE.format(
                persona_a=persona_a, persona_b=persona_b
            ),
            attainable_projected_probability=self._attainable(signals, base_rate),
        )

        return PersonaLinkageAssessment(
            persona_a=persona_a,
            persona_b=persona_b,
            proposition=PROPOSITION_TEMPLATE.format(persona_a=persona_a, persona_b=persona_b),
            opinion=result.opinion,
            band=band,
            base_rate=base_rate,
            candidate_population=candidate_population,
            population_measured_against=population_measured_against,
            fusion=result,
            contributions=contributions,
            collapsed_groups=collapsed,
            alternatives=_alternatives_for(signals),
            settling_evidence=_settling_evidence(signals, result),
            ceiling=ceiling,
            supporting_claims=_claims(signals, SignalDirection.SUPPORTS),
            contradicting_claims=_claims(signals, SignalDirection.CONTRADICTS),
            warnings=tuple(warnings),
        )

    def refuse_human_identity(
        self,
        persona: str,
        *,
        offered_signals: Sequence[LinkageSignal] = (),
        asserted_identities: Sequence[str] = (),
    ) -> HumanIdentityRefusal:
        """Refuse to name the natural person behind a persona. Always.

        There is no branch in this method. Human identification is a legal determination
        requiring process this platform does not have — compelled subscriber disclosure, a
        judicial finding — and not a confidence threshold that better evidence could clear.
        Implementing it as a threshold, however high, would concede the shape of the
        argument: an adversary who knows the number exists only has to manufacture enough
        agreement to cross it, and agreement is cheap in the channels where names circulate.

        ``asserted_identities`` is counted and discarded. Recording the name here would
        create a personal-data record about someone the platform has just declined to
        accuse, and a stored name is repeated eventually.
        """
        return HumanIdentityRefusal(
            persona=persona,
            signals_offered=len(offered_signals),
            identity_assertions_offered=len(asserted_identities),
            reason=HUMAN_IDENTIFICATION_IS_NOT_A_THRESHOLD,
        )

    # -- internals ------------------------------------------------------------

    def _contributions(
        self,
        signals: Sequence[LinkageSignal],
        sourced: Sequence[SourcedOpinion],
        result: FusionResult,
        base_rate: float,
    ) -> tuple[SignalContribution, ...]:
        # Measured against the EVIDENTIAL figure, not the margined one. The margin removes
        # a whole fact on purpose, so scoring leave-one-out against the post-margin result
        # mixes two different questions and produces arithmetic that reads as nonsense: with
        # the margin on, the signal doing all the work showed "no movement" and the one
        # contributing nothing showed -0.712. What a reader wants here is what each signal
        # was worth to the evidence; what the margin then did to that is reported separately,
        # in its own line, and is not a property of any single signal.
        full = (result.evidential_opinion or result.opinion).projected_probability
        contributions: list[SignalContribution] = []
        for index, signal in enumerate(signals):
            without = [item for position, item in enumerate(sourced) if position != index]
            contributions.append(
                SignalContribution(
                    label=f"{signal.kind.value} ({signal.shared_attribute})",
                    kind=signal.kind,
                    correlation_group=signal.correlation_group,
                    delta_projected=full - _projected(without, base_rate),
                )
            )
        return tuple(contributions)

    def _collapsed_groups(
        self, signals: Sequence[LinkageSignal]
    ) -> tuple[CollapsedSignalGroup, ...]:
        by_key: dict[str, list[LinkageSignal]] = {}
        for signal in signals:
            by_key.setdefault(signal.independence_key(), []).append(signal)
        return tuple(
            CollapsedSignalGroup(
                group=members[0].correlation_group,
                independence_key=key,
                signals=tuple(signal.kind.value for signal in members),
            )
            for key, members in by_key.items()
            if len(members) > 1
        )

    def _attainable(self, signals: Sequence[LinkageSignal], base_rate: float) -> float:
        """Where this signal set would land with every match perfect and every attribute
        maximally selective.

        Only the strongest member of each correlation group is counted. Within a group the
        weaker members are traces of the same decision, and weighted fusion averages them
        against the strong one — so summing them would make the ceiling *fall* when a weak
        correlated signal is added, which is not a ceiling.

        Contradicting signals are excluded: their perfect form argues the other way, and
        this is a statement about the best case for the linkage. Trust discounting is kept,
        because a perfect match reported by an unvetted scrape is still an unvetted-scrape
        finding, and a ceiling that discounted it away would promise an analyst a figure no
        further collection from that source could deliver.
        """
        best: dict[str, tuple[float, SourcedOpinion]] = {}
        for signal in signals:
            if signal.direction is not SignalDirection.SUPPORTS:
                continue
            source = _grouped_source(signal)
            mass = min(signal.belief_ceiling, 1.0 - IRREDUCIBLE_UNCERTAINTY)
            reachable = mass * trust_of_source(source).belief
            key = signal.independence_key()
            if key in best and best[key][0] >= reachable:
                continue
            best[key] = (
                reachable,
                SourcedOpinion(
                    source=source,
                    opinion=Opinion(
                        belief=mass,
                        disbelief=0.0,
                        uncertainty=1.0 - mass,
                        base_rate=base_rate,
                    ),
                    label=signal.kind.value,
                ),
            )
        return _projected([opinion for _, opinion in best.values()], base_rate)


def _claims(signals: Sequence[LinkageSignal], direction: SignalDirection) -> tuple[ClaimId, ...]:
    """Claim ids cited by signals pointing one way, deduplicated in order of first sight."""
    seen: dict[str, None] = {}
    for signal in signals:
        if signal.direction is not direction:
            continue
        for claim in signal.supporting_claims:
            seen.setdefault(claim, None)
    return tuple(seen)
