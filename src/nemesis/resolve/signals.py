"""Linkage signals: the individual reasons to suspect two personas are one operator.

The proposition every signal in this module speaks to is exactly one sentence:
*"persona A and persona B are operated by the same person or people."* Nothing here speaks
to who that person is, and nothing here can be made to.

The honest answer to that proposition is usually "we cannot tell", and this module is built
so that "cannot tell" is what falls out unless something genuinely selective is present.
Four properties do that work.

**Selectivity sets the weight, not the signal type.** A shared attribute is worth what it
narrows. :class:`~nemesis.core.relationships.PivotSelectivity` already carries the
population count and the corpus it was measured against, so it is reused here rather than
reinvented: a handle advertised by two personas is strong, an alias stem shared by three
hundred is nearly nothing, and an *uncounted* attribute is worth zero rather than worth
guessing. That last rule is the one that stops "shares an attribute" from meaning "shares
an operator" by default.

**Correlated signals are stamped with one independence key.** An alias, a published key
fingerprint and an advertised contact handle are not three findings. They are one decision
by one actor about how to present itself, published in one listing — and copied, when
copied, in one act. Fusing them as independent sources multiplies a single decision into
apparent corroboration, which is how a persona-linkage engine talks itself into confident
nonsense. Each signal therefore reports a :class:`CorrelationGroup`, and
:meth:`LinkageSignal.to_sourced_opinion` rewrites the source's ``upstream_of_record`` to
that group so :func:`nemesis.core.fusion.fuse` collapses them with weighted fusion instead
of accumulating them with cumulative fusion.

**Contradiction is available, but only where absence means something.** Disjoint posting
hours over a large sample is weak evidence *against* one operator. The absence of a shared
key is not: an operator who compartmentalises has no shared key by design, so admitting
disbelief there would punish the adversary's good tradecraft by manufacturing confidence
that two personas are different people.

**Stylometry is capped hard and can never be decisive.** See :data:`BELIEF_CEILING`.
"""

from __future__ import annotations

import difflib
from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.confidence import Opinion
from nemesis.core.entities import (
    SHARED_INFRASTRUCTURE_TYPES,
    EntityType,
    normalize_identifier,
)
from nemesis.core.fusion import SourcedOpinion
from nemesis.core.ids import ClaimId
from nemesis.core.provenance import SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotMethod, PivotSelectivity


class LinkageSignalKind(StrEnum):
    """What kind of resemblance was observed between two personas."""

    SHARED_CRYPTOGRAPHIC_IDENTITY = "shared_cryptographic_identity"
    """A full PGP or SSH fingerprint appearing under both personas."""

    SHARED_CONTACT_HANDLE = "shared_contact_handle"
    """A messaging handle or email address advertised by both."""

    SHARED_WALLET_CLUSTER = "shared_wallet_cluster"
    """Addresses used by both resolve into one heuristic wallet cluster."""

    ALIAS_SIMILARITY = "alias_similarity"
    """The names themselves resemble each other."""

    ACTIVITY_HOURS_OVERLAP = "activity_hours_overlap"
    """The two posting routines occupy the same window of the day."""

    INFRASTRUCTURE_REUSE = "infrastructure_reuse"
    """Both are tied to the same host, certificate or netblock."""

    WRITING_STYLE_SIMILARITY = "writing_style_similarity"
    """An authorship-attribution method scored the two bodies of text as similar."""


class CorrelationGroup(StrEnum):
    """The generating process a signal is a trace of.

    Two signals produced by *one* decision or *one* habit of *one* actor are not two
    sources, however differently they were collected. Grouping is by generating process
    rather than by collection channel, because that is where the dependence actually lives:
    an operator who decides to carry a reputation across venues republishes the alias, the
    key and the contact handle together, and an impersonator who decides to steal that
    reputation copies all three from the same public listing in a single afternoon.
    """

    SELF_PRESENTATION = "self_presentation"
    """Chosen and published by the actor: alias, advertised key fingerprint, contact
    handle. Cheap to copy, and copied all at once."""

    CRYPTOGRAPHIC_KEY_CONTROL = "cryptographic_key_control"
    """A demonstration that both personas hold one private key. Independent of
    self-presentation because it cannot be produced by copying a public value."""

    BEHAVIOURAL_ROUTINE = "behavioural_routine"
    """Traces of one working life: when the posts happen, how the prose reads. Both are
    downstream of the same locale and schedule, and both are what a successor persona
    imitates when it wants to be mistaken for its predecessor."""

    FINANCIAL_LEDGER = "financial_ledger"
    """Derived from ledger structure rather than from anything the actor says."""

    OPERATIONAL_INFRASTRUCTURE = "operational_infrastructure"
    """Derived from machines and keys in use rather than from self-description."""


class SignalDirection(StrEnum):
    """Whether the observation argues for or against one operator."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


CORRELATION_GROUP_OF: dict[LinkageSignalKind, CorrelationGroup] = {
    LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY: CorrelationGroup.SELF_PRESENTATION,
    LinkageSignalKind.SHARED_CONTACT_HANDLE: CorrelationGroup.SELF_PRESENTATION,
    LinkageSignalKind.ALIAS_SIMILARITY: CorrelationGroup.SELF_PRESENTATION,
    LinkageSignalKind.ACTIVITY_HOURS_OVERLAP: CorrelationGroup.BEHAVIOURAL_ROUTINE,
    LinkageSignalKind.WRITING_STYLE_SIMILARITY: CorrelationGroup.BEHAVIOURAL_ROUTINE,
    LinkageSignalKind.SHARED_WALLET_CLUSTER: CorrelationGroup.FINANCIAL_LEDGER,
    LinkageSignalKind.INFRASTRUCTURE_REUSE: CorrelationGroup.OPERATIONAL_INFRASTRUCTURE,
}
"""Which generating process each signal is a trace of.

A published fingerprint sits in ``SELF_PRESENTATION`` rather than in a cryptographic group
of its own, because publishing a fingerprint demonstrates nothing about holding the key —
it is a copyable string in a listing the actor wrote. A signal that carries
``demonstrated_key_control`` moves to :attr:`CorrelationGroup.CRYPTOGRAPHIC_KEY_CONTROL`;
see :meth:`LinkageSignal.correlation_group`.
"""

PIVOT_METHOD_OF: dict[LinkageSignalKind, PivotMethod] = {
    LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY: PivotMethod.CRYPTOGRAPHIC_IDENTITY,
    LinkageSignalKind.SHARED_CONTACT_HANDLE: PivotMethod.SHARED_ATTRIBUTE,
    LinkageSignalKind.SHARED_WALLET_CLUSTER: PivotMethod.TRANSACTION_GRAPH,
    LinkageSignalKind.ALIAS_SIMILARITY: PivotMethod.SHARED_ATTRIBUTE,
    LinkageSignalKind.ACTIVITY_HOURS_OVERLAP: PivotMethod.BEHAVIORAL_PATTERN,
    LinkageSignalKind.INFRASTRUCTURE_REUSE: PivotMethod.INFRASTRUCTURE_REUSE,
    LinkageSignalKind.WRITING_STYLE_SIMILARITY: PivotMethod.LINGUISTIC_SIMILARITY,
}
"""The analytic technique behind each signal, so an edge built from an assessment can say
how it was established rather than only how confident it is."""


STYLOMETRY_BELIEF_CEILING = 0.15
"""The hardest cap in this module, and the one most often set far too high elsewhere.

Two findings from the adversarial-stylometry literature drive it. First, deliberate
obfuscation — imitating another author, or simply writing unlike oneself — degrades
authorship attribution severely, in several published evaluations to around chance. Second,
the accuracy figures usually quoted come from *closed-world* experiments, where the true
author is guaranteed to be among a small candidate set; open-world performance, where the
author may be none of the candidates, is far worse. A criminal forum is an open world whose
participants have every incentive to obfuscate, so both discounts apply at once.

Capping belief at 0.15 means a stylometric match cannot on its own lift an opinion out of
the vacuous range, whatever score the method returns. :mod:`nemesis.resolve.engine` also
refuses to report a band when stylometry is the only support, so the guarantee survives
someone raising this number without reading the paragraph above.
"""

BELIEF_CEILING: dict[LinkageSignalKind, float] = {
    # A full fingerprint appearing under both personas is the strongest thing this engine
    # can see. It is still not certainty: publication is not possession, so the ceiling
    # sits below 1.0 and the alternative "someone copied it" is always reported.
    LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY: 0.95,
    LinkageSignalKind.SHARED_WALLET_CLUSTER: 0.75,
    LinkageSignalKind.SHARED_CONTACT_HANDLE: 0.70,
    LinkageSignalKind.INFRASTRUCTURE_REUSE: 0.60,
    # An identical, unusual alias across two venues is real evidence and weak evidence at
    # once: impersonating an established vendor to inherit its reputation is a routine
    # practice in these markets, and it costs a registration form.
    LinkageSignalKind.ALIAS_SIMILARITY: 0.30,
    LinkageSignalKind.ACTIVITY_HOURS_OVERLAP: 0.25,
    LinkageSignalKind.WRITING_STYLE_SIMILARITY: STYLOMETRY_BELIEF_CEILING,
}
"""Most belief a signal of each kind may ever contribute, before selectivity and trust.

Calibration choices, not measurements — the same standing caveat as
:meth:`PivotSelectivity.evidential_weight`. They are ordered by how expensive the signal is
for an adversary to stage, which is the property that matters when the adversary knows how
the engine works.
"""

DEMONSTRATED_KEY_CONTROL_CEILING = 0.97
"""A signature by both personas over collected material proves one key was held twice.

Higher than a published fingerprint because it cannot be produced by copy-paste, and still
short of certainty: keys are sold, shared inside a crew, and stolen.
"""

CONTRADICTION_BELIEF_CEILING = 0.35
"""Most disbelief a single signal may contribute.

Negative evidence is weaker than it feels here. Two personas with disjoint posting windows
may be one operator working two shifts, one operator plus a scheduler, or one operator who
moved. The cap keeps "they never post at the same time" from becoming a refutation.
"""

IRREDUCIBLE_UNCERTAINTY = 0.05
"""No single signal may claim more than this much of the mass.

A dogmatic opinion asserts that no future evidence could change the conclusion, which in a
domain with an adversary who is actively arranging what we see is never true.
"""

MIN_POSTS_FOR_A_ROUTINE = 30
"""Below this many posts on either side, an activity-hour comparison is scaled down.

Five posts describe an afternoon, not a routine, and the Jaccard overlap of two tiny hour
sets is mostly noise about when the collector happened to look.
"""

OPEN_WORLD_STYLOMETRY_PENALTY = 0.5
"""Applied when the true author may be outside the candidate set — the real case."""

OBFUSCATION_STYLOMETRY_PENALTY = 0.2
"""Applied when there is any indication the text was written to defeat attribution.

Deliberate obfuscation is the documented failure mode of authorship attribution, and a
persona that has already survived one takedown has every reason to attempt it.
"""

_RELIABILITY_ORDER: tuple[SourceReliability, ...] = (
    SourceReliability.COMPLETELY_RELIABLE,
    SourceReliability.USUALLY_RELIABLE,
    SourceReliability.FAIRLY_RELIABLE,
    SourceReliability.NOT_USUALLY_RELIABLE,
    SourceReliability.UNRELIABLE,
    SourceReliability.CANNOT_BE_JUDGED,
)

_CONTRADICTION_CAPABLE: frozenset[LinkageSignalKind] = frozenset(
    {
        LinkageSignalKind.ACTIVITY_HOURS_OVERLAP,
        LinkageSignalKind.WRITING_STYLE_SIMILARITY,
    }
)
"""Kinds where a mismatch is itself an observation.

Everything else is present-or-absent: two personas of one operator need not share a wallet,
a host or a key, so reading their absence as disbelief would let an adversary earn a
"different people" finding simply by compartmentalising properly.
"""

_KEY_ENTITY_TYPES: frozenset[EntityType] = frozenset({EntityType.PGP_KEY, EntityType.SSH_KEY})


def least_reliable(*sources: SourceDescriptor) -> SourceDescriptor:
    """The weakest of several sources, by Admiralty reliability.

    A linkage signal is a comparison of two observations, and a match is worth no more than
    its weaker half: a fingerprint seen by a trusted archive on one side and by an unvetted
    scrape on the other is an unvetted-scrape finding. Callers building a cross-venue signal
    pass the result of this rather than picking whichever source looks better.
    """
    if not sources:
        raise ValueError("least_reliable needs at least one source")
    # Highest index in _RELIABILITY_ORDER, which runs strongest-first: the weaker half of
    # the match is the one that governs. Taking the minimum here returns the *best* source
    # and grades a half-unvetted match as though the trusted side had seen all of it.
    return max(sources, key=lambda source: _RELIABILITY_ORDER.index(source.reliability))


class LinkageSignal(BaseModel):
    """One observed resemblance between two personas, with what it is worth.

    A record of an observation, not a conclusion: it says what matched, how selective the
    matching attribute is, and who saw it. Turning that into an opinion requires a base
    rate, which only the engine knows, because it depends on how many candidate personas
    the pair was drawn from.
    """

    model_config = ConfigDict(frozen=True)

    kind: LinkageSignalKind
    observed_by: SourceDescriptor
    """Source of record for the match. For a cross-venue comparison, :func:`least_reliable`
    of the two sides."""

    shared_attribute: Annotated[str, Field(min_length=1, max_length=512)]
    """What matched, in a form an analyst can check: the fingerprint, the handle, the
    cluster identifier, the hour window."""

    selectivity: PivotSelectivity
    """How much the matching attribute narrows the field. An uncounted population here
    makes the signal worthless by construction, which is the intended behaviour."""

    match_strength: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    """How well the two observations agree, in [0, 1]. Exact-value signals are 1.0;
    similarity scores and sample-limited comparisons are below it."""

    direction: SignalDirection = SignalDirection.SUPPORTS
    demonstrated_key_control: bool = False
    """True only when both personas signed collected material with one private key.
    Publishing a fingerprint is not this."""

    supporting_claims: tuple[ClaimId, ...] = ()
    note: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def _check_signal_rules(self) -> Self:
        if self.selectivity.is_globally_unique and (
            self.kind is not LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY
        ):
            raise ValueError(
                f"{self.kind.value} cannot be globally unique: only a full cryptographic "
                "fingerprint identifies by construction. Marking an alias, a handle or a "
                "phrase unique makes a copyable string decisive."
            )
        if self.demonstrated_key_control and (
            self.kind is not LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY
        ):
            raise ValueError("only a cryptographic-identity signal can demonstrate key control")
        if (
            self.direction is SignalDirection.CONTRADICTS
            and self.kind not in _CONTRADICTION_CAPABLE
        ):
            raise ValueError(
                f"a {self.kind.value} signal cannot contradict: the absence of a shared "
                "attribute is not evidence that two personas are different people"
            )
        return self

    @property
    def correlation_group(self) -> CorrelationGroup:
        """The generating process this signal is a trace of.

        A cryptographic signal moves out of self-presentation only when key control was
        demonstrated. Until then it is a string the actor chose to publish, and it is
        correlated with every other string the actor chose to publish.
        """
        if self.demonstrated_key_control:
            return CorrelationGroup.CRYPTOGRAPHIC_KEY_CONTROL
        return CORRELATION_GROUP_OF[self.kind]

    @property
    def pivot_method(self) -> PivotMethod:
        return PIVOT_METHOD_OF[self.kind]

    @property
    def belief_ceiling(self) -> float:
        if self.demonstrated_key_control:
            return DEMONSTRATED_KEY_CONTROL_CEILING
        return BELIEF_CEILING[self.kind]

    @property
    def evidential_weight(self) -> float:
        """Selectivity of the attribute times how well the two observations agree.

        Zero when nobody counted the population, which makes the whole signal vacuous.
        """
        return self.selectivity.evidential_weight() * self.match_strength

    def to_opinion(self, *, base_rate: float) -> Opinion:
        """The opinion this signal alone justifies, before trust discounting.

        Mass is ``ceiling x selectivity x match strength`` and lands in belief or disbelief
        according to direction; everything left over is uncertainty, never disbelief. A
        weak signal must leave us ignorant, not convinced of the opposite.
        """
        mass = min(self.belief_ceiling * self.evidential_weight, 1.0 - IRREDUCIBLE_UNCERTAINTY)
        if self.direction is SignalDirection.CONTRADICTS:
            mass = min(mass, CONTRADICTION_BELIEF_CEILING)
            return Opinion(belief=0.0, disbelief=mass, uncertainty=1.0 - mass, base_rate=base_rate)
        return Opinion(belief=mass, disbelief=0.0, uncertainty=1.0 - mass, base_rate=base_rate)

    def independence_key(self) -> str:
        """The key on which :func:`nemesis.core.fusion.fuse` will collapse this signal."""
        return f"persona-linkage:{self.correlation_group.value}"

    def fact_key(self) -> str:
        """Which fact about the world this signal attests.

        A *fact* here is one specific shared attribute: this fingerprint, this handle, this
        wallet cluster. Two collectors reporting the same fingerprint are two accounts of one
        fact and accumulate as such; a fingerprint and a wallet cluster are two facts and are
        independent evidence.

        This is the axis the robustness margin works on, and it is deliberately *not* the
        independence key. That one answers "were these signals produced by one choice of the
        actor's?"; this one answers "how many different things about the world would an
        adversary have had to arrange?". A linkage resting on one arranged thing is not a
        linkage, however many collectors found it.
        """
        return f"persona-linkage-fact:{self.kind.value}:{self.shared_attribute}"

    def to_sourced_opinion(self, *, base_rate: float) -> SourcedOpinion:
        """Package this signal for fusion, stamped with its correlation group.

        The stamp deliberately overrides whatever independence key the descriptor carried.
        Within one assessment every signal describes a different *attribute* of the same
        pair of personas, so two signals are not dependent because one collector carried
        both — they are dependent because one actor's single choice produced both. Grouping
        by collection channel here would collapse a wallet cluster into a published alias
        merely for having arrived through the same feed, while leaving two self-presentation
        signals from two venues to masquerade as corroboration.

        The residual risk the override creates — every signal reaching us through one
        poisonable channel — is not silently absorbed. The engine reports it as a caveat.
        """
        grouped = self.observed_by.model_copy(
            update={"upstream_of_record": self.independence_key()}
        )
        return SourcedOpinion(
            source=grouped,
            opinion=self.to_opinion(base_rate=base_rate),
            supporting_claims=self.supporting_claims,
            label=self.kind.value,
            fact_key=self.fact_key(),
        )


# ---------------------------------------------------------------------------
# Extractors
#
# Each builds one signal from raw observations. They are the place where a naive
# implementation goes wrong quietly, so each names the population its attribute was counted
# against and refuses to guess when nobody counted.
# ---------------------------------------------------------------------------


def _selectivity(
    attribute: str,
    *,
    population_size: int | None,
    population_corpus: str | None,
    is_globally_unique: bool = False,
) -> PivotSelectivity:
    return PivotSelectivity(
        attribute=attribute,
        population_size=population_size,
        population_measured_against=population_corpus,
        is_globally_unique=is_globally_unique,
    )


def shared_cryptographic_identity(
    *,
    fingerprint: str,
    observed_by: SourceDescriptor,
    key_type: EntityType = EntityType.PGP_KEY,
    demonstrated_key_control: bool = False,
    supporting_claims: tuple[ClaimId, ...] = (),
    note: str = "",
) -> LinkageSignal:
    """Both personas published the same full key fingerprint.

    Normalization is delegated to :func:`nemesis.core.entities.normalize_identifier`, which
    refuses anything shorter than a 160-bit PGP fingerprint. That refusal is the point: a
    32-bit key id can be collided on a laptop, and an engine that accepted one would hand an
    adversary a way to manufacture identity between any two personas it chose.
    """
    if key_type not in _KEY_ENTITY_TYPES:
        raise ValueError(f"{key_type.value} is not a key type; expected a PGP or SSH key")
    normalized = normalize_identifier(key_type, fingerprint)
    return LinkageSignal(
        kind=LinkageSignalKind.SHARED_CRYPTOGRAPHIC_IDENTITY,
        observed_by=observed_by,
        shared_attribute=f"{key_type.value}:{normalized}",
        selectivity=_selectivity(
            f"{key_type.value} fingerprint",
            population_size=None,
            population_corpus=None,
            is_globally_unique=True,
        ),
        demonstrated_key_control=demonstrated_key_control,
        supporting_claims=supporting_claims,
        note=note,
    )


def shared_contact_handle(
    *,
    handle: str,
    platform: str,
    observed_by: SourceDescriptor,
    population_size: int | None = None,
    population_corpus: str | None = None,
    supporting_claims: tuple[ClaimId, ...] = (),
    note: str = "",
) -> LinkageSignal:
    """Both personas advertise the same messaging handle or address.

    ``population_size`` is how many personas in the corpus advertise this handle, not how
    many messages were seen. Shop fronts, escrow services and resellers are advertised by
    many unrelated vendors, and that is exactly the case the count exists to catch.
    """
    return LinkageSignal(
        kind=LinkageSignalKind.SHARED_CONTACT_HANDLE,
        observed_by=observed_by,
        shared_attribute=f"{platform}:{handle.strip().casefold()}",
        selectivity=_selectivity(
            f"{platform} handle",
            population_size=population_size,
            population_corpus=population_corpus,
        ),
        supporting_claims=supporting_claims,
        note=note,
    )


def shared_wallet_cluster(
    *,
    cluster_identifier: str,
    heuristic: str,
    heuristic_reliability: float,
    known_failure_modes: Sequence[str],
    observed_by: SourceDescriptor,
    population_size: int | None = None,
    population_corpus: str | None = None,
    supporting_claims: tuple[ClaimId, ...] = (),
) -> LinkageSignal:
    """Addresses used by both personas fall into one heuristic wallet cluster.

    ``heuristic_reliability`` has no default on purpose. Multi-input clustering is an
    inference about wallet software, not a fact about the ledger, and its documented failure
    modes — CoinJoin, mixers, custodial services that co-spend for unrelated customers —
    are precisely the tools a paid criminal vendor uses. A caller who cannot state how often
    the heuristic is wrong has not established that the two personas share anything.
    """
    if not 0.0 <= heuristic_reliability <= 1.0:
        raise ValueError("heuristic_reliability must lie in [0, 1]")
    failures = ", ".join(known_failure_modes) or "none stated"
    return LinkageSignal(
        kind=LinkageSignalKind.SHARED_WALLET_CLUSTER,
        observed_by=observed_by,
        shared_attribute=f"cluster:{cluster_identifier}",
        selectivity=_selectivity(
            f"wallet cluster {cluster_identifier}",
            population_size=population_size,
            population_corpus=population_corpus,
        ),
        match_strength=heuristic_reliability,
        supporting_claims=supporting_claims,
        note=f"clustering heuristic {heuristic!r}; known failure modes: {failures}",
    )


def _alphanumeric(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def alias_similarity(
    *,
    alias_a: str,
    alias_b: str,
    observed_by: SourceDescriptor,
    stem_population_size: int | None = None,
    population_corpus: str | None = None,
    supporting_claims: tuple[ClaimId, ...] = (),
) -> LinkageSignal:
    """The two names resemble each other.

    Similarity is computed on the case-folded alphanumeric forms, so ``Gl4ss_Anvil`` and
    ``GlassAnvil`` are not treated as unrelated. The ratio alone is close to meaningless —
    two three-letter handles collide by chance — so ``stem_population_size`` (how many
    personas in the corpus carry the shared stem) is what decides whether the resemblance
    discriminates. Left uncounted, the signal is worth nothing, which is correct.
    """
    left, right = _alphanumeric(alias_a), _alphanumeric(alias_b)
    if not left or not right:
        raise ValueError("an alias must contain at least one alphanumeric character")
    matcher = difflib.SequenceMatcher(None, left, right)
    longest = matcher.find_longest_match(0, len(left), 0, len(right))
    stem = left[longest.a : longest.a + longest.size]
    return LinkageSignal(
        kind=LinkageSignalKind.ALIAS_SIMILARITY,
        observed_by=observed_by,
        shared_attribute=f"stem:{stem}" if stem else "stem:<none>",
        selectivity=_selectivity(
            f"alias stem {stem!r}",
            population_size=stem_population_size,
            population_corpus=population_corpus,
        ),
        match_strength=matcher.ratio(),
        supporting_claims=supporting_claims,
        note=(
            f"{alias_a!r} vs {alias_b!r}: similarity {matcher.ratio():.2f}, "
            f"longest shared run {stem!r}"
        ),
    )


def activity_hour_overlap(
    *,
    hours_a: Sequence[int],
    hours_b: Sequence[int],
    observed_by: SourceDescriptor,
    population_size: int | None = None,
    population_corpus: str | None = None,
    supporting_claims: tuple[ClaimId, ...] = (),
) -> LinkageSignal:
    """The two posting routines occupy the same hours of the day.

    ``hours_a`` and ``hours_b`` are the UTC hour of every observed post, repeats included,
    because the sample size is half the answer: overlap computed over five posts describes
    when the collector looked, not when the operator works. Below
    :data:`MIN_POSTS_FOR_A_ROUTINE` the strength is scaled down proportionally.

    A working window is not a timezone and a timezone is not a nationality or an identity.
    Roughly a twelfth of the internet shares any given window, which is why the result is
    still governed by ``population_size`` — how many personas in the corpus post in the
    same window — and why the ceiling for this kind is low.
    """
    if not hours_a or not hours_b:
        raise ValueError("both personas need at least one observed posting hour")
    for hour in (*hours_a, *hours_b):
        if not 0 <= hour <= 23:
            raise ValueError(f"{hour} is not a UTC hour of the day")

    set_a, set_b = set(hours_a), set(hours_b)
    overlap = len(set_a & set_b) / len(set_a | set_b)
    sample_confidence = min(1.0, min(len(hours_a), len(hours_b)) / MIN_POSTS_FOR_A_ROUTINE)

    supports = overlap > 0.0
    direction = SignalDirection.SUPPORTS if supports else SignalDirection.CONTRADICTS
    strength = (overlap if supports else 1.0) * sample_confidence

    # Reported as min..max rather than as a modal window: a routine that straddles midnight
    # is not contiguous in UTC, and printing a tidy range there would misdescribe it.
    window_a = f"{min(set_a):02d}-{max(set_a):02d}"
    window_b = f"{min(set_b):02d}-{max(set_b):02d}"
    return LinkageSignal(
        kind=LinkageSignalKind.ACTIVITY_HOURS_OVERLAP,
        observed_by=observed_by,
        shared_attribute=f"utc-hours:{window_a}|{window_b}",
        selectivity=_selectivity(
            "utc posting window",
            population_size=population_size,
            population_corpus=population_corpus,
        ),
        match_strength=strength,
        direction=direction,
        supporting_claims=supporting_claims,
        note=(
            f"{len(hours_a)} and {len(hours_b)} posts; UTC windows {window_a} and "
            f"{window_b}; hour-set overlap {overlap:.2f}"
        ),
    )


def infrastructure_reuse(
    *,
    attribute: str,
    infrastructure_type: EntityType,
    observed_by: SourceDescriptor,
    population_size: int | None = None,
    population_corpus: str | None = None,
    shared_infrastructure_justification: str | None = None,
    supporting_claims: tuple[ClaimId, ...] = (),
    note: str = "",
) -> LinkageSignal:
    """Both personas are tied to the same host, certificate or netblock.

    Mirrors the rule :class:`~nemesis.core.relationships.Relationship` enforces on edges: an
    attribute whose type is shared by unrelated parties by default — a registrar, an
    exchange, an ASN, a proxy — needs a stated reason why *this* instance means something.
    Without it, every tenant of a bulletproof host becomes the same operator.
    """
    if infrastructure_type in SHARED_INFRASTRUCTURE_TYPES and not (
        shared_infrastructure_justification
    ):
        raise ValueError(
            f"{infrastructure_type.value} is shared by unrelated parties by default; "
            "linking two personas through it requires an explicit justification"
        )
    reason = shared_infrastructure_justification
    return LinkageSignal(
        kind=LinkageSignalKind.INFRASTRUCTURE_REUSE,
        observed_by=observed_by,
        shared_attribute=f"{infrastructure_type.value}:{attribute}",
        selectivity=_selectivity(
            f"{infrastructure_type.value} {attribute}",
            population_size=population_size,
            population_corpus=population_corpus,
        ),
        supporting_claims=supporting_claims,
        note=f"{note} {reason or ''}".strip(),
    )


def writing_style_similarity(
    *,
    score: float,
    method: str,
    candidate_set_size: int,
    population_corpus: str,
    observed_by: SourceDescriptor,
    open_world: bool = True,
    obfuscation_indicators: Sequence[str] = (),
    supporting_claims: tuple[ClaimId, ...] = (),
) -> LinkageSignal:
    """An authorship-attribution method scored the two bodies of text as similar.

    Three discounts apply before the ceiling in :data:`STYLOMETRY_BELIEF_CEILING` even
    comes into play:

    - ``candidate_set_size`` becomes the selectivity population, so a match found against
      three candidates and a match found against thirty thousand are not the same finding.
    - ``open_world`` (the default, and the real case) halves the score, because published
      accuracy figures almost always come from closed-world experiments where the true
      author is guaranteed to be in the set.
    - any ``obfuscation_indicators`` cut it by four fifths, because deliberate obfuscation
      is the documented way to defeat these methods and a persona that has survived a
      takedown has every reason to use it.

    Even at a perfect score against two candidates in a closed world with no obfuscation,
    the resulting opinion stays vacuous. That is not a bug to tune away.
    """
    if not 0.0 <= score <= 1.0:
        raise ValueError("a stylometric score must lie in [0, 1]")
    if candidate_set_size < 2:
        raise ValueError("a candidate set smaller than two candidates decides nothing")

    strength = score
    if open_world:
        strength *= OPEN_WORLD_STYLOMETRY_PENALTY
    if obfuscation_indicators:
        strength *= OBFUSCATION_STYLOMETRY_PENALTY

    world = "open-world" if open_world else "closed-world"
    flags = ", ".join(obfuscation_indicators) or "none observed"
    return LinkageSignal(
        kind=LinkageSignalKind.WRITING_STYLE_SIMILARITY,
        observed_by=observed_by,
        shared_attribute=f"stylometry:{method}",
        selectivity=_selectivity(
            f"{method} candidate set",
            population_size=candidate_set_size,
            population_corpus=population_corpus,
        ),
        match_strength=strength,
        supporting_claims=supporting_claims,
        note=(
            f"{method} scored {score:.2f} {world} against {candidate_set_size} candidates; "
            f"obfuscation indicators: {flags}"
        ),
    )
