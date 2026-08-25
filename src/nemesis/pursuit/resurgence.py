"""Recognising an adversary whose indicators have all changed.

A disruption that works destroys the adversary's operational continuity. It must not destroy
ours. When the C2 goes dark, the domain lapses and the persona stops posting, the question is
not "is this indicator on a list" — every indicator is new by construction — but *does the
combined evidence support, and how strongly, that this new cluster is the campaign we already
know*.

**The failure that matters is not missing a return.** It is deciding two unrelated operations
are one because they share a registrar, a hosting provider or a TLS stack. That mistake
compounds: a wrongly merged cluster makes the next link look better supported, and the error
propagates through every conclusion downstream of it. Most of the machinery here exists to
refuse.

**None of the arithmetic is new.** :func:`~nemesis.core.fusion.fuse` already stages sources by
fact, collapses dependent origins, and applies the robustness margin that drops the most
load-bearing plantable fact; :class:`~nemesis.core.relationships.PivotSelectivity` already turns
"shares an attribute" into a weight that goes to zero when nobody counted the population. This
module contributes a vocabulary and a set of ceilings, and hands the sums to code that was
adversarially tested before it existed.

**Why not in** :mod:`nemesis.resolve`. That plane holds the same shape of calculus for persona
linkage, and reusing it directly was the obvious move. Two things stop it. Its
``PROPOSITION_TEMPLATE`` hard-locks it to one sentence about two personas; and everything it
emits is ``INTERNAL_LEAD`` under founder decision D1, while a campaign-resurgence finding is a
deliverable. Routing a deliverable through a quarantined plane either breaks an import contract
or misclassifies the output. Moving the shared calculus into ``core`` is the better long-term
answer and is deliberately not attempted here: it would relocate the repository's most
safety-critical arithmetic in the same change that adds a feature, turning the calibration
freeze red across the whole diff at exactly the moment a reviewer's attention is worst.

**A limitation the local bench measured, and it is not small.** The robustness margin keeps a
fact attested by a channel an adversary cannot author, and
:attr:`~nemesis.core.provenance.SourceDescriptor.is_adversary_influenceable` justifies that by
saying an adversary "can cause an observation but cannot author the record". For artifact-borne
signals those two come apart. :mod:`nemesis.calibration.localbench` runs a framer — a different
operator who copies another's public key and kit — and our own sensor honestly observes both
artifacts, so the margin leaves them standing and this engine calls the framer a resurgence of
the party they framed. **2 of 3 adversarial pairs on that bench.**

The margin's model is about who authored the *record*, not who arranged the *fact*, and causing
the observation turns out to be enough. Nothing here fixes it: the fix is a threat-model change
rather than a constant, and it belongs in an ADR rather than in a quiet edit to a ceiling.

**Disclosure travels with the evidence.** An assessment resting on a persona signal takes the
persona's classification. The wrapper does not get to publish what its contents may not say,
and this is the one place a resurgence finding could have laundered an internal lead into a
deliverable.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.confidence import ConfidenceBand, Opinion, band_of, describe
from nemesis.core.disclosure import DisclosureClass, disclosure_of_entity, most_restrictive
from nemesis.core.entities import EntityType
from nemesis.core.fusion import FusionResult, SourcedOpinion, fuse
from nemesis.core.ids import ClaimId
from nemesis.core.proposition import PropositionClass
from nemesis.core.provenance import SourceDescriptor
from nemesis.core.relationships import PivotSelectivity
from nemesis.core.temporal import TemporalExtent


class ResurgenceSignalKind(StrEnum):
    """What kind of continuity was observed between the old operation and the new one."""

    SHARED_PRIVATE_KEY = "shared_private_key"
    """The new infrastructure proves control of key material the old operation used.

    A private key is not shared by accident. This is the strongest signal available and it is
    still not certainty: an adversary who lost a key, or one framing a competitor with a stolen
    one, produces the same observation."""

    SHARED_EXFILTRATION_ENDPOINT = "shared_exfiltration_endpoint"
    """The new operation delivers its takings to where the old one did.

    Ranked just below key control and above a republished fingerprint, and the argument is the
    fixture's own: an exfiltration endpoint has to *work for the operator*, which makes it
    expensive to fake compared with a comment. Copying a drop address to have somebody else
    blamed means sending your victims' credentials to the party you are framing — a cost a
    framer does not usually accept, and one a lazy imitator gains nothing from."""

    SHARED_PUBLISHED_FINGERPRINT = "shared_published_fingerprint"
    """A public fingerprint the operator republishes — a PGP key on a new persona's profile.

    Weaker than key control because publishing a fingerprint demonstrates nothing about holding
    the key. Anyone can copy a public value onto a profile, and doing so is the cheapest way to
    make a new operation look like an old one."""

    SHARED_TOOLING_ARTIFACT = "shared_tooling_artifact"
    """A trace of the same toolchain: a build path, a beacon configuration, a kit hash."""

    SHARED_FINANCIAL_ENDPOINT = "shared_financial_endpoint"
    """Funds moving to an address clustered with the old operation's."""

    PROVIDER_AND_TIMING_PATTERN = "provider_and_timing_pattern"
    """The same provider, in the same kind of window. Weak by construction: providers are
    shared by tens of thousands of unrelated parties, which is what the selectivity count is
    for."""

    NAMING_PATTERN = "naming_pattern"
    """The domains resemble the old ones. The weakest signal and the easiest to imitate — and
    therefore the easiest to use to frame somebody."""


class SuccessionGroup(StrEnum):
    """The generating process a signal is a trace of.

    Two signals from one process are one choice of the operator's, not two pieces of evidence.
    An adversary who reuses a single key across five hosts must not thereby produce five
    independent confirmations of their own return.
    """

    KEY_CONTROL = "key_control"
    EXFILTRATION = "exfiltration"
    SELF_PRESENTATION = "self_presentation"
    TOOLING = "tooling"
    FINANCIAL_LEDGER = "financial_ledger"
    PROVIDER_CHOICE = "provider_choice"


BELIEF_CEILING: Final[dict[ResurgenceSignalKind, float]] = {
    ResurgenceSignalKind.SHARED_PRIVATE_KEY: 0.90,
    ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT: 0.75,
    ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT: 0.70,
    ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT: 0.60,
    ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT: 0.50,
    ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN: 0.30,
    ResurgenceSignalKind.NAMING_PATTERN: 0.15,
}
"""The most any one signal of this kind may contribute, before selectivity is applied.

**These are invented numbers and nothing in this repository validates them.** They are ordered
by how expensive the signal is to stage — the principle the persona-linkage table already uses
and defends.

**This docstring used to add that the ordering was the defensible part and the magnitudes were
not. That was an assertion, and measuring it did not support it.**
:mod:`nemesis.calibration.ceilings` perturbs the table and counts the verdicts that move: a
uniform scaling to 0.6, which preserves the ordering perfectly, moved one probe verdict, while
flattening every ceiling to the mean — which destroys the ordering entirely — moved none. On
that probe set the magnitudes are doing at least as much work as the order.

What survives unchanged is that the *structural* controls do not depend on any ceiling being
right: the correlation grouping, the zero-for-uncounted-populations rule, the robustness margin
and the single-origin veto hold whatever these numbers are. A reviewer cutting one thing should
still keep those. What they should no longer be told is that the numbers beside them are
harmless.

No confidence figure this system produces has been validated against outcomes, and as of
2026-08-24 none will be: the controlled-operations experiment that was the only path to ground
truth here was costed at ~283 operations for a ±10% answer and declined (ADR-0012).

**So read every band this module produces as ordinal, not probabilistic.** *Likely* means this
engine ranked something above what it calls *unlikely*. It does not mean 70%, and a consumer
treating it as a probability is making a claim the project has explicitly declined to fund. See
``docs/calibration/PROTOCOL.md`` and :mod:`nemesis.calibration.ceilings`, which measures how much
these numbers are load-bearing rather than asserting that they are not.
"""

CORRELATION_GROUP_OF: Final[dict[ResurgenceSignalKind, SuccessionGroup]] = {
    ResurgenceSignalKind.SHARED_PRIVATE_KEY: SuccessionGroup.KEY_CONTROL,
    ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT: SuccessionGroup.EXFILTRATION,
    ResurgenceSignalKind.SHARED_PUBLISHED_FINGERPRINT: SuccessionGroup.SELF_PRESENTATION,
    ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT: SuccessionGroup.TOOLING,
    ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT: SuccessionGroup.FINANCIAL_LEDGER,
    ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN: SuccessionGroup.PROVIDER_CHOICE,
    ResurgenceSignalKind.NAMING_PATTERN: SuccessionGroup.SELF_PRESENTATION,
}
"""``NAMING_PATTERN`` groups with self-presentation deliberately: a domain-naming habit and a
republished fingerprint are both things the operator chose to show, and they are correlated for
that reason rather than because one collector found both."""


FRAMER_COSTLY_KINDS: Final[frozenset[ResurgenceSignalKind]] = frozenset(
    {
        ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT,
        ResurgenceSignalKind.SHARED_FINANCIAL_ENDPOINT,
    }
)
"""Signals a framer cannot present without handing the proceeds to the party being framed.

**An allowlist, and everything not named here is cheap.** The same discipline
:func:`~nemesis.core.provenance.SourceDescriptor.is_adversary_influenceable` adopted after its
blocklist version turned out to be the bug: a kind nobody has classified must be unable, on its
own, to make a finding actionable. The opposite default flatters the evidence, which is the
direction that takes somebody's infrastructure away.

The membership test is not "how hard was this to obtain" — it is **"what does using it to frame
somebody cost the framer, continuously".** Both members route the operation's *takings*:

- ``SHARED_EXFILTRATION_ENDPOINT`` — the module's own argument, and the reason this table has
  the shape it does: "Copying a drop address to have somebody else blamed means sending your
  victims' credentials to the party you are framing."
- ``SHARED_FINANCIAL_ENDPOINT`` — the same mechanism with money. Its own docstring does not make
  this argument and it is made here: funds moving to an address clustered with the old
  operation's means the framer's proceeds land in the framed party's cluster.

Notably absent, and this is the point of ADR-0013 rather than an oversight:

- ``SHARED_PRIVATE_KEY`` carries the highest ceiling and is **not** framer-costly. Stealing a key
  is expensive; *using a stolen one* costs nothing further, and this module's own docstring says
  so — "an adversary who lost a key, or one framing a competitor with a stolen one, produces the
  same observation". A ceiling ordered by acquisition cost cannot answer a question about
  ongoing cost.
- ``SHARED_TOOLING_ARTIFACT`` is a copy. On the local bench it is the fact that tips a framed
  pair past the single-origin veto, having cost the framer nothing.
"""


def _check_tables_are_total() -> None:
    """Import-time check, in the house style of ``authorization._check_risk_table``.

    A new signal kind with no ceiling would default to being maximally persuasive under a
    ``dict.get(kind, 1.0)``, and a new kind with no group would collapse with nothing and
    accumulate freely. Both failures flatter the evidence, which is the direction that gets
    somebody's server taken away.
    """
    missing_ceiling = set(ResurgenceSignalKind) - set(BELIEF_CEILING)
    missing_group = set(ResurgenceSignalKind) - set(CORRELATION_GROUP_OF)
    if missing_ceiling or missing_group:
        raise RuntimeError(
            f"resurgence signal kind(s) without a ceiling {sorted(missing_ceiling)} or a "
            f"correlation group {sorted(missing_group)}"
        )
    unknown = FRAMER_COSTLY_KINDS - set(ResurgenceSignalKind)
    if unknown:
        raise RuntimeError(f"FRAMER_COSTLY_KINDS names non-kinds {sorted(unknown)}")
    if not FRAMER_COSTLY_KINDS:
        raise RuntimeError(
            "FRAMER_COSTLY_KINDS is empty, which makes every resurgence finding unreachable; "
            "an empty allowlist is a refusal to decide wearing a control's name"
        )


_check_tables_are_total()


IRREDUCIBLE_UNCERTAINTY: Final = 0.02
"""No finite evidence about an adversary actively trying to mislead us yields certainty."""

BASE_RATE_FLOOR: Final = 1e-6
BASE_RATE_CEILING: Final = 0.25

ACTIONABLE_FLOOR: Final = 0.55
"""Below this projected probability a resurgence claim is not something to act on.

The same value and the same argument as the ownership floor in the disruption plane: a
resurgence finding feeds a decision to re-open a case against a named campaign, and "likely"
is not good enough to carry that.
"""


def base_rate_for_campaign_population(
    candidate_population: int, *, tracked_fraction: float = 0.30
) -> float:
    """The prior that a new cluster belongs to one *particular* tracked campaign.

    Two factors, kept separate because they fail differently. ``tracked_fraction`` is the share
    of new malicious infrastructure attributable to any campaign we already follow — most of the
    internet's new badness belongs to somebody we have never heard of, and assuming otherwise is
    how every new cluster becomes a returning adversary. The second factor is one over the
    number of campaigns tracked: given that it *is* one of ours, it is a priori any of them.

    Both are assumptions rather than measurements. ``tracked_fraction`` in particular is a guess
    stated as a parameter so that it can be argued with rather than buried in a constant.
    """
    if candidate_population < 2:
        raise ValueError(
            "a corpus of fewer than two campaigns contains no alternative to assess; pass the "
            "number of campaigns the cluster was compared against, not one"
        )
    if not 0.0 < tracked_fraction <= 1.0:
        raise ValueError("tracked_fraction is a share and must fall in (0, 1]")
    raw = tracked_fraction / candidate_population
    return min(BASE_RATE_CEILING, max(BASE_RATE_FLOOR, raw))


class ResurgenceSignal(BaseModel):
    """One observed continuity between a known campaign and a candidate cluster."""

    model_config = ConfigDict(frozen=True)

    kind: ResurgenceSignalKind
    shared_attribute: Annotated[str, Field(min_length=1)]
    selectivity: PivotSelectivity
    observed_by: SourceDescriptor

    new_entity_type: EntityType
    new_entity_key: Annotated[str, Field(min_length=1)]
    prior_entity_key: Annotated[str, Field(min_length=1)]

    match_strength: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    """How well the two observations agree. Exact identity is 1.0; a fuzzy resemblance is not."""

    extent: TemporalExtent
    supporting_claims: tuple[ClaimId, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.selectivity.attribute != self.shared_attribute:
            raise ValueError(
                "the selectivity must be measured against the attribute this signal shares; "
                "counting one population and citing another is not a count"
            )
        return self

    @property
    def correlation_group(self) -> SuccessionGroup:
        return CORRELATION_GROUP_OF[self.kind]

    @property
    def belief_ceiling(self) -> float:
        return BELIEF_CEILING[self.kind]

    @property
    def disclosure(self) -> DisclosureClass:
        """What the entity this signal points at may be said about.

        A signal naming a persona carries the persona's class, so an assessment built from it
        cannot be published as a deliverable however infrastructural the rest of it looks.
        """
        return disclosure_of_entity(self.new_entity_type)

    @property
    def evidential_weight(self) -> float:
        """Selectivity times agreement. Zero when nobody counted the population."""
        return self.selectivity.evidential_weight() * self.match_strength

    def to_opinion(self, *, base_rate: float) -> Opinion:
        """The opinion this signal alone justifies, before trust discounting.

        Everything not committed to belief is uncertainty, never disbelief: a weak signal must
        leave us ignorant about a return, not convinced there was none.
        """
        mass = min(self.belief_ceiling * self.evidential_weight, 1.0 - IRREDUCIBLE_UNCERTAINTY)
        return Opinion(belief=mass, disbelief=0.0, uncertainty=1.0 - mass, base_rate=base_rate)

    def independence_key(self) -> str:
        """The key :func:`fuse` collapses on: the generating process, not the channel.

        Two signals are dependent because one choice of the operator's produced both, not
        because one collector carried both. Grouping by collection channel instead would let two
        self-presentation signals from two venues masquerade as corroboration.
        """
        return f"resurgence:{self.correlation_group.value}"

    def fact_key(self) -> str:
        """Which fact about the world this attests.

        The axis the robustness margin works on, and deliberately not the independence key. That
        one asks "were these produced by one choice of the actor's"; this asks "how many
        different things would an adversary have had to arrange". A resurgence resting on one
        arranged thing is not a resurgence, however many collectors found it.
        """
        return f"resurgence-fact:{self.kind.value}:{self.shared_attribute}"

    def to_sourced_opinion(self, *, base_rate: float) -> SourcedOpinion:
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


class AlternativeExplanation(BaseModel):
    """A competing account of the same observations."""

    model_config = ConfigDict(frozen=True)

    hypothesis: Annotated[str, Field(min_length=1)]
    would_be_ruled_out_by: Annotated[str, Field(min_length=1)]


class SignalContribution(BaseModel):
    """What one signal actually moved, after selectivity and collapse."""

    model_config = ConfigDict(frozen=True)

    kind: ResurgenceSignalKind
    shared_attribute: str
    weight: float
    ceiling: float
    group: SuccessionGroup

    @property
    def is_negligible(self) -> bool:
        return self.weight < 0.01


class ResurgenceAssessment(BaseModel):
    """Whether a candidate cluster is a known campaign returning, and on what basis."""

    model_config = ConfigDict(frozen=True)

    campaign: Annotated[str, Field(min_length=1)]
    assessed_at: datetime
    opinion: Opinion
    fusion: FusionResult
    contributions: tuple[SignalContribution, ...] = ()
    alternatives: tuple[AlternativeExplanation, ...] = ()
    disclosure: DisclosureClass = DisclosureClass.DELIVERABLE
    base_rate: float = 0.0
    candidate_population: int = 0

    @property
    def band(self) -> ConfidenceBand:
        return band_of(self.opinion)

    @property
    def rests_on_internal_material(self) -> bool:
        return self.disclosure is not DisclosureClass.DELIVERABLE

    @property
    def is_single_origin(self) -> bool:
        """Whether everything here traces back to one independent origin."""
        return self.fusion.is_single_sourced

    @property
    def is_actionable(self) -> bool:
        """Whether this is strong enough to re-open a case against the named campaign.

        Five conditions, each able to veto. The band must be estimable at all; the projected
        probability must clear the floor; the finding must not rest solely on facts an adversary
        could have planted; it must not rest on a single independent origin; and at least one
        contributing signal must be one a framer could not present without paying for it.

        The fifth was added by ADR-0013, after the local bench attributed a *framer* — a
        different operator who copied a key and a kit — to the party they framed, in 2 of 3
        adversarial pairs. The measurement that decided its shape: the genuine pair and the
        framed pair are the same object, band by band and field by field, because the
        observations are identical. Nothing that reweights what is already there can separate
        them, so the veto asks for something else to be present rather than scoring what is.

        Why a fifth veto and not a correction to the fourth: an adversary can *cause* an
        observation our own sensor honestly records, and the plantability model is about who
        authored the record. For a copyable artifact those come apart, and the margin —
        correctly, by its own terms — leaves the framer's facts standing.

        The last one is not implied by the others and was added after measuring: one
        certificate match attested by one own-sensor — unplantable, so the robustness margin
        leaves it standing — projected 0.811 and read as *very likely*. The margin defends
        against arranged evidence and says nothing about fragility. This repository's own rule,
        written into the disruption plane's ownership test, is that a single confident source
        and three corroborating ones can project the same probability and only the second is
        safe to act on. A resurgence finding re-opens a case against a named campaign, which is
        exactly the kind of decision that rule exists for.
        """
        return (
            self.band is not ConfidenceBand.INSUFFICIENT_BASIS
            and self.opinion.projected_probability >= ACTIONABLE_FLOOR
            and not self.fusion.rests_only_on_plantable_evidence
            and not self.is_single_origin
            and self.has_framer_costly_signal
        )

    @property
    def has_framer_costly_signal(self) -> bool:
        """Whether any contributing signal is one a framer would have to pay to present.

        Read off :data:`FRAMER_COSTLY_KINDS`, which is an allowlist: a kind nobody classified is
        cheap. Separate from :meth:`is_actionable` so a reader can see *which* veto refused, and
        so the renderer can say it.
        """
        return any(item.kind in FRAMER_COSTLY_KINDS for item in self.contributions)

    def render(self) -> str:
        lines = [
            f"Resurgence assessment for {self.campaign}: {describe(self.opinion)}",
            f"  prior: {self.base_rate:.2e} against {self.candidate_population} tracked "
            f"campaign(s)",
            f"  disclosure: {self.disclosure.value}",
        ]
        if not self.contributions:
            lines.append("  no signals were offered; this is a prior, not a finding")
        for item in self.contributions:
            note = " (negligible)" if item.is_negligible else ""
            lines.append(
                f"  {item.kind.value}: {item.shared_attribute} — weight {item.weight:.2f} "
                f"of ceiling {item.ceiling:.2f} [{item.group.value}]{note}"
            )
        for warning in self.fusion.warnings:
            lines.append(f"  ! {warning}")
        for alternative in self.alternatives:
            lines.append(f"  alternative: {alternative.hypothesis}")
            lines.append(f"    ruled out by: {alternative.would_be_ruled_out_by}")
        if self.is_single_origin:
            lines.append(
                "  ! everything here traces to one independent origin; corroboration from a "
                "second would change what this supports"
            )
        lines.append(
            "  actionable: "
            + ("yes" if self.is_actionable else "no — this is a lead, not a conclusion")
        )
        return "\n".join(lines)


def _alternatives_for(signals: Sequence[ResurgenceSignal]) -> tuple[AlternativeExplanation, ...]:
    """Competing accounts, always at least one.

    A finding with no alternative on the page is an argument rather than an assessment, and the
    two that matter here are the ones an adversary can arrange on purpose.
    """
    alternatives = [
        AlternativeExplanation(
            hypothesis=(
                "Another operator copied the observable — a published certificate, a leaked "
                "kit, a documented naming habit — either to save effort or to be mistaken for "
                "this campaign."
            ),
            would_be_ruled_out_by=(
                "A signal requiring possession rather than knowledge: demonstrated control of "
                "the private key, or an artifact never published anywhere."
            ),
        ),
        AlternativeExplanation(
            hypothesis=(
                "The observables are staged. An adversary who wants this campaign blamed can "
                "arrange every fact an honest collector then finds."
            ),
            would_be_ruled_out_by=(
                "A fact attested by a channel the adversary cannot write into, which is what "
                "the robustness margin already tests for."
            ),
        ),
    ]
    if any(signal.selectivity.population_size is None for signal in signals):
        alternatives.append(
            AlternativeExplanation(
                hypothesis=(
                    "The shared attribute is simply common, and nobody counted how common."
                ),
                would_be_ruled_out_by=(
                    "A population count against a named corpus and date for every attribute "
                    "offered as evidence."
                ),
            )
        )
    if any(
        signal.kind
        in {
            ResurgenceSignalKind.PROVIDER_AND_TIMING_PATTERN,
            ResurgenceSignalKind.NAMING_PATTERN,
        }
        for signal in signals
    ):
        alternatives.append(
            AlternativeExplanation(
                hypothesis=(
                    "Both operations independently chose a provider and a naming style that "
                    "large numbers of unrelated operations also choose."
                ),
                would_be_ruled_out_by=(
                    "A signal that does not rest on a choice thousands of others make too."
                ),
            )
        )
    return tuple(alternatives)


class ResurgenceEngine:
    """Scores whether a candidate cluster is a known campaign returning.

    Stateless, holds no graph handle and reaches no collector: it reasons over signals it is
    handed and returns a judgement. Assembling the signals from the graph is the caller's job,
    which keeps the scoring testable without a world and keeps this plane unable to go looking
    for evidence that would support the answer it is reaching.
    """

    def __init__(self, *, tracked_fraction: float = 0.30) -> None:
        self._tracked_fraction = tracked_fraction

    def assess(
        self,
        *,
        campaign: str,
        signals: Sequence[ResurgenceSignal],
        candidate_population: int,
        assessed_at: datetime,
    ) -> ResurgenceAssessment:
        """Fuse the signals into one judgement about one campaign.

        ``candidate_population`` has no default for the same reason the persona engine's does
        not: every value that could be defaulted is either the permissive one that produces a
        confident answer from a weak resemblance, or a strict one that silently suppresses real
        findings. The caller states what corpus the comparison was drawn from.
        """
        base_rate = base_rate_for_campaign_population(
            max(candidate_population, 2), tracked_fraction=self._tracked_fraction
        )
        sourced = [signal.to_sourced_opinion(base_rate=base_rate) for signal in signals]
        result = fuse(sourced, proposition=PropositionClass.SHARED_ORIGIN)

        # The fused opinion carries the base rate of whatever it was handed; restate the prior
        # explicitly so a reader sees which number the projection rests on.
        opinion = result.opinion.model_copy(update={"base_rate": base_rate})

        disclosure = most_restrictive(
            DisclosureClass.DELIVERABLE, *(signal.disclosure for signal in signals)
        )
        contributions = tuple(
            SignalContribution(
                kind=signal.kind,
                shared_attribute=signal.shared_attribute,
                weight=signal.evidential_weight,
                ceiling=signal.belief_ceiling,
                group=signal.correlation_group,
            )
            for signal in signals
        )
        return ResurgenceAssessment(
            campaign=campaign,
            assessed_at=assessed_at,
            opinion=opinion,
            fusion=result,
            contributions=contributions,
            alternatives=_alternatives_for(signals),
            disclosure=disclosure,
            base_rate=base_rate,
            candidate_population=candidate_population,
        )


__all__ = [
    "ACTIONABLE_FLOOR",
    "BELIEF_CEILING",
    "CORRELATION_GROUP_OF",
    "AlternativeExplanation",
    "ResurgenceAssessment",
    "ResurgenceEngine",
    "ResurgenceSignal",
    "ResurgenceSignalKind",
    "SignalContribution",
    "SuccessionGroup",
    "base_rate_for_campaign_population",
]
