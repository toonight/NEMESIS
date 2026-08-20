"""Evidence fusion: combining what several sources said into one calibrated opinion.

This is the module where attribution goes wrong quietly, so the choices here are argued
rather than asserted. Three of them were made against the obvious answer, after checking
the primary sources; see ADR-0002 for the full record.

**Dependent sources are fused with Weighted Belief Fusion, not Averaging Belief Fusion.**
The textbook answer is that averaging fusion is the operator for dependent sources, and
that is what Jøsang says. But ABF has no neutral element: a source carrying *no evidence
at all* still drags the result. Measured on our own implementation, one real source at
P=0.66 with uncertainty 0.20, plus nine vacuous sources:

    ABF  ->  P = 0.4286, uncertainty 0.7143
    WBF  ->  P = 0.6600, uncertainty 0.2000  (exactly unchanged)

An adversary who stands up nine feeds that say nothing collapses our confidence for free.
That is a denial-of-confidence attack with zero evidence cost, and it rules ABF out for a
system whose sources an adversary can create. WBF weights each source by its confidence
``1 - u``, so a vacuous source contributes nothing — which is the correct behaviour, and
also the safe one.

**Fusion is N-ary in one operation. Pairwise reduction is refused.**
Neither ABF nor WBF is associative; Jøsang states this explicitly. Folding a list of
sources two at a time produces an answer that depends on the bracketing. Measured on three
real opinions: N-ary gives P=0.3207, left-associated gives 0.3322, right-associated gives
0.3723. A confidence score that changes when sources arrive in a different order is not a
confidence score. The API therefore takes a sequence and there is no binary operator to
misuse.

**Trust discounting is uncertainty-favouring, not base-rate sensitive.**
The base-rate-sensitive variant hands an *unknown* source with a generous base rate almost
total trust: an unknown source (b=0, d=0, u=1, a=0.99) asserting something with certainty
yields derived belief 0.990. Jøsang flags this himself and calls the base-rate-insensitive
operator "safe and conservative". Facing whitewashing and Sybil identities, the
uncertainty-favouring variant returns a vacuous opinion for an unknown source — we learn
nothing from a stranger, which is correct.

**Duplicate sources are collapsed before cumulative fusion.**
CBF is evidence summation and is not idempotent: the same evidence re-reported through N
fronts inflates confidence from 0.833 to 0.962 at N=5 with no new information, and shifts
the point estimate too. The remedy used here is structural — Jøsang's "canonical
expression": ensure every real source is counted once.
:meth:`SourceDescriptor.provenance_cluster` supplies the grouping.

A partial-dependence operator **does** exist and is not used here. Jøsang, Marsh & Pope,
*Exploring Different Types of Trust Propagation* (iTrust 2006), Definition 4 and Theorem 3,
define a consensus operator for partially dependent opinions: dependence factors λ split
each source's evidence into dependent and independent fractions, the dependent parts are
averaged and the independent parts cumulatively fused. An earlier version of this module
claimed no such operator existed. That claim was false, and it was false in the most
predictable way — an argument from absence, refuted by a paper the project had already
cited. It is not used because λ has to be *estimated per pair per claim* and we have no
basis for those numbers; structural grouping is the cruder answer we can actually defend.
That is a different and weaker justification than the one originally given.

**The attack this module is now designed against is not the one it was built for.**
Nine empty feeds are cheap to notice. The dangerous case is *provenance laundering*: one
adversary-planted artifact, observed honestly by many genuinely different collectors, whose
lineage is incomplete by the time it reaches fusion. Nobody lies, no source is unreliable,
no conflict fires — and cumulative fusion counts each honest observation as independent
support for an actor. Measured here, ten such reports of one planted opinion reach P=0.97
having learned nothing about the actor at all. The defence is
:meth:`SourceDescriptor.provenance_cluster` refusing to read missing lineage as
independence, plus reporting unresolved dependence rather than absorbing it.

Primary sources: A. Jøsang, *Subjective Logic*, Springer 2016 (§12.3 cumulative p.225,
§12.4 averaging p.229, §12.5 weighted p.231, §14.3 discounting p.255); Jøsang,
*Categories of Belief Fusion*, JAIF 13(2), 2018 (Eq. 23 cumulative N-ary, Def. 4 Eq. 55
weighted N-ary); Jøsang, Ivanovska & Muller, *Trust Revision for Conflicting Sources*,
FUSION 2015 (conflict-driven trust revision).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from enum import StrEnum
from math import prod

from pydantic import BaseModel, ConfigDict

from nemesis.core.confidence import Opinion
from nemesis.core.proposition import ROBUSTNESS_MARGIN, MarginOutcome, PropositionClass
from nemesis.core.provenance import SourceDescriptor, SourceReliability

_EPS = 1e-12


class FusionError(ValueError):
    """A fusion was attempted in a way that would produce a meaningless number."""


# ---------------------------------------------------------------------------
# Trust discounting
# ---------------------------------------------------------------------------


def trust_of_source(source: SourceDescriptor) -> Opinion:
    """Our opinion about whether this source tells the truth.

    Derived from Admiralty reliability. ``CANNOT_BE_JUDGED`` maps to a **vacuous** opinion,
    not to a middling one: we have no basis, and under uncertainty-favouring discounting a
    vacuous trust opinion correctly nullifies whatever the source claims. A new source is
    not a half-credible source; it is an unknown one.
    """
    table = {
        SourceReliability.COMPLETELY_RELIABLE: (0.90, 0.02),
        SourceReliability.USUALLY_RELIABLE: (0.75, 0.05),
        SourceReliability.FAIRLY_RELIABLE: (0.55, 0.10),
        SourceReliability.NOT_USUALLY_RELIABLE: (0.25, 0.45),
        SourceReliability.UNRELIABLE: (0.05, 0.85),
        SourceReliability.CANNOT_BE_JUDGED: (0.00, 0.00),
    }
    belief, disbelief = table[source.reliability]
    return Opinion(
        belief=belief,
        disbelief=disbelief,
        uncertainty=1.0 - belief - disbelief,
        base_rate=0.5,
    )


def discount(trust: Opinion, claim: Opinion) -> Opinion:
    """Apply our trust in a source to what that source claims.

    Uncertainty-favouring ("safe and conservative") discounting:

        b = b_trust · b_claim
        d = b_trust · d_claim
        u = d_trust + u_trust + b_trust · u_claim
        a = a_claim

    Distrust and ignorance about the source both convert into *uncertainty* about the
    claim rather than into disbelief of it. That distinction matters: a source we distrust
    saying "X is true" is not evidence that X is false. Treating it as such would let an
    adversary refute a true claim by having a known-bad source assert it — a cheap and
    well-documented attack.
    """
    belief = trust.belief * claim.belief
    disbelief = trust.belief * claim.disbelief

    # Written as ``1 - b_t·(b_c + d_c)`` rather than the textbook
    # ``d_t + u_t + b_t·u_c``. The two are algebraically identical, since
    # ``d_t + u_t = 1 - b_t``, but the textbook form sums three floats that already carry
    # rounding error and overshoots 1 by an epsilon on ordinary inputs — enough for the
    # Opinion validator to reject a perfectly valid discounting. Found by a property test
    # on a vacuous claim, which the hand-written cases had missed.
    uncertainty = 1.0 - trust.belief * (claim.belief + claim.disbelief)

    return Opinion(
        belief=belief,
        disbelief=disbelief,
        uncertainty=uncertainty,
        base_rate=claim.base_rate,
    )


# ---------------------------------------------------------------------------
# Fusion operators — N-ary only
# ---------------------------------------------------------------------------


def weighted_belief_fusion(opinions: Sequence[Opinion]) -> Opinion:
    """Fuse N opinions weighted by their confidence. For **dependent** sources.

    Jøsang 2018 Definition 4, Eq. (55). Each source is weighted by ``1 - u``, so a source
    with nothing to say has no effect.

    **Idempotence is narrower than it looks, and the difference is exploitable.** Fusing
    identical opinions returns them unchanged, but that guarantee evaporates as soon as one
    differing opinion is present. With ``A=(.6,.2,.2)`` and ``B=(.2,.6,.2)``,
    ``WBF(A,B)`` gives P=0.500 while ``WBF(A,A,B)`` gives P=0.567 — duplicating one side of
    a disagreement still shifts the result. So this operator resists exact duplicates; it
    does not resist an adversary who can produce near-clones of the side they want believed.
    Grouping by provenance is what has to catch that, not the operator.

    Must receive every source at once. Applying it pairwise gives order-dependent results.
    """
    if not opinions:
        return Opinion.vacuous()
    if len(opinions) == 1:
        return opinions[0]

    uncertainties = [o.uncertainty for o in opinions]
    confidences = [1.0 - u for u in uncertainties]

    def without(index: int) -> float:
        return prod(uncertainties[:index] + uncertainties[index + 1 :])

    denominator = sum(confidences[i] * without(i) for i in range(len(opinions)))

    # Case III: every source is vacuous. Nothing was learned.
    if all(o.is_vacuous for o in opinions):
        return Opinion(
            belief=0.0,
            disbelief=0.0,
            uncertainty=1.0,
            base_rate=sum(o.base_rate for o in opinions) / len(opinions),
        )

    # Case II: two or more dogmatic sources. They have full confidence, so they alone
    # determine the result, averaged. A single dogmatic source is handled by Case I,
    # where the general formula reduces to that source.
    if denominator <= _EPS:
        dogmatic = [o for o in opinions if o.is_dogmatic]
        weight = 1.0 / len(dogmatic)
        return Opinion(
            belief=sum(o.belief for o in dogmatic) * weight,
            disbelief=sum(o.disbelief for o in dogmatic) * weight,
            uncertainty=0.0,
            base_rate=sum(o.base_rate for o in dogmatic) * weight,
        )

    confidence_total = sum(confidences)
    belief = sum(o.belief * confidences[i] * without(i) for i, o in enumerate(opinions))
    disbelief = sum(o.disbelief * confidences[i] * without(i) for i, o in enumerate(opinions))
    uncertainty = confidence_total * prod(uncertainties)
    base_rate = sum(o.base_rate * confidences[i] for i, o in enumerate(opinions))

    return Opinion(
        belief=belief / denominator,
        disbelief=disbelief / denominator,
        uncertainty=uncertainty / denominator,
        base_rate=base_rate / confidence_total,
    )


def cumulative_belief_fusion(opinions: Sequence[Opinion]) -> Opinion:
    """Fuse N opinions by accumulating evidence. For **independent** sources only.

    Jøsang 2018 Eq. (23). Uncertainty shrinks as independent sources agree, which is the
    behaviour we want — and precisely the behaviour that is wrong when the sources are not
    independent. Not idempotent: never pass the same underlying source twice. Use
    :func:`fuse` rather than calling this directly; it does the grouping.
    """
    if not opinions:
        return Opinion.vacuous()
    if len(opinions) == 1:
        return opinions[0]

    count = len(opinions)
    uncertainties = [o.uncertainty for o in opinions]
    product = prod(uncertainties)

    def without(index: int) -> float:
        return prod(uncertainties[:index] + uncertainties[index + 1 :])

    partial_sum = sum(without(i) for i in range(count))
    denominator = partial_sum - (count - 1) * product

    # Case II: two or more dogmatic sources drive the denominator to zero.
    if denominator <= _EPS:
        dogmatic = [o for o in opinions if o.is_dogmatic]
        weight = 1.0 / len(dogmatic)
        return Opinion(
            belief=sum(o.belief for o in dogmatic) * weight,
            disbelief=sum(o.disbelief for o in dogmatic) * weight,
            uncertainty=0.0,
            base_rate=sum(o.base_rate for o in dogmatic) * weight,
        )

    belief = sum(o.belief * without(i) for i, o in enumerate(opinions)) / denominator
    disbelief = sum(o.disbelief * without(i) for i, o in enumerate(opinions)) / denominator
    uncertainty = product / denominator

    base_denominator = partial_sum - count * product
    if abs(base_denominator) > _EPS:
        base_numerator = (
            sum(o.base_rate * without(i) for i, o in enumerate(opinions))
            - sum(o.base_rate for o in opinions) * product
        )
        base_rate = base_numerator / base_denominator
    else:
        base_rate = sum(o.base_rate for o in opinions) / count

    return Opinion(
        belief=belief,
        disbelief=disbelief,
        uncertainty=uncertainty,
        base_rate=min(1.0, max(0.0, base_rate)),
    )


# ---------------------------------------------------------------------------
# Conflict
# ---------------------------------------------------------------------------


def degree_of_conflict(left: Opinion, right: Opinion) -> float:
    """How much two opinions genuinely disagree, in [0, 1].

    Jøsang, Ivanovska & Muller, FUSION 2015: ``DC = PD · CC``, where ``PD`` is the
    projected distance and ``CC = (1-u_left)(1-u_right)`` is the conjunctive certainty.

    Multiplying by certainty is what makes this usable. Two sources that both know nothing
    are not in conflict, however far apart their priors sit; two confident sources that
    disagree are. Without the certainty factor, every pair of ignorant sources would raise
    an alarm, and an alarm that fires constantly is one nobody reads.
    """
    projected_distance = abs(left.projected_probability - right.projected_probability)
    conjunctive_certainty = (1.0 - left.uncertainty) * (1.0 - right.uncertainty)
    return projected_distance * conjunctive_certainty


def revise_trust_on_conflict(
    trust: Opinion, own_uncertainty: float, other_uncertainty: float, conflict: float
) -> Opinion:
    """Lower our trust in a source that conflicts with a better-supported one.

    Jøsang, Ivanovska & Muller, FUSION 2015. The revision factor is driven by the
    *relative* uncertainty of the two sources: the more uncertain source loses more trust,
    on the reasoning that the better-evidenced account is more likely the correct one.

        UD = (u_own - u_other) / (u_own + u_other)
        RF = (1 + UD) / 2
        b' = b - b·RF·DC,  d' = d + (1-d)·RF·DC,  u' = u - u·RF·DC

    Conflict converts trust into **distrust**, not into uncertainty — that is Jøsang's
    design choice and it is the right one here: a source that contradicts well-evidenced
    findings is not merely unknown, it is evidence about itself.

    A deliberate limitation, stated rather than hidden: this penalises the *minority*
    account. A single honest source contradicting a coordinated set of false ones is
    exactly what this mechanism punishes. It is therefore applied only where source
    independence has already been established, and a high conflict figure is surfaced to
    an analyst rather than silently resolved.
    """
    total = own_uncertainty + other_uncertainty
    uncertainty_difference = (own_uncertainty - other_uncertainty) / total if total > _EPS else 0.0
    revision = (1.0 + uncertainty_difference) / 2.0
    factor = revision * conflict

    return Opinion(
        belief=trust.belief - trust.belief * factor,
        disbelief=trust.disbelief + (1.0 - trust.disbelief) * factor,
        uncertainty=trust.uncertainty - trust.uncertainty * factor,
        base_rate=trust.base_rate,
    )


# ---------------------------------------------------------------------------
# The API the platform actually uses
# ---------------------------------------------------------------------------


class SourcedOpinion(BaseModel):
    """What one source says, with enough about the source to fuse it honestly."""

    model_config = ConfigDict(frozen=True)

    source: SourceDescriptor
    opinion: Opinion
    supporting_claims: tuple[str, ...] = ()
    label: str = ""

    fact_key: str = ""
    """Which underlying fact this source is attesting.

    Several sources reporting the same fact establish that fact once; they are not several
    pieces of evidence about who is responsible for it. Empty collapses into one shared
    ``fact:unknown`` bucket, the same asymmetry as an unknown provenance cluster and for the
    same reason: not knowing which fact a source attests is not evidence that it attests a
    new one."""

    @property
    def grouping_fact(self) -> str:
        return self.fact_key or UNKNOWN_FACT


class DependenceHandling(StrEnum):
    """How the dependence structure was resolved. Reported, never assumed silently."""

    INDEPENDENT_ACCUMULATED = "independent_accumulated"
    DEPENDENT_COLLAPSED = "dependent_collapsed"
    MIXED = "mixed"
    SINGLE_SOURCE = "single_source"
    NO_SOURCES = "no_sources"


class FusionResult(BaseModel):
    """A fused opinion plus everything needed to argue with it.

    The diagnostics are not decoration. ``independent_source_count`` is the number that
    determines how much the result should be believed, and it is routinely much smaller
    than the number of feeds consulted.
    """

    model_config = ConfigDict(frozen=True)

    opinion: Opinion
    dependence_handling: DependenceHandling

    total_sources: int
    independent_source_count: int
    """Distinct origins after resolving resellers, mirrors and aggregators. This, not the
    feed count, is what corroboration means."""

    collapsed_groups: tuple[tuple[str, ...], ...] = ()
    """Sources found to share an origin, grouped. Shown so an analyst can see that five
    feeds were three sources."""

    max_conflict: float = 0.0
    conflicting_pairs: tuple[tuple[str, str, float], ...] = ()
    """Pairs of confident sources that disagree, with the degree. A deception operation
    often shows up here first."""

    adversary_influenceable_sources: int = 0
    """How many contributing sources sit in channels an adversary can plant into."""

    warnings: tuple[str, ...] = ()

    proposition: PropositionClass = PropositionClass.OBSERVATION
    evidential_opinion: Opinion | None = None
    """What the evidence says before the robustness margin is applied.

    Kept because the margin removes support deliberately, and a reader must be able to see
    both what was established and what survived losing a plantable fact. Reporting only the
    margined figure would hide the size of the reduction; reporting only the evidential one
    would be the defect this mechanism exists to fix."""

    robustness_margin: int = 0
    margin_outcome: MarginOutcome = MarginOutcome.NO_MARGIN
    facts_established: int = 0
    unplantable_facts: int = 0
    """Facts attested by at least one channel an adversary cannot author. These are the ones
    the margin will not remove, and the number an analyst should look at first."""

    removed_fact: str | None = None

    @property
    def is_single_sourced(self) -> bool:
        return self.independent_source_count <= 1

    @property
    def rests_only_on_plantable_evidence(self) -> bool:
        return self.facts_established > 0 and self.unplantable_facts == 0


CONFLICT_ALERT_THRESHOLD = 0.20
"""Above this degree of conflict, an analyst is told rather than the number being smoothed.

Set at 0.20 rather than higher because trust discounting compresses the scale: two sources
that flatly contradict each other, both graded reliable, land around 0.25 once discounted.
A threshold above that would stay silent on the clearest disagreement the system can see.
The value is a calibration choice and should be re-set against observed cases."""


UNKNOWN_FACT = "fact:unknown"


def establish_fact(
    sourced: Sequence[SourcedOpinion],
    *,
    apply_trust_discounting: bool = True,
    revise_on_conflict: bool = False,
) -> FusionResult:
    """Fuse what several sources said about ONE fact into one opinion, honestly.

    This is the whole of what ``fuse`` used to be, and its arithmetic is unchanged. Several
    origins attesting one fact still accumulate exactly as before; the staging that
    :func:`fuse` adds around it is about combining *different* facts, not about weakening
    corroboration of a single one.

    The procedure, in order:

    1. Discount each source's claim by our trust in that source (uncertainty-favouring).
    2. Group sources by :meth:`SourceDescriptor.provenance_cluster`, resolving resellers and
       mirrors back to a common origin.
    3. Within each group — sources that are *not* independent — fuse with WBF, which is
       idempotent, so three feeds carrying one origin's data count once.
    4. Across groups — genuinely independent origins — fuse with CBF, which accumulates,
       so agreement between real independent sources reduces uncertainty.
    5. Report conflict, group collapses, and how many sources an adversary could have
       planted into.

    ``revise_on_conflict`` is off by default. It penalises the minority account, which is
    correct against noise and wrong against a coordinated false majority — the exact
    scenario NEMESIS must survive. Enable it only where source independence is established.
    """
    if not sourced:
        return FusionResult(
            opinion=Opinion.vacuous(),
            dependence_handling=DependenceHandling.NO_SOURCES,
            total_sources=0,
            independent_source_count=0,
            warnings=("No sources contributed; this is a prior, not a finding.",),
        )

    warnings: list[str] = []

    # 1. Discount by trust in the source.
    discounted: list[tuple[SourcedOpinion, Opinion]] = []
    for item in sourced:
        opinion = (
            discount(trust_of_source(item.source), item.opinion)
            if apply_trust_discounting
            else item.opinion
        )
        discounted.append((item, opinion))

    # 2. Group by origin, not by feed name.
    groups: dict[str, list[tuple[SourcedOpinion, Opinion]]] = {}
    for item, opinion in discounted:
        groups.setdefault(item.source.provenance_cluster(), []).append((item, opinion))

    collapsed = tuple(
        tuple(sorted(item.source.identifier for item, _ in members))
        for members in groups.values()
        if len(members) > 1
    )
    if collapsed:
        warnings.append(
            f"{sum(len(g) for g in collapsed)} feeds resolved to {len(collapsed)} origin(s); "
            "counted once each. Feed count is not source count."
        )

    # 3. Conflict, measured between origins rather than between feeds.
    labels = {
        key: members[0][0].label or members[0][0].source.identifier
        for key, members in groups.items()
    }
    per_group = {key: [opinion for _, opinion in members] for key, members in groups.items()}
    group_opinions = {key: weighted_belief_fusion(ops) for key, ops in per_group.items()}

    conflicts: list[tuple[str, str, float]] = []
    all_conflicts: list[float] = []
    keys = sorted(group_opinions)
    for i, left_key in enumerate(keys):
        for right_key in keys[i + 1 :]:
            conflict = degree_of_conflict(group_opinions[left_key], group_opinions[right_key])
            all_conflicts.append(conflict)
            if conflict >= CONFLICT_ALERT_THRESHOLD:
                conflicts.append((labels[left_key], labels[right_key], round(conflict, 4)))

    # The maximum is taken over EVERY pair, not only over the pairs that cleared the alert
    # threshold. Taking it over the alerting subset reports 0.0 — "no disagreement at all" —
    # whenever real disagreement sits just below the threshold, which is precisely the
    # regime where an analyst most needs to see the number rather than a silence.
    max_conflict = round(max(all_conflicts, default=0.0), 4)

    if revise_on_conflict and len(keys) > 1:
        revised: dict[str, Opinion] = {}
        for key in keys:
            own = group_opinions[key]
            worst = 0.0
            worst_uncertainty = own.uncertainty
            for other_key in keys:
                if other_key == key:
                    continue
                conflict = degree_of_conflict(own, group_opinions[other_key])
                if conflict > worst:
                    worst, worst_uncertainty = conflict, group_opinions[other_key].uncertainty
            if worst > 0:
                trust = revise_trust_on_conflict(
                    trust_of_source(groups[key][0][0].source),
                    own.uncertainty,
                    worst_uncertainty,
                    worst,
                )
                revised[key] = discount(trust, own)
            else:
                revised[key] = own
        group_opinions = revised

    # 4. Accumulate across independent origins.
    independent = [group_opinions[key] for key in keys]
    fused = cumulative_belief_fusion(independent)

    if len(keys) == 1:
        handling = (
            DependenceHandling.SINGLE_SOURCE
            if len(sourced) == 1
            else DependenceHandling.DEPENDENT_COLLAPSED
        )
        warnings.append(
            "All evidence traces to a single origin. Agreement here is not corroboration."
        )
    elif collapsed:
        handling = DependenceHandling.MIXED
    else:
        handling = DependenceHandling.INDEPENDENT_ACCUMULATED

    influenceable = sum(1 for item, _ in discounted if item.source.is_adversary_influenceable)
    if influenceable and influenceable == len(sourced):
        warnings.append(
            "Every contributing source sits in a channel an adversary can plant into; "
            "treat this as a deception hypothesis, not a finding."
        )
    if max_conflict >= CONFLICT_ALERT_THRESHOLD:
        warnings.append(
            f"Independent sources disagree (max conflict {max_conflict:.2f}). "
            "Investigate the disagreement before relying on the fused figure."
        )

    return FusionResult(
        opinion=fused,
        dependence_handling=handling,
        total_sources=len(sourced),
        independent_source_count=len(keys),
        collapsed_groups=collapsed,
        max_conflict=max_conflict,
        conflicting_pairs=tuple(conflicts),
        adversary_influenceable_sources=influenceable,
        warnings=tuple(warnings),
    )


def summarize_fact(fact_key: str) -> str:
    """Name a dropped fact by what it is, never by dumping its key.

    A fact key is an internal structure: a JSON object carrying the subject, the predicate
    and every qualifier the pivot was measured against. Interpolating one into a caveat put
    that structure — including a persona handle — into the *external* attribution product,
    which is a document written for somebody outside this platform. An API test caught it by
    walking every byte of a response, which is exactly what the slice tests do to stages and
    what nothing had yet done to a deliverable.

    Whatever ends up in a fact key ends up wherever the caveat goes, so the caveat says the
    kind and the internal record keeps the key.

    Public, and shared, because the same defect then appeared on a second surface: the analyst
    HTML view rendered ``removed_fact`` verbatim and put a persona handle back on a page that
    gets mailed and printed. One summariser, so a correction lands everywhere the key travels.
    """
    try:
        parsed = json.loads(fact_key)
    except (ValueError, TypeError):
        return "one shared attribute"
    predicate = str(parsed.get("predicate", "a shared attribute"))
    method = (
        str(parsed.get("qualifiers", {}).get("pivot_method", ""))
        if isinstance(parsed.get("qualifiers"), dict)
        else ""
    )
    return f"a '{predicate}' fact" + (f" found by {method}" if method else "")


def fuse(
    sourced: Sequence[SourcedOpinion],
    *,
    proposition: PropositionClass,
    apply_trust_discounting: bool = True,
    revise_on_conflict: bool = False,
) -> FusionResult:
    """Fuse what several sources said, staged by fact, and report what survives.

    ``proposition`` is required and has no default, for the same reason
    :meth:`PersonaResolutionEngine.assess` requires a candidate population: every value that
    could be defaulted is either the permissive one that reproduces the defect this staging
    exists to fix, or a strict one that would silently suppress legitimate observations.

    Three stages:

    1. **Establish each fact.** Sources are grouped by :attr:`SourcedOpinion.fact_key` and
       each group goes through :func:`establish_fact` unchanged. Several origins attesting
       one fact accumulate exactly as they did before this mechanism existed.
    2. **Recombine across facts.** Facts attested by an identical set of origins are fused
       with WBF — they are one origin's account of the world, not independent evidence —
       and distinct signatures accumulate with CBF.
    3. **Apply the robustness margin.** For anything but an OBSERVATION, drop the most
       load-bearing *plantable* fact and report what is left. A fact is unremovable when at
       least one attesting origin is a channel an adversary cannot author.

    The consequence worth stating plainly: a conclusion resting on one plantable fact is
    reported as vacuous, however confident that fact looked. That is the point. An adversary
    who plants one artifact and lets honest collectors find it can no longer produce a band
    anybody would act on, and the price is that genuine single-fact findings now need a
    second fact or an unplantable attestation before they are actionable.
    """
    if not sourced:
        return FusionResult(
            opinion=Opinion.vacuous(),
            dependence_handling=DependenceHandling.NO_SOURCES,
            total_sources=0,
            independent_source_count=0,
            proposition=proposition,
            warnings=("No sources contributed; this is a prior, not a finding.",),
        )

    by_fact: dict[str, list[SourcedOpinion]] = {}
    for item in sourced:
        by_fact.setdefault(item.grouping_fact, []).append(item)

    established: dict[str, FusionResult] = {
        key: establish_fact(
            members,
            apply_trust_discounting=apply_trust_discounting,
            revise_on_conflict=revise_on_conflict,
        )
        for key, members in sorted(by_fact.items())
    }
    origins_of: dict[str, frozenset[str]] = {
        key: frozenset(item.source.provenance_cluster() for item in by_fact[key]) for key in by_fact
    }
    unplantable: set[str] = {
        key
        for key, members in by_fact.items()
        if any(not item.source.is_adversary_influenceable for item in members)
    }

    # Stage 2. Facts seen by exactly the same origins are that origin-set's account, not
    # independent evidence; only distinct signatures accumulate.
    by_signature: dict[frozenset[str], list[Opinion]] = {}
    for key, result in established.items():
        by_signature.setdefault(origins_of[key], []).append(result.opinion)
    combined = cumulative_belief_fusion(
        [weighted_belief_fusion(group) for _, group in sorted(by_signature.items(), key=str)]
    )

    margin = ROBUSTNESS_MARGIN[proposition]
    base_rate = combined.base_rate
    outcome = MarginOutcome.NO_MARGIN
    reportable = combined
    removed: str | None = None

    if margin > 0:
        supporting = [
            key
            for key, result in established.items()
            if result.opinion.projected_probability - base_rate > _EPS
        ]
        removable = [key for key in supporting if key not in unplantable]

        if combined.projected_probability - base_rate <= _EPS:
            # Nothing to be robust about. Margining a conclusion that does not accuse would
            # push it further from accusing, and would zero every deception alternative,
            # which are single-source hypotheses by construction (invariant 13).
            outcome = MarginOutcome.NOT_AN_ACCUSATION
        elif not removable:
            outcome = MarginOutcome.NO_REMOVABLE_FACT
        elif len(supporting) <= margin:
            # Removing the margin exhausts the support. The condition is on how many facts
            # SUPPORT the conclusion, not on how many are removable: with four plantable
            # facts and a margin of one, three still stand after the removal, and treating
            # "all of them are removable" as "remove all of them" would refuse every
            # finding whose evidence happens to be plantable — which is most of them.
            outcome = MarginOutcome.EVERY_FACT_REMOVED
            reportable = Opinion.vacuous(base_rate=base_rate)
            removed = ", ".join(sorted(removable))
            removed_summary = f"{len(removable)} plantable fact(s)"
        else:
            worst_key, worst = min(
                ((key, _without(established, origins_of, key)) for key in removable),
                key=lambda pair: pair[1].projected_probability,
            )
            outcome = MarginOutcome.SURVIVED
            reportable = worst
            removed = worst_key
            removed_summary = summarize_fact(worst_key)

    inner = establish_fact(
        sourced,
        apply_trust_discounting=apply_trust_discounting,
        revise_on_conflict=revise_on_conflict,
    )
    warnings = list(inner.warnings)
    if outcome is MarginOutcome.EVERY_FACT_REMOVED:
        warnings.append(
            "Every supporting fact could have been planted by an adversary, so removing one "
            "removes the finding. Reported as no basis rather than as the figure the "
            "evidence alone would give."
        )
    elif outcome is MarginOutcome.SURVIVED:
        warnings.append(
            f"Reported after dropping the most load-bearing plantable fact ({removed_summary}); "
            "the evidential figure before that removal is carried separately."
        )
    elif outcome is MarginOutcome.NO_REMOVABLE_FACT:
        warnings.append(
            "Every supporting fact is attested by a channel an adversary cannot author, so "
            "the margin removed nothing."
        )

    return FusionResult(
        opinion=reportable,
        dependence_handling=inner.dependence_handling,
        total_sources=len(sourced),
        independent_source_count=inner.independent_source_count,
        collapsed_groups=inner.collapsed_groups,
        max_conflict=inner.max_conflict,
        conflicting_pairs=inner.conflicting_pairs,
        adversary_influenceable_sources=inner.adversary_influenceable_sources,
        proposition=proposition,
        evidential_opinion=combined,
        robustness_margin=margin,
        margin_outcome=outcome,
        facts_established=len(established),
        unplantable_facts=len(unplantable),
        removed_fact=removed,
        warnings=tuple(warnings),
    )


def _without(
    established: dict[str, FusionResult],
    origins_of: dict[str, frozenset[str]],
    dropped: str,
) -> Opinion:
    """Recombine every fact except one."""
    by_signature: dict[frozenset[str], list[Opinion]] = {}
    for key, result in established.items():
        if key == dropped:
            continue
        by_signature.setdefault(origins_of[key], []).append(result.opinion)
    if not by_signature:
        return Opinion.vacuous()
    return cumulative_belief_fusion(
        [weighted_belief_fusion(group) for _, group in sorted(by_signature.items(), key=str)]
    )
