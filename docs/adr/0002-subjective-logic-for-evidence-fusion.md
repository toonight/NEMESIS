# ADR-0002: Subjective logic for evidence fusion and confidence calibration

> **SUPERSEDED.** This ADR contains a claim that is false and an argument that does not
> hold. It is kept unedited below because the record of what was believed, and why it was
> wrong, is worth more than a clean document.
>
> - It asserts that subjective logic has no operator for partially dependent sources.
>   **False.** Jøsang, Marsh & Pope, *Exploring Different Types of Trust Propagation*
>   (iTrust 2006), Definition 4 and Theorem 3, define one. It was an argument from absence,
>   refuted by a paper this project had already cited.
> - It argues that invariant 4 *selects* subjective logic. It does not. The invariant rules
>   out a bare scalar; it does not force a second-order representation, and a polarized
>   disagreement is a Beta **mixture** that a single opinion cannot express at all.
>
> See [ADR-0003](0003-evidence-fusion-corrected.md) for the corrected decision.


- **Status:** **SUPERSEDED by [ADR-0003](0003-evidence-fusion-corrected.md)** (2026-08-15)
- **Date:** 2026-08-15
- **Deciders:** founding architect
- **Plane:** core domain model, attribution
- **Reversibility:** expensive — every confidence figure in the graph, every attribution,
  and every disruption decision derives from this. Changing the formalism means
  recomputing history and invalidating stored opinions.

## Context

Invariant 4 requires that confidence and uncertainty be explicit, and invariant 13 assumes
an adversary who deliberately poisons attribution. A scalar confidence value cannot satisfy
either. It cannot distinguish the two situations that matter most:

- **Nobody has looked.** The honest answer is the prior.
- **Credible sources disagree.** Something is wrong and an operation should stop.

Both land on 0.5. The second — the one that should halt a takedown — becomes invisible.

Three further requirements shaped the choice. The formalism must handle **correlated
sources** honestly, because naive multiplication across sources that share an upstream is
the standard way attribution confidence gets inflated. It must be able to represent
**source reliability separately from information credibility**. And it must not be
steerable by an adversary who can create sources.

## Decision

**Subjective logic (Jøsang) as the representation, with a specific, non-default choice of
operators.**

An opinion is `ω = (b, d, u, a)` with `b + d + u = 1`. Vacuity (`u = 1`) is distinct from
balance (`b = d`, low `u`). Projected probability is `P = b + a·u`.

Three operator choices went **against** the obvious answer:

### 1. Weighted Belief Fusion for dependent sources, not Averaging Belief Fusion

Jøsang's taxonomy nominates ABF for dependent sources, and that is what a careful reading
of the literature suggests. It is the wrong choice here, because **ABF has no neutral
element**: a source carrying no evidence at all still moves the result. Measured on this
implementation, one real source `(0.60, 0.20, 0.20, a=0.30)` at P=0.66:

| operator | + 1 vacuous source | + 9 vacuous sources |
|---|---|---|
| ABF | P=0.6000, u=0.3333 | **P=0.4286, u=0.7143** |
| WBF | P=0.6600, u=0.2000 | **P=0.6600, u=0.2000** |

An adversary who stands up nine feeds saying nothing collapses our confidence from 0.66 to
0.43 at zero evidence cost. WBF weights each source by its confidence `1-u`, so a vacuous
source contributes exactly nothing. The discriminator between ABF and WBF is not the
dependence axis — both assume dependence — it is Jøsang's own selection criterion on
whether a vacuous argument should influence the result.

### 2. N-ary fusion in one operation; no binary operator is exposed

Neither ABF nor WBF is associative; Jøsang states this explicitly for ABF ("only meaningful
for fusing a single pair of sources"). Folding a list pairwise makes the answer depend on
bracketing. Measured on three real opinions: N-ary P=0.3207, left-associated P=0.3322,
right-associated P=0.3723 — an 8.7-point spread on identical inputs. A confidence score
that changes with arrival order is not a confidence score, so the API takes a sequence and
there is no binary operator available to misuse.

### 3. Uncertainty-favouring trust discounting, not base-rate sensitive

The base-rate-sensitive operator gives an *unknown* source with a generous base rate almost
total trust: `ω_trust = (0, 0, 1, a=0.99)` applied to a claim of `(1, 0, 0)` yields derived
belief **0.990**. Jøsang flags this himself, warns that it amplifies along trust paths, and
calls the base-rate-insensitive variant "safe and conservative". Against whitewashing and
Sybil identities that is decisive. We use:

```
b = b_trust · b_claim
d = b_trust · d_claim
u = d_trust + u_trust + b_trust · u_claim
```

An unknown source yields a vacuous opinion — we learn nothing from a stranger. Distrust
converts into *uncertainty*, not disbelief, so an adversary cannot refute a true claim by
having a known-bad source assert it.

### 4. Dependence is removed structurally, not by an operator

There is no off-the-shelf subjective-logic operator for *partially* dependent sources; the
dependence axis in the taxonomy is binary. The remedy is Jøsang's **canonical expression**:
ensure every real source is counted once. `SourceDescriptor.independence_key()` resolves
resellers, mirrors and aggregators back to their origin; `fuse()` groups by that key, uses
WBF (idempotent) *within* a group and CBF (accumulating) *across* groups. `FusionResult`
reports `independent_source_count` separately from `total_sources`, because the second is
what gets mistaken for corroboration.

This matters because CBF is evidence summation and is not idempotent. The same evidence
re-reported through N fronts:

| copies | uncertainty | confidence | P |
|---|---|---|---|
| 1 | 0.1667 | 0.833 | 0.750 |
| 3 | 0.0625 | 0.938 | 0.781 |
| 5 | 0.0385 | 0.962 | 0.789 |

Both the confidence and the point estimate drift on zero new information.

### 5. Admiralty grading feeds the model on two axes

Source reliability (A–F) drives the trust opinion used for discounting. Information
credibility (1–6) drives the belief/disbelief split. `CANNOT_BE_JUDGED` on reliability maps
to a **vacuous** trust opinion, not a middling one: a new source is unknown, not
half-credible.

## Alternatives considered

**Plain Bayesian networks / Bayes factors.** Rejected as the primary representation.
Cannot express "no evidence" distinctly from "evenly balanced" without an explicit
second-order construction, which is subjective logic by another name. Bayesian methods
remain the right tool for specific calibrated sub-models (e.g. a trained classifier's
output), whose result enters as one opinion.

**Dempster-Shafer.** Rejected. Zadeh's counterexample: normalizing away conflict produces
conclusions that contradict both sources. Conflict between sources is a *finding* in this
domain — often the first sign of a deception operation — and an operator that erases it is
disqualifying.

**Analysis of Competing Hypotheses alone.** Not rejected, but not sufficient. ACH is a
discipline for structuring analysis, not a fusion calculus, and it produces no number to
threshold. It is complementary and belongs in the attribution layer's presentation of
alternative hypotheses.

**A single calibrated float with an uncertainty interval.** Rejected. Simpler to build and
to display, but it cannot represent the conflict case, which is the case that must stop an
operation.

## Consequences

### Positive

- "No evidence" reports `INSUFFICIENT_BASIS` rather than a probability band. A prior is
  never dressed up as a finding.
- Two documented attacks on the confidence machinery — denial-of-confidence via empty
  sources, inflation via duplicate fronts — are structurally prevented and covered by
  regression tests.
- Independent source count is a first-class output, so an analyst sees that five feeds
  were three sources.

### Negative / accepted costs

- Analysts must be taught a four-tuple. Mitigated by `describe()`, which renders a band, a
  point estimate and an uncertainty in one line, and never shows a bare number.
- Subjective logic is less widely known than Bayes; a court-facing explanation will need
  work. The Beta-distribution equivalence is the bridge and should be used for that.
- **The numeric mappings are calibration choices, not measurements.** The Admiralty→opinion
  weights, the selectivity decay `1/log2(population)`, the conflict alert threshold of
  0.20 and the vacuity threshold of 0.70 are defensible starting points with no empirical
  backing. They are stated explicitly in code so they can be argued with, and they must be
  recalibrated against real case outcomes.

### Residual risk

**Calibration is untested and currently untestable.** Attribution rarely has ground truth,
so the usual instruments (Brier score, reliability diagrams) have nothing to score against.
Until a corpus of resolved cases exists, every confidence figure this system produces is
*internally consistent* but not *externally validated*, and should be presented that way.
This is the largest open weakness in the design and it is not solved by better mathematics.

**Trust revision on conflict penalises the minority account.** Implemented per Jøsang,
Ivanovska & Muller (FUSION 2015), but **off by default**: a single honest source
contradicting a coordinated false majority is exactly what it punishes, which is the
scenario NEMESIS must survive.

**Published critique exists and is not fully answered.** Cerutti, Toniolo, Oren & Norman
(*Subjective Logic Operators in Trust Assessment*, Inf. Syst. Frontiers) publish desiderata
that Jøsang's cumulative fusion fails on all counts and averaging fusion on all but one.
Their discounting critique targets the *older uncertainty-favouring* operator — the one we
selected — so it applies to us and is not dismissed. Dezert et al. (FUSION 2014) claim
deeper foundational problems; **that paper could not be accessed and its arguments are
recorded here as UNVERIFIED**, neither endorsed nor dismissed.

**Cyber attribution is epistemic, not aleatory.** An attack is a unique past event, not a
repeatable random process. Jøsang's epistemic operators with uncertainty maximisation may
be more appropriate than the aleatory ones used here. Not implemented; flagged as the most
likely correction to this ADR.

## Verification status

Formulas were checked against primary sources by a pass tasked with refuting them, then
**re-derived and measured independently** before being encoded. Everything in the tables
above is my own computation from the cited equations, not a reported figure.

| Formula | Verdict | Source |
|---|---|---|
| `P = b + a·u` | CONFIRMED, with caveat | Jøsang 2018 Eq. 6. Valid only where no belief mass sits on composite values; NEMESIS uses binary propositions, so it holds. |
| Beta mapping, `W = 2` | CONFIRMED | Jøsang 2017 Eq. 15; `W=2` convention cited to book p.33 |
| Cumulative fusion, N-ary | CONFIRMED | Jøsang 2018 Eq. 23; book §12.3.1 p.225. N=2 reduction reproduces the published worked example to 3 decimal places. |
| Weighted fusion, N-ary | CONFIRMED | Jøsang 2018 Def. 4 Eq. 55; book §12.5 p.231. Additivity, idempotence and vacuous-neutrality verified numerically. |
| Uncertainty-favouring discounting | CONFIRMED | Jøsang Def. 23; book §14.3. Additivity verified algebraically. |
| Conflict / trust revision | CONFIRMED | Jøsang, Ivanovska & Muller, FUSION 2015 |

Ratio: 6 of 6 formulas confirmed as encoded; 3 carried material gaps in the first pass
(missing dogmatic cases, invalid pairwise application) that were corrected before encoding.

**Not verified:** the published Springer 2016 text itself was inaccessible; verification
rests on Jøsang's own pre-publication draft plus his 2017 and 2018 papers, which restate
the same definitions. Page numbers cited above come from the book's table of contents, not
from the pages themselves.

## Challenge, 2026-08-15 — and the response

A second, independent research pass recommended **not** adopting subjective logic as the
primary engine, proposing linear/logarithmic **opinion pools** instead. It was the only one
of eight topics whose recommendation the adversarial reviewer judged not to survive. It is
recorded here in full rather than dismissed, because two of its three arguments are sound.

### Argument 1 — Karvetski, Mandel & Irwin. **Rejected: category error.**

The challenge leaned on PMID 32065440 (*Improving Probability Judgment in Intelligence
Analysis: From Structured Analysis to Statistical Aggregation*, Risk Analysis 40(5), 2020),
quoting that analytic decomposition techniques "were ineffective in improving accuracy and
handling correlated evidence" while "coherentization and aggregation yielded large accuracy
gains" — and concluding that subjective logic belongs to the class that failed.

Identifier verified: the PMID resolves, and the title matches the use being made of it.
The abstract does not support the conclusion. The study pits **ACH against a factorized
Bayes's theorem method** — both techniques for helping a *human analyst* decompose a
probability judgment — and finds that statistical post-processing of the resulting
judgments beats both.

Subjective logic is neither. It is not a human-facing structured analytic technique; it is a
machine calculus for combining opinions, which puts it structurally on the side of
*aggregation* — the thing that won. Reading the paper as an indictment of fusion calculi is
a well-sourced answer to a different question.

**But the paper does carry a real finding we are not using.** *Coherentization* —
enforcing internal coherence across a set of related judgments before aggregating them —
produced large accuracy gains and is **not implemented** in NEMESIS. Recorded as a gap
below, and it is a more actionable takeaway than the one the challenge drew.

### Argument 2 — opinion pools interpolate partial dependence. **Accepted.**

Sound, and it matches what our own verification pass found independently: subjective logic
has CBF (treats sources as independent) and WBF/ABF (treats them as dependent), with
**nothing between**. Real intelligence sources are partially dependent. A logarithmic pool
approaches independence, a linear pool approaches full dependence, and a Hölder pool
interpolates with a single parameter. Subjective logic cannot express that at all.

Our answer is structural rather than parametric: `independence_key()` groups sources by
origin, WBF within a group, CBF across groups. That is a claim that CTI dependence is
**discrete and knowable** — you know three feeds resell one upstream — rather than a
continuous quantity to be tuned. For resold feeds and mirrors that holds. For sources that
are *partially* correlated for subtler reasons (two scanners with overlapping vantage
points, two forums with overlapping membership) it does not, and there our grouping is
binary where reality is graded. **This is a real limitation and the challenge is right
about it.**

### Argument 3 — opinion pools have published validation in this exact domain. **Accepted.**

arXiv:2401.14090, *A Modular Approach to Automatic Cyber Threat Attribution using Opinion
Pools* (Teuwen). Identifier verified; title matches the use. There is no comparable
published application of subjective logic to cyber attribution — a point our own
verification pass also made. That is a genuine asymmetry in evidence, and it is on the
challenge's side.

### What the challenge does not address, and why the decision stands

**Invariant 4 is not satisfiable by an opinion pool over plain PMFs.** A pool operates on
probability distributions. Over a binary proposition, "nobody has looked" and "two credible
sources flatly disagree" are both `(0.5, 0.5)`. The distinction this platform exists to
preserve — the one that should stop an operation — is unrepresentable in the object being
pooled. Recovering it requires a second-order distribution over the probability, which is
the Beta distribution, which is isomorphic to a subjective-logic opinion.

So the representation is not really in contest; only the aggregation operator is. The
choice of subjective logic here was never "it aggregates best" — it was "it is the only
representation on the table that can say *we don't know*".

### Decision, revised

1. **Keep the opinion representation.** Required by invariant 4; the challenge does not
   touch it.
2. **Make the aggregation operator pluggable.** `fuse()` becomes one strategy behind an
   interface, so an opinion-pool strategy over the Beta parameters can be scored against it
   rather than argued about.
3. **Build the scoring harness before defending either.** Coherentization, Brier
   decomposition and false-match-rate measurement against the synthetic generator, with
   injected false-flag scenarios. ADR-0002 already named "calibration is untested and
   currently untestable" as its largest residual risk; the challenge is right that this
   should be built early rather than treated as future work.
4. **Add coherentization** as a pre-aggregation step, per Karvetski et al.

This is an amendment, not a reversal. If the harness shows an opinion pool over Beta
parameters beats WBF/CBF on injected-deception scenarios, this ADR gets superseded and the
representation survives the change.

### Counter-verification of this challenge

Both load-bearing identifiers were checked mechanically against their primary registries,
and both titles match the use made of them. The overall research pass reported 286 claims
checked with **62.2% confirmed, 7.3% FALSE, 8.4% OVERSTATED, 7.7% UNVERIFIABLE** — so
roughly 38% did not survive intact. That ratio is the reason this challenge was examined
argument by argument rather than adopted or dismissed as a whole, and it is why one of its
three arguments was rejected on reading the source it cited.

## Revisit when

- The scoring harness exists and can settle operator choice by measurement.
- A corpus of resolved cases exists and calibration can actually be measured. This should
  be treated as a milestone, not an aspiration.
- Attribution needs belief mass on composite hypotheses ("APT28 or APT29"), which breaks
  the reduced projection formula and requires the relative-base-rate term.
- The epistemic-versus-aleatory question is settled — most likely in favour of epistemic.
