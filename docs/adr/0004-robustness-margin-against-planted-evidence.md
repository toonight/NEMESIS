# ADR-0004: A robustness margin against planted evidence

- **Status:** accepted
- **Date:** 2026-08-16
- **Deciders:** founding architect
- **Plane:** core domain model, attribution
- **Reversibility:** moderate. The mechanism is additive and `OBSERVATION` is bit-identical
  to the previous behaviour, so it can be disabled per proposition class. What is not cheap
  to reverse is the product decision it encodes.

## Context

[ADR-0003](0003-evidence-fusion-corrected.md) fixed provenance laundering: sources with
unknown lineage collapse into one cluster, and confidence inflation from re-reporting one
source through eight fronts became exactly `0.000000`.

The calibration harness then measured the result, and the result was that it had not
helped. **False-match rate under laundering: 100%.** Identical whether the planted artifact
was re-reported through eight collectors or one.

Both numbers were correct and they did not conflict. The anti-laundering defence stops N
sources being worth more than one. It is beside the point, because one planted source from a
reliable-looking origin already cleared the band an analyst would act on. Defending against
amplification is not defending against planting.

### The finding that decided the design

A stated design constraint turned out to be unsatisfiable, and it is withdrawn here
explicitly rather than quietly bent.

The constraint was *"keep one origin at LIKELY"*. Measured, the planted single source and
the legitimate single source produce **the same object**:

```
planted : P=0.7812 u=0.4375 likely
genuine : P=0.7812 u=0.4375 likely
```

Byte-identical in shape. No mechanism can separate them, so any fix that leaves one origin
actionable has not fixed anything. **One origin can no longer reach an actionable band on an
attribution.** That is a real cost and it is the price of the defect being real.

### The finding that decided the key

Four designs were produced independently. Three keyed the fix on distinct *origins*. A judge
pass measured what that would do to the actual product and found what none of the four had
checked: **every dimension of the GLASS ANVIL slice has exactly one independent origin** —
all fixture sources collapse into `lineage:unknown` — while carrying three or four distinct
statements. An origin-margin would have refused the entire demonstration on all five
dimensions, and only 3 of 432 tests would have caught it, because the unit fixture has three
origins where the product run has one.

The root is therefore the **distinct fact**, not the distinct origin.

## Decision

### D1 — Fusion is told what proposition it is fusing

`fuse()` takes a required keyword-only `proposition: PropositionClass`, with no default —
for the same reason `PersonaResolutionEngine.assess` requires a candidate population: every
value that could be defaulted is either the permissive one that reproduces the defect or a
strict one that suppresses legitimate observations.

| Class | Margin | Because |
|---|---|---|
| `OBSERVATION` | 0 | Planting does not change the truth of an observation. A domain an adversary registered really did resolve where it resolved, so one reliable observer remains sufficient and this path is bit-identical to before. |
| `SHARED_ORIGIN` | 1 | Planting *does* change this. An adversary who places their certificate on a third party's host manufactures exactly this proposition. |
| `ACTOR_ATTRIBUTION` | 1 | The claim that ends in a takedown request or a referral. |

### D2 — The robustness margin

Three stages. Stage 1 is the previous `fuse()` unchanged, now named `establish_fact`.

1. **Establish each fact.** Group by `SourcedOpinion.fact_key`; each group runs the existing
   pipeline. Several origins attesting one fact accumulate exactly as they did before.
2. **Recombine across facts.** Facts attested by an identical origin set are that set's
   account of the world, not independent evidence: WBF within a signature, CBF across.
3. **Drop the most load-bearing plantable fact** and report what survives. A fact is
   unremovable when at least one attesting origin is a channel an adversary cannot author.

The margin is a **count of facts an adversary must own**, not a threshold on strength. That
distinction is the whole design, and `run_identity_gate` had already articulated it:
*a threshold on strength is a threshold on the adversary's budget.* A margin cannot be
bought down with more confident-looking evidence.

### D3 — Plantability becomes an allowlist

`is_adversary_influenceable` was a blocklist naming open-source, dark-web and internet-scan,
which read every other class as unplantable. Measured: laundering one artifact through a
commercial feed, a partner, a human analyst, a honeypot, a blockchain or a model reached
**0.897, VERY_LIKELY**. After inversion: refused.

`UNPLANTABLE_SOURCE_CLASSES` is `{OWN_SENSOR, LAW_ENFORCEMENT}` and nothing else. Notably
absent: `HONEYPOT`, because an adversary writing into it is the point of deploying one and
ownership is not unplantability; `BLOCKCHAIN`, because a ledger is unforgeable about what
was written and silent about who chose to write it; `MODEL_INFERENCE`, which inherits the
plantability of whatever it read.

### D4 — Two guards, and one deliberately not taken

**Taken.** A conclusion at or below its prior is never margined. Removing support from a
finding that already fails to accuse pushes it further from accusing, which is not a safety
property — and it would flatten every planting hypothesis, which is single-source by
construction. Invariant 13 would go inert. `_planting_alternative` additionally declares
`OBSERVATION` explicitly; this carve-out is load-bearing and tested.

**Not taken.** A "no sign reversal" guard was proposed. Rejected here because conflict
policy is its own decision, and today's behaviour on two credible origins that flatly
contradict is a separate defect this change must not silently pocket.

### D5 — Both opinions are reported

`FusionResult.evidential_opinion` carries what the evidence gave before the margin;
`opinion` carries what survived. The margin removes support deliberately, and hiding how
much would be its own defect. `DimensionAssessment` carries both, plus `margin_outcome` and
the name of the removed fact, so a refusal is explainable (invariant 12).

## Measured consequences

| Case | Before | After |
|---|---|---|
| 1 planted fact, 1 / 3 / 8 collectors | LIKELY | **refused** |
| 1 fact, 8 declared operators, A-graded | 0.972 ALMOST_CERTAIN | **refused** (evidential 0.972 retained) |
| 1 / 2 / 3 / 4 / 5 distinct facts | 0.781 / 0.860 / 0.897 / 0.919 / 0.933 | **refused / 0.781 / 0.860 / 0.897 / 0.919** |
| 1 / 2 / 3 origins, unplantable channel | 0.781 / 0.860 / 0.897 | **unchanged to the digit** |
| Single own-sensor observation | 0.838 VERY_LIKELY | **unchanged** |
| Harness false-match rate under laundering | **100%** | **0.0%** |
| Harness laundering inflation | 0.000000 | 0.000000 |

`report(n) = evidence(n−1)`: n distinct facts now report what n−1 used to. The GLASS ANVIL
demonstration still concludes on three dimensions, and all six structural properties in the
calibration harness still pass.

## Alternatives considered

**Band ceiling on plantable single-source evidence.** Rejected: its ceiling was LIKELY, and
LIKELY is actionable. Its measured 0% depended entirely on the generator's undeclared
operators; with operators declared, the same attack reached VERY_LIKELY.

**A fact→actor likelihood with an explicit divisor K.** Structure adopted, arithmetic
rejected: its refusal was a strength threshold in disguise, and an adversary laundering
through an A-graded channel defeated it (measured LIKELY at K=2).

**A planting-resistance weight table.** Rejected: eleven asserted constants, three pinned so
the "derived" rule came out, and a mechanism that could *raise* the estimate by +0.28 at
attribution priors. A control against false accusation that can move toward accusation is
disqualified whatever else it does.

**Margin of 2 for `ACTOR_ATTRIBUTION`.** Measured: the false-match rate was already 0% at 1,
so it bought nothing and cost a further large drop in actionable findings on genuinely
corroborated true cases. The class is kept distinct from `SHARED_ORIGIN` so this can be
raised later without a schema change.

## Consequences

### Negative / accepted costs

- **One fact is never actionable on an attribution**, however strong. This is the withdrawn
  constraint and the main cost. Genuine single-fact findings now need a second fact or an
  unplantable attestation.
- Actionable findings on genuinely corroborated true cases fall substantially. The
  calibration harness measures this and it should be watched.
- Callers must declare a proposition class. Four test call sites and every production call
  site changed; two attribution tests encoded the pre-margin thresholds and were corrected
  rather than the dimensions exempted.

### Residual risk

- **Persona resolution is not margined.** It calls `establish_fact` directly. Two reasons:
  its output is an internal lead the D1 wall already keeps inside the platform, and its
  signals carry no fact keys, so margining it today would refuse every linkage for a
  bookkeeping reason rather than an evidentiary one. Wiring it properly means giving signals
  fact keys first. **This is the largest remaining gap in the mechanism.**
- **`fact_key` is caller-supplied.** A caller that gives two reports of one artifact distinct
  keys defeats the margin, exactly as a caller that fabricates lineage defeats the
  provenance cluster. The attribution engine derives it from `claim.statement.canonical()`,
  which is not gameable from inside a connector, but nothing enforces that for other callers.
- **The margin does not model an adversary who plants two facts.** Margin 1 is a cost of one
  artifact. A patient adversary who plants two independent-looking artifacts defeats it, and
  raising the margin to 2 is the obvious response — measured as available and currently
  unjustified.

## Verification status

Every figure in this ADR was reproduced locally against this implementation before adoption,
including the two findings that decided the design (the identical planted/genuine single
source, and the one-origin-per-dimension property of the slice). 12 new invariant tests;
444 passing; all 8 plane contracts kept; `nemesis demo` and `nemesis calibrate` both exit 0.

## Revisit when

- Persona resolution gets fact keys and can be margined.
- An adversary planting two facts is observed or judged likely, making margin 2 the honest
  setting.
- Blind, adjudicated cases exist, at which point the actionable-findings cost can be
  measured against real outcomes instead of against a generator.
