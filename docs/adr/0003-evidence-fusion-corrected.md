# ADR-0003: Evidence fusion, corrected after external challenge

- **Status:** accepted
- **Date:** 2026-08-15
- **Supersedes:** [ADR-0002](0002-subjective-logic-for-evidence-fusion.md)
- **Deciders:** founding architect
- **Plane:** core domain model, attribution
- **Reversibility:** expensive for the representation, cheap for the operators — which is
  itself part of this decision.

## Why this exists

ADR-0002 was checked four times before it was accepted: a research pass, an adversarial
refutation pass, a dedicated formula-verification agent, and my own re-derivation of every
number. All four were Claude. They agreed, and the agreement was worthless in the way
agreement between correlated reviewers always is.

The first check by a different model (GPT-5.5 via Codex) returned a verdict of *"the
decision should not be held as stated"* and found, in one pass, one false claim, one
unsound central argument, one overclaimed guarantee, and an attack strictly worse than the
one the design had been built against. Every arithmetic claim it made was reproduced
against this implementation before anything was changed; all of them held.

That result is the most important calibration datum this project has produced, and it is
about process, not mathematics: **model consensus is one opinion, and this project treated
it as four.**

## What was wrong in ADR-0002

### 1. A false claim: "subjective logic has no partial-dependence operator"

It does. Jøsang, Marsh & Pope, *Exploring Different Types of Trust Propagation*, iTrust
2006, **Definition 4** (partially dependent beta PDFs) and **Theorem 3** (consensus operator
for partially dependent opinions). Dependence factors λ split each source's evidence into
dependent and independent fractions; the dependent parts are averaged, the independent parts
cumulatively fused. The paper was retrieved and the definitions read directly.

The failure mode is textbook and this project has a written rule against it: *attack every
"never / only / does not exist" claim by hunting the counter-example inside the sources
already cited.* The counter-example was in a paper the verification pass had itself named
and marked unverifiable. The rule existed, was written down, and was not applied.

### 2. An unsound argument: "invariant 4 selects subjective logic"

It does not. The invariant rules out a bare scalar. It does not force a second-order
representation:

- A Bayesian model that **retains the reports** distinguishes the two cases without any
  second-order machinery. With `P(H)=0.5` and two independent 99%-accurate sources, "no
  reports" and "one + and one −" both give a posterior of 0.5 — but the prior-predictive
  probability of that ordered conflict is `0.5(0.99)(0.01) + 0.5(0.01)(0.99) = 0.0099`.
  The conflict is visible in the *predictive surprise*, not in the posterior.
- Worse for the original argument: a polarized disagreement is a **Beta mixture**,
  `½Beta(100,1) + ½Beta(1,100)`, which is bimodal and **is not a Beta at all**. A single
  subjective-logic opinion cannot represent it. Equal-weight logarithmic pooling of the same
  inputs gives `Beta(50.5, 50.5)` — sharply concentrated on 0.5, conflict erased.
- And subjective logic has its own version of the failure it was chosen to avoid: aleatory
  CBF maps `(r,s) = (100,100)` to `(b,d,u) = (0.495, 0.495, 0.0099)`, which is near-total
  confidence in a perfect contradiction.

So the invariant is an **output-schema requirement** — retain coverage and disagreement —
not a constraint that picks a calculus.

### 3. An overclaimed guarantee: WBF idempotence

ADR-0002 leaned on WBF being idempotent. It is, only when every input is identical. With
`A=(.6,.2,.2)` and `B=(.2,.6,.2)`: `WBF(A,B)` gives P=0.500 and `WBF(A,A,B)` gives P=0.567.
The operator resists exact duplicates and does **not** resist an adversary producing
near-clones of the side they want believed. The original test only exercised the
all-identical case, so it passed while the property it claimed to protect did not hold.

### 4. The wrong attack

ADR-0002 was designed against nine empty feeds collapsing our confidence. That attack is
real but cheap to notice. The dangerous one is **provenance laundering**:

1. An adversary plants one artifact — a certificate, a handle, a code fragment — on
   compromised or rented infrastructure.
2. Passive DNS, CT logs, scanners, sandboxes and vendors all **honestly** observe different
   descendants of it.
3. Lineage is incomplete by the time the reports reach fusion.
4. Every report becomes its own origin, and cumulative fusion counts each honest observation
   as fresh evidence *about the actor*.

Nobody lies. No source is unreliable. No conflict fires, so the conflict halt never
triggers. Measured on this implementation, ten such reports of one planted opinion reached
**P = 0.9724** having learned nothing about the actor at all. In likelihood terms, one
planted fact at prior 0.01 and LR 20 gives a correct posterior of 0.168; miscounting three
reports as independent gives 0.988.

The mechanism was `independence_key()` falling back to the source's own identifier when
lineage was unknown — **converting missing provenance into asserted independence**, while
its docstring described itself as "deliberately conservative".

## Decision

### D1 — Keep subjective logic, but as bookkeeping, not as the argument

The representation stays. It is a compact, well-documented way to carry belief, disbelief,
uncertainty and a base rate together, and the codebase and tests are built on it. What is
withdrawn is the claim that it is *required*. It is a defensible local encoding, and the
project must stop treating "the invariant forces it" as a reason.

### D2 — Provenance clustering with asymmetric semantics

`independence_key()` is replaced by `provenance_cluster()`:

- **Same cluster is positive evidence of dependence.**
- **Different clusters are not evidence of independence.**

Sources with no recorded lineage collapse into one shared cluster rather than each claiming
its own. Measured effect: ten unknown-lineage reports now yield 1 origin and P=0.768; ten
genuinely distinct operators still yield 10 origins and P=0.949, so real corroboration
survives the fix. `IMPLEMENTED`.

### D3 — The partial-dependence operator is available and deliberately not used

Jøsang/Marsh/Pope's λ-based operator exists and is now cited. It is not used because λ must
be estimated **per source pair, per claim**, and this project has no basis for those
numbers. Inventing them would move the guesswork somewhere harder to see. Structural
grouping is the cruder answer we can actually defend — which is a weaker justification than
ADR-0002 gave, and the correct one.

### D4 — Report a vector, not a confidence

A single fused figure is not a sufficient product for any consequential decision. Alongside
the opinion, the system must carry and display:

| Field | Why |
|---|---|
| causal-root count | how many *independent facts*, not reports |
| coverage | what was looked at, versus what exists |
| source-level conflict | disagreement, distinct from ignorance |
| unresolved dependence | how much lineage is simply unknown |
| entity-link uncertainty | hard merges create transitive false corroboration |
| unknown-actor probability | the candidate set may not contain the answer |
| leave-one-root-out sensitivity | does the conclusion survive removing any single root |

`FusionResult` carries the first four. The rest are `PROPOSED`.

### D5 — Coercive action gates on the conservative result

Before any consequential effect, the conclusion must survive: removal of every single causal
root; maximal plausible dependence; the false-flag and compromised-infrastructure
alternatives; and it must include confirmatory evidence **not used to discover the suspect**,
plus at least one line supporting *control* rather than mere observation or registration.
`PROPOSED` — currently only partly expressed, through the ownership-evidence gate in the
disruption planner.

### D6 — Discounting happens before fusion, and this is now stated

The two do not commute: discount-then-CBF gives P=0.557 where CBF-then-discount gives
P=0.500 on the same inputs. Per-source discounting is applied first, because a per-source
trust judgement is meaningless after the sources have been merged.

## What survives from ADR-0002

- WBF over ABF for dependent sources. Still right, and still because a vacuous source should
  not move the result — but this is now understood as a **missing-data semantic** choice.
  "Did not look", "looked and found nothing with adequate detection probability", and
  "looked and remains agnostic" are three different states that WBF papers over, and the
  first should be an omitted source rather than a vacuous one.
- N-ary-only fusion. A good guardrail, and not a solution to dependence.
- Uncertainty-favouring discounting as a conservative default — though the justification in
  ADR-0002 was semantically wrong. A trust opinion of `(0,0,1,a=0.99)` means "no observations,
  99% prior trustworthiness", not "ignorance". The operator behaved correctly; the bad input
  was `a=0.99`. The chosen operator also collapses four distinct source states — never
  assessed, incompetent, compromised, strategically deceptive — which must be carried
  separately.
- Everything in the "known weaknesses" section, all of which still stands.

## Also corrected: both literature positions were overclaimed

- Saying Karvetski et al. leaves subjective logic untested was right. Adding that SL is
  "structurally on the side that won" was **the same category error in reverse**. The study
  validates neither; it supports empirical calibration and aggregation of analyst judgments.
- The opinion-pool cyber-attribution paper (Teuwen 2024) was conceded too readily as domain
  validation. It uses **artificial data**, states that every simulated indicator was strongly
  correlated with the responsible actor, and explicitly warns that its numbers should not be
  read as real attributor performance. It weakens the opposing case as much as ours.

## Consequences

### Positive

- The most dangerous default in the system is gone, with a regression test that fails if it
  returns.
- The intellectual record now shows where it was wrong, which is worth more to a future
  reader than a document that reads as though it never was.

### Negative / accepted costs

- Unknown-lineage sources are under-counted when they really were independent, which
  understates confidence and costs investigation time. Accepted: the opposite error costs
  somebody their infrastructure.
- D4 and D5 are largely unimplemented, so the product is currently narrower than this ADR
  describes.

### Residual risk

**A calibration harness over a synthetic generator cannot settle the operator question.** It
will reward whichever assumptions were coded into the generator. Settling it needs blind
cyber-range or proficiency-test cases, injected false flags, lineage-laundering exercises,
and independently adjudicated subclaims. Until those exist, this is investigative support
and not seizure-grade evidence, and it should be described that way to any buyer.

**The projected probability is not a validated posterior that a person did something.**
Forensic interpretation guidance evaluates how probable the observations are under explicit
opposing propositions, and warns specifically against reversing that conditional into a
probability of guilt. Presenting `P` to a court-facing audience without that framing is the
most likely way this system causes harm while behaving exactly as designed.

## Verification status

Reproduced locally against this implementation before adoption: the WBF near-clone result
(0.500 → 0.567), the ten-copy laundering result (P=0.9724), the discount/fusion
non-commutation (0.557 vs 0.500), and the fix's effect (unknown lineage → 1 origin,
P=0.768; known distinct lineage → 10 origins, P=0.949). The Jøsang/Marsh/Pope PDF was
retrieved and Definition 4 and Theorem 3 read in the source.

Not verified: the claim that no adequate public attribution dataset exists (an absence claim,
and this ADR should not repeat the mistake it was written to correct).

## Revisit when

- Blind, adjudicated attribution cases exist. That is the milestone that turns every
  "internally consistent" caveat in this repository into something measurable.
- D4's full output vector is implemented and the product stops reporting a confidence where
  it should report a vector.
- Anyone proposes to put `P` in front of a court.
