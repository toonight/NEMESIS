# Calibration protocol

**Status: milestone 1 `IMPLEMENTED`, milestones 2 and 6 `PROPOSED` (specified below),
milestones 3–5 `REQUIRES_EXTERNAL_DATA`.**

> **Correction, 2026-08-20.** Milestone 1 was first labelled `IMPLEMENTED` when it was partial,
> and an external review demonstrated the gap in one run: changing `BAND_RANGES` moved a
> published band from *likely* to *almost certain* while both checks stayed green. The scanner
> matched only `NAME = <digit>`, so every dial that is a **table** was invisible; it compared
> bare names, so a homonym elsewhere counted as registered; and the golden vectors froze fusion
> and nothing else. Over-labelling is the defect this project rejects, committed inside the
> mechanism built to prevent silent drift. The registry now holds **26** constants including
> tables, the scan is AST-based and fully qualified over **8** modules, and the vectors cover
> bands, refusals, robustness margins and method ceilings.

No confidence figure this platform produces has ever been scored against a known-correct
answer. That is the project's largest declared weakness, and it is not a mathematics problem:
attribution rarely has ground truth, so the usual instruments have nothing to measure against.
Only a corpus of resolved cases fixes it.

This document is the protocol for building that corpus and using it. It is written **before**
the corpus exists, deliberately, because the decisions that make an evaluation meaningful are
all made before any data is collected — and a protocol written afterwards is indistinguishable
from a description of whatever happened to work.

---

## 1. Freeze the constants and the algorithm — `IMPLEMENTED`

A score obtained by tuning against the same cases that measure you is a score of your tuning.
Every calibration constant here is a documented *choice*, which makes the temptation concrete:
each is a dial, and each moves a number somebody is about to grade.

`nemesis.calibration.freeze` makes the freeze mechanical rather than a promise:

- **26 registered constants** across 8 modules, **scalars and tables alike**, folded into a
  digest. `BAND_RANGES`, `ROBUSTNESS_MARGIN`, `METHOD_RELIABILITY_CEILING`, `BELIEF_CEILING`,
  `DEFAULT_BASE_RATE` and `PLANTING_BELIEF_BY_COST` are dictionaries and decide as much as any
  scalar — `BAND_RANGES` decides the *word* a reader sees, which is the only output most
  consumers ever read.
- **An AST-based scan for unregistered constants**, compared fully qualified. A regex matching
  `NAME = <digit>` could not see a table, and a bare-name comparison let a homonym in another
  module count as registered. Numerical-stability epsilons are registered rather than excused:
  "it is only an epsilon" is exactly the reasoning that lets a dial escape.
- **Golden vectors** pinning *answers* rather than source — fusion, published bands, the
  refusal threshold at and above the line, robustness margins per proposition class, and method
  reliability ceilings. Hashing the source would break on a reworded comment and survive a
  changed sign.

Changing a constant is allowed. Changing it *silently*, or *during* an evaluation, is what this
prevents: updating `FROZEN_DIGEST` is one line, in its own commit, with a reason, at a moment
somebody chose.

## 2. Population, case categories, ground-truth rules — `PROPOSED`

An evaluation is only as meaningful as the population it claims to generalise to. Three things
must be written down before a single case is generated, because each is unfalsifiable once
results exist:

**The target population.** What kind of adversary infrastructure the corpus claims to
represent, and — as importantly — what it does not. A corpus of commodity phishing kits says
nothing about a state actor's operational security, and a score presented without its
population is a number wearing a suit.

**The case categories.** At minimum: *linkable* (shared infrastructure, provable), *not
linkable* (independent operations that superficially resemble each other), *adversarially
linked* (a planted artifact designed to create a false link), and *ambiguous* (genuinely
undecidable with the evidence available). The fourth category is the one most corpora omit and
the one this platform's refusal machinery exists for — a system that cannot be graded on
correct refusals will be tuned to stop refusing.

**The ground-truth rule.** What makes a label true, decided in advance and applied by someone
who did not build the engine. "The operator told us" and "two analysts agreed" and "we
controlled both endpoints" are different standards producing different corpora, and mixing them
silently produces a corpus whose accuracy is unmeasurable.

## 3. Controlled operations on infrastructure we own — `REQUIRES_EXTERNAL_DATA`

The MVP rule is *never touch infrastructure we do not own*. Nothing in it forbids **running
infrastructure we do own** — honeypot ranges, synthetic operations across hosts and identities
under our control, with the linkage known because we created it.

That is the only path to ground truth available to this project, and it was not in the plan
until an external review pointed out that the constraint permits the experiment the honesty
section calls indispensable.

This is the milestone that needs a decision about infrastructure and cost. It is not code.

## 4. Separate generation, labelling and evaluation — `REQUIRES_EXTERNAL_DATA`

Three roles, and they must not be one person in three hats:

- **Generation** creates the operations and knows the truth.
- **Labelling** records what is true, from the generator's records, in a fixed schema.
- **Evaluation** runs the engine against the cases and never sees the labels until after.

The failure this prevents is not dishonesty. It is that somebody who knows the answer
unconsciously generates cases the engine happens to handle, and the corpus quietly becomes a
mirror.

## 5. A sealed test set — `REQUIRES_EXTERNAL_DATA`

A held-out set, never used to adjust anything, opened once. The moment it informs a change it
stops being a test set and becomes a training set with a misleading name, so:

- it is sealed with the evidence vault's own machinery, so opening it is an event;
- the number of times it has been opened is reported alongside any score from it;
- a change made after opening it invalidates every figure it produced, and the protocol says so
  in advance rather than negotiating afterwards.

## 6. What is measured — `PROPOSED`

Four things, because a single headline number hides exactly the failures that matter here:

**Calibration.** Predicted probability against observed frequency, per attribution dimension.
A reliability curve and its Brier decomposition. A well-discriminating, badly-calibrated model
is worse than an ignorant one in this domain, because its confidence is acted upon.

**Discrimination.** Does it separate linkable from not-linkable at all? Calibration without
discrimination describes a system that says "50%" to everything and is perfectly honest about
being useless.

**Correct refusals.** On the *ambiguous* class and on the human-identity gate: how often does
it decline when declining is right, and how often does it decline when the answer was
available? A refusal rate reported without both halves rewards a system that never answers.

**Robustness per attack class.** Accuracy under each adversarial category separately — planted
artifacts, laundered lineage, shared-infrastructure coincidence — because a single average
hides the one class an adversary will choose.

### The definitions, frozen with the constants

Written as formulas rather than prose, because a metric described in words is one that gets
reinterpreted after results exist — and "we meant macro-averaged" is a sentence nobody can
disprove six months later.

- **Reliability.** Bin predictions into the seven `BAND_RANGES` intervals. For each bin *b*
  with *n_b* cases: `observed_b = (true positives in b) / n_b`, plotted against the bin's
  midpoint. Bins with *n_b* < 20 are reported with their count and excluded from any summary
  statistic, never silently merged.
- **Brier score**, decomposed: `BS = reliability − resolution + uncertainty`, over the same
  bins, using the Murphy decomposition. The three terms are reported separately; a single `BS`
  hides whether a model is badly calibrated or merely facing a hard problem.
- **Discrimination.** AUC over *linkable* vs *not linkable* only. The *ambiguous* class is
  **excluded** from AUC and graded solely under refusals, because scoring a case with no true
  answer as a discrimination failure rewards guessing.
- **Correct refusals.** Two numbers, always together:
  `refusal_precision = (refusals on ambiguous) / (all refusals)` and
  `refusal_recall = (refusals on ambiguous) / (all ambiguous)`. Reporting either alone rewards
  a system that never answers or one that never declines.
- **Robustness.** Accuracy computed **per adversarial class** — planted artifact, laundered
  lineage, shared-infrastructure coincidence — and never averaged across them. The average
  hides the class an adversary will choose, which is the only class that matters.

Every figure is reported with its population (§2), its ground-truth standard (§2), the freeze
digest it was measured under (§1), and the number of times the sealed set has been opened (§5).
A number without those four is not a result.

---

## What this protocol cannot do

It cannot make the constants right; freezing a choice does not validate it. It cannot tell an
honest recalibration from a convenient one — only make both visible. And it cannot establish
that a corpus built from operations we ran resembles operations we did not: the population
claim in §2 is an argument, not a measurement, and it is the first thing an external reviewer
should attack.
