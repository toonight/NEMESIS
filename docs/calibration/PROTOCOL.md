# Calibration protocol

**Status: milestone 1 `IMPLEMENTED`. Milestones 2, 4 and 5 have their apparatus
`IMPLEMENTED` and their corpus `REQUIRES_EXTERNAL_DATA` — `nemesis corpus` runs the whole of
it against synthetic cases. Milestone 3 `REQUIRES_EXTERNAL_DATA`, milestone 6 `PROPOSED`.**

> **What the apparatus label means, and what it does not.** Roles are separated *structurally*:
> an evaluator is handed `CaseInput` objects and there is no argument through which an answer
> could arrive. Answers are sealed, and unsealing is counted, attributed and reported beside
> every figure. All four case categories exist, including `ambiguous`, which is graded only on
> whether the engine declined. **None of this produces calibration.** The cases are synthetic, so
> the figures measure agreement with a generator's assumptions; that is milestone 3's problem and
> it is a question of cost, not of code.

> **What `IMPLEMENTED` claims here, and what it does not.** It claims that the freeze is
> mechanical and enforced by tests seen to fail without it, over three overlapping scopes:
> a normalised syntax digest covering **148 modules** — every file in `src/nemesis`, so literals
> in function bodies, class defaults and pure logic are all inside it; a derived digest of
> **499 dials** with no list to be absent from; and **43 constants frozen by imported value**
> for a named diagnostic. Plus golden vectors that run real inputs through the attribution and
> resolution engines to their published bands. It claims nothing about whether the frozen values
> are **right** — freezing a choice does not validate it — and nothing about milestones 2–6.
>
> **How it got here, because the history is the argument.** Milestone 1 was labelled
> `IMPLEMENTED` four times while partial, and external review walked through five different
> holes, every one the same shape: something a human had to remember to list.
>
> 1. The scanner matched only `NAME = <digit>`, so every dial that is a **table** was invisible.
>    Changing `BAND_RANGES` alone moved a published band from *likely* to *almost certain* with
>    both checks green. It also compared bare names, so a homonym elsewhere counted as
>    registered.
> 2. Two of the most consequential tables — `ROBUSTNESS_MARGIN`, `METHOD_RELIABILITY_CEILING` —
>    lived in **modules the list did not name**, so no scanner could have found them.
> 3. `CORRELATION_GROUP_OF` is **categorical**: moving `ALIAS_SIMILARITY` between correlation
>    groups changed a published band from *unlikely* to *roughly even* while containing no
>    digits at all, which a numeric scan is structurally incapable of noticing. The same review
>    found the Admiralty weights inlined inside a method body, where a module-level scan is
>    blind, and that the metrics were specified in this document and contradicted by the code.
>
> 4. Found here rather than by a reviewer, by deriving the module set from the imports instead
>    of remembering it: `DARK_BAZAAR_PERSONA_POPULATION` and `CLUSTER_MIN_CONFIDENCE` in
>    `slice/scenario.py` — the first being the denominator of the base rate every persona
>    linkage in the demonstration rests on.
> 5. The derivation was applied to the scanner and **not** to `engine_digest()`, which still
>    hashed the old hand-written list. So `LINKAGE_PROPOSITION` in `calibration/harness.py` was
>    discovered by one mechanism and hashed by neither: flipping it from `ACTOR_ATTRIBUTION` to
>    `OBSERVATION` took both reported false-match rates from 0.0 to 1.0 and the mean forecast
>    from 0.4956 to 0.5884, with every check green. Worse, the derivation itself was wrong —
>    `core/provenance.py` imports none of the confidence machinery and holds
>    `UNPLANTABLE_SOURCE_CLASSES`, the table deciding which evidence gets inverted. A tree-wide
>    count then found dozens of categorical dials — constants holding no numeric literal
>    anywhere — of which the freeze had registered exactly one.
>
> 6. Found internally by auditing the exclusion rule that instance 5's fix introduced. A dial
>    was skipped when every literal in its value was a string — which let a **lookup table of
>    strings** out through the same door as a sentence. `LOW_PLANTING_COSTS =
>    frozenset({"trivial", "low"})` is the table `_is_cheaply_plantable` reads: delete one word
>    and the attribution engine stops inverting cheaply plantable evidence, so a planted group
>    name reads as *support* for whoever the adversary named. `UNSIGNED_FIELDS`,
>    `OBSERVABLE_STOP_CONDITIONS` and every validation regex were escaping identically. The rule
>    is now structural — a value that **constructs or looks up** is a table however much of it is
>    text — and coverage went from 150 dials to 174.
>
> 7. Found by an adversarial sweep run against the fix for instance 6. Every mechanism so far
>    read **module-level assignments**, so a bare `6.0` inside a function body was invisible:
>    `pursuit/materialize.py::_confidence_from` sets the evidence weight for every edge with no
>    measurable selectivity, and changing it to `20.0` moves the GLASS ANVIL attribution's
>    ORGANIZATION dimension from *unlikely* (0.4470) to *likely* (0.5873) — the direction
>    reverses — with all four checks clean and all 913 tests passing. Dataclass field defaults
>    (`GeneratorAssumptions`) escaped the same way, and with them every number `nemesis
>    calibrate` prints.
> 8. From the same sweep, and the one that settled the architecture: `attribute/disclosure.py`
>    can be made to publish the pre-margin opinion by changing **two lines and no constant**,
>    moving the ORGANIZATION band in the *external deliverable* — the artefact handed to a
>    provider or a regulator — from *unlikely* to *roughly even*. No digest of values, however
>    complete, can see that. Only the logic can.
>
> The lesson is not "the list was too short" — that was the conclusion after instances 2, 3 and
> 4, and it was wrong three times. It is that **enumeration loses**, including the clever
> derivations that replace it: "modules that import the confidence machinery" is still a rule
> somebody has to get right. What holds is scope with no seam at all. Every dial in the tree is
> now hashed, and a dial that *appears* is reported alongside one that moves.

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

- **One scope, `frozen_modules()`** — every `.py` under `src/nemesis` except `freeze.py` itself
  — read by all three digests, so they cannot disagree about what is covered. They did disagree
  once, and that was instance 5. The self-exclusion is the one real hole left, closed socially
  rather than mechanically: a diff touching `MODULE_DIGESTS`, `CONSTANT_DIGESTS` or
  `FROZEN_VALUE_DIGESTS` is the thing a reviewer is meant to stop at. The scope takes an
  argument, so the freeze can be exercised against a tampered **copy** of the tree — which is
  how the tests demonstrate it rather than asserting around it. A test creates a module that
  exists only in the copy and requires its dial and its path by name; another asks the syntax
  tree of `freeze.py` whether any function accepts `tree` and never reads it, because an
  argument that exists and is never read is a promise in a signature.
- **Every dial in the tree, hashed by normalised syntax** (`discovered_constants`), **354 of
  them holding no numeric literal at all** — which is the whole lesson in one number: most of
  what decides a published figure here is not a number, and four scans that looked for digits
  found four different subsets of nothing. **A dial is any module-level upper-case assignment,
  with no classification rule at all.** Two rules were tried — "not all-strings", then "anything
  that constructs or looks up" — and each excluded something load-bearing, most recently four
  security tables of plain strings. Including the genuine prose costs nothing, because rewording
  a message already moves that module's syntax digest. A constant that *appears* is reported as
  well as one that moves, which closes "add a dial and don't register it".
- **43 constants additionally frozen by imported value**, for the diagnostic a syntax tree
  cannot give: `drifted()` names the one that moved. Both mechanisms are needed, and
  `PUBLISHED_BAND_BINS` is the case that proves it — derived from `BAND_RANGES`, its own syntax
  never changes when the band edges move, and only reading the value notices.
- **Values canonicalised, not `repr()`-ed.** Sets are sorted because their order carries no
  meaning; sequences are not, because theirs does. Registering the first categorical dials made
  the digest depend on CPython's per-process hash randomisation: five seeds gave five different
  digests. CI would have gone red at random, and an intermittently red tripwire teaches a reader
  that a red tripwire means nothing.
- **A normalised syntax digest covering 148 modules** — every file in the tree — docstrings
  stripped, one digest per module so a failure names which files moved. This covers what no value-based mechanism can: literals
  inside function bodies, dataclass field defaults, and pure logic changes that touch no
  constant at all. It was narrowed to fourteen hand-picked modules on the argument that hashing
  everything would fire too often to stay armed; an adversarial sweep went through that argument
  twice within the hour, and **measuring it showed the argument was wrong anyway** — replayed
  over this repository's history, eight of the last ten commits move it, each naming one to
  three modules. That is a readable question, not noise. Rewording a docstring still changes
  nothing, which is the property that keeps it armed.
- **Regeneration is scripted**, `scripts/refreeze_calibration.py`, not hand-edited — and it
  **measures in a subprocess under a fresh `PYTHONPYCACHEPREFIX`**. CPython validates a `.pyc` on
  *size and whole-second mtime*, and every rewrite here swaps one 64-character digest for
  another, so the size never changes. Dropping the one module's cache was the first fix and was
  not enough: the values are imported from every other module, each with a cache of its own.
  Demonstrated on the real tree — with a poisoned cache an ordinary interpreter read
  `DECEPTION_BASE_RATE` as 0.25 while the source said 0.99. A refreeze that appears to work and
  does not is worse than one that fails.
- **Golden vectors** pinning *answers* rather than source — fusion, published bands, the
  refusal threshold at and above the line, robustness margins per proposition class, and method
  reliability ceilings. *(Corrected: this bullet used to justify them by claiming a source hash
  would "survive a changed sign". That is simply false — a hash of the bytes breaks on any edit,
  including that one. The real argument is narrower and is about false positives: a byte hash
  also breaks on a reworded comment, so it cannot distinguish a changed sign from a changed
  adjective, and a check that fires on both gets switched off. The syntax digests above are what
  make that distinction; these vectors pin the **answers**, which is a different guarantee again
  — code can be rewritten wholesale and still have to produce 0.697368.)*
- **Two end-to-end vectors that traverse the engines**, because everything above pins a table
  and none of it would notice a change in how the engines *use* those tables. Signals in,
  published band out: one cryptographic fingerprint alone yields *likely* evidentially and
  *insufficient basis* publicly, because the robustness margin removes the single plantable fact
  and nothing survives; a group name embedded in a binary, offered as **supporting** evidence,
  comes out as disbelief 0.30 because the engine inverts what an adversary could plant cheaply.
  Both were watched failing with their control removed. Every figure in them was read off the
  engine and written down afterwards — an earlier draft of the fusion vectors guessed four
  numbers and got all four wrong, inside the mechanism built to stop exactly that.

Changing a constant is allowed. Changing it *silently*, or *during* an evaluation, is what this
prevents: updating `FROZEN_DIGEST` is one line, in its own commit, with a reason, at a moment
somebody chose.

**What this still does not stop.** Anyone who can edit a dial can regenerate the tables in the
same commit; this is a tripwire for drift and for self-deception, not a control against a
determined author.

*(Corrected: this paragraph previously also claimed that a probability hard-coded inline, in a
module importing nothing from `core.confidence`, would escape. That was true of the derived scan
it was written against and stopped being true when the syntax digest was widened to the whole
tree — which is exactly the case it now exists to catch. A stale limitation reads as modesty and
is the same defect as a stale capability.)*

The one real scope hole left is `calibration/freeze.py` itself, excluded because the frozen
tables live in it and would be self-referential. It is closed socially rather than mechanically:
a diff touching `MODULE_DIGESTS`, `CONSTANT_DIGESTS` or `FROZEN_VALUE_DIGESTS` is the thing a
reviewer is meant to stop at.

## 2. Population, case categories, ground-truth rules — apparatus `IMPLEMENTED`

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

**What exists.** `PopulationClaim` refuses to be constructed without all four, and `excludes` is
required rather than optional — every corpus author can describe what they built, and almost
none writes down what it says nothing about. `CaseCategory` carries the four categories and is
kept deliberately separate from `CaseKind`, which records how the evidence was *constructed*:
AUC runs over categories, robustness runs per construction, and collapsing them would hide the
class an adversary would choose behind an average.

## 3. Controlled operations on infrastructure we own — `REQUIRES_EXTERNAL_DATA`

The MVP rule is *never touch infrastructure we do not own*. Nothing in it forbids **running
infrastructure we do own** — honeypot ranges, synthetic operations across hosts and identities
under our control, with the linkage known because we created it.

That is the only path to ground truth available to this project, and it was not in the plan
until an external review pointed out that the constraint permits the experiment the honesty
section calls indispensable.

This is the milestone that needs a decision about infrastructure and cost. It is not code.

## 4. Separate generation, labelling and evaluation — apparatus `IMPLEMENTED`

Three roles, and they must not be one person in three hats:

- **Generation** creates the operations and knows the truth.
- **Labelling** records what is true, from the generator's records, in a fixed schema.
- **Evaluation** runs the engine against the cases and never sees the labels until after.

The failure this prevents is not dishonesty. It is that somebody who knows the answer
unconsciously generates cases the engine happens to handle, and the corpus quietly becomes a
mirror.

**What exists.** The separation is a type, not a promise: `BlindEvaluator` takes `CaseInput`
objects, which carry the evidence and the candidate population and nothing else. Three leaks
were closed because each would have made the blindness decorative — cases are shuffled *before*
identifiers are assigned, identifiers are opaque, and `distinct_real_origins` (the one field
that distinguishes laundering from honest corroboration) lives in the sealed label. A test runs
evaluators that use only the position and only the identifier, and requires them to land at
chance; with the shuffle removed, guessing from position alone scores 0.83 and it fails.

## 5. A sealed test set — apparatus `IMPLEMENTED`

A held-out set, never used to adjust anything, opened once. The moment it informs a change it
stops being a test set and becomes a training set with a misleading name, so:

- it is sealed so that opening it is an event;
- the number of times it has been opened is reported alongside any score from it;
- a change made after opening it invalidates every figure it produced, and the protocol says so
  in advance rather than negotiating afterwards.

**What exists, and one thing that does not.** `SealedLabels` counts every unsealing, refuses one
without a named actor and a stated reason, keeps an append-only log, and publishes a digest that
identifies the answers without revealing them. The count is rendered in the report, and a second
opening annotates every figure below it as suspect. *(Corrected: this section said "sealed with
the evidence vault's own machinery". It is not — the vault is asynchronous and sits behind a
different plane boundary, so the seal is self-contained and tamper-**evident** rather than
encrypted. It does not stop somebody reading the object in a debugger. Wiring it to the vault is
a real improvement and is not done; claiming it was would be the defect this repository rejects.)*

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

- **Reliability.** Bin predictions into the seven `BAND_RANGES` intervals — `PUBLISHED_BAND_BINS`
  in `calibration.scoring`, derived from `BAND_RANGES` rather than copied, so the two cannot
  drift. Deciles remain available as a finer diagnostic; a *reported* figure uses the published
  bands, because calibration should be measured on what a reader is told. Nobody acts on 0.83;
  they act on "very likely", and a model can be well calibrated across deciles while
  systematically misplacing the boundary that decides the word.
  For each bin *b* with *n_b* cases: `observed_b = (true positives in b) / n_b`, plotted against
  the bin's **mean forecast**. *(Corrected: this document first said "midpoint", and the
  implementation was right and the protocol wrong — the Murphy decomposition is defined on the
  mean forecast, and a midpoint introduces bias whenever predictions are not uniform within a
  bin.)*

  **Underpowered bins**, *n_b* < `MIN_BIN_COUNT` (20), are handled in exactly two ways, and the
  distinction is load-bearing:

  - They are **excluded from the reported reliability figure and from the plotted curve**
    (`BrierDecomposition.reported_reliability`), and reported **with their count**
    (`cases_excluded_as_underpowered`). Never merged into a neighbour — merging hides exactly
    where the evidence ran out. What a reader over-trusts is the curve point, not the weighted
    contribution: "at *almost certain* we were right every time" reads as calibration when it is
    three cases.
  - They are **retained in the Brier score and in all three Murphy terms**. *(Corrected: this
    document first said they were excluded from "any summary statistic", and the implementation
    kept them. Here too the code was right. A Brier score is over cases, not over bins; dropping
    the inconvenient ones makes it a score of a chosen subset, and the decomposition identity
    `BS = REL − RES + UNC` only holds over the whole sample.)*

  When **every** bin is underpowered there is no reported figure at all — `None`, not zero.
  Zero would read as perfect calibration on the strength of five cases.
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

**Where that stands today: one of the four is attached, and it was none until it was checked.**
`CalibrationReport` now carries a `MeasurementProvenance` — the three freeze digests plus the
resolved Python and runtime-dependency versions — rendered above the headline so a reader cannot
reach a number without having passed it. When the tree has moved it says so by name and says the
figures must not be compared with any taken at the frozen digests.

The other three are not attached and cannot be yet: population and ground-truth standard are
milestone 2, the sealed-set count is milestone 5, and both are `PROPOSED`. So this section
currently describes a rule the harness satisfies in one quarter. Saying so is the point — the
sentence above was written as a requirement and honoured in none of its four parts for as long
as nobody checked, which is what "a claim contradicting the code is a defect" means when the
claim is the protocol's own.

The environment is in the stamp for a reason the freeze cannot cover: **no digest over
`src/nemesis` changes when `pydantic` does.** A coercion or float-handling change in a
dependency moves a published band with all three digests green. It is recorded rather than
asserted, because a dependency bump should make two numbers *incomparable*, not make CI red.

---

## What this protocol cannot do

It cannot make the constants right; freezing a choice does not validate it. It cannot tell an
honest recalibration from a convenient one — only make both visible. And it cannot establish
that a corpus built from operations we ran resembles operations we did not: the population
claim in §2 is an argument, not a measurement, and it is the first thing an external reviewer
should attack.
