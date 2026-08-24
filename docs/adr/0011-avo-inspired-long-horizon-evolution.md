# ADR-0011: An AVO-inspired Evolution plane, above the pilot seam and strictly weaker than it

- **Status:** accepted
- **Date:** 2026-08-23
- **Deciders:** founding architect, founder
- **Plane:** evolution (new, plane 12), pilot (two additive changes), core (five id prefixes),
  slice (a demonstration), cli (one command)
- **Reversibility:** high, and deliberately kept that way. `nemesis.evolution` is additive: nothing
  below it knows it exists, and the two contracts written for it plus the six extended to name it
  would simply lose their lines. Deleting the plane removes a capability and breaks nothing that
  investigates, authorizes or seals — `nemesis pilot`, `nemesis demo` and every containment test
  run unchanged with the package absent. The two pilot-plane changes are the only parts that would
  need reverting rather than deleting, and both are strictly additive: an optional
  `Briefing.research_context` field that is `None` everywhere else, and a `continue_session` entry
  point that runs the loop `drive` already ran.

## Context

NEMESIS's autonomy story stops at one session. `PilotMediator.drive` opens an investigation, asks
a pilot for up to forty moves, and returns. That is enough to demonstrate the limiter, which is
what it was built for. It is not enough to answer the question the platform exists to answer,
because real attribution work is not forty moves long — it is hundreds, spread over hours or days,
and the interesting failure is not that the pilot does something forbidden on move three. It is
that on move three hundred it re-runs, at cost, the passive-DNS pivot that returned nothing on move
four, because nothing in the architecture remembers that it did.

A conventional stateless or context-only loop degrades in three specific ways, and each one is a
mechanism rather than a vibe:

**The context window rolls over and the investigation forgets.** What is lost first is exactly what
is least redundant: the negative results. A finding that mattered gets restated in the graph and
survives; "we looked at the certificate history and it showed nothing" exists only in a transcript
that has scrolled away.

**Nothing measures whether the run is still learning.** A pilot that has stopped making progress
looks, from inside the loop, identical to one that is about to make some. Budget goes on being
spent, moves go on being accepted, and the only signal that the trajectory stalled is a human
noticing.

**There is no unit of progress to compare.** Without one, there is nothing to promote, nothing to
reject, and no way to say which of two lines of enquiry was worth the money.

[AVO — *Agentic Variation Operators for Autonomous Evolutionary Search*, Terry Chen et al., NVIDIA,
arXiv:2603.24517v1, 2026-03-25](https://arxiv.org/abs/2603.24517) addresses the same three
problems in a different domain. Its formulation is `Vary(P_t) = Agent(P_t, K, f)`: an agent, given
the lineage of previous candidates and their outcomes, domain knowledge, and an objective function,
autonomously inspects, hypothesises, attempts, diagnoses, repairs, changes strategy and continues —
across long horizons, with a self-supervision mechanism that fires when progress plateaus
(§3, §3.1, §3.2, §3.3, §4.4).

Two things about that are directly useful here and one thing about it is actively dangerous.

Useful: **persistent structured lineage** and **an explicit evaluation function** are precisely
what a long investigation lacks, and **plateau-triggered redirection** is precisely the control a
loop with no human in it needs. Dangerous: AVO's objective is a benchmark that is correct by
construction. Cyber attribution has no such oracle, and the tempting substitution is fatal — see
the Decision.

## Problem

Can NEMESIS gain AVO's long-horizon research behaviour without gaining any of AVO's autonomy over
*effects*? The research loop must become more capable. The authority boundary must not become more
permissive. Those are separable only if the loop sits somewhere it cannot reach the boundary from —
and "somewhere" has to mean an import graph and a set of held objects, not a paragraph.

## Decision

Introduce **plane 12, `nemesis.evolution`**, sitting *above* the pilot seam in the layering and
holding strictly less than the plane below it.

### 1. The candidate is an investigation checkpoint, and deliberately not an attribution

This is the single most important decision in the ADR and everything else follows from it.

The obvious mapping — candidate `x_i` = an attribution, fitness `f(x_i)` = its confidence — is a
**Goodhart trap with a foreseeable failure**: the system would learn to raise a number rather than
to find out what is true, and it would do so convincingly, because producing a confident-sounding
attribution is exactly what a frontier model is good at. Attributing a criminal organization
wrongly is a serious error; building the machinery that optimises for that error and then
supervising it is not a plan.

So `x_i` is an `InvestigationCheckpoint` — the epistemic and operational state of an investigation
at a point in its trajectory — and what is measured is whether the state improved *as an
investigation*. A candidate that asserted a stronger conclusion and learned nothing scores zero, by
construction rather than by a check somebody has to remember.

### 2. The evaluation is hierarchical, gated, and reads nothing a model wrote

`PursuitEvaluator` runs in a fixed order:

| Order | What | Effect |
|---|---|---|
| Gate 0 | Hard validity — seven `EpistemicGate` members | `INVALID`, at any apparent gain |
| Tier 1 | Epistemic progress | Compared first, lexicographically |
| Tier 2 | Investigation utility | Compared only on a tier-1 tie |
| Tier 3 | Efficiency | A tie-break, negated so more is better |

Gate 0 is AVO's correctness requirement, and the analogy is exact: an extremely fast CUDA kernel
that computes the wrong answer is not an improvement, and an epistemically invalid trajectory is
not one either. A gate is not a term in a score and is never traded against one.

**Never a weighted sum.** A sum lets a large gain in a cheap dimension buy a loss in an expensive
one, which in attribution means entity volume buying away source independence.
`ScoreVector.ordering_key()` is a tuple of tuples; a candidate wins on epistemic progress or it does
not get to argue about anything else.

**Tier 1's internal order is a stated choice with a real cost.** Robustness first
(`origin_floor_gain`), then independent origins, then contradictions resolved, then hypotheses
settled, then uncertainty reduced, then evidence-backed claims. The cost is that a candidate
resolving two contradictions loses to one adding a single robust origin. That is accepted
deliberately, because the alternative ordering is the one that prefers a fragile spectacular
finding — and this repository has an ADR (0004) about exactly that preference being wrong.

**`origin_floor` is ADR-0004's counterfactual applied to a trajectory.** Group the sealed evidence
into provenance clusters, remove the single most load-bearing cluster an adversary could have
authored, count what is left. It reuses the two primitives fusion itself rests on —
`SourceDescriptor.provenance_cluster()` and `UNPLANTABLE_SOURCE_CLASSES` — so the two cannot drift
apart on what independence means, and it does **not** re-run `nemesis.core.fusion`, because fusion
combines opinions about a stated proposition and a trajectory is not a proposition.

**Nothing a model wrote appears in any term.** A `record_belief` move appears in exactly one place,
`moves_spent`, which is a cost. There is no term a rationale, a confidence phrase or a natural
language assertion can move. `test_model_confidence_cannot_raise_evolution_score` runs two
otherwise-identical steps, one of which asserts at length that it is 95% certain, and asserts the
epistemic keys are equal.

### 3. Memory is structured, classified, and carries no hidden reasoning

`ResearchMemory` holds useful findings, unresolved questions, assumptions under test,
contradictory observations, source and evidence gaps, high-value and exhausted pivot families,
branch notes, and untrusted hints — each entry carrying a `MemorySource`, a creator, a source
reference and a repeat key.

There is no `chain_of_thought` field and nowhere for one to go. NEMESIS does not request private
reasoning traces and has nothing to persist one in — the rule
`PilotResponseMetadata` states for a single turn, applied to a memory that outlives the turn.

The structure carries its own classification as a `Literal`:
`MODEL_GENERATED_OPERATIONAL_MEMORY`. It is not evidence, not an observation, not a fact and not an
attribution, and there is no field on it that could hold an artifact.

### 4. A long horizon makes prompt injection durable, so hints are contained four ways

An injection that survives one turn is a bad move the mediator refuses. An injection that reaches
persistent memory is a bad move the mediator refuses **on every future turn of every future
session**, and it arrives in the briefing wearing the platform's own voice. That is what this plane
adds to the threat model, and it is contained in four layers, listed in increasing order of how
much they are relied on:

1. **Sanitization.** Control characters, line and paragraph separators, the zero-width space and
   the bidi overrides are replaced (with a space, not deleted — deleting a zero-width space glues
   two tokens into a third that neither said); NEMESIS's internal vocabulary is redacted; the line
   is truncated.
2. **Classification.** `reads_as_an_instruction` names nine instruction shapes. A matching entry is
   **kept** — deleting it would hide the attack from the humans who must respond to it — and marked
   `imperative`, which excludes it from every projection into a briefing.
3. **Separated vocabularies.** No string can become a `ResearchDirective`, because a directive is a
   member of a closed enumeration and no string is a member of an enumeration. The controller's own
   strategy vocabulary is unreachable from anything a person or a model typed.
4. **The seam is unchanged.** A pilot that reads the smuggled suggestion and obeys it still has four
   verbs, and every one of them is still ruled on by a mediator this plane cannot reach.

Layers 1 and 2 are blunt and say so — a paraphrase gets through both, and
`test_the_classifier_is_honest_about_paraphrase` asserts that rather than leaving it implied. Layers
3 and 4 are the ones the security argument rests on.

### 5. Plateau detection is deterministic; supervision is optional and non-operational

`StagnationDetector` is code. Asking a model after every move whether the investigation is stuck
would put a nondeterministic judgement on the hot path of a loop whose whole value is that it
reconstructs, and would spend a provider call to learn something the numbers already say. Eight
signals, every threshold in `StagnationPolicy` with a documented default and a stated reason, no
magic number inside a comparison.

`TrajectorySupervisor` runs **only after** the deterministic detector says there is something to
consult about, and it holds no authority by construction. `DirectiveType` has nine members and not
one of them does anything: no `APPROVE`, no `ESCALATE`, no `RUN_PIVOT`, no `AUTHORIZE`, and
deliberately no `EXPAND_SCOPE` to pair with `REDUCE_SCOPE`. A directive changes one word in the next
briefing plus a focus and a rationale. The worst a hijacked, hallucinating or hostile supervisor
achieves is an investigation that changes strategy when it should not have: wasted budget, never an
unauthorized action — the same asymmetry `MoveChallenger` rests on.

A supervisor that raises, stalls or answers outside the vocabulary does **not** stop the run. The
directive becomes `CONTINUE_ON_FAILURE` with `answered=False` recorded beside it, for the reason
the challenger gives: making an advisory control able to halt an investigation hands anyone who can
degrade it a way to stop one.

**The shipped supervisor is deterministic and holds no model.** A model-backed one is `PROPOSED`;
see "What is not claimed" below.

### 6. The trajectory is append-only and hash-chained, and keeps what it rejected

`LineageStore` distinguishes the **active lineage** (the chain of promoted checkpoints, which is
what a resume restores) from the **complete audit trajectory** (every entry ever appended). A
rejected candidate does not leave the second one. Three separate things depend on that: not
repeating spent work, answering "why did you not look there?", and invariant 11, which does not
exempt a decision that was later reversed.

It chains for the reason the spend ledger chains: deleting a rejected attempt is the obvious way to
make a run look better than it was and — worse — to make an exhausted direction look fresh so it
gets retried at cost. Its honest limit is this repository's standing one: deleting the *newest*
entry is undetected, because nothing follows the tail.

### 7. Branching partitions an allowance and never multiplies one

`BranchPortfolio.open` subtracts from a fixed number and raises `BudgetError` when the number runs
out. Three branches from a twelve-step run are three ways of spending twelve steps. Closing a branch
returns its **unspent** allowance and never what it spent.

The autonomous-**effect** budget is not partitioned here because it is not held here. It belongs to
`AutonomyEnvelope`, which this plane cannot import, cannot read and cannot spend — so branching
cannot multiply it for the strongest available reason, which is that there is nothing here to
multiply.

### 8. Two additive changes to the pilot plane, and no fifth verb

**`Briefing.research_context: ResearchContext | None = None`.** Bounded by its own model
(`MAX_CONTEXT_ITEMS = 8` per list, 240 characters per line), `extra="forbid"`, and with
`untrusted_hints` as its own separately-named field for the reason `InboundSignal` is a different
type from `CollaborationEvent`: a structure that flattened suggestions into findings would let the
first be read as the second. `None` for every session that does not run under a long-horizon
driver, which is what keeps the seam unchanged for `nemesis pilot`, the benchmark, and every
containment test written before the field existed.

**`PilotMediator.continue_session(...)`.** `drive` opens a new investigation every time it is
called, so a driver evaluating a trajectory every few moves would have had to restart the pursuit on
each segment — new hypotheses, new branches, and a pivot budget that resets, which is budget
multiplication by another name. `continue_session` is the loop `drive` already ran, entered at a
different point, with the same vocabulary, the same envelope, the same challenger, the same
disclosure wall and the same audit records. Its `max_moves` is clamped **down, never up**:
`min(requested, self._max_moves)`. A segment cannot buy itself a larger ceiling.

**No fifth verb, and the absence is asserted.**
`test_evolution_does_not_add_a_fifth_pilot_verb` checks the union members, the tool-suite names and
the count; a second test checks that nothing in `nemesis.evolution` declares a move-shaped
discriminator.

### 9. Redaction inside the research context, not refusal

The mediator redacts NEMESIS's internal markers from every string in a supplied `ResearchContext`
before the briefing is assembled, using a token (`[redacted]`, ten characters) that is **shorter
than the shortest marker** — a property a test asserts rather than assumes, because redaction here
happens after the model's own length bounds have been checked.

Redaction rather than refusal, for the reason the entity listing gives for a natural key: this text
comes from a channel an adversary can write into, so treating a marker in it as a *leak* would hand
them a way to halt an investigation by typing one. There is no leak to prevent — nothing in the
structure is classified — and the fail-closed scan at the end of `_brief` keeps its single meaning
for the fields the platform itself authors.

### 10. Buzz remains a projection surface

Evolution state lives in NEMESIS. `nemesis.evolution.projection` builds `CollaborationEvent`s
through the existing factory, so DELIVERABLE-only, bounded payloads, the internal-marker scan,
content-addressed identifiers and references-instead-of-content all apply unchanged. Two refusals
are specific to this plane:

**A hint is never echoed back.** `hint_event` publishes that a suggestion arrived, who sent it, how
it was classified and whether it will reach the pilot — and not one character of what it said.
Repeating it under NEMESIS's own actor would amplify an adversary's message with the platform's name
on it.

**Progress is projected as counts, never as confidence.** Every event carries `confidence=None` with
an `uncertainty_note` saying why. A directive is published as `RECOMMENDATION`, which is the
vocabulary's existing word for a proposed course of action that authorizes nothing by existing.

## The adversarial review, and the 25 things it found

This design was attacked before it was accepted. Six independent reviewers each took one lens —
seam bypass, supervisor authority, Goodhart pressure on the evaluator, memory poisoning, durability
and audit, invariant regression — against the ten claims above. A second pass then tried to
*refute* each finding by reproducing it, with `REFUTED` as the default and `UNVERIFIABLE` available
as an honest verdict. **29 findings were verified: 25 confirmed, 4 refuted.**

That confirm rate is much higher than this repository's own measured baseline (about two thirds of
first-pass findings normally do not survive), and the reader should treat that as information about
the *code*, not about the review: a plane written in one pass had a lot wrong with it.

Every confirmed finding is fixed and pinned by a test in
`tests/invariants/test_evolution_review_regressions.py`. **Each of those 17 fixes was reverted and
the pinning test seen to go red**, and that check earned its keep immediately: 3 of the tests passed
against the broken code on the first attempt — they were vacuous, because an outer layer already
sanitized what the inner layer was supposed to guard — and were rewritten to exercise the layer they
name.

The four shapes, which are more useful than the list:

**A bound applied to one field of six.** The seam caps a research-context line at 240 characters
and a memory entry may hold 400. One list was truncated and five were not, so a *benign*
305-character suggestion typed into a channel raised a `ValidationError` out of the step and killed
the run permanently — the entry stayed in memory, so every retry raised again, and `stop_reason` was
never set. The asymmetry is the sting: a long *hostile* hint is quarantined by the classifier and
harmless, so the weapon was a long innocuous one. This is exactly the denial of service §9 above
says it refuses to have, reintroduced through length instead of through vocabulary.

**A control the untrusted party can fire.** An author reference containing an internal marker made
the *quarantine notice* unpublishable — so the one event that reports an injection attempt was the
one an attacker could suppress by choosing their own display name.

**A predicate that cannot be true.** The `SOURCE_INDEPENDENCE` gate counted duplicates in a
deduplicated tuple. It could not fire for any input, and its presence read as coverage. Two other
terms were similarly hollow: `novel_pivot_families` counted families the pilot merely *proposed*,
refused ones included, so a candidate could be promoted for naming three new directions on an
entity that does not exist; and `moves_spent` appeared in no ordering key, so the `record_belief`
cost this ADR describes did not exist.

**A head read where a trajectory should have been.** `resume()` refunded every step taken since the
last promotion, silently reversed a recorded stop, and cleared the hard-gate strike counter — three
ways of turning a restart into free budget.

Two more worth naming individually. `chain_hash` encoded through `canonical_bytes`, which **sorts
arrays**, so reordering a checkpoint's evidence references produced a byte-identical digest and a
journal could be edited without breaking the chain — the same lesson `derive_event_id` states in
the collaboration plane. And `_origins` marked a whole cluster unplantable when any one member was,
which for the `lineage:unknown` bucket meant one anonymous own-sensor artifact laundered nine
anonymous planted ones into the robustness floor: the exact laundering the bucket exists to
prevent, one level up.

**What the review could not break.** It found no way for the plane to bypass the mediator, no fifth
verb, no path from a supervisor to an executed action, no way for a channel hint to become evidence
or to widen an envelope, and no way for a model's stated confidence to raise a score. Those are the
claims the design rests on and they held. One finding is worth recording as a *limitation rather
than a defect*: the controller holds a mediator, and the mediator holds the engine, the envelope and
the registry, so `controller._mediator._envelope` reaches them by attribute traversal. Python has no
object-capability enforcement; what the contracts and tests establish is the import graph and the
declared API, and this ADR does not claim more.

---

## What is borrowed from AVO, and what is not claimed

| AVO concept | NEMESIS realisation | Status |
|---|---|---|
| Candidate `x_i` | `InvestigationCheckpoint` — **not** an attribution | `IMPLEMENTED` |
| Lineage `P_t` | `LineageStore`, hash-chained, keeps rejections | `IMPLEMENTED` |
| Knowledge `K` | The existing `Briefing` — minimized, scanned, deliverable-class | `IMPLEMENTED` |
| Objective `f` | `PursuitEvaluator` — gated, hierarchical, structural | `IMPLEMENTED` |
| Variation operator | `EvolutionController` composing a context; the pilot proposing moves | `IMPLEMENTED` |
| Execution feedback | `PilotMediator` rulings, read by the controller | `IMPLEMENTED` |
| Persistent memory | `ResearchMemory`, classified, no reasoning traces | `IMPLEMENTED` |
| Correctness gate | `EpistemicGate`, seven members, checked before any gain | `IMPLEMENTED` |
| Self-supervision | `StagnationDetector` + `DeterministicSupervisor` | `IMPLEMENTED` |
| Self-supervision by a model | The seam exists and re-validates identically | `PROPOSED` |
| Population / islands | `BranchPortfolio`, serial | `IMPLEMENTED` (serial) |
| Multi-model islands, concurrent | — | `PROPOSED` |
| Human observability | The existing collaboration plane, extended | `IMPLEMENTED` |

**This is not NVIDIA's AVO.** Their production agent harness is not published; nothing here
reproduces it, and no claim in this repository should be read as an implementation of their system.
What is taken is the *shape* of the idea — lineage, an explicit objective, negative-result memory,
plateau redirection — adapted to a domain where the objective function is the hard part rather than
a given.

**The model-backed supervisor is deferred for a stated reason, not forgotten.** Reusing
`ProviderSeat` (as `ModelChallenger` does) would require `PilotContext` to carry a third kind of
content: it holds a briefing and an optionally proposed move, and a trajectory dossier is neither.
Widening the least-trusted plane in the tree to carry a new content type is not a change to make
speculatively for a component whose deterministic form answers most plateaus correctly. The seam
accepts any `TrajectorySupervisor` and re-validates its output through the closed vocabulary, and
`test_a_hostile_supervisor_cannot_run_a_pivot_or_request_an_effect` constructs one that tries to
act.

## Alternatives considered

**Optimise attribution confidence directly.** Rejected as a Goodhart trap, in detail, above. It is
the design most readers will expect and it is the one that produces a system that gets more
confident without getting more right.

**Put the loop inside the mediator.** Rejected because it inverts the trust story. The mediator is
the limiter; giving it a memory, an evaluator and a strategy would make the component that enforces
the limits also the component that wants to make progress, and those two jobs conflict at exactly
the moments that matter.

**Give the Evolution plane its own narrow execution path** — let it run pivots directly for
"cheap" evaluation reads. Rejected outright. It is the one change that would make the plane a second
driver, and every containment argument in ADR-0008 assumes there is only one.

**Compare a candidate's score against the incumbent's score.** Implemented first, and *wrong* — the
correction is recorded here because a run found it rather than a review. Both are deltas, so the
comparison asks "did this step improve more than the previous step did", which freezes the head at
whichever step happened to make the largest jump while the investigation goes on learning.
Comparing deltas is the right question for **siblings** (several variations of one parent, which is
what AVO selects between) and the wrong one for a chain. `promotes()` is the chain rule;
`best_of()` is the sibling rule and is where the ordering key belongs.

**A separate store for research memory, referenced by checkpoints.** Rejected in favour of
embedding the memory in the checkpoint. A reference into a mutable store lets a resumed run read
memory that has since changed, and a checkpoint is supposed to be the state *at that point*.

**Make plateau detection a model call.** Rejected: nondeterminism on the hot path of a loop whose
value is that it reconstructs, at provider cost, to learn what the numbers already say.

**No new plane — put Evolution inside `pursuit`.** Rejected because planes here are separated by
trust level, not by function, and this one is genuinely different: it composes what an untrusted
model is told, which is a job that must not sit beside the code that executes collection.

## Consequences

- `nemesis evolution` runs a bounded long-horizon run end to end and exits 0. It shows the memory
  paying for itself, a plateau, a redirect, a quarantined hint, and a refused effect.
- Two new `import-linter` contracts, both **verified to break on a probe rather than merely to
  pass**: adding `from nemesis.authz.envelope import AutonomyEnvelope` to a controller module breaks
  `evolution-holds-no-platform-handles`; adding an evolution import to `nemesis.pilot.moves` breaks
  both `pilot-does-not-know-about-evolution` and the layering contract. Six existing contracts were
  extended to name the new plane.
- The pilot seam gained one optional field and one entry point. Every containment test written
  before this work passes unchanged, which is the property that makes the addition safe.
- Three tier-1 terms are computed from state nothing in the shipped engine writes —
  `hypotheses_settled` and `uncertainty_reduction` read a `Hypothesis` whose state and `Opinion` the
  pursuit engine never updates, and `contradictions_resolved` reads `contradicted_by_claims`, which
  no shipped connector populates. The code is real and unit-tested against constructed state; in the
  reference demonstration those three terms are always zero. Stated here because a metric that
  cannot move is not a metric that is working.
- `discriminating_relationships` reads zero on the current fixtures, for a reason that is a defect
  in the plane below: `materialize` mints entity ids and builds edges against them, and
  `PursuitEngine._absorb` upserts the entities (merging an existing one and returning the canonical
  id) while adding the edges unchanged — so every edge touching a known entity references an
  identifier the graph does not hold. Measured: three executions of one registration pivot leave two
  entities in the store and six distinct endpoint identifiers on three edges, none of which resolve.
  The evaluator refuses to count an edge whose endpoints the graph cannot vouch for, so it cannot be
  *inflated* by the defect; the defect itself is reported rather than quietly patched from a plane
  that must not write the graph.
- The scoring shape, the tier ordering and every stagnation threshold are `PROPOSED` as calibration.
  They are documented choices, frozen so they can be argued with, and not one of them has been
  validated against a resolved case — because none exists. This is the same standing every other
  constant in this repository has, and the Evolution plane does not improve it.

## Enforcement

| Property | Enforced by |
|---|---|
| Evolution cannot reach effects, authz, evidence, the graph or the engine | `evolution-holds-no-platform-handles`, verified to break on a probe |
| The pilot seam does not know Evolution exists | `pilot-does-not-know-about-evolution`, verified to break on a probe |
| `core` cannot import the plane | `core-is-independent`, extended |
| Effects cannot reach it (exfiltration path) | `effects-no-ambient-authority`, extended |
| The vault cannot reach it | `evidence-vault-isolation`, extended |
| A provider adapter cannot reach it | `provider-adapters-hold-no-handles`, extended |
| No fifth pilot verb | `test_evolution_does_not_add_a_fifth_pilot_verb` |
| The supervisor emits no move and holds no authority | `test_a_supervisor_cannot_emit_a_pilot_move`, `test_a_hostile_supervisor_cannot_run_a_pivot_or_request_an_effect` |
| Branching cannot multiply a budget | `test_branching_does_not_multiply_budget`, `test_a_long_run_does_not_widen_the_effect_envelope` |
| Model confidence cannot raise a score | `test_model_confidence_cannot_raise_evolution_score` |
| Memory and checkpoints are not evidence | `test_research_memory_is_not_evidence`, `test_checkpoint_is_not_evidence` |
| A hostile hint stays data, for ever | `tests/invariants/test_evolution_memory_poisoning.py` (23 tests) |
| A resume restores no authority | `test_resume_does_not_restore_expired_authority` |
| Rejected candidates stay in the trajectory | `test_a_failed_attempt_remains_in_the_audit_trajectory` |
| An invalid candidate cannot be promoted | `test_an_invalid_candidate_cannot_be_promoted_at_any_gain` |
| Unknown provenance gains no independence | `test_unknown_provenance_does_not_gain_independence` |
| Every defect the adversarial review confirmed | `tests/invariants/test_evolution_review_regressions.py` (26 tests, 17 mutation-checked) |

## Residual risk

**The classifier is a blunt instrument and a paraphrase defeats it.** Asserted as a test rather than
admitted in prose. What makes it survivable is layers 3 and 4, and a reader who trusts layers 1 and
2 has misread this ADR.

**A long horizon multiplies exposure to a hosted vendor.** Every step sends a briefing, and now the
briefing carries operational memory as well. The material is deliberately the same class as before —
deliverable, scanned, minimized — but there is more of it and it goes out more often. A deployment
sending briefings to a vendor should read `MAX_CONTEXT_ITEMS` as a decision it is making.

**Nothing validates that the loop is better than a stateless one.** The scientific question this
plane was built to make answerable — does structured lineage plus explicit evaluation plus
negative-result memory plus plateau redirection let a frontier model keep making progress after
hundreds of pivots — is *not* answered by building it. It is measurable now, on the same fixtures,
against the existing `nemesis pilot` loop, and that comparison has not been run.

**The trajectory has no external anchor**, so the same insider gap the evidence vault reports
applies: an operator who controls the store can recompute the chain, and deleting the newest entry
is undetected.

## Revisit when

- A resolved-case corpus exists, and the scoring constants can be calibrated rather than argued.
- The single-lineage loop has been measured against the conventional pilot loop on the same
  fixtures. That comparison, not multi-model islands, is the next step.
- The Pursuit-plane materialization defect is fixed, at which point `discriminating_relationships`
  becomes informative and the evaluator's workaround becomes unnecessary (though still correct).
- Concurrent islands are actually wanted, at which point the lineage store needs the atomic
  reservation `SqliteAuthorizationStore` gives the spend ledger, and the portfolio needs a
  concurrency story that this ADR deliberately does not have.

## References

- [AVO: Agentic Variation Operators for Autonomous Evolutionary Search](https://arxiv.org/abs/2603.24517)
  — Terry Chen et al., NVIDIA, arXiv:2603.24517v1, 2026-03-25. §3 Agentic Variation Operators,
  §3.1 Formulation, §3.2 Anatomy of a Variation Step, §3.3 Continuous Evolution, §4.4 Evolution
  Trajectory.
- [ADR-0008](0008-the-pilot-seam-and-envelope-bounded-autonomy.md) — the pilot seam, and why
  authority lives outside the model
- [ADR-0004](0004-robustness-margin-against-planted-evidence.md) — the counterfactual `origin_floor`
  is modelled on
- [ADR-0002](0002-subjective-logic-for-evidence-fusion.md) / [ADR-0003](0003-evidence-fusion-corrected.md)
  — why provenance clusters, not source names, count
- [ADR-0010](0010-buzz-as-an-optional-collaboration-provider.md) — the collaboration plane this one
  projects into
- [`docs/architecture/evolution-plane.md`](../architecture/evolution-plane.md) — the integration map

## Verification status

**Counter-verified against the code, by running it:**

- The `arXiv:2603.24517v1` identifier, the author, the institution, the date and the section
  numbers are **as supplied in the engineering brief that commissioned this work and were NOT
  independently verified** — no network access was used and the paper was not fetched. Read every
  citation of it here as "the brief says", not as "checked". If the identifier is wrong, the
  architecture is unaffected and the citation must be corrected.
- The two new import contracts were verified to **break on a deliberate probe** and then restored;
  the transcript is in the commit message.
- The materialization defect described under Consequences was **reproduced**, not inferred: three
  registration pivots, `entity_count() == 2`, six distinct endpoint identifiers on three edges, none
  resolving.
- The delta-versus-delta promotion error was found by **running the reference demonstration** and
  observing the head freeze at step one; the corrected rule is `promotes()` and the demonstration
  now shows five promotions across six steps.
- The duplicate-edge scoring hole was found the same way and is pinned by the evaluator counting
  assertions rather than identifiers.
- The adversarial review's 25 confirmed findings were each **reproduced** by a second pass whose
  instruction was to refute them, and each fix was **mutation-tested**: the fix reverted, the
  pinning test seen red, the fix restored. The mutation transcript is in the commit message.
- Everything else in this ADR is a claim about code in this commit and is asserted by a test named
  in the Enforcement table.

**Not verified:** that the scoring shape is *right*. It has never been scored against a known-correct
answer and cannot be until resolved cases exist.

---

## Amendment, 2026-08-23: what a measurement pass found

Somebody went to take the measurement this ADR asks for and did not get that far. What they
found first is recorded here rather than in a commit message, because two of the items below
change what this document may claim.

**Four defects, each reproduced against the code as it shipped** and fixed in
`tests/invariants/test_evolution_detector_defects.py`:

1. `StagnationDetector.assess` summed **four of the six** tier-1 terms. It read
   `epistemic_key[0]` and `[1]` positionally and then named `contradictions_resolved` and
   `hypotheses_settled` by attribute — the same tuple reached two ways — so
   `uncertainty_reduction` and `evidence_backed_claim_gain` were never added. A step gaining an
   evidence-backed claim counted as zero movement, and the shipped default policy assessed four
   such steps as a plateau. It now folds over the key, so a term added to the tier is counted the
   day it exists.
2. `StepRecord.pivot_families` was the checkpoint's `pivots_attempted`, built from the
   investigation's **cumulative** executed-pivot history. A family run once appeared in every
   later checkpoint, so `REPEATED_PIVOT_FAMILY` counted it once per step in the window, for ever.
   The reference demonstration escaped it only by overriding the window to 3, where the count
   lands exactly on a strict `>`. It is now read per step from the transcript's proposals.
3. The supervisor's two exhaustion guards compared against the **immediately previous**
   directive, so alternating `seek_independent_origin` and `revisit_prior_branch` defeated both
   permanently — neither was ever "in force for two steps", and the `STOP_LOW_YIELD` escalation
   beneath them was unreachable. Measured over four consecutive steps with no promotion, no
   epistemic gain, every candidate rejected and the budget burning. The state now carries every
   posture issued during the gainless streak.
4. `_verdict_detail` wrote *"the candidate beat the incumbent on the epistemic tier"* into the
   hash-chained lineage on **every** promotion, including ones whose epistemic key was all zeros.
   `promotes()` does not compare epistemic tiers and says so in its own docstring. It now names
   the tier that moved.

**Two claims in this ADR need reading more narrowly.** Neither was false when written; both are
narrower in the shipped build than the prose suggests, and the difference matters to anyone
planning to measure this plane.

- *"Evaluation is gated and lexicographic, never a weighted sum."* The gating is real and the
  lexicographic comparison exists — but `ordering_key()` and `best_of()` have no caller outside
  their own module. That is consistent with `promotes()`, which argues that comparing deltas is
  the wrong question for a chain and leaves the ordering to *sibling* selection; sibling selection
  is `BranchPortfolio`, which is itself unwired. So in the shipped loop the decision is a coarse
  boolean over tiers 1 and 2, and tier 3 is inert. Nothing here is wrong; the ADR simply presents
  as the evaluation a comparison the running loop does not perform.
- *"The supervisor's whole vocabulary does nothing."* True, and more literally than intended:
  **8 of the 9 `DirectiveType` members have zero references outside `supervisor.py`.** Only
  `STOP_LOW_YIELD` reaches a code path. A redirect changes the next briefing's wording and
  nothing else — which is the containment property this ADR wanted, and also means the
  "redirection" half of *plateau redirection* is not yet a mechanism a benchmark could measure.

**And one measurement about the memory.** After a full reference run, 3 of the 10
`ResearchMemory` lists are populated. Two of the seven empty ones — `unresolved_questions` and
`contradictory_observations` — are projected into *every* briefing, so the pilot is shown two
headings that are structurally always blank.

**The benchmark this ADR names as the next step is not buildable as written.** The fixture world
holds **37** answerable `(pivot type, entity)` pairs, counted from `glass_anvil.py`; there is no
frontier model wired to any of the six provider seats; and `pilotbench` drives `mediator.drive`
where the comparison needs `continue_session`. See milestone 1 in `PROJECT_STATE.md` for the
counts and for the two honest options that replace it.
