# The Evolution plane — how an investigation keeps learning after 500 moves

Plane 12. The integration map for `nemesis.evolution`: what it is, what it holds, what it cannot
reach, and where each claim is enforced. For *why* it is shaped this way, see
[ADR-0011](../adr/0011-avo-inspired-long-horizon-evolution.md). For what the adversary is assumed
to do, see [THREAT_MODEL.md](THREAT_MODEL.md).

Component status carries the labels defined in `CLAUDE.md`.

---

## The one-line version

**Evolution decides what to ask next. The Pilot proposes a move. The Mediator decides whether that
move is allowed.**

Adding a research loop above the limiter must not make the limiter more permissive, and the way that
is guaranteed here is that the loop sits *outside* the seam and speaks to the model only through the
briefing.

---

## The shape

```
                            BUZZ (or any collaboration provider)
                                        |
                         projections out  |  hints in, UNTRUSTED
                                        v
     +--------------------------------------------------------------+
     |  PLANE 12  EVOLUTION            (control, strictly weaker)   |
     |                                                              |
     |  EvolutionController ── LineageStore (append-only, chained)  |
     |          |             ResearchMemory (classified)           |
     |          |             PursuitEvaluator (gated, tiered)      |
     |          |             StagnationDetector (deterministic)    |
     |          |             TrajectorySupervisor (no authority)   |
     |          |             BranchPortfolio (partitions only)     |
     +----------|---------------------------------------------------+
                | a Briefing carrying a bounded ResearchContext
                v
          PLANE --  PILOT SEAM        run_pivot · record_belief
                |                     request_effect · conclude
                v
            PILOT MEDIATOR   ── holds every handle Evolution does not
                |
     +----------+-----------+------------+
     v          v           v            v
  Pursuit    Graph      Evidence    Attribution → Disrupt → Authz → Effects
```

The arrows that do **not** exist are the design:

- Evolution has no arrow to Effects, Authorization, the Evidence vault, the graph writer, a
  connector, or the Pursuit engine. It cannot import any of them (`evolution-holds-no-platform-handles`).
- The Pilot seam has no arrow *up* into Evolution. Every provider adapter, the mediator and the
  benchmark behave identically whether a long-horizon driver is running or not
  (`pilot-does-not-know-about-evolution`).
- A collaboration channel has no arrow into evidence, scope or authority. A hint is data.

---

## What each component is

| Module | Status | What it is |
|---|---|---|
| `evolution/models.py` | `IMPLEMENTED` | `InvestigationCheckpoint`, `ScoreVector`, `EvaluationResult`, `EvolutionBranch`, `EvolutionRun`, `EpistemicGate`, `StopReason`. `promotes()` for a chain, `best_of()` for siblings |
| `evolution/memory.py` | `IMPLEMENTED` | `ResearchMemory`, `MemoryEntry`, `NegativeResult`, `MemorySource`, sanitization and instruction classification |
| `evolution/lineage.py` | `IMPLEMENTED` (in memory and durable) | Hash-chained append-only trajectory; `active_lineage()`; `FileLineageStore` with fsync and replay |
| `evolution/evaluator.py` | `IMPLEMENTED` | `PursuitEvaluator` — seven hard gates, then three tiers, over structure the model cannot write |
| `evolution/stagnation.py` | `IMPLEMENTED` (mechanism) / `PROPOSED` (thresholds) | Eight deterministic plateau signals, every threshold configurable and documented |
| `evolution/supervisor.py` | `IMPLEMENTED` (deterministic) / `PROPOSED` (model-backed) | `DirectiveType` (nine members, none of which act), `ResearchDirective`, `validate_directive`, `DeterministicSupervisor` |
| `evolution/portfolio.py` | `IMPLEMENTED` (serial) / `PROPOSED` (concurrent islands) | `BranchPortfolio` — partitions one allowance, never creates one |
| `evolution/controller.py` | `IMPLEMENTED` | The loop. Holds a mediator, an evaluator, a lineage store, a detector and a supervisor — and nothing else |
| `evolution/projection.py` | `IMPLEMENTED` | Evolution → `CollaborationEvent`. Publishes counts, never confidence; never echoes a hint |
| `evolution/ports.py` | `IMPLEMENTED` | `EntityReader`, `ClaimReader`, `EvidenceReader` — narrowings of existing ports, satisfied structurally |
| `slice/evolution_session.py` | `IMPLEMENTED` (harness) / `SIMULATED` (pilot, connectors) | The reference run behind `nemesis evolution` |

---

## One variation step, in order

```
  1. compose      a bounded ResearchContext from memory + the standing directive
  2. drive        mediator.continue_session(pilot, investigation, max_moves, context)
  3. observe      the transcript: rulings, evidence sealed, entities surfaced
  4. remember     write negative results and high-value families from the RULINGS
  5. evaluate     seven gates, then three tiers, against the parent measurement
  6. decide       promotes() — valid AND made measurable progress over its parent
  7. record       promotion or rejection, both, into the append-only trajectory
  8. detect       deterministic plateau assessment over the recent window
  9. redirect     only if stalled: consult a supervisor, validate its directive
 10. stop         when a deterministic condition fires, and say which one
```

Step 4 is worth pausing on: memory is written from the **mediator's rulings**, not from anything the
pilot said about its own move. A pivot the pilot rationalized beautifully and which sealed nothing
is recorded as having sealed nothing.

---

## The evaluation, concretely

**Gate 0 — hard validity.** Failing any one makes a candidate `INVALID`, at any apparent gain. It is
never traded against a score; the score is still *reported* so an operator can see what the
candidate would have been promoted for.

| Gate | Fails when |
|---|---|
| `SCOPE` | An entity the checkpoint names is not in the graph |
| `PROVENANCE` | An evidence reference does not resolve in the vault |
| `SOURCE_INDEPENDENCE` | The origin count exceeds the number of *named* clusters plus one for all unknown-lineage sources together |
| `EVIDENCE_SEMANTICS` | A pilot belief is anything other than HYPOTHESIS / MODEL_ASSERTION |
| `IDENTITY` | An internal-classified entity reached the checkpoint's references. A backstop: the references are filtered first, and how many were withheld is recorded (founder decision D1) |
| `AUTHORIZATION_BOUNDARY` | An effect reported contact with the outside world, **or ran and did not say** |
| `POLICY` | The segment spent more moves than its ceiling allowed |

**Tier 1 — epistemic progress**, compared first and in this order:
`origin_floor_gain` → `independent_origin_gain` → `contradictions_resolved` → `hypotheses_settled`
→ `uncertainty_reduction` → `evidence_backed_claim_gain`.

**Tier 2 — investigation utility**, compared only on a tier-1 tie:
`useful_entities_discovered` → `discriminating_relationships_gained` → `novel_pivot_families`.
Novelty is counted over pivots the mediator **accepted**, never over what the pilot proposed: a
review found that counting proposals let a candidate be promoted for naming three new directions on
an entity that does not exist, all three refused.

**Tier 3 — efficiency**, a tie-break only, negated so more is better:
`redundant_pivots` → `pivots_spent` → `moves_spent` → `budget_spent` → `refused_moves`.

`origin_floor` is the counterfactual: group sealed evidence into provenance clusters, remove the
single most load-bearing cluster an adversary could have authored, count what survives. Ordering on
it first is how "robust beats fragile" stops being a slogan.

A *named* cluster survives removal when any source in it is unplantable — sources known to share an
origin vouch for each other. The `lineage:unknown` bucket **never** survives, whatever it contains,
because it is a bag of sources about which nothing is established rather than a set that shares an
origin. Treating it as vouched-for because one anonymous own-sensor artifact landed in it would
launder every other anonymous artifact beside it, which is the laundering the bucket exists to
prevent.

---

## Where the trust boundary is enforced

| Property | Enforced by |
|---|---|
| Cannot bypass the mediator | `evolution-holds-no-platform-handles` + `test_no_evolution_module_names_a_plane_that_acts` + `test_the_controller_holds_no_capability_and_no_writer` |
| No fifth verb | `test_evolution_does_not_add_a_fifth_pilot_verb` |
| The supervisor holds nothing | `test_a_supervisor_cannot_emit_a_pilot_move`, `test_a_supervisor_has_no_verb_that_executes_authorizes_or_widens` |
| Branching cannot multiply a budget | `test_branching_does_not_multiply_budget`, `test_a_long_run_does_not_widen_the_effect_envelope` |
| Model confidence cannot score | `test_model_confidence_cannot_raise_evolution_score` |
| Memory / checkpoints are not evidence | `test_research_memory_is_not_evidence`, `test_checkpoint_is_not_evidence` |
| A hostile hint stays data for ever | `tests/invariants/test_evolution_memory_poisoning.py` |
| A resume restores no authority | `test_resume_does_not_restore_expired_authority` |
| Rejections stay in the trajectory | `test_a_failed_attempt_remains_in_the_audit_trajectory` |
| Every meaningful decision is auditable | `test_every_meaningful_decision_reaches_the_trajectory` |

Both new import contracts were **verified to break on a probe** rather than merely to pass.

---

## Hints from a collaboration channel

A human or a foreign agent can put a research suggestion into a case channel. It becomes a
`MemoryEntry` with `MemorySource.HUMAN_HINT` — sanitized, classified, bounded — and it stays
untrusted for the life of the run.

```
  channel message
        |  InboundSignal (a different type from CollaborationEvent, deliberately)
        v
  sanitize   control chars, bidi overrides, internal markers, length
        |
  classify   reads_as_an_instruction() -> nine instruction shapes
        |
   +----+------------------------------+
   |                                   |
  clean                            instruction-shaped
   |                                   |
  stored in untrusted_hints        stored in untrusted_hints, marked imperative
   |                                   |
  projected into the briefing      NEVER projected. Kept, so a human can see the attempt.
   |                                   |
   +----------------+------------------+
                    v
              still cannot become: evidence · a directive · an effect · scope · authority
```

It can never become a directive because a directive is a member of a closed enumeration and no
string is a member of an enumeration. That is the containment worth relying on; the classifier is a
blunt instrument that a paraphrase defeats, and a test asserts that rather than leaving it implied.

---

## What `nemesis evolution` shows

```bash
uv run nemesis evolution
```

Six bounded steps over one investigation, no human intervention anywhere:

1. Two productive pivots. The candidate beats an empty incumbent and is **promoted**.
2. A hijacked effect request — the pilot obeys an instruction planted in collected content. The
   capability **refuses** it, exactly as it does with no evolution loop above it.
3. A question no connector can answer, asked three times. Nothing refuses it; the trajectory
   **records** it, and the third repeat is charged as redundant work. The candidate is **rejected**.
4. The next briefing carries `exhausted_directions`, and the pilot changes direction on its own.
   **This is the mechanism the plane exists for**, and nothing forced it.
5. A **plateau** fires; the deterministic supervisor issues `SEEK_INDEPENDENT_ORIGIN`; the next
   briefing carries it. The directive runs nothing.
6. The trajectory stays flat, the supervisor recommends stopping, and the run **stops** on
   `low_yield` — a deterministic condition, not a mood.

Two suggestions arrive from a channel before the run. One is research and reaches the pilot labelled
untrusted; one is an injection and is kept, classified and never shown.

---

## What an adversarial review found

Six independent lenses attacked this plane's ten design claims; a second pass reproduced each
finding rather than confirming it. **29 verified: 25 confirmed, 4 refuted.** Every confirmed one is
fixed and pinned in `tests/invariants/test_evolution_review_regressions.py`, and each of the 17
fixes was reverted and its test seen to go red — a check that immediately earned its keep, because
3 of the tests passed against the broken code on the first attempt and had to be rewritten.

What it could **not** break: bypassing the mediator, a fifth verb, a supervisor causing an action, a
channel hint becoming evidence or widening an envelope, or a model's stated confidence raising a
score. Those are the claims the design rests on.

What it broke, in one line each:

| Shape | The defect |
|---|---|
| A bound on one field of six | A **benign** 305-character channel hint raised a `ValidationError` out of the step and killed the run permanently. A long *hostile* hint was quarantined and harmless — the weapon was the innocuous one |
| A control the attacker can fire | An author reference carrying an internal marker made the *quarantine notice* unpublishable, so the event reporting an injection was suppressible by choosing a display name |
| A predicate that cannot be true | The `SOURCE_INDEPENDENCE` gate counted duplicates in a deduplicated tuple and could never fire |
| A term charged to nobody | `novel_pivot_families` counted families the pilot merely *proposed* — refused ones included — so naming three directions on a non-existent entity promoted a checkpoint |
| A cost that did not exist | `moves_spent` was in no ordering key, so a `record_belief` was free despite the docstring saying otherwise |
| A head read as a trajectory | `resume()` refunded every step since the last promotion, reversed a recorded stop, and cleared the hard-gate strike counter |
| A hash blind to order | `chain_hash` used `canonical_bytes`, which **sorts arrays**, so a checkpoint's references could be reordered without breaking the chain |
| Laundering, one level up | One anonymous own-sensor artifact marked the whole `lineage:unknown` bucket unplantable, carrying nine anonymous planted ones into the robustness floor |
| No timeout on an advisory call | A supervisor that accepted the call and stalled parked the run for ever, with no `RUN_STOPPED` written |
| Two doors, one guard | A payload quarantined as a *hint* travelled verbatim into a briefing as a supervisor's *rationale* |
| A tautological stop | `STOP_LOW_YIELD` needed only a plateau, and plateaus are common early — so a hostile supervisor could end almost any run on its first one |
| An allowance that could grow | Closing an overspent branch set its allowance to what it spent, so `allocated` could exceed `total_steps` |

One finding is a **limitation rather than a defect** and is recorded as such: the controller holds a
mediator, and the mediator holds the engine, the envelope and the registry — so
`controller._mediator._envelope` reaches them by attribute traversal. Python has no object-capability
enforcement. What the contracts and tests establish is the import graph and the declared API, and
nothing here claims more than that.

---

## Known limitations, stated rather than discovered

**Three tier-1 terms cannot currently move.** `hypotheses_settled` and `uncertainty_reduction` read
a `Hypothesis` whose state and `Opinion` the pursuit engine never updates;
`contradictions_resolved` reads `contradicted_by_claims`, which no shipped connector populates. The
code is real and unit-tested against constructed state, and in the reference run all three are zero.
A metric that cannot move is not a metric that is working.

**`discriminating_relationships` reads zero on the current fixtures**, because of a defect in the
plane below. `nemesis.pursuit.materialize` mints entity ids and builds edges against them, and
`PursuitEngine._absorb` upserts the entities — merging one that already exists and returning the
canonical id — while adding the edges unchanged. Every edge touching a known entity therefore
references an identifier the graph does not hold. Reproduced: three executions of one registration
pivot leave two entities in the store and six distinct endpoint identifiers on three edges, none
resolving. The evaluator refuses to count an edge whose endpoints the graph cannot vouch for, so it
cannot be inflated by the defect. **The defect itself is not fixed here** — changing graph-write
semantics is a separate change with its own blast radius, and it is reported rather than quietly
patched from a plane that must not write the graph at all.

**The reference fixture corpus has exactly one provenance operator**, so an investigation over it
rests on one independent origin and `origin_floor` is zero throughout. That is the provenance logic
being correct, not a bug — and it means the demonstration cannot exhibit origin growth. It also
means the supervisor's "seek an independent origin" directive is, on these fixtures, the right and
permanent answer.

**No confidence figure and no scoring constant here has been validated.** The tier ordering, the
stagnation thresholds and the promotion rule are documented choices, frozen so they can be argued
with. This plane does not improve the repository's largest standing weakness; it inherits it.

**The trajectory has no external anchor.** Deleting the newest entry is undetected, because nothing
follows the tail — the same gap the evidence vault, the revocation chain and the spend ledger
report about themselves.

**Nothing has measured whether this is better than a stateless loop.** The question the plane was
built to make answerable is not answered by building it. See "Recommended next step" below.

---

## Recommended next step

Not multi-model islands. The next step is the measurement:

> Run **single-lineage Evolution** and the existing **conventional pilot loop** over the same
> synthetic fixtures, with the same budget, and compare: pivots per useful discovery, redundant
> pivots avoided, independent origins reached, and how far into a run each one is still making
> progress.

Islands are `PROPOSED` and the abstraction is in place (`BranchPortfolio`, serial, with a budget
that partitions). Concurrency needs the atomic reservation `SqliteAuthorizationStore` gives the
spend ledger, which the lineage store does not have, and it should not be built before the
single-lineage claim is measured.
