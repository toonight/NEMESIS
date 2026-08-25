# ADR-0013 — Corroboration must weigh staging cost, not count facts

**Status: ACCEPTED, 2026-08-25.** The finding is measured and reproducible; the decision below
changes what the resurgence engine requires before calling something actionable, and deliberately
does **not** change the plantability model. Implementation is a separate change and this ADR is
what it must satisfy.

Supersedes nothing. Extends [ADR-0004](0004-robustness-margin-against-planted-evidence.md), whose
control this defect defeats.

## Context

`nemesis.calibration.localbench` runs controlled operations on a loopback range where the linkage
is ground truth because the module minted it. It includes one adversarial case: a *framer* — a
different operator who copies another party's key and tooling kit. On 2026-08-24 it reported, and
still reports:

```
ADVERSARIAL: 2/3 pairs where a *different* operator copied the observables were called a finding
```

A false attribution. The failure this platform exists to avoid.

The finding was pinned as a deliberately-failing expectation in `tests/planes/test_localbench.py`
with a note that the fix is a threat-model change and belongs in an ADR rather than in a test run.
This is that ADR.

### A. The two cases are the same object

Measured side by side against the shipped bench at 30 operations:

| pair | band | belief | facts | unplantable | margin | independent | actionable |
|---|---|---|---|---|---|---|---|
| genuine `op000 × op001` | `very_likely` | 0.8100 | 2 | 2 | `no_removable_fact` | 2 | yes |
| framed `op000 × framer` | `very_likely` | 0.8100 | 2 | 2 | `no_removable_fact` | 2 | yes |

Identical in every diagnostic `fuse` produces, because the observations are identical:

```
genuine : ['shared_private_key', 'shared_tooling_artifact']
framed  : ['shared_private_key', 'shared_tooling_artifact']
```

**No rule operating on this evidence can separate them.** That kills, before any design work
begins, every fix that reweights what is already there: counting facts, counting origins, ranking
signal kinds, or reading the source class. All four produce the same answer for both rows because
both rows are the same row.

### B. The blunt fix trades the framer for the whole engine

`OWN_SENSOR` is one of the two classes `provenance.py` treats as unplantable. Removing it —
monkeypatched, tree untouched:

| configuration | recall | single-fact refusals | false positives | ADVERSARIAL |
|---|---|---|---|---|
| shipped | **10/10** | 20 | 2 | **2/3** |
| `OWN_SENSOR` no longer unplantable | **0/10** | 20 | 0 | **0/3** |

The engine stops being wrong by stopping saying anything. Any fix reported only against the
ADVERSARIAL row is indistinguishable from this one, and three published figures move, not one.

### C. Why the existing defence did not fire

The domain model already knew about this attack. `PropositionClass.SHARED_ORIGIN`:

> Margin 1. **Planting changes the truth here** — an adversary who places their certificate on a
> third party's host manufactures exactly this proposition.

`ROBUSTNESS_MARGIN[SHARED_ORIGIN] = 1` is the designed answer: a conclusion must survive losing
its most load-bearing *plantable* fact. It does not fire because of one line,
`src/nemesis/core/fusion.py:695-700`:

```python
unplantable: set[str] = {
    key
    for key, members in by_fact.items()
    if any(not item.source.is_adversary_influenceable for item in members)
}
```

Plantability is read off the **source class alone**. `is_adversary_influenceable` is correct about
what it claims — its justification for `OWN_SENSOR` is *"An adversary can cause an observation but
cannot author the record"* — and that claim is true here. Our sensor's record of the framer's key
is authentic. What is false is the inference drawn from it, because **authorship of the record was
being used to answer a question about authorship of the fact**, and for a copyable artifact those
come apart.

### D. The reasoning that would have caught it is already in the module — as prose

`BELIEF_CEILING` says of itself:

> They are ordered by **how expensive the signal is to stage**.

And the signal-kind docstrings are a staging-cost argument, explicitly:

- `SHARED_EXFILTRATION_ENDPOINT` (0.75): *"Copying a drop address to have somebody else blamed
  means sending your victims' credentials to the party you are framing — a cost a framer does not
  usually accept."*
- `SHARED_PUBLISHED_FINGERPRINT` (0.70): *"Anyone can copy a public value onto a profile, and
  doing so is the cheapest way to make a new operation look like an old one."*
- `NAMING_PATTERN` (0.15): *"the easiest to imitate — and therefore the easiest to use to frame
  somebody."*
- `SHARED_PRIVATE_KEY` (0.90): *"an adversary who lost a key, or one framing a competitor with a
  stolen one, produces the same observation."*

So staging cost is encoded — as a **magnitude**, in a ceiling — and the control that actually
decides whether a conclusion survives never consults it. That is the defect, stated exactly:

> **The ceiling knows what a framer can cheaply stage. The corroboration step does not, and the
> corroboration step is what decides.**

In the bench pair, the private key is expensive to stage (you must steal it) and the module's own
docstring says a thief produces the same observation. The *kit hash* is free. The kit is what tips
the pair past the single-origin veto — so the second "independent" fact is not independent evidence
of identity at all. It is a fact the framer got for nothing, counted as corroboration.

### E. The apparatus removed the one signal that discriminates

`SHARED_EXFILTRATION_ENDPOINT` is the one kind whose docstring argues a framer-cost asymmetry. It
fires **zero times** in the shipped bench: `signals_between` tests `left.drop == right.drop`, and
every operation is minted with a unique drop. Three places claim otherwise —
`EXERCISED_KINDS`'s docstring ("a drop address inside a kit"), `run_local_bench`'s docstring
("successive pairs share a key, a kit or a drop"), and the rendered report.

Rebuilding the same range with a drop shared per family — what a real operator does, because the
takings have to go somewhere — while the framer keeps its own:

| fixture | genuine called | framer called | genuine signals |
|---|---|---|---|
| shipped, unique drops | 3/3 | 2/2 | key + tooling |
| operators reuse a drop | **9/9** | 2/2 | **exfil + key + tooling** |

The framer is not fixed by the fixture change — today's engine still calls it on key + tooling
alone. But the two cases **stop being the same object**: the genuine pair now carries a signal the
framer does not, and cannot copy without sending its victims' credentials to the party it is
framing. Under a rule that requires one such signal, this fixture gives genuine 9/9 and framer 0/2.

Conclusion A is therefore about the apparatus as it stands, not about the world. **The framer is
separable. The bench simply deleted the discriminator.**

### F. What is not available, and one thing that looked available and is not

- The bench's framer **holds the private key**: `Range.key` memoises one keypair per id and the
  framer is minted with `key_id="key-0"`. A challenge-response possession proof — the obvious fix
  — would not discriminate here, and any design resting on one must say so.
- Resurgence signals are **monotone-positive**: `to_opinion` returns `disbelief=0.0` always, by a
  stated choice ("everything not committed to belief is uncertainty, never disbelief"). Nothing in
  this vocabulary can argue *against* an identity. Modelling framing as a competing hypothesis
  therefore means new machinery, not new wiring.
- The production fixture prices the flow it does not have: `glass_anvil.py:1619` records
  `"drop_location": "kit/include/mailer.php"` with `"action": "blocked"` — a string read out of a
  kit file, carrying the 0.75 ceiling justified by an endpoint that *works for the operator*.

## Decision

**1. Actionability requires at least one signal a framer cannot cheaply stage.**
A resurgence assessment reaches `is_actionable` only if at least one contributing signal is
framer-costly. The judgement is a table, closed and total over `ResurgenceSignalKind`, enforced at
import by the existing totality check — and it **defaults to cheap**, in the same allowlist
discipline `provenance.py` adopted after its blocklist version was found to be the bug.

This is a fifth veto beside the four `is_actionable` already applies. It is deliberately *not* a
reweighting: magnitudes are what conclusion A proved cannot help.

**2. The plantability model does not change.** `is_adversary_influenceable`,
`UNPLANTABLE_SOURCE_CLASSES` and the `OWN_SENSOR` exemption stay as they are. They answer "could
the adversary have written this record", correctly, and the fix is to stop using that answer for a
question it was never about. Nothing in `nemesis.core.provenance` is touched, and the shared
`fuse` arithmetic every other plane depends on is not moved.

**3. The bench must fire the signal it claims to exercise.** Operations in one family share a drop;
the framer does not. Without this the bench cannot tell a good fix from a blunt one — conclusion B
and conclusion E are the same measurement in that respect — and the repository has three docstrings
asserting a linkage that never occurs.

**4. The production fixture's exfiltration signal is re-priced or re-labelled.** A string in a kit
file is not a completed flow and must not carry the ceiling a flow earns.

**5. The pinned expectation is rewritten, never deleted.**
`test_a_framer_who_copies_the_observables_is_attributed_to_the_party_framed` currently asserts the
failure. When the framer is refused it must be rewritten to assert the refusal *and* to assert that
genuine recall survived — its own docstring already says so, and conclusion B is why the second half
is not optional.

## Consequences

**Accepted.** Recall is preserved where the evidence supports it (9/9 under the corrected fixture)
and lost where it does not: any campaign whose only continuity is copyable artifacts becomes a lead
rather than a finding. That is the correct answer, and it is the same answer the platform already
gives elsewhere — the robustness report scored `laundered` at 0.0000 when the engine had declined
on all forty cases, and that was the defence working.

**Published figures move.** The bench's recall, single-fact-refusal and ADVERSARIAL rows all change
under decisions 1 and 3, and `docs/architecture/PROJECT_STATE.md` quotes all three. They are
restated from the measurement, not adjusted to match.

**A ceiling now has two jobs and should eventually have one.** `BELIEF_CEILING` orders by staging
cost and `PivotSelectivity.evidential_weight` orders by how many parties could share the attribute
by accident. The code multiplies them, so a globally-unique-but-freely-copyable artifact scores
`0.90 × 1.0`. Coincidence-selectivity and adversarial-selectivity are different axes and this ADR
separates them only for the actionability veto. Separating them in the arithmetic is a larger change
and is **not** decided here.

**What this does not fix, stated plainly.** A framer who accepts the cost — who really does route
victims' credentials to the party being framed — still produces evidence indistinguishable from a
return, and will still be called one. Decision 1 raises the price of framing; it does not make
framing impossible, and no arrangement of the evidence this platform collects can. The engine's
honest position remains that artifact continuity is what it observes and operator identity is what
it infers, and `_alternatives_for` already prints the framing alternative beside every assessment
with its refutation criterion.

**Not decided here.** Whether a resurgence assessment should split its conclusion — reporting
artifact-continuity as established and operator-identity as not established, rather than emitting
one proposition — is the more thorough answer and touches the watch plane, the rendering and the
disclosure class. It is recorded as the open question this ADR deliberately scoped out.
