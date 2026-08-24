# ADR-0012 — Controlled operations for ground truth (milestone 3)

**Status: PROPOSED. This ADR does not implement milestone 3 and cannot.**
Date: 2026-08-24.

## Context

Every confidence figure NEMESIS produces rests on constants nobody has validated. That was
already recorded; what changed on 2026-08-24 is that it stopped being a caveat and became a
measurement.

`nemesis.calibration.ceilings` perturbs the resurgence belief ceilings over a swept grid of 525
cases and counts the verdicts that move, reported against the 90 that can move at all:

| perturbation | ordering | movable verdicts moved |
|---|---|---|
| ×0.8 | preserved | 19% |
| ×1.25 | preserved | 24% |
| ×0.6 | preserved | 48% |
| flattened to the mean | destroyed | 28% |
| ordering inverted | destroyed | 56% |

A twenty per cent change that preserves the ordering perfectly moves a fifth of the movable
verdicts. The repository had been asserting the opposite — that the ordering carried the
decision and the magnitudes were harmless — in a module docstring, in `PROJECT_STATE.md` and in
several commit messages. That assertion is withdrawn. `ACTIONABLE_FLOOR` is load-bearing too:
moving it between 0.45 and 0.65 against the shipped ceilings moves 2 to 28 of the 525.

So: eight numbers decide whether NEMESIS calls a returning adversary a finding or a lead, and
nothing validates any of them.

`docs/calibration/PROTOCOL.md` names the only remedy available to this project. Milestone 3 is
**controlled operations on infrastructure we own** — honeypot ranges, operations across hosts
and identities under our control, with the linkage known because we created it. The MVP rule
forbids touching infrastructure we do not own and says nothing against running our own. The
protocol's own last word on it is that it "needs a decision about infrastructure and cost. It is
not code."

## Decision

**No decision is taken here.** This ADR exists to put a number on the one that is needed, and to
record what it would commit us to.

### What it would cost, in operations

Derived in `nemesis.calibration.sizing`, from the measured discriminating fraction rather than
from prose, so it moves when the engine or the grid moves:

| target precision | discriminating pairs | pairs total | controlled operations |
|---|---|---|---|
| ±10% | 97 | 566 | ~283 |
| ±5% | 385 | 2 246 | ~1 123 |
| ±2% | 2 401 | 14 006 | ~7 003 |

Halving the margin roughly quadruples the requirement, which is why ±2% — what "calibrated"
usually means — is a programme rather than an experiment.

**The assumptions, because the numbers are worthless without them.** Sizing uses the worst-case
rate, so these are the honest upper bound of the arithmetic and not a pessimistic flourish. The
inflation from 97 pairs to 566 is the discriminating fraction: 17.1% of swept cases can move
under a ceiling perturbation at all, and pairs that cannot move teach a calibration nothing.
That fraction is a real measurement of *this engine* against a grid whose shape is a choice, and
it assumes real operations would land near the decision boundary about as often — which they
would not, exactly. Two pairs per operation is a frank guess and a parameter for that reason.
The arithmetic assumes independent cases; operations sharing a provider or a week are not, so
the true requirement is **higher** than the table.

Read the whole column as an order of magnitude. What it establishes is that the cheapest useful
version is a few hundred operations, not a dozen and not a hundred thousand.

### What it would commit us to

- Registering domains, renting hosts and obtaining certificates, sustained over months — a
  resurgence signal needs a *gap* between an operation and its successor, so the corpus cannot
  be generated in a weekend at any budget.
- Running the three roles of milestone 4 as separate people. The apparatus enforces the
  blindness structurally, but a generator, a labeller and an evaluator who are one person in
  three hats produce a corpus that is a mirror, and no type can prevent that.
- Writing the population claim of milestone 2 **before** the first operation. Commodity
  phishing infrastructure is what this could plausibly build; it would say nothing about a
  state actor's tradecraft, and the corpus must say so where nobody can add it afterwards.

### The risks, which are not small

- **Our infrastructure would look like an adversary's.** Other defenders scan, publish and
  block; a controlled operation is indistinguishable from the real thing by construction, which
  is what makes it useful. Expect our ranges in somebody's feed, and expect that to be
  permanent.
- **It could be abused.** Infrastructure built to resemble a phishing operation is
  infrastructure somebody else can misuse if it is left reachable or badly scoped.
- **Legal and contractual exposure.** Registrars and hosts have acceptable-use terms; operating
  deliberately adversary-shaped infrastructure under them is a question for counsel and not for
  an engineer, whatever the intent.
- **It must never touch anyone else.** No third-party recipients, no unsolicited contact, no
  live credential capture. The value comes from the *linkage* between our own assets, and
  nothing in the calibration needs a victim.

None of these is a reason not to do it. All of them are reasons the decision is not an
engineer's to take.

## Consequences

**If it is funded**, milestone 3 moves to `IMPLEMENTED` only when operations have actually run
and been labelled; the apparatus for milestones 2, 4 and 5 already exists and has been waiting
for a corpus rather than for code.

**If it is not**, nothing breaks and one thing must change: the eight numbers stay unvalidated,
and every figure downstream of them keeps saying so. What is no longer acceptable is the
formulation this ADR withdrew — that the ordering carries the decision and the magnitudes are a
footnote. They are not, and it is measured.

**Either way**, the sizing is re-derivable rather than quoted: `nemesis calibrate` prints it, and
it moves if the engine or the grid does.
