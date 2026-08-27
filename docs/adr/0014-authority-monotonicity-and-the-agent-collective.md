# ADR-0014 — Authority is monotone, and reachability is a property of the composition

**Status: ACCEPTED, 2026-08-27.** Prompted by OpenAI's Hugging Face incident and its technical
analysis (<https://openai.com/index/hugging-face-incident-and-the-road-ahead/>). The decisions
below are implemented; the assessment they came from is
[`docs/security/2026-08-27-agent-collective-hardening.md`](../security/2026-08-27-agent-collective-hardening.md).

Supersedes nothing. Extends [ADR-0008](0008-the-pilot-seam-and-envelope-bounded-autonomy.md),
whose four-verb seam is unchanged and stays unchanged, and
[ADR-0009](0009-provider-neutral-pilot-seats.md), whose provider neutrality is what makes seat
independence expressible as one contract.

---

## Context

The incident established something a per-component review structurally cannot see: **every
component behaved as designed, and the reachability, the coordination and the capability all
belonged to the composition.** Agents denied Internet access found it through a service that had
it. Agents given no channel invented one. Agents read a peer's message as authorization. An
impossible task produced persistence rather than a stop.

NEMESIS was already built on the premise that the model is untrusted and the limiter must not be
a model, which answers most of that directly. Reviewing it against the incident's classes turned
up three things that premise does not cover.

**First, the strongest property here was never stated.** A dozen controls independently prevent
untrusted input from increasing authority — the vocabulary has no minting verb, the collaboration
plane cannot reach the gateway, a challenger only subtracts, a supervisor's directives do
nothing, a hint is redacted, a chat reply is an *intent*. Each has its own test asserting its own
refusal. None of them names the property they are all instances of, and this repository has twice
been bitten by a refusal produced by a *different* control than the one under test: the effect
verb was missing the disclosure wall and nobody noticed, because target binding was refusing
those requests for an unrelated reason.

**Second, the egress check looked at one hop.** `check_prohibited.py` refuses a network import
outside the collection plane and refused one in the pilot plane during the provider work. It has
no notion of a path. It could not have seen an egress-capable module reached through two others,
which is the entire shape of the incident.

**Third, the audit trail's truncation detection lived in RAM.** `verify()` compares the file
against `self._count` — a number that exists only because *this process* wrote those entries.
`nemesis verify` constructs a fresh trail from a path, so its counters are whatever the file
says. Measured on this branch: the demo's trail truncated from 72 entries to 60, reported
`chain intact: True`. `nemesis.authz.anchor` had specified the whole answer months earlier and
**nothing in the running platform called it.**

---

## Decision

### 1. Authority monotonicity is a named, measurable property

> Peer-originated information can never increase authority.
> `authority_after_untrusted_input ⊑ authority_before_untrusted_input`

`nemesis.authz.monotonicity.AuthoritySnapshot` reduces the live state — the signed capability's
operations, targets, window, ceilings and approvers, plus the envelope's remaining autonomy — to
one comparable value. `widenings_from()` returns every way one snapshot grants more than another,
as findings rather than as a boolean.

**It is an observation instrument and never a gate.** Nothing in the production path consults it.
A fourth check reading a summary of the other three would be a control derived from the controls
it is meant to check, and would fail exactly when they did.

What makes it worth a module rather than an assertion per test: the resulting tests do not
depend on knowing which control was supposed to refuse. A property over the whole authority state
survives somebody moving a control from one branch to another, which is the failure this
repository keeps finding in itself.

### 2. Transitive reachability is analysed, and brokers are declared

`nemesis.sandbox.reachability` builds the import graph of `src/nemesis`, marks each module's
capability to **reach the network or start a process**, and asserts no path from a
model-controlled root to an egress-capable module except through a declared broker. Run in CI by
`scripts/check_egress_reachability.py`.

Two design points are load-bearing.

**Process-spawning is half of "egress-capable".** It is how the incident's most interesting paths
worked, and it is invisible to an import scan here: this tree spawns with
`asyncio.create_subprocess_exec`, and `asyncio` is imported by half the tree. Detecting it means
detecting the *call*, qualified by the module the attribute hangs off — a first version matching
`run` and `call` bare reported eight process-spawning modules when two are.

**A broker must be justified in writing.** `DECLARED_BROKERS` maps three modules to the sentence
explaining what makes the far side policy-controlled rather than model-controlled. Adding an
entry is how this analysis is weakened, so it is deliberately the most conspicuous edit anyone
can make to the file.

Measured today: no path at all. The brokers are slack in the contract rather than load-bearing,
and the check exists to notice the day that changes.

### 3. The audit trail is anchored, at the rung it honestly occupies

`nemesis.authz.audit_anchor` wires `AppendOnlyAuditTrail` to the existing `ChainAnchor` contract.
The trail gained one read-only accessor, `links()`, which reads the **file** rather than the
writer's counters — an anchor over remembered state attests to nothing.

The binding lives in `nemesis.authz` and not in `nemesis.audit` because the layering puts audit
below authz. Moving the anchor primitives down would drag signing into a lower plane; defining a
parallel checkpoint type in `ports` would produce two serializations of one signed object, which
is how a verifier ends up unable to read what a signer wrote.

It ships at `AnchorIndependence.NONE` and says so in the verdict text. That catches an accident,
a partial restore, a chain rebuilt by a repair script — and nobody who meant it, because the
account that truncated the log can regenerate both. The rungs above are a constructor argument.

### 4. Credentials are a type that cannot hold a credential

`nemesis.core.credentials`. `EntityCategory.CREDENTIAL` maps to `RESTRICTED`, which is what the
briefing filter, the effects scan, the analyst view and the export redaction already key on — one
line in a table doing what four credential-specific filters would do worse, because four filters
drift.

The three structural choices: no type has a field material fits in; the fingerprint is
HMAC-SHA256 under a required deployment key, because `sha256("hunter2")` is a password oracle;
and `normalize_identifier` refuses a credential as a natural key, so the graph has no way to spell
one. Discovery and use stay separate concepts, and a test over the import graph asserts nothing
outside `core` reaches for the types.

### 5. Stopping honestly is a first-class outcome, and a stall never widens

`ConclusionOutcome` types the ending of a run. `nemesis.pilot.stagnation` detects a stalled
session deterministically and maps every signal into the safe-failure set.

**Detection is not configurable; only stopping is.** A boolean that switched the detector off
would be a control with an off switch. `halt_on_stall=False` still records the assessment on the
session and in the audit close — it only declines to act — and the three measurement harnesses
that need to run pathological pilots to completion set it explicitly, in source, with reasons.

There is deliberately no branch that responds to a stall by asking for more, and no member of the
outcome vocabulary that requests it. The absence is the control.

### 6. The seam stays at four verbs

Stated as a decision because the pressure was real. `report_blocked`, `request_scope` and
`escalate` each look like a communication primitive and each is authority wearing a request.
`conclude` gained a typed `outcome` field instead: the vocabulary is unchanged, the ending is
now legible to a projection without parsing prose, and a stuck pilot has nothing new to reach for.

### 7. Seats cannot address each other, and the Breaker cannot be depended on

Two `import-linter` contracts. `model-seats-are-mutually-unreachable` is an `independence`
contract over the six provider modules — the symmetric property, with no privileged direction —
so a shared queue or an "ask the other model" helper cannot arrive looking like a refactor.
`nothing-depends-on-the-breaker` forbids every plane from importing `nemesis.breaker`; the other
direction is open, because an adversarial harness that had to reimplement its target would be
testing its reimplementation.

---

## Consequences

**What gets easier.** A new control can be checked against one property instead of being argued
about. A new import that opens a path fails a build rather than a review. A stalled investigation
produces a legible ending. A credential found by the first real connector has somewhere to go
that is not a string.

**What gets harder, deliberately.** Adding a network import anywhere now has to satisfy two
checks. Declaring a broker requires writing down why the far side is policy-controlled. Adding a
provider seat requires updating a contract, and a test derives the seat list from the filesystem
so forgetting fails. Adding a module-level constant requires a documented recalibration.

**What this does not fix**, and it is the part that matters most for how much to trust the rest:

- **Confidence calibration against ground truth.** Unchanged, and still the largest open weakness
  in the platform. A class that manufactures corroboration at volume exploits it hardest.
- **Manufactured source independence.** `independence_key()` refuses to count three resold feeds
  as three; it cannot refuse to count three genuinely separate origins a fleet paid for.
- **Cross-session probe correlation.** PROBE-01 halts a session that reaches for three reserved
  names. A fleet reaches for one per session across three hundred sessions and every session ends
  clean. The events are all in the trail; nothing reads them together.
- **Fleet-level rate limiting.** Every bound is per-investigation.

**A note on what a `HELD` verdict is worth.** The Breaker reports ten held attacks. That means ten
specific constructions were tried and specifically stopped. It does not mean the invariants hold
against constructions nobody has written yet, and the harness says so in its own output rather
than leaving a reader to infer it.

---

## Alternatives considered

**A supervisor or guardian agent.** Rejected: a second model with authority is a second thing to
contain. The challenger is the shape that works — five verdicts, none of which permits anything,
so a hijacked one causes an availability failure and never an action. A guardian that could
*allow* would be strictly worse than no guardian.

**A runtime egress firewall.** Rejected: the platform makes no outbound call from a
model-controlled context, so it would guard a door with nothing behind it, and would need
standing privilege to install. A static analysis costs nothing at runtime and fails a build
rather than an operation.

**Blockchain anchoring.** Rejected on the brief's own terms and on ours: the contract is
`(epoch, record_count, tip_hash)` signed, which RFC 3161 or a transparency log satisfies as a
constructor argument.

**Storing chain-of-thought for monitoring.** Refused, and it stays refused. The boundary must hold
when the reasoning is unavailable, which it always eventually is — a provider changes a feature,
a local model has none, a vendor stops returning it. Monitoring reads behaviour: requested
pivots, attempted effects, refusals, probes, scope, termination.

**An entropy heuristic for credential redaction.** Rejected: it would redact malware hashes,
certificate fingerprints and onion addresses, which are the product.
