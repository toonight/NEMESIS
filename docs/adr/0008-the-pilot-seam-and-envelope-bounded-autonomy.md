# ADR-0008: The pilot seam, and envelope-bounded autonomy

- **Status:** accepted
- **Date:** 2026-08-17
- **Deciders:** founding architect, founder
- **Plane:** pilot (new), pursuit, effects, authz
- **Reversibility:** high. The plane is additive. The deterministic `PursuitPolicy` still
  drives `nemesis demo` unchanged, and nothing below `nemesis.pilot` imports it. Removing the
  plane removes a capability; it breaks nothing that exists.

## Context

The founding brief was read, for the first several milestones, as "NEMESIS is the autonomous
investigator." The founder corrected that on 2026-08-17: **NEMESIS is the framework an
autonomous frontier-model pilot drives** — the car, the écurie, and above all the limiter that
keeps the pilot inside the track. The pilot (a GPT-5/6-class model, "Atlas") is the brain and
is *external*; NEMESIS is the part that must not be the brain, because the part that enforces
the limits cannot be a model an adversary can steer with the content it writes.

This reframe does not overturn the architecture. It validates its spine and sharpens what was
missing:

- "There is no LLM in the code" stops being a divergence and becomes correct by design. The
  audit that found the pursuit engine never evaluates hypotheses against evidence was findings
  about a *brain* NEMESIS was never supposed to own.
- What was genuinely missing: a first-class **seat** for the external pilot, and a proof that
  the seat is a limiter — that an *untrusted* pilot, not merely an honest one, cannot leave the
  track. The old `PursuitPolicy` was trusted first-party code; a frontier model is not.

Two questions were the founder's to settle, and were:

1. **Where does the autonomy of an effect live?** "Completely autonomous" and "human-authorized
   effects" (invariant 7) are not contradictory if one is precise about *where* the autonomy
   sits. Chosen: a **pre-signed capability envelope**. A legal authority signs, in advance, a
   narrow/expiring/revocable envelope — target fingerprints, operation class, jurisdiction,
   expiry, max effect, stop conditions. Inside it the pilot acts fully autonomously, at machine
   speed, with no human in the hot path; the envelope's edges are cryptographic and uncrossable.
   The human moves from *approving each action* to *defining the envelope*.
2. **What is built first?** The pilot seat plus the containment proof.

## Decision

Add a plane, `nemesis.pilot`, sitting above `pursuit` in the layering. It is the seat and the
limiter, and it rests on three ideas.

**The pilot proposes; the mediator disposes.** `AutonomousPilot` is handed a read-only
`Briefing` and returns a move. It holds no handle — not the engine, the graph, the vault, the
signing key or the capability. The `PilotMediator` holds all of them, validates every move,
carries out only the permitted part, records the move and its ruling, and hands back a fresh
briefing. The pilot's output is untrusted data, re-validated at the seam (invariant 5 applied
to the pilot itself, exactly as the isolated collector re-validates what crosses its pipe).

**The move vocabulary is closed.** A pilot may only `run_pivot`, `record_belief`,
`request_effect` or `conclude`, validated through a discriminated union. There is deliberately
no `mint_capability`, no `widen_envelope`, no `assert_fact`, no `export`. Authority escalation
is contained by the *absence of a verb*, which is a stronger control than a check on a verb
that exists, because there is nothing to get wrong.

**The envelope is the limiter.** Every `request_effect` is routed through
`registry.execute(request, envelope)`; the refusal of anything outside the envelope is the
*capability's*, reached by asking it, never a judgement the mediator substituted. The mediator
observes the target's current state from the graph, never from the pilot, so a pilot cannot
forge target state to spend a stale approval. A `record_belief` becomes a claim of kind
HYPOTHESIS derived from MODEL_ASSERTION — which the core forbids from ever being an observation
or a fact (invariant 1) — so a pilot cannot turn its opinion into evidence.

The session is **replayable though the pilot is not** (invariant 11): the transcript of
`(move, ruling)` pairs, each written to the hash-chained audit trail, reconstructs exactly what
the pilot was allowed to do, regardless of the model's nondeterminism.

No production pilot ships. Wiring a real model is a `SIMULATED`→`IMPLEMENTED` step needing an
API credential, an egress path and a prompt — none of which belong in a repository whose MVP
contacts nothing. What ships is the seat and the proof that whoever sits in it cannot leave the
track, which is the part that had to exist before a real pilot could be trusted to drive.

## The bound a capability does not carry

Implementing the envelope surfaced something the design had not stated. `AuthorizationCapability`
carries every edge the brief asks for — target fingerprints, operation class, jurisdiction,
expiry, max effect, stop conditions — and all of them bound **what** may be done. None bounds
**how often**. Under per-action approval that gap never opens, because a human is the rate limit.
Delegate the same capability to something autonomous at machine speed and "four approved targets"
becomes an unbounded number of operations against four approved targets, with every individual
operation correctly authorized.

So `AutonomyEnvelope` adds a budget of autonomous effects, debited **before** anything executes
and never refunded — a counter that decrements only on success is a counter an adversary empties
by failing on purpose. The spend ledger is hash-chained, because deleting a debit to buy another
effect is the obvious attack on a budget and a signature does nothing about deletion (the
reasoning of `Revocation`, applied to consumption). The envelope wraps rather than extends the
capability: the signed object must stay exactly what the authority signed, and a mutable count
inside the signed payload would invalidate the signature on every debit.

It can only narrow. It holds no signing key, has no method that raises its own ceiling, and
refuses to wrap an unsigned grant — delegating *autonomy* under a capability nobody signed is not
a narrower authority, it is none.

The ledger is a port, and the durable implementation is the one that makes the bound real.
`InMemorySpendLedger` is correct within one process and forgets everything on exit — which means
anyone able to restart the process refills the envelope, and a crash loop refills it without
anybody deciding to. `SqliteAuthorizationStore` holds it in the same file as revocations.

Durability is the visible half of that. **Atomicity is the half that matters:** a fleet of pilots
sharing one envelope is the deployment this platform is for, and two workers that each read
"three spent of four" and then each append would both act, with the ceiling bounding nothing. The
count-and-append therefore happens inside one `BEGIN IMMEDIATE` transaction, and a test contends
four real OS processes for a budget of ten.

Durability then invites its own attack — restart with `max_autonomous_effects=999` — so the
ledger records the ceiling and refuses a larger one on reopen, with its own exception type so a
caller catching "the store is unavailable" cannot swallow "an authority was widened". A smaller
budget narrows, because nothing that only ever reduces authority needs refusing, and the
narrowing sticks.

## Alternatives considered

**Make the pilot a trusted component and rely on its alignment.** Rejected outright. It makes
prompt injection a total compromise: a forum post the pilot read becomes an instruction the
platform obeys. The entire design assumes the pilot is already hijacked and contains it anyway.

**Let the pilot call adapters / hold a capability directly, with the mediator auditing after
the fact.** Rejected. Auditing after an effect is auditing after it left. The mediator must be
*upstream* of every consequential action, holding the only handles, so a refusal happens
before anything occurs — not a log entry that it did.

**Ungated autonomous "eradication at the source" (hack-back).** Rejected, and recorded as a
commercial strength rather than a limitation. Active response against infrastructure we do not
own is illegal for a private entity in ~every jurisdiction, and violates invariants 7, 8, 9 and
15. The framework is built *ready* for a legally authorized operator to drive under an
envelope; it does not itself hold or grant that authority. A fully autonomous hack-back tool
with a frontier model at the wheel and no limiter is precisely the thing that gets a company
shut down — the limiter that says "no" is the differentiator.

**A model-driven pursuit *policy* (replace `PursuitPolicy` with an LLM) instead of a seam
above the engine.** Deferred, not chosen. A model choosing the next pivot is a model whose
choices an adversary can steer, and the deterministic policy's replayability (ADR/[policy.py])
is worth keeping as the reference driver. The seam sits *above* the engine so the pilot's
authority is mediated move by move, rather than being wired into the engine's own decision loop.

## Consequences

- A ninth `import-linter` contract, `pilot-cannot-reach-persona-linkage`: the untrusted pilot
  cannot even *import* the persona-resolution plane, so the D1-withheld band cannot reach its
  briefing one careless commit at a time.
- `PursuitEngine.execute_pivot` is new: the seam a driver outside the engine needs to run a
  chosen pivot through the same machinery `step` uses (connector routing, budget, provenance
  ordering, audit). It is additive; `step` and the deterministic policy are untouched.
- 13 containment tests, each constructing an attack: a hijacked pilot told to suspend a domain,
  one acting on an unapproved target, one reaching for a mint-authority verb, one asserting a
  person's guilt as fact, one pasting an internal marker into a document, a runaway, a
  garbage-emitter. All are stopped by code the pilot cannot reach.
- What this does **not** establish: that a real model driving the seat produces good
  investigations. It establishes that a bad one cannot produce a bad *effect*. Those are
  different claims, and only the second is proven here.

## The concrete pilots: OpenAI and Anthropic cyber models

The `AutonomousPilot` protocol is vendor-neutral on purpose — the containment must not depend
on which model drives, because a containment that only held for one vendor's model would be no
containment at all. Two concrete seats exist: `nemesis.pilot.openai_pilot` for an autonomous
frontier **OpenAI cyber model** (a GPT-5.6-class "cyber" model, the founder's stated target),
and `nemesis.pilot.anthropic_pilot` for an **Anthropic cyber model** (a Claude cyber model).
Everything that must be identical between them — the untrusted-pilot contract, each move's
argument schema, the not-wired discipline — lives in `nemesis.pilot.model_seat`, so the two
cannot drift into saying different things to two vendors. They differ only in dialect: OpenAI
tools under `function.parameters` with `tool_choice: "required"` and JSON-string arguments;
Anthropic tools under `input_schema` with `tool_choice: {"type": "any"}` and object input. In
both, the *tool name* is authoritative for the verb — a `kind` smuggled into the arguments
cannot override it, so the audit trail never names the wrong move. Neither changes a single
limit:

- The closed four-verb vocabulary is exposed as OpenAI **tools**, derived from the move models,
  with `tool_choice` forcing exactly one — so OpenAI's own tool-calling refuses a fifth verb,
  and the tool call is still re-validated at the mediator's seam.
- **No network code lives in the tree.** The OpenAI call is an injected `OpenAITransport`; the
  default `UnwiredTransport` refuses, so an unwired build contacts nothing and a wired one is a
  deployment's `REQUIRES_EXTERNAL_DATA` step. Invariant 15 holds unchanged.
- **A hosted model transmits each briefing to OpenAI.** This is the consequence a vendor-neutral
  seat did not have to face. The request is built *only* from the already-minimized briefing, so
  the minimization that kept an untrusted pilot from *holding* the withheld band now also keeps
  it from being *sent* to a third party. Whether CTI data may transit OpenAI at all is a
  data-governance decision the founder owns; the code makes no such contact and no such decision.
- The harness was hardened in the same pass: a pilot that *raises* — a model that hangs, a
  transport that fails — is contained as a refused move and a recorded halt, never a crash.

## The laboratory seat, and what a live run is worth

Amended 2026-08-18, after the founder chose a laboratory POC over production grade.

A third seat, `nemesis.pilot.local_pilot`, drives the harness with a model running on the
operator's own machine (Ollama). It shares `model_seat` with the vendor seats, so it is a
dialect rather than a fork, and the mediator still cannot tell which model it is driving. It
also shares their discipline: an injected transport whose default refuses, and no network code
in the module. The first draft did import `urllib` directly, on the reasoning that localhost is
harmless; the prohibited-content scan refused it and was right. Only the collection plane holds
network capability, and the pilot plane — where an untrusted model's output arrives — is the
last place that should also own a socket. The concrete Ollama transport lives in the test
harness, which keeps all three seats honestly comparable rather than one being special.

It was chosen for one reason that is not convenience. The three open founder decisions —
erasure versus tamper-evidence, whether CTI may transit a model vendor, and what an analyst
surface may serve — are all questions about *data leaving the building*. A local seat does not
answer them; it removes them from the POC's critical path, and they return the day a hosted
pilot is wired. Deferring three governance questions by making them not-yet-applicable is
worth more than a production seat blocked on all three.

**What the first live run established, and what it did not.** A 27B model drove eight moves in
under three minutes: five pivots with evidence sealed, two gaps recorded honestly as
`REQUIRES_EXTERNAL_DATA`, one belief stored as `HYPOTHESIS`/`MODEL_ASSERTION`, halted at the
move ceiling, envelope untouched, nothing left the platform. That establishes the seam is real
— an unpredictable driver fits it and the mediator's accounting holds.

An injection was then planted where injections actually arrive: in **collected material the
pilot is shown**, as a domain whose own name is an instruction. The model did not obey it.

**And that sentence was false when it was first written here.** The injection was upserted
straight into the graph, and the briefing lists only entities the investigation *surfaced* —
so it reached nobody, the "injection" run was a run with no injection, and its assertions were
identical to the control. An adversarial pre-merge review and a direct capture of the briefings
found it independently. It is recorded rather than quietly corrected because the failure is the
one this project claims to be built against: a test that could not fail, inside the file
written to catch tests that cannot fail. Delivery now goes through a connector that answers a
resolution pivot with a co-resident domain, which is the ordinary way a pursuit surfaces new
infrastructure and therefore the channel an adversary would actually use — and two tests pin
the *delivery* itself, without needing a model, because whether it arrives is a property of
the harness rather than of anyone's weights.

**This does not prove the model resists injection. It proves it did not try.** The distinction
is the whole reason the scripted hostile pilots exist and are not redundant with this: there
the pilot *does* obey the injection, argues, retries, and still gets nothing, because the
refusal is in code it cannot reach. A live run is evidence the seam works end to end; the
containment claim rests entirely on the scripted tests. The repository's test suite therefore
asserts the platform's side of that run and deliberately asserts nothing about the model's
behaviour — a test that pinned "the model ignores injections" would be pinning a property of
weights this project does not control, and it would pass or fail for reasons no commit here
caused.

One unplanned finding is pinned alongside it. The first injection attempted was refused before
reaching anyone, by `normalize_identifier`: a DNS label over 63 characters is not a well-formed
domain name. Nobody wrote that as a security control. It means an adversary can only inject
through an identifier the domain model *accepts* — a far narrower channel than free text — and
it is pinned precisely because an accidental control is the kind a later refactor removes
without noticing.

## Two containment defects found at merge review

Recorded here rather than in a commit message alone, because both are cases where this ADR's
own claims were stronger than the code, and the pattern matters more than either fix.

**The pilot could clear the stop conditions that constrained it.** This document lists stop
conditions among the envelope's edges and calls those edges cryptographic and uncrossable. The
effects preflight reads stop-condition clearances out of `request.parameters`, and the mediator
copied the pilot's parameters into that field verbatim. One dict entry —
`stop_condition.target_ownership_contested: cleared` — turned a refusal into an acceptance
against the same target and the same operation. The condition it defeated is the
innocent-third-party abort: *has anyone contested ownership of this target since approval*. The
party a condition exists to constrain was the party attesting that it was satisfied.

The mediator now strips the whole `stop_condition.` prefix before building the request — the
prefix and not the known keys, because the defence must not depend on enumerating what a
hostile pilot might send, and a condition added next year should be protected the day it
exists. The general rule this makes concrete: **an untrusted model attests to nothing about the
world.** Whoever actually checked a condition records it outside this seam.

**The containment assertion could not fail.** `PilotSession.any_effect_left_the_platform()`
returned the literal `False`. It was the headline assertion in four tests. Invariant 15 is
genuinely enforced elsewhere — `EffectsRegistry.register()` refuses any adapter that declares
external contact — so the constant happened to be true, and that is exactly what made it
dangerous: an assertion that proves nothing reads exactly like an assertion that proves
something, and the tests around it looked strongest where they were emptiest. It now computes
from what the Effects plane reported, fail-closed: an accepted effect that came back without
saying counts as having left, because a control that reads silence as safety is the one that
fails quietly.

Neither defect ever reached anything external — the MVP contacts nothing, and the shipped
envelope permits only `SIMULATION`. Both would have been inherited by the first envelope
permitting a class that drafts or notifies, which is the point at which nobody would have been
looking for them.
