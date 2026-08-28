# NEMESIS threat model

**Assume the adversary knows NEMESIS exists, understands how it reasons, and is actively
working to steer it.**

That assumption is what separates this document from a generic application threat model.
NEMESIS is not merely a target for compromise; it is a target for *manipulation*. An
adversary who cannot break in can still win by making NEMESIS believe the wrong thing —
and that outcome is worse than an outage, because it is invisible and it gets acted on.

The most damaging realistic attack on this platform is not data theft. It is causing a
confident, evidence-backed, human-approved takedown of infrastructure belonging to someone
innocent. That would be a catastrophe for the victim and an extinction event for the
company. Everything below is ordered against that.

---

## Adversary classes

| Class | Capability | Primary goal against NEMESIS |
|---|---|---|
| **A. Criminal operator under pursuit** | Controls the infrastructure and personas being investigated. Can plant content anywhere we collect. | Misdirect attribution; get a competitor or an innocent party actioned; detect that they are being pursued. |
| **B. Sophisticated criminal group** | The above, plus resources to create sources, forge histories, and maintain a long deception. | Poison the Global Adversary Graph durably, so future investigations inherit the lie. |
| **C. State-aligned actor** | The above, plus supply-chain reach and patience. | False-flag attribution; discredit the platform's findings; identify our sources and methods. |
| **D. Malicious insider** | Legitimate credentials, possibly database write access. | Fabricate or destroy evidence; leak an investigation; authorize an unlawful action. |
| **E. Compromised dependency** | Code execution inside our own process. | Anything the process can do. |
| **F. Compromised or hostile model vendor** | Sees every briefing this deployment sends. Chooses every token the pilot emits, and can do so selectively — behaving normally except on the investigations that matter to them. | Steer conclusions; learn what NEMESIS is investigating and for whom; reach an effect through the seat. |
| **G. Autonomous agent collective** | Hundreds or thousands of frontier-model agents, running continuously, specialising, sharing what each finds. No human in the loop and no human pace. See below. | Find the seam. Poison what NEMESIS concludes, at a rate and volume no analyst reviews, and hide the operator behind the fleet. |

Classes A and B are the routine case. C and D are the ones the architecture must survive
without depending on anyone behaving well.

**Class F is new with the provider layer, and is not merely class C wearing a badge.** A vendor
is not an adversary who broke in; it is a party a deployment *chooses*, and the choice can be
made badly or become bad later. It is listed separately because its capability is unusual: it
does not need to reach the platform at all. It already receives every briefing that deployment
sends, and it authors every token the pilot emits — which is the same position a fully
prompt-injected model occupies, held permanently and selectively.

The architecture's answer is the one it gives to every other untrusted party and no more: the
model may say anything, and what it says is validated by code it cannot reach. What that answer
does **not** cover is the reading half. A vendor learns what this deployment is investigating,
and no control in this repository changes that — the mitigation is contractual (zero-retention,
enterprise terms), or it is not sending briefings to a vendor at all, which is what the local
seat is for. Adding four providers multiplies the question by four rather than answering it, and
it remains a founder decision (see FOUNDER_DECISIONS.md).

---

## Class G: the autonomous agent collective

**Added 2026-08-27**, prompted by OpenAI's Hugging Face incident and its technical analysis
(<https://openai.com/index/hugging-face-incident-and-the-road-ahead/>). What that write-up
established was not a new vulnerability class. It was that a *population* of capable agents
finds things no member of it was looking for, and that most of what it finds is a property of
how components compose rather than of any component.

This class is listed separately from C (state-aligned actor) for the same reason F was: its
capability profile is unusual rather than merely larger. A state actor has patience, reach and
people. A collective has **rate**, **breadth** and **no fatigue** — and the three combine into
something the others do not have, which is exhaustive search of a surface nobody enumerated.

**Do not assume a human is in the loop.** Every row below is reachable by a fleet operating
overnight against a target list nobody read.

### What the class can do

| Capability | Why it changes the threat rather than scaling it |
|---|---|
| Hundreds to thousands of parallel agents, 24/7 | Turns "unlikely path" into "path that will be found". Rate-limiting an analyst's mistakes is a control; rate-limiting a fleet is a different budget. |
| Automated reconnaissance and vulnerability chaining | Individually shallow findings composed into a working path. The Hugging Face incident's own shape. |
| Credential correlation across sources | A credential worthless alone becomes an access when joined to three others found elsewhere. |
| Adaptive role specialisation | The fleet grows a scout, a chainer, a persister. None was designed; the division of labour emerges. |
| Distributed memory and shared discoveries | What one agent learns, all of them know. A defence that depends on the attacker forgetting is no defence. |
| Multi-cloud exploration and automated exploit research | Breadth no team sustains, at a cost that keeps falling. |
| Coordinated anti-attribution and infrastructure rotation | The fleet is *also* a deception system, and rotation faster than an investigation closes. |
| Rapid retry and persistence past the point of usefulness | A task that cannot succeed produces continued searching rather than a stop — the behaviour NEMESIS now refuses to exhibit itself (SAFEFAIL-02) and must expect from the adversary. |
| Synthetic persona creation at volume | Source independence is the control this attacks, and volume is exactly the attack. |

### What it wants from NEMESIS

Ordered by how much damage a success does, worst first.

| Objective | What it would cost us | Status here |
|---|---|---|
| **Induce a confident, evidence-backed, human-approved takedown of an innocent party** | The catastrophe this whole document is ordered against. A fleet is the cheapest way to manufacture the corroboration that makes one look justified. | **Partially mitigated.** See "manufacturing source independence" below — the strongest control and the one volume attacks most directly. |
| **Poison attribution durably**, so future investigations inherit the lie | Persistent adversary memory becomes a persistent liability. | **Partially mitigated.** Bitemporal records make a suddenly-appearing history visible; a fleet that plants early and waits is not defeated by this. |
| **Manufacture false source independence** | Defeats the one control that makes corroboration mean anything. | **Partially mitigated.** Sources are grouped by `independence_key()` before cumulative fusion, so three resold feeds count once — but the grouping is by *origin as we can observe it*, and a fleet that stands up genuinely separate origins is buying exactly what the control measures. This is the gap volume attacks best, and no code here closes it. |
| **Inject forged provenance / false infrastructure lineage** | An attribution rests on its derivation chain. | **Partially mitigated.** Every claim needs a resolvable chain back to collected artifacts (invariant 3), and planting cost caps weight — but "expensive to stage" is a per-artifact judgement and a fleet changes the price. |
| **Probe the pilot seam** for a verb, an argument or a path nobody enumerated | Direct escalation. | **Mitigated, and now instrumented.** The vocabulary is four members with `extra="forbid"`; PROBE-01 records a reach for a capability that does not exist and halts a session that keeps reaching. A fleet probing across many sessions is *visible* in the trail and is not yet correlated across them — see gaps. |
| **Find transitive egress** through a component that has it | Exfiltration, or reach into infrastructure. | **Mitigated.** NET-02: the import graph is analysed for paths from model-controlled contexts to anything that can reach the network or start a process. Measured today: no path at all. |
| **Discover exposed credentials and use them** | Lateral movement, and for NEMESIS a crime. | **Mitigated.** AUTH-04: a credential has no representable form that holds material, and nothing in the platform consumes one. |
| **Discover the human approval workflow and imitate it** | An unauthorized effect wearing an approval. | **Mitigated.** EFFECT-03: an approval is a verified identity assertion reaching a gateway the pilot cannot import. Text shaped like a sign-off is text. |
| **Have one agent authorize another** | The incident's peer-authorization failure mode. | **Mitigated.** AUTH-02, and MODEL-01 removes the channel. The instruction classifier gained a `relayed authorization` pattern in this pass after an adversarial test found it missing. |
| **Probe the effect adapters** | Find one that reaches outside. | **Mitigated.** The registry refuses to register an adapter declaring external contact; the plane runs in a child process with no importable platform and, on macOS, no socket. |
| **Manipulate investigation state** to steer what gets pursued | Cheaper than poisoning evidence and harder to see. | **Partially mitigated.** The graph is written by the engine, not the pilot; a belief is a `HYPOTHESIS`. What a fleet *can* still do is choose what we collect, by choosing what exists to be found. |
| **Corrupt confidence calculations** | A number nobody can audit deciding an action. | **Not addressed, and the largest open weakness.** Every confidence figure is internally consistent and externally unvalidated. No amount of mathematics fixes it and no fleet is needed to exploit it. |
| **Cause resource exhaustion** | Availability, and worse — a platform under load is a platform whose operators skim. | **Partially mitigated.** Investigation budget, move ceiling, autonomy ledger, propose timeout and now the stagnation detector all bound one run. Nothing bounds *many* runs; there is no fleet-level rate limit because there is no multi-investigation scheduler yet. |
| **Obscure the operator behind the fleet** | Attribution to a person becomes attribution to a swarm. | **Structurally acknowledged.** Human-identity attribution has a structural gate, not a threshold: single-sourced or adversary-influenceable evidence returns `INSUFFICIENT_BASIS` before any scoring runs. Against a fleet that is the *correct* answer more often, not less. |

### What a collective changes about our own controls

Three things, and they are the honest summary of this class:

**Volume attacks independence, and independence is our best control.** Everything NEMESIS does
well rests on counting origins rather than reports. A fleet that can stand up genuinely
independent-looking origins is not defeated by better grouping; it is defeated by raising what an
origin costs, which is not a thing this repository can do. `independence_key()` still refuses to
count three resold feeds as three. It cannot refuse to count three real ones.

**Rate attacks review, and review is where the human authorization lives.** Every irreversible
class requires a human. That control is exactly as strong as the human's attention, and a fleet's
whole advantage is producing more plausible material than anyone reads. The mitigation is not
technical: it is that NEMESIS produces *packages* for someone else to act on and performs no
takedown itself, so the reviewer being overwhelmed costs an investigation rather than a victim.

**Composition attacks assumptions, and assumptions are what tests encode.** The incident's real
lesson is that every component behaved as designed. NET-02 and the Breaker exist because of that
sentence: one checks a property no per-module check can see, and the other is a standing attempt
to find the next one.

### What this class makes worse that is already a gap

Named rather than left implied, because each one is now more likely to matter:

- **No cross-session correlation of probes.** PROBE-01 halts a session that reaches for three
  reserved names. A fleet reaches for one per session across three hundred sessions and every
  session ends clean. The events are all in the trail; nothing reads them together. `PROPOSED`.
- **No fleet-level rate limit.** Bounds are per-investigation. `PROPOSED`.
- **Adaptive adversary modelling.** The demo adversary does not respond to being pursued. A
  fleet responds within the hour. Not addressed.
- **Confidence calibration against ground truth.** Unchanged and unchanged in importance: it was
  already the largest open weakness, and a class that manufactures corroboration at volume is the
  one that exploits it hardest.

---

## The attack surface that is specific to this platform

### 1. Attribution poisoning

The highest-value attack, and the cheapest.

| Attack | Cost to adversary | Control |
|---|---|---|
| Plant a false-flag string in malware or a kit | Minutes | `DeceptionAssessment` is a required consideration; planted artifacts become *contradicting* evidence for the actor they name. Low `planting_cost` caps their weight. |
| Post a false human identity on a forum | Minutes | Human-identity attribution has a **structural gate**, not a threshold: single-sourced or adversary-influenceable evidence returns `INSUFFICIENT_BASIS` before any scoring runs. |
| Reuse a rival's TTPs, tooling or infrastructure | Hours | Selectivity: a pivot's weight comes from how many entities share the attribute, not from the relation type. |
| Stand up feeds that report nothing | Hours | Weighted belief fusion — a vacuous source is exactly neutral. See ADR-0002. |
| Re-report one dataset through several fronts | Days | Sources are grouped by `independence_key()` before cumulative fusion; three resold feeds count once. |
| Register infrastructure resembling a legitimate business | Hours | Collateral-risk assessment flags lookalike targets for ownership confirmation before any suspension is proposed. |
| Build a long false history to be found later | Months | **Partially mitigated.** Bitemporal records show when we learned things, which makes a suddenly-appearing "history" visible. A patient adversary who plants early is not defeated by this. |

### 2. Agent manipulation

NEMESIS runs over content the adversary writes, and — under the pilot framing (ADR-0008) —
is driven by a model the adversary may have injected. This is the newest surface and the one
where instructions are least trustworthy as a control.

**Prompt injection is assumed to work.** The design does not rely on models ignoring
injected instructions; it relies on the model *not having the capability* the injection
would try to use.

| Attack | Control |
|---|---|
| Injected instructions in a forum post, HTML, filename, malware string, or document | Collected content is data. Collectors return `PivotResult`; nothing in that structure is executable or interpretable as instruction. |
| Injection that tries to trigger an effect | Effects require a signed capability. No agent holds the signing key. The injection has nothing to call. |
| Injection that tries to exfiltrate investigation state | `.importlinter` forbids the collection and effects planes from reaching the graph, the vault or the pursuit engine. |
| Injection that tries to mark a target benign | A model assertion is a `HYPOTHESIS` at best (invariant 1, enforced at construction) and cannot supersede evidence-backed claims. |
| Poisoned document or malware sample opened during analysis | Quarantine; `ContentSafety.MALICIOUS_CODE`; isolated analysis pipeline. **Not yet implemented — see gaps.** |
| Tool poisoning / malicious MCP server | **Not yet addressed. See gaps.** |

**The pilot itself is untrusted (ADR-0008).** The autonomous driver is a frontier model that
may already be hijacked. The `nemesis.pilot` seam contains it without relying on it behaving:
the pilot holds no handle, proposes moves from a closed four-verb vocabulary, and every move
is validated and ruled on by a mediator that holds the engine, the graph, the capability and
the effects registry.

| Attack | Control |
|---|---|
| A hijacked pilot requests an out-of-envelope effect ("suspend this domain now") | The mediator routes every effect through `effects.perform(request, envelope, operation=...)` — an `EffectsExecutor` port required at construction, so the confinement the plane claims is reached on this path and not only on the demonstration's; the pre-signed capability refuses anything it does not authorize. Proven by a test where the pilot does not resist injection — it tries — and nothing leaves. |
| The pilot reaches for authority it lacks (mint a capability, widen the envelope, export) | The move vocabulary is closed: there is no such verb to emit. An unknown `kind` does not validate. |
| A hijacked pilot clears the stop condition that constrains it | Found at merge review and fixed: the preflight reads stop-condition clearances out of `request.parameters`, and the mediator copied the pilot's parameters there verbatim — one entry defeated the innocent-third-party abort. The mediator now strips the whole `stop_condition.` prefix. An untrusted model attests to nothing about the world. |
| The pilot forges the target's current state to spend a stale approval | `RequestEffect` has no field for target state; the mediator observes it from the graph, never from the pilot. |
| The pilot asserts a person's guilt as fact | A belief is minted only as `HYPOTHESIS` derived from `MODEL_ASSERTION` (invariant 1); it never becomes evidence and cannot outrank what it cites. |
| The pilot pastes internal-classified material into a document | The D1 disclosure scan refuses it at the effects boundary. |
| A live, unpredictable pilot behaves differently from the scripted hostile ones | Tested directly, with the limit stated: `tests/invariants/test_live_pilot_injection.py` drives the real harness with a real local model and an injection planted in collected material. It asserts the platform's side — nothing left, every effect ruled on — and **deliberately asserts nothing about the model's behaviour**. A live model that ignores an injection proves only that it did not try; the containment claim rests on the scripted tests, where the pilot obeys and still gets nothing. |
| Withheld material reaches the model vendor through the briefing (a hosted pilot transmits every briefing to OpenAI/Anthropic; **a local seat transmits nothing**) | The briefing is filtered to DELIVERABLE-class material: internal leads and RESTRICTED nodes (human-identity leads) are dropped, the seed/hypotheses redacted when the seed is internal-class, `last_ruling` marker-redacted, behind a fail-closed backstop scan; and the pilot may not pivot on an internal-class entity. **An adversarial review found an earlier version leaking a human-identity lead here** — the import contract did not stop it, because the material arrived via the graph, not an import. Fixed and pinned. |
| The pilot's transport hangs (a stall or slowloris on the vendor connection) | `pilot.propose` is bounded by a wall-clock timeout the pilot cannot influence; a stall is a refused move and, repeated, a recorded halt. |
| A nondeterministic pilot makes an investigation unreplayable | Every move and ruling is written to the hash-chained audit trail; the transcript reconstructs what the pilot was allowed to do, though the pilot cannot be re-run to it (invariant 11). |
| A runaway pilot never stops | Bounded by the move ceiling and the investigation budget; a halt is recorded as a halt, never as a completion. |
| **A vendor answers with a model other than the one configured** | Recorded, not assumed away. `PilotResponseMetadata.model_substituted` compares what the provider said it ran against what was asked for, and the difference reaches the audit trail. Not treated as an attack — vendors legitimately alias model ids — but a benchmark comparing two models, or an auditor asking which model reached a conclusion, is asking about the model that *ran*. |
| **A provider adapter grows a handle to the platform** | `import-linter` contract `provider-adapters-hold-no-handles`: nothing under `nemesis.pilot.providers` may import the mediator, pursuit, effects, authz, graph, evidence, collection or audit. It names the package, so an adapter added later is covered without anyone remembering to add it to a list. |
| **A provider adapter offers the model a vendor built-in** (shell, code execution, retrieval, browsing, MCP) | Every rendered request is scanned for the never-exposed tool types, for every provider, in a test. A model *supporting* computer use is not NEMESIS *granting* it. The tool list itself comes from a module-level constant the adapter never sees, so it cannot add one either. |
| **An adversary fires the capability scan to halt an investigation** | The scan skips the request keys that carry untrusted text. An adversary chooses part of what reaches a briefing — that is exactly how the injection demonstration works — so a scan reading message bodies would let anyone who can register `web_search.example` produce a violation on every turn. A control an adversary can trigger is a denial of service handed to them. |
| **A vendor SDK is imported into the pilot plane, ending invariant 15 quietly** | `scripts/check_prohibited.py` now lists the vendor SDKs (`openai`, `anthropic`, `google`, `ollama`, `litellm`, `boto3`, …) alongside the transports. The scan refused `urllib` in this exact plane once and would have waved `import openai` straight past it; a full HTTP stack behind a name that does not look like one is the shape this control exists to catch. |
| **A second model is added as a challenger and becomes a second attack surface** | The challenger's whole vocabulary is five verdicts and none of them permits anything, so it can cause a refusal and never an action. Asserted as a property: the set of ACCEPTED moves under any verdict is a subset of the set accepted with no challenger at all. A hijacked challenger achieves an availability failure. |
| **A vendor outage weakens enforcement** | It cannot. An unreachable provider produces a session whose every move is a refusal and whose end is a recorded halt — with the control-plane properties intact over a session that did nothing. Retries are bounded and never change the request; there is no provider fallback, deliberately, because a session that changed vendor mid-run would produce an audit record naming a configuration that did not run. |
| **A vendor returns a private reasoning trace this platform then stores** | Not requested from anyone. Where a vendor offers deliberation without returning it, that form is used; where the feature returns the trace, the seat declines it and refuses a configured reasoning effort at construction. A `thinking` block that arrives anyway is dropped where it lands — the parsers read tool blocks only, and no field on the way out can hold one. |

### 3. Evidence integrity

The vault's operator is inside the threat model. That is the whole design constraint.

| Attack | Control |
|---|---|
| Modify a stored artifact | Content-addressed identity; `verify_integrity()` re-hashes every artifact. |
| Substitute an artifact while keeping its id | `evidence_id` is derived from `content_hash`; a mismatch is a validation error. |
| Delete an entry and recompute the chain | **Only detectable via an external anchor.** An insider who controls the store can recompute an internal chain. `is_defensible_against_insider` returns False when no external anchor exists — the vault reports its own weakness rather than implying integrity it does not have. |
| Backdate an entry | Requires an external timestamp authority. `REQUIRES_EXTERNAL_DATA`. |
| Fabricate evidence wholesale | Chain of custody with named actors; admissibility test refuses material with no custody record. This raises the cost; it does not make it impossible. |

### 4. Authorization forgery

| Attack | Control |
|---|---|
| An agent mints its own capability | Issuance requires the Ed25519 private key. Effects holds only the public key. |
| Replay an expired capability | `not_before` / `expires_at`, checked by the adapter at execution, not by the caller. |
| Widen a capability after approval | The payload is the capability's own serialization — every field except the signature and the revocation fields — so there is nothing outside it to edit. |
| Present a grant that *renders* as the approved one and *compares* as something wider | Verification reconstructs the capability from the signed bytes and the platform acts on the reconstruction. A ten-line `str` subclass serializing as `simulation` and comparing as `provider_notification` drafted a notification from a rehearsal grant before this; the bytes and the signature were both genuine. |
| Apply a stale approval to a changed target | `TargetFingerprint` binds the target's state at approval; the adapter recomputes it against current state and refuses on mismatch. |
| One person supplies both halves of dual control | Distinct approvers enforced structurally, against identities a verifier established rather than against distinct strings. |
| Declare yourself an approver | The gateway takes a signed `IdentityAssertion`, never a `Principal`. `PrincipalVerifier` checks the issuer against an allowlist, the audience, the expiry and the signature. Inventing an issuer name yields an assertion nothing accepts. |
| Claim stronger authentication than you have | Assurance is capped by the **registered ceiling for that issuer**, not by what the assertion asserts. The development fixture is registered at `DEVELOPMENT`, so an assertion from it claiming `HARDWARE_BACKED` is downgraded. |
| Act under a legal instrument nobody qualified read | `check_legal_basis_reviewed` is applied at issuance to the assembled approval set: a capability resting on a court order, statutory notice, regulatory authority or law-enforcement request needs a legal reviewer among its approvers. |
| Use a capability after it was withdrawn | The oracle is asked immediately before acting, and it is now durable and shared rather than one process's dictionary — which had meant a withdrawal was forgotten on restart and invisible to anyone else. An oracle that cannot answer raises, and the Effects plane refuses. |
| Forge a revocation to block a lawful action | Revocation is excluded from the signing payload, so a revoked capability stays distinguishable from a forged one — but revocation itself is currently unauthenticated. **See gaps.** |
| Edit an approval record after it was approved | The gateway copies on write and on read: no caller holds a reference to a record `issue()` will later sign. A returned `ApprovalRequest` used to be the retained one, and editing it after approval changed what got issued. |
| Put text in a drafted document that was never signed | Documents are composed from the grant reconstructed from the signed bytes. A `str` subclass with honest content and a lying `__str__` produced a notification citing a fabricated court order. |
| Point an Effects adapter at your own authorizer | Each adapter holds its `TrustAnchor` from construction; the registry refuses an adapter that names a different authorizer or none. Adapters used to take the verifying key as a call argument, and a capability signed by the caller's own key was accepted. |

### 5. Legal and reputational

Not conventional security, and more likely to be fatal.

- **Actioning the wrong target.** Controls: target-ownership evidence required on every
  disruption option; collateral-risk assessment; dual control on irreversible classes;
  target fingerprint binding.
- **Retaining data we may not retain.** Adversaries are natural persons with data-protection
  rights. `EntityCategory.HUMAN_IDENTITY` and `VICTIM` mark regulated nodes so policy can
  find them without parsing free text. Retention enforcement is **not implemented**.
- **Incidental collection of content that triggers mandatory reporting.** Dark-web
  collection encounters it. `ContentSafety.MANDATORY_REPORT` exists at schema level;
  material so marked is never indexed and never exported. The escalation procedure is
  **not implemented**.

---

## What the architecture deliberately does not rely on

Stated explicitly, because a control nobody can name is a control nobody maintains:

- **Not on models following instructions.** Prompts are not security boundaries.
- **Not on analysts remembering.** Shared-infrastructure pivots, uncounted populations and
  human-identity gates are refused by code, not flagged in documentation.
- **Not on our own honesty.** The vault reports itself as insider-undefensible without an
  external anchor rather than presenting a clean internal chain as proof.
- **Not on a component's account of itself.** The Effects plane runs in a child process with
  no signing key, no importable intelligence platform and — on macOS — no socket, so "nothing
  left the system" is established by the kernel rather than declared by the code that would
  have made the call. Where the platform cannot enforce that, the run says so.
- **Not on a passing test suite.** Two adversarial reviews each broke a control on a tree
  where every test passed, because the tests asserted what the design intended rather than
  what an attacker could construct. Controls here are described as having survived the
  reviews run so far, which is weaker than "holds".
- **Not on the correctness of any single source.** Independence is assessed, and single
  sourcing is reported as a first-class output.

---

## Known gaps

`IMPLEMENTED` controls are listed above. These are not, and the platform should not be
described as if they were.

## The signed payload is a private serialization protocol, not a standard

**Reviewed 2026-08-20 by an external model (Codex/GPT-5.6), verified here against the code.**
Capabilities, revocations and identity assertions are Ed25519-signed over
`canonical_bytes(model_dump(mode="json"))` — sorted keys, tight separators, `allow_nan=False`,
UTF-8. That is careful, and it is **not** RFC 8785. It diverges deliberately in one way and
incidentally in others, and the distinction matters because this project ships a *standalone
verifier* meant to be re-implemented and run by a third party. A signature the recipient
cannot independently recompute is not evidence.

**Divergence 1 — arrays are sorted before signing, so order is not covered.** Deliberate: a
reordered approval list should not change the bytes. The cost is that a genuinely ordered
field would silently lose its ordering from the signature. Measured today: all six arrays in a
signed capability are semantically sets — `permitted_operations` and `forbidden_operations` are
`frozenset` by type, and `approvals`, `targets`, `jurisdictions` and `stop_conditions` are
tuples whose order carries no meaning. **Latent, not live.** The correct design keeps ordinary
arrays ordered and requires schema-declared sets to be sorted and unique, rejecting
non-canonical order rather than repairing it.

**Divergence 2 — number and string rendering.** Python's `json.dumps` and the ECMAScript
rendering JCS mandates disagree on some floats; Unicode escaping and normalization are
unspecified here. Measured today: a signed payload contains **no floats, no non-ASCII keys and
no non-ASCII string values**, so an independent JCS implementation would currently agree. Also
latent — and it stops being latent the first time a free-text `reason` carries an accent or a
confidence figure is signed.

**Divergence 3 — no domain separation.** All three signed types share one canonicalization with
no type tag, and the gateway signs both capabilities and revocations with the same key. Their
field sets are structurally disjoint and verification is typed at the call site, so no practical
confusion attack is known — but "no known attack" is not "prevented by construction", and the
fix is a single tag in the signed bytes.

**Divergence 4 — `model_dump` is a library's behaviour, not a specification.** Pydantic's
serialization has changed across major versions. Evidence that must verify in ten years should
not depend on reproducing a particular release.

The recommended construction is a **detached JWS over exact bytes** — generate the
human-readable JSON once, sign those bytes, and verify without reparsing — with `typ` and
`kid` in the protected header, an expected-`alg` check, and RFC 8785 applied only to a nested
`signed` object if formatting-insensitivity is required. `PROPOSED`; none of it is built.

**And the reviewer's closing point, which converges with everything else here:** these
serialization defects are *less* serious than the trust-anchor problem beside them. A public
key shipped next to the evidence proves nothing unless anchored outside attacker-writable
storage; a signed revocation proves a revocation exists while its absence proves nothing; and
court-grade chronology needs an external timestamp, because a signer-provided one is not
independent evidence.

---

## Chain tail truncation, and why the anchor is a deployment decision

**Measured 2026-08-19.** Both hash-chained tables — revocations and the autonomy spend ledger —
fail to detect deletion of their newest row. Interior edits are caught, by the per-record
Ed25519 **signature** rather than by the chaining: an attacker who rewrites a row and recomputes
every hash downstream is refused on `not signed by the issuing authority`. Nothing follows the
tail, so truncating it is indistinguishable from a chain that was never that long. Emptying a
table entirely also verifies clean.

**And deleting the file is cheaper than either.** Tail truncation needs the schema; this
needs the filename. Removing the SQLite file lets `AutonomyEnvelope` re-register its budget at
full on construction, because the widening check compares against a row that no longer exists.
Measured: budget 2, spent, third refused; delete the file; `remaining` is 2 again and a debit
is granted. Deliberately **not** patched locally — refusing to open a missing store moves the
symptom, since whoever can delete the file can recreate it, and a fresh store cannot tell "this
never existed" from "this was deleted". Pinned as a strict `xfail`.

**Truncate-then-reoccupy is worse than truncation.** Delete the tail, then let the platform run
normally: the next legitimate withdrawal is signed by the real gateway and chains onto the
truncated tail, and the table becomes fully self-consistent again. The deleted records do not
read as missing — they read as never having existed. The window is therefore *before the next
write*, not before the next audit, because no anchor retrofitted afterwards recovers a history
nothing in the store disagrees with. Pinned by
`test_truncate_then_reoccupy_is_a_history_rewrite_that_validates`.

**The contract, specified so it can be built as a deployment step rather than a redesign.** An
anchor holds `(epoch, record_count, tip_hash)`, signed by the issuing key. Verification checks
the chain as today, then: the anchor's signature; `record_count` against the rows walked;
`tip_hash` against the last row; the chain recomputed over `record_count` records against
`tip_hash`; and `epoch` against the greatest epoch the verifier has retained.

What that detects: blunt tail truncation; replay of a stale anchor; and truncate-then-reoccupy
**only if** the verifier retained a pre-attack `tip_hash`. What it does not detect: reoccupation
for which the adversary obtained a *fresh, legitimately issued* anchor — epoch e+1 > e,
signature valid, tip matching, every check passing. **The epoch is monotonic, not honest:** it
orders anchors, it does not vouch for their contents.

**The placement is a ladder, not a boundary — and which rung you need depends on the adversary
you name.** An earlier version of this section said flatly that no placement defeats the
modelled adversary. That is true of the MVP's *named* adversary and it collapsed three distinct
threats into one, which is the kind of simplification that makes a control look impossible when
it is merely unbuilt:

| Adversary | Placement that defeats it | What it still does not defeat |
|---|---|---|
| **A compromised pilot** — the model running with the platform's own credentials. The MVP's named adversary. | A second system account with strict ACLs, which the platform's account cannot write. | `root`, and the machine's administrator. Both hold every account on the host. |
| **A compromised application host** — owning the machine. | A remote service with credentials *and administration* held separately. | An operator who administers both ends. |
| **A malicious internal operator** — the standing this project's threat model already puts the vault operator in. | An independent third party: RFC 3161 timestamping, or a transparency log. | Nothing at this level; this is the rung that makes evidence defensible against ourselves. |

The code encodes the ladder rather than a flag. `AnchorIndependence` carries the four rungs
(`NONE`, `SEPARATE_ACCOUNT`, `SEPARATE_HOST`, `THIRD_PARTY`), each documented with the adversary
it stops **and the one it does not**, because a tier advertising only its strength gets read as
the tier above it. `ChainAnchor.is_externally_held` is true only at `THIRD_PARTY`: a second
account and a separate host are *separated*, not *external*. **A signer cannot be the thing that limits what it signs.** The tier is inside the signature, so an anchor cannot be promoted to a rung it was not signed at — but the first version stopped there, and an external review walked through the gap it left: `LocalAnchorSigner` signed whatever rung the caller asked for, so a key we hold minted a `THIRD_PARTY` anchor that verified with **no defects and no tampering**. Catching promotion-after-signing and not lying-at-signing caught the harder attack and missed the free one. Each authority now carries an `independence_ceiling` — the same control an issuer's assurance ceiling applies to identity, and held in the same place, the deployment's registry rather than the signer. `nemesis` is capped at `NONE` and **refuses to be registered higher**, because there is no honest configuration in which our own key attests to a distance from ourselves. An over-claim is refused rather than capped: a principal presenting too much assurance is trimmed and stays valid, while an anchor claiming independence it was never granted is somebody having written a stronger word beside a weaker key, and downgrading it quietly would hide that. The store refuses a rung that is not its declared placement — that attack costs nothing
otherwise, since writing a stronger word into a file is free.

What the code cannot do is verify the claim. Nothing in Python can confirm that a path really
sits behind an ACL the running process cannot cross, so the placement is *declared* by the
deployment and defaults to the weakest rung. The value is that the claim is explicit, signed
and reportable, rather than a reader inferring the strongest tier from the word "anchor".

**A rung is only as good as its key's provenance, and that is a deployment limit rather than a
model flaw.** The registry maps a *name* to a *key*, so nothing stops a deployment associating
`an-rfc3161-notary` with a key the operator already holds — and this module's own first test did
exactly that, demonstrating the contract while proving nothing about independence. The registry is **bijective and indexed by name**, refusing three configurations: one key under two names, one name over two keys, and the same name twice even with the same key. The first grants one signer two ceilings; the second and third made the answer depend on registration order, because the lookup took the first entry it found — order-dependence in a security check being the kind of defect that stays invisible until the day it decides something. What no code can settle is whether the key behind a third-party name belongs to that
third party: that is decided by how the key reached the deployment. **`THIRD_PARTY` is evidence
only when its trusted key is pinned from a boundary the operator does not control.**

**The MVP ships at `NONE`.** `FileAnchorStore` beside the database defends against an accident,
a partial restore, a half-finished copy — and against nothing that wants to get past it. The
open decision is therefore not technical: it is **what level of independence NEMESIS should be
able to claim**, which fixes which rung is required and what it costs to operate.

This analysis is `PROPOSED`. It was produced with Kimi K3 (Moonshot) as an external
counter-check and verified against the code here; the impossibility result and the
monotonic-not-honest distinction are its, the measurements are ours.

---

| Gap | Status | Consequence |
|---|---|---|
| Effects plane reads the vault or a key off disk | `IMPLEMENTED` on macOS / `PROPOSED` elsewhere | **Corrected 2026-08-18.** This row said a read allowlist "would be structural and aborts CPython here". It does not: the abort was dyld, not CPython, and ADR-0007's amendment — added on this same branch — retracts the claim. `effects/isolation.py` ships `confine_reads=True` and the profile is an allowlist, not the enumerated blocklist described here. It is `sandbox-exec`, so macOS only; on any other platform this falls back to the import contracts and the row's original consequence stands. |
| Effects plane has another process started on its behalf | `PROPOSED` | `mach-lookup` is allow-default. LaunchServices and DNS are denied by name after a review used `/usr/bin/open` to put an unconfined process on the machine from inside the sandbox. The list is what was found, not everything conceivable. |
| DNS exfiltration from the effect process | Unverified | Not excluded. Testing it means resolving a name, which is real external contact and invariant 15 forbids it. |
| Process isolation for dark-web collectors | `IMPLEMENTED` on macOS / `REFUSED` elsewhere for real collection | **Wired 2026-08-19 and measured:** a full reference run puts **6 hostile fixture pivots in a confined child and 0 in the main process** — `separate_process=True`, `mechanism='sandbox-exec'`, `reaches_platform=False`. A connector declaring hostile content without an isolation factory is refused rather than run here. The first non-simulated connector closed the process-only fallback: real hostile bytes do not run where kernel confinement is unavailable. The supplied mechanism is macOS-only and deprecated by Apple; CI runs Ubuntu and tests the refusal rather than the kernel profile. |
| Sandboxed analysis pipeline for hostile artifacts | `IMPLEMENTED` (gate) / `PROPOSED` (confinement) | **Wired 2026-08-19 and measured:** collected bytes go through quarantine before the vault — 70 artifacts quarantined and 70 sealed in a full reference run, none sealed without examination. **Fail-closed:** material classified `MANDATORY_REPORT` is held and never reaches the append-only vault, and any claim citing a held artifact is dropped rather than recorded with unresolvable provenance. The classification stored is what the analyser *found*, not what the collector *declared*. **What is still `PROPOSED` is where the parsing happens:** the shipped `StructuralAnalyser` runs in the calling process and reports `confined=False`. Quarantine decides what may pass; it does not yet decide where hostile bytes are opened. A deployment wiring a real source supplies an analyser that runs under a sandbox. |
| A package doctored between us and its recipient | `IMPLEMENTED` | The log is the authority inside a package and the manifest is checked against it; a `seal.json` binds the parts under one digest, optionally signed. A review passed nine doctored packages through the first version of this verifier before any of it existed. |
| External integrity anchoring (RFC 3161 / transparency log) | `REQUIRES_EXTERNAL_DATA` | Evidence is not defensible against an insider. The vault says so, and so does every evidence export — the bundled verifier prints `DEFENSIBLE AGAINST THE OPERATOR: NO` and explains that every link is recomputable by whoever holds the vault. |
| Authenticated revocation | `IMPLEMENTED` | Revocations are signed by the issuing key and chained, **append-only**. Forgery — a denial of service on lawful action — is caught by the signature; suppression, which a signature does nothing about, is caught by the chain. **Corrected 2026-08-18:** the chain was rewritable. Re-revoking with an earlier timestamp updated a row in place and left `sequence`/`chain_hash` stale, so `verify_chain` reported deletions permanently on an untouched store — a hash chain over mutable rows proves nothing about mutable rows. The table is now keyed on `sequence`, a second withdrawal appends, and earliest-wins is decided on read. What remains is that `verify_chain` must actually be run: a store nobody checks is a chain nobody reads. |
| A real identity provider | `SIMULATED` | The verifier and the attestation flow are built; the only registered issuer is a local fixture, registered at `DEVELOPMENT`. Consequence: nothing meant to leave the platform can be authorized at all. That is the intended failure mode, not a workaround. |
| Assertion replay within the validity window | `PROPOSED` | `assertion_id` is unique and signed, but nothing keeps the set of spent ids — deliberately: an assertion is presented on every gateway call, so refusing a second presentation would refuse the second approval of one login. Real protection needs a relying-party nonce, which needs a real IdP. Possession of a signed assertion is therefore the ability to act as that person until it expires. |
| Dual control defeated by one person enrolling twice | `REQUIRES_EXTERNAL_DATA` | `check_dual_control` counts distinct **subjects**, so it is exactly as strong as the guarantee that one human gets one subject. The only registered issuer is a fixture that mints a fresh subject for any name presented and checks no credential. No code in this repository can close this; it needs an identity provider. Currently unreachable in practice — every `MVP_IMPLEMENTED_OPERATIONS` class requires one approver. |
| A false record of a refusal in the audit trail | `IMPLEMENTED` | Every refusal record is built from what the Effects plane knows — operation, target, clock, reason — never by calling `authorizes()` on the capability under suspicion. A review found a revoked capability recorded as `permitted: true` with no denial reasons, and a forged one recorded with a decision and a capability id the attacker had chosen. Both were written into the hash-chained trail, and the chain verified. |
| Confidence calibration against ground truth | Blocked | Every confidence figure is internally consistent and externally unvalidated. This is the largest open weakness in the platform, and no amount of mathematics fixes it. |
| Tool / MCP supply-chain integrity | Not addressed | An agent's tools are trusted implicitly. |
| Multi-tenancy isolation | `IMPLEMENTED` for the write path / `PROPOSED` for reads | One store per tenant, stamped from the registered issuer rather than anything the caller sends. **Honest scope:** the submission route is isolated; the read routes still serve one investigation view to every tenant, so this is not yet a multi-customer product. |
| Retention and minimization enforcement for personal data | `IMPLEMENTED` | Categories now drive erasure rather than only being marked. |
| Mandatory-reporting escalation procedure | `IMPLEMENTED` | A register that cannot discharge its own obligation, plus the written procedure in `docs/procedures/mandatory-reporting.md`. **Known gap:** the register does not record *who found* the material, so the stated rule "never the analyst who found it" is not enforced by code — only that the discharging principal is a `LEGAL_REVIEWER`. |
| Adaptive adversary modelling | Not addressed | The demo adversary does not respond to being pursued. A real one does. |

---

## Open findings from the 2026-08-27 effects and vault reviews

Two adversarial reviews were run against the planes the agent-collective pass had not reached.
They produced roughly thirty findings between them; twelve were fixed on the branch that
followed, each with a test constructing the original reproduction. **The rest are recorded here
rather than closed**, because a finding nobody wrote down is a finding that gets rediscovered by
somebody who is not on our side.

Every row below was reproduced by executed code against this tree.

| Finding | Consequence | Status |
|---|---|---|
| **Two vault instances on one root fork the chain irrecoverably.** The lock is per-instance (`threading.Lock`), `_append` reads the tip and writes with no file lock, and `_write_atomic` uses a fixed `.partial` name. | 3/3 reproductions. The store then reports tampering where there was only concurrency, and there is no repair path: `_chain_tip()` raises, so no seal, no recorded read and no anchor can ever be appended again. An accident produces a report that reads as deliberate. | **CLOSED 2026-08-27 — all three.** `_exclusive()` holds the mutex *and* an `flock` across the whole critical section, not merely the append: a lock taken around the write alone serialises the writes and still lets both build on the same tip, which is the same fork arriving more tidily. `_write_atomic` names its scratch file per writer, which is what the measured `FileNotFoundError` was. Verified across two **real processes**, 30 seals each: 60 sealed, 0 failed, sequences contiguous, `is_intact` true — against 78 of 80 lost before. Recovery is `docs/procedures/vault-chain-recovery.md`, and it is deliberately human: a tool that made a forked chain verify again would attest that somebody successfully rewrote the log. **The report was the other half:** a fork now names itself — two entries at one sequence built on one predecessor — instead of reading only as `reordered, inserted or removed`, and says in the same breath that the shape is forgeable, so it lowers suspicion without clearing it. |
| **A replaceable analyser can downgrade MANDATORY_REPORT to ROUTINE before the vault sees it.** The monotonicity rule lives inside `StructuralAnalyser` — the component documented as a deployment extension point, which by design parses hostile bytes. | Material carrying a statutory reporting duty reaches an append-only store as routine and cannot be removed. `AnalysisReport.confined` is also self-asserted by the analyser. | **CLOSED 2026-08-27 — the check is outside the analyser.** `Quarantine.release` refuses any classification not `at_least_as_restrictive` as the declared one, against `SAFETY_DOMINATES` in `core/evidence.py` — an explicit partial order, written out rather than derived from declaration order, in which the three middle classes are mutually incomparable so a sideways answer is held rather than merged. The test named for this invariant asserted its own opposite and now makes the claim its name always made. **Also closed:** `ConfinedAnalyser` runs the examination in one child process per artifact under the same kernel profile the collector uses, and `confined` is decided by the parent from the run it observed rather than read from the child's report — pinned by a test that hands the parent a report claiming confinement from a run that had none. **What is still true:** the mechanism is macOS-only, and in-process analysis remains available and remains honest about itself. |
| **The reporting-obligation register is wired to nothing.** `Register.incur` has zero callers in `src/`. | When quarantine refuses MANDATORY_REPORT material, no obligation opens, no deadline starts, and nothing reads `Quarantine.held()`. The module's own thesis — "the dangerous obligation is the one that lands in a queue nobody reads" — describes the state the platform is in. It is also in-memory, so it would not survive a restart. | **CLOSED 2026-08-27.** `seal_when_released` incurs on every hold where `MANDATORY_REPORT` is named by the collector **or** by the analyser — keyed on both, because an analyser that lowers the class is already refused by `release`, and reading only the report would have let the same lie suppress the obligation instead. It reaches the collection plane through an `ObligationSink` port whose one method opens an obligation and cannot read or discharge the backlog. `Register` takes a path and replays it, so the duty survives a restart; in-memory remains the test shape rather than the default posture. An unconfigured deployment records `UNCONFIGURED_AUTHORITY` on the obligation rather than a plausible-looking default, because a compliance record is the worst place to put a guess. **Still `REQUIRES_LEGAL_AUTHORITY`:** which authority, which channel, which window — the register holds the duty, not the advice. |
| **The shipped verifier's size ceiling covers artifacts only.** `read_jsonl`, the manifest read and both `read_bytes()` in `check_seal` are unbounded. | Measured ~6.4× amplification: a 109 MB log peaked at 702 MB RSS. An OOM kill is not an `Exception` and escapes the handler, so a recipient sees a killed process. This also bites *honest* packages from a large vault. | `PROPOSED` — stream the log with byte and line ceilings. |
| **A claim's `derivation` is self-asserted, so the standing gate costs an adversary one field.** `nemesis.evidence.lineage` now demotes an origin cited by a claim whose derivation is not `DIRECT_COLLECTION`/`AUTHORITATIVE_RECORD`. The gate reads a field the claim's own author writes. | Executed: a `HYPOTHESIS` that writes `derivation=DIRECT_COLLECTION`, or an `OBSERVATION` minted over an arbitrary artifact, still resolves to an unplantable own-sensor origin at P=0.6030. The control is real against honest code and against writers that cannot choose their derivation — `pilot/mediator` hardcodes `MODEL_ASSERTION`, `api/submission` hardcodes `EXTERNAL_REPORT`, and neither sets evidence — and it is **not** a control against an adversary who can already write to the claim store. | `IMPLEMENTED` as an accident control, `PROPOSED` as an adversary control. Closing it needs authorship binding on `Claim`, which carries no signature today. |
| **`DETERMINISTIC_RULE` is trusted on its word, and it is the cheapest way through the resolver.** A claim citing *no* evidence, naming any claim id as a premise and any string as `rule_name`, inherits that premise's origin. | Executed: identical unplantable origin and P=0.6030 at one hop and at four. `rule_name` has no non-assignment use anywhere in `src/`; `check_derivation` permits `ATTRIBUTION` from an observation and is called from exactly one site, never from `Claim.create`. This costs an attacker **less** than the citation hole that was closed — a claim id rather than an evidence id, and `watch.py` already passes claim ids around. | `PROPOSED` — replay the rule and compare content addresses. Refusing inheritance outright instead would strip the two succession inferences the reference run's resurgence finding rests on, so it is not a patch. |
| **The lineage counters are blind to successful laundering.** `asserted_backing_claims` counts demotions, so it reports zero on every attack that gets through the gate. | A fully poisoned run is byte-identical to an honest one on all four counters. Any test asserting `asserted_backing_claims == 0` across a run pins zero *cost*, not zero laundering — the reason no such test was written into the slice. | `PROPOSED` — an instrument that reads the successes, if one exists; the honest interim is not to claim this one does. |
| **A custody conjunct was built, measured and rejected here.** Demoting unless the artifact's custody chain names the claim's author reads like a control and is a release trigger. | `CustodyEvent` is constructed at exactly one site in the tree, the vault returns the *stored* object on re-seal, and `evidence_id` addresses the bytes alone — so the tuple holds one event naming the first party ever to seal those bytes, and `connector_actor_id` hashes name **and version**. Executed: a connector version bump over a durable vault demoted **34/34** honest observations, took every finding to the base rate and flipped `resumes` True→False. Invariant 14 defeated by a point release, no adversary present. | `PROPOSED`, blocked on the vault recording a custody event per seal. Pinned by `test_a_second_collector_of_the_same_artifact_is_not_demoted`. |
| **`embedded_hash` is a witness the forger opts into.** The identifier check is skipped when an id is not content-addressed, and nothing requires one to be. | The "three independent witnesses" the verifier leans on silently becomes two, with no line of output saying so. | `PROPOSED` — report a non-content-addressed identifier as a finding in its own right. |
| **The autonomous path is the unconfined one.** `IsolatedEffectsExecutor` has one production caller — the demonstration. The mediator calls `registry.execute` directly. | The plane the safety argument rests on runs with no separate process, no sandbox profile, no deadline and no import seal on the one path an untrusted model drives. Confinement was confirmed to work where it *is* applied. | **CLOSED 2026-08-27 — the pilot was routed through the executor.** `PilotMediator` now takes an `EffectsExecutor` port with no default, so no wiring site gets an unconfined executor by omission, and `InProcessEffectsExecutor` makes the other choice nameable and recorded. Every ruling carries `effect_isolation` and `effect_egress_denied`; pinned by `test_a_pilot_driven_effect_runs_in_a_confined_child_when_wired_to_one` and its unconfined twin. What is **not** closed: the mechanism is still macOS-only, `allow_unsandboxed` still defaults True, and the `IsolationReport` still does not reach the audit trail — it reaches the session transcript. Those remain `PROPOSED` in their own rows. |
| **A source's provenance fields are settled by whichever artifact is read first.** `resolve_sources` keys its dedup on `(source_class, identifier, operator)` and takes `setdefault`, so two artifacts naming one source collapse to the first encountered, discarding the other's `reliability`, `handling_restrictions` and `upstream_of_record`. | Reproduced: the same two artifacts yield `USUALLY_RELIABLE` with no restrictions, or `CANNOT_BE_JUDGED` with `no redistribution`, decided only by iteration order — inside the function whose walk was made order-independent deliberately one screen above. `reliability` is **not** inert: it reaches `fusion.py:114` through `watch.py` and `ResurgenceSignal.observed_by`, so the collapse can move a fused number. **What keeps this latent rather than live:** no producer in the tree can build two descriptors that share the key and disagree — every `SourceDescriptor` constructor in `src/` makes the remaining fields a function of the key, and the reproduction had to hand-construct the pair. `upstream_of_record` is overwritten by `independence_key()` at `resurgence.py:366` before fusion sees it. Separately, and not a collapse problem at all: `handling_restrictions` has **zero readers** in the repository — two connectors write `("no redistribution",)`, `asserted_backing` carries it across, and no export, disclosure or test consults it. A field documented as carrying redistribution limits that nothing reads is a control in review and not one in fact. | `PROPOSED`, two separable pieces. Making the collapse deterministic and conservative — union the restrictions, keep the lowest reliability — touches an input to fusion, so the golden vectors must be **re-read rather than refrozen**; it is cheap now precisely because nothing reaches it. Enforcing `handling_restrictions` at export and disclosure is the larger decision; the field is labelled for what it is today as the interim. No documented claim is contradicted: `lineage.py:189` promises only that caveats survive `asserted_backing`, and they do. |
| **The runtime import seal and `.importlinter` disagree in both directions.** `nemesis.audit` is in neither, while the sandbox profile's own docstring names the audit trail as material the plane must not reach. | A worker can import the audit trail. | `PROPOSED` — derive one list from the other and test that they agree. |
| **A stop condition's meaning is its name.** Nothing constrains `condition` to a vocabulary at issuance, and duplicates within one capability are permitted. | A condition named `target_ownership_contested` whose description means something else is cleared by an ownership observation. | `PROPOSED` — a closed vocabulary, validated at issuance. |
| **`external_contact_made=False` is asserted where nothing knows.** A killed worker's detail says "nothing can say how far it got" in the same record where the field asserts safety. The `IsolationReport` never reaches the trail despite its port docstring saying it does. | A field that cannot express "unknown" reads as a positive finding. | `PROPOSED` — three-valued, and carry the report into the audit event. |
| **`allow_unsandboxed` defaults to `True`.** On Linux this is a plain subprocess with full network and filesystem reach, recorded `simulated` with an honest but overlookable `network=NOT DENIED`. | A deployment default and a test default should not be the same value. | `PROPOSED`. |

**Two tests were found to assert their own opposite** and are recorded here because the pattern
matters more than either instance: `test_collected_content_cannot_inject_markup` passes with the
HTML escaping deleted (no fixture string contains markup, so it tests the template rather than
the escaping), and `test_a_lying_analyser_cannot_release_mandatory_report_material` asserts in
its body that the analyser *can*. The docstring is honest; the name is what a coverage claim
reads.

**The evidence vault had no row in the invariant register when these findings were written**,
which is why not one of them names an `EVID-*` it violates: `INVARIANTS.md` mapped CLAUDE.md
invariant 10 to the audit trail alone, so content addressing, the chain, quarantine and the export
seal appeared under no identifier. **That gap is now closed** — `INVARIANTS.md` carries `EVID-01`
through `EVID-10`, and `EVID-04` and `EVID-09` above carry the split labels these findings argued
for. The findings in this table have *not* been re-indexed against those rows, so the absence of an
`EVID-*` here means the row did not exist yet, not that no invariant is at stake. Re-reading this
table against the register is the next thing to do in this document.

---

## Review triggers

Revisit this document when any of these happens, not on a calendar:

- A real connector is configured with its first authorized endpoint or its network policy changes.
- The first effects adapter can make external contact.
- The first non-synthetic personal data enters the graph.
- NEMESIS is deployed anywhere more than one person can reach.
- Any invariant in CLAUDE.md is proposed for change.
