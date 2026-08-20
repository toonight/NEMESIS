# Project state

**Last updated: 2026-08-18.** How a future session finds its bearings quickly.

Everything below carries its epistemic label. These are never silently upgraded, and a
label change is a documented event.

---

## What NEMESIS is (read this first)

**NEMESIS is the framework an autonomous frontier-model pilot drives — not the pilot.** The
car, the écurie, and above all the limiter that keeps the pilot inside the track. The pilot
(a GPT-5/6-class model, "Atlas") is the brain and is *external*; NEMESIS is the part that
must not be a model, because the part that enforces the limits cannot be one an adversary
steers with the content it writes. The founder set this framing on 2026-08-17 (ADR-0008),
correcting an earlier reading where the deterministic Python engine was mistaken for the
brain. Consequence: "there is no LLM in the code" is correct by design, and the 15 invariants
are the evolved guardrail. Autonomy of an *effect* lives inside a **pre-signed capability
envelope** — inside it the pilot acts alone at machine speed; its edges are cryptographic.
Ungated hack-back is off the table (illegal for a private entity; violates invariants 7/8/9/15)
and the framework is built *ready* for a legally authorized operator rather than holding that
authority itself.

**What "takedown" means here, precisely.** NEMESIS tracks threat actors and prepares the
disruption of their infrastructure, autonomously, with a human authorizing before anything
leaves. It does **not** perform the takedown: registrar suspension, domain seizure,
sinkholing and hosting termination are declared operation classes with *no adapter*, and a
test asserts the registry has nothing to call. What the platform produces is the evidence
package a registrar, host, or court acts on. The autonomy is in reaching that package at
machine speed; the authority to act on it belongs to someone else, by design and by law.

**Current posture: laboratory POC, not production grade** (founder call, 2026-08-18). The
pilot runs *locally* — see the local seat below — which takes all three open founder
decisions off the critical path, because each of them is a question about data leaving the
building and here none does. Production grade is deferred, not cancelled; what it needs is
recorded in [FOUNDER_DECISIONS.md](FOUNDER_DECISIONS.md).

---

## Counter-verification status (read before trusting anything below)

| Area | Reviewed by | Standing |
|---|---|---|
| Everything up to the HTTP API | External challenge (a different model family), plus internal adversarial passes | Six reviews, each broke a control declared working. All fixed with regression tests that construct the attack. |
| **The pilot seam, both model seats, the autonomy envelope, the durable spend ledger** | **Claude subagents only — the same model family that wrote the code**, plus a local `qwen3.8:27b` pass (a genuinely different family, but a much smaller model — treat it as a second opinion, not a stronger one) | **NOT independently confirmed.** Found four real defects (all fixed), so not worthless; by this project's own discipline it is *one correlated opinion*. An external pass is briefed in [docs/review/2026-08-20-external-review-brief.md](../review/2026-08-20-external-review-brief.md) and blocked on quota until 2026-08-20. Read claims about this code as "survived a correlated review", which is weaker than "holds". |

---

## Where this stands in one paragraph

The domain model, the confidence machinery, all nine platform planes, the pilot seam and the
end-to-end vertical slice exist with tests. `uv run nemesis demo` runs DETECT through
RESURGENCE and exits 0. Nothing has ever touched a real system, by construction: every
connector reads a fixture, every address in the scenario is reserved for documentation and
cannot resolve. The largest weakness is not a missing feature — it is that no confidence
figure this system produces has ever been validated against a known-correct answer, and none
can be until a corpus of resolved cases exists.

---

## What exists and works

| Component | Status | Notes |
|---|---|---|
| Core domain model | `IMPLEMENTED` | Claims, evidence, entities, relationships, confidence, fusion, authorization. No I/O, no internal dependencies — enforced. |
| Epistemic rules | `IMPLEMENTED` | A model cannot produce an observation or a fact. A conclusion never outranks its weakest premise. Both enforced at construction, not by convention. |
| Bitemporal model | `IMPLEMENTED` | Valid time vs transaction time; four-point extents keeping "observed between X and Y" distinct from "held exactly X to Y". |
| Selectivity | `IMPLEMENTED` | Edge weight derives from how many entities share the pivot attribute. Uncounted populations weigh zero. |
| Method reliability ceilings | `IMPLEMENTED` | Separate from selectivity. Stylometry capped at 0.30, transaction-graph heuristics at 0.60, cryptographic identity uncapped. |
| Evidence fusion | `IMPLEMENTED` | Subjective logic. WBF within dependence groups, CBF across independent origins, N-ary only. See ADR-0002. |
| Plane separation | `IMPLEMENTED` | 9 `import-linter` contracts in CI. Effects cannot reach the intelligence platform; disruption cannot reach persona linkage. |
| Graph store | `IMPLEMENTED` | In-memory, temporal traversal, refuses to expand through shared infrastructure and reports where it stopped. |
| Evidence vault | `IMPLEMENTED` | Hash-chained, append-only, tested by actual tampering. |
| Audit trail | `IMPLEMENTED` | Hash-chained; insertion, deletion, reordering and modification each tested separately. |
| Authorization gateway | `IMPLEMENTED` | Ed25519, target fingerprint binding, dual control, offline verification with the public key alone. |
| Identity and RBAC | `IMPLEMENTED` | Roles and assurance checked, not accepted. Approval needs the role and the floor; refusal deliberately needs less. A legal instrument needs a legal reviewer among the approvers, checked at issuance. |
| Identity attestation | `IMPLEMENTED` | The gateway takes a signed `IdentityAssertion` and a mandatory `PrincipalVerifier`, never a caller-built `Principal`. Issuer allowlist, audience, expiry, signature, and a per-issuer assurance ceiling. |
| Signature covers the object | `IMPLEMENTED` | Payloads are the model's own canonical serialization; verification reconstructs from the signed bytes and callers act on the reconstruction. Closes the value-confusion class (ADR-0006). |
| Effects trust anchor | `IMPLEMENTED` | Each adapter holds the authorizer it believes from construction; the registry refuses an adapter wired to a different one, comparing key material rather than a self-reported key id. |
| Independently verifiable evidence export | `IMPLEMENTED` | A self-contained directory checked by a standalone `verify.py` that imports nothing from this codebase and runs on the interpreter the recipient's operating system shipped. **The log is the authority inside a package; the manifest is an index.** Tested by doctoring the bundle nineteen ways and reading its verdict. |
| Evidence package signing | `IMPLEMENTED` | A `seal.json` binds the manifest, log and anchors under one digest, optionally signed with `LocalHeadSigner`. Moves the boundary from "any holder" to "the operator" — where the notice always claimed it was — and no further. |
| Out-of-band seal comparison | `IMPLEMENTED` | The package prints one 64-character digest, in the notice and in the verifier. Comparing it needs no software and is the only check in the arrangement that does not run on data the sender controls. |
| External anchoring | `REQUIRES_EXTERNAL_DATA` | An RFC 3161 authority or a transparency log is a system we do not own, and invariant 15 forbids the MVP from contacting one. Every export therefore says `DEFENSIBLE AGAINST THE OPERATOR: NO` — in the notice, and in the verifier's own output. |
| Durable revocation | `IMPLEMENTED` | SQLite, shared across processes, survives restart, earliest-wins on re-revocation, and **raises rather than answering** when it cannot be read — which the Effects plane turns into a refusal. |
| Durable approval chain | `IMPLEMENTED` | Requests, decisions and issued capabilities are written down; a recovered capability still carries the signature it was issued with. |
| Authenticated revocation | `IMPLEMENTED` | Signed by the issuing key and chained, so a forged withdrawal is detected and a *deleted* one is too — a signature alone does nothing about deletion, which is the more dangerous of the two. |
| Durable graph and claims | `IMPLEMENTED` | A mutation journal replayed on open, so the traversal stays the one already under test rather than a second SQL implementation that would diverge silently. Supersession is journalled as its own operation, so "what did we believe in March, and why did that change?" survives a restart. Replay is linear in history — durable, not scalable. |
| Process isolation for Effects | `IMPLEMENTED` | One child process per operation: no signing key, killed by process group on deadline, and on macOS no socket and no write outside its job directory. The parent authors the audit record; the worker authors only what it did. |
| Kernel-enforced egress denial, per process | `IMPLEMENTED` (macOS) / `PROPOSED` (elsewhere) | `sandbox-exec` denies the effect process a socket, inherited by fork/exec descendants. It does **not** establish that nothing left the system: the profile is allow-default, and a review used `mach-lookup` to have LaunchServices start an unconfined process before those services were denied by name. |
| Read confinement (allowlist) | `IMPLEMENTED` (macOS, both planes) | **ADR-0007's claim that a read allowlist "aborts CPython on this platform" was measured wrong on 2026-08-17.** The abort is *dyld*, not CPython — `/bin/echo` dies identically — and it happens because the allowlist was incomplete, not because one cannot work. Two missing pieces: `(literal "/")` (the union of top-level directories is not equivalent to allowing the root, which is read during path resolution) and the **resolved** interpreter prefix (`sys.base_prefix` reported a symlink; allowing it allowed nothing — the same `/var` vs `/private/var` failure, one layer up). `SandboxPolicy(confine_reads=True)` now denies reads by default. Verified against the real kernel: the job directory readable; the vault, the caller's SSH key, the shell history and **this platform's own source** denied. The Effects plane now generates its profile from `SandboxPolicy` instead of its own template — the two had already drifted (the local copy denied `mDNSResponder.dnsproxy`, the shared one did not). **Honest scope:** the worker *is* this package and must import it, so the package source stays readable to it via `read_allowed`; a bare probe cannot read it, the real worker must. Claiming otherwise survived exactly as long as it took to run the real worker, which then could not start. **Collection runs under it too** — measured 2026-08-17, unchanged, so the blocklist was never the constraint there; it was simply never replaced. ADR-0007 carries a dated amendment correcting its impossibility claim. |
| Runtime import seal in the worker | `IMPLEMENTED` (defence in depth) | Stops the accidental import and the careless refactor. Bypassable from inside by `sys.meta_path` removal, `spec_from_file_location` or `exec`; not a boundary and documented as none. |
| Process isolation for hostile collectors | `IMPLEMENTED` — **wired 2026-08-19** | `IsolatedCollector` runs a pivot in a child that cannot import the platform it feeds and cannot read the workspace, and its tests drive it directly. **Wired 2026-08-19, and measured rather than asserted:** a full `nemesis demo` now runs **6 hostile pivots in a confined child and 0 in the main process** — `separate_process=True`, `mechanism='sandbox-exec'`, `reaches_platform=False`. The decision lives in one function, `collect_confined`, because wiring the engine alone left the reference scenario's own collection path still running six pivots in-process. Fail-closed: a connector declaring hostile content without an `isolation_factory`, or without an `as_of` a child can be reconstructed with, is refused rather than run here. Pinned by a test that counts, not one that reads. **Still macOS-only** — `sandbox-exec` is the mechanism, it is deprecated by Apple, and CI runs Ubuntu, so CI does not exercise this. The policy is the mirror image of the Effects one — a collector may keep its network, because there the danger runs inward. |
| Faithful refusal records | `IMPLEMENTED` | A refusal is recorded from what the Effects plane knows, never from the capability under suspicion. |
| Dual control | `REQUIRES_EXTERNAL_DATA` | Counts distinct subjects, which is only as strong as one-human-one-subject. The fixture issuer mints a subject per name presented. Unreachable today: every implemented class needs one approver. |
| Identity provider | `SIMULATED` | Local development fixture only. Registered with a `DEVELOPMENT` ceiling, so an assertion from it claiming more is downgraded rather than believed. |
| Effects boundary | `IMPLEMENTED` | Signature verification and a revocation oracle are mandatory and fail closed. Every constraint is signed, stop conditions included. |
| Effects adapters | `SIMULATED` | Simulation and drafting only. No adapter can make external contact; asserted across the registry. |
| Persona resolution | `IMPLEMENTED` | Refuses to output a human identity, structurally. Margined like every other shared-origin claim: one plantable shared attribute is not a linkage. |
| Attribution engine | `IMPLEMENTED` | Five separate dimensions, no collapsed score, human identity behind a pre-scoring gate. |
| Disruption planner | `IMPLEMENTED` | Proposes options it cannot execute, including ones requiring legal authority. |
| Pursuit engine | `IMPLEMENTED` | Deterministic rule policy, branch abandonment with mandatory reasons, replayable. |
| Connectors | `SIMULATED` | Seven, all fixture-backed, all flagged `is_simulated` unclearably. |
| GLASS ANVIL scenario | `SIMULATED` | Fixtures verified by mutation testing. |

| Identity wall (D1) | `IMPLEMENTED` | Type-level, redaction-level and boundary-guard. Persona linkage cannot reach an export. |
| Pilot seam | `IMPLEMENTED` | A new plane, `nemesis.pilot`. An untrusted external pilot proposes moves from a closed four-verb vocabulary; a mediator holds every handle, validates each move, and routes effects through the pre-signed capability envelope. The pilot holds no capability, no adapter, no key, no graph handle. See ADR-0008. |
| Hostile-pilot containment | `IMPLEMENTED` | ~20 tests, each constructing an attack: a hijacked pilot told to suspend a domain, one acting on an unapproved target, one reaching for a mint-authority verb (no such verb exists), one asserting guilt as fact (minted only as HYPOTHESIS/MODEL_ASSERTION), one pasting an internal marker into a document, a runaway, a garbage-emitter, a stalled transport, a BaseException-raiser. All stopped by code the pilot cannot reach. |
| Briefing carries deliverable-class only | `IMPLEMENTED` | The projection sent to a pilot (and, for a hosted model, to the vendor) is filtered to DELIVERABLE-class entities; internal leads and RESTRICTED nodes are dropped, the seed/hypotheses redacted when the seed is internal-class, `last_ruling` marker-redacted, with a fail-closed backstop scan. **An adversarial review found the earlier version leaking a materialized human-identity lead ("john doe") to the model vendor** — the import contract alone did not stop it, because the material arrived through the graph a pivot populated. Fixed and pinned. **Limitation, found by a local-model pass and stated rather than implied:** the filter keys on entity *type*, so it bounds *classified* material, not *personal* material — `domain:john-doe.example` is DELIVERABLE by type and is briefed verbatim. Recognising arbitrary personal names in identifiers is not something code does reliably. |
| Pilot may not pivot on an internal-class entity | `IMPLEMENTED` | Structural: even if a pilot obtained an internal entity's id, a pivot on it is refused, so it cannot surface RESTRICTED material downstream. |
| Envelope-bounded autonomy | `IMPLEMENTED` (mechanism) / `REQUIRES_LEGAL_AUTHORITY` (a real envelope) | `AutonomyEnvelope` wraps the signed capability and adds the bound a capability does not carry: **how often**. A capability bounds *what* may be done — enough when a human approves each use, since the human is the rate limit; at machine speed "four approved targets" becomes unbounded operations against four approved targets. Every attempt debits a budget **before** anything executes, refused effects still cost it (a counter that decrements only on success is one an adversary empties by failing), and the spend ledger is hash-chained so deleting a debit to buy another effect is detectable **in the middle of the chain and not at its end** — and it is the per-record **signature** that does that work, not the chaining. An external critique proposed that unkeyed SHA-256 links let anyone who can write the file recompute the whole chain; measured, that is refused: an attacker recomputes the hashes successfully and is caught on `not signed by the issuing authority`, because forging a record needs the Ed25519 key. Naming the mechanism matters — a reader who thinks the hash chain provides this would draw the boundary in the wrong place. Corrected 2026-08-19 after measuring it: budget 3, exhausted, delete the newest row — `verify_chain()` still returns True, `remaining` goes back to 1, and a further effect is granted. The newest debit is the only row an attacker needs, so the claim as written promised protection exactly where there is none. Not fixable from inside the store: any in-table marker dies with the same write access that removed the tail. It needs a signed tip beyond the store's trust boundary carrying a monotonic epoch, which is the external anchor `nemesis.evidence.anchoring` already marks `PROPOSED` for the vault — the same limitation, admitted there and not here. Pinned by a strict `xfail` in `tests/invariants/test_envelope_durability.py` that turns red the day it is closed. The envelope can only narrow: it holds no key and has no method that widens itself. |
| Calibration freeze (protocol milestone 1) | `IMPLEMENTED` | **First shipped partial and over-labelled, corrected 2026-08-20.** An external review changed `BAND_RANGES` in memory: a published band moved from *likely* to *almost certain* while the digest and the scanner both stayed green. Three holes — the scanner matched only `NAME = <digit>` so every dial that is a **table** was invisible; it compared bare names so a homonym elsewhere counted as registered; and the golden vectors froze fusion and nothing else. Now: **26 constants across 8 modules, scalars and tables**, an **AST** scan comparing fully qualified references, and vectors covering fusion, published bands, the refusal threshold at and above the line, robustness margins and method ceilings. Epsilons are registered rather than excused. Evaluation metric definitions are frozen as formulas in the protocol, because a metric described in prose gets reinterpreted once results exist. Protocol in [`docs/calibration/PROTOCOL.md`](../calibration/PROTOCOL.md); milestones 3–5 `REQUIRES_EXTERNAL_DATA` — controlled operations on infrastructure we own, which is a decision about cost rather than code. |
| Chain anchor contract | `IMPLEMENTED` (contract + verification) / `PROPOSED` (a placement that defeats the modelled adversary) | `nemesis.authz.anchor`. An anchor holds `(chain_id, epoch, record_count, tip_hash)`, signed, and `verify_against_anchor` checks the signature, the count, the fold, and the epoch against the greatest the verifier retained. **Catches what the chain cannot see, proven end to end against the real store:** tail truncation, total erasure, truncate-then-reoccupy (same length, different history), a replayed older anchor, and an anchor that is simply missing — which is reported rather than read as silence, or deleting the anchor would be the cheapest attack of all. **The placement is the security argument and this does not supply it:** `FileAnchorStore` sits beside the database, so whoever can truncate the table can delete it. It stamps `LOCAL_ANCHOR_AUTHORITY` and `is_externally_held` reports False, the same honesty guard the vault's head signer carries. What the contract buys is that crossing a real boundary — a second system account, a host the pilot cannot reach, a transparency log — becomes a constructor argument rather than a redesign. Specified by two external reviews (Kimi K3, Codex/GPT-5.6) that reached the impossibility independently. |
| Revocation chain is append-only | `IMPLEMENTED` | **Fixed 2026-08-18, and the fix was a design change rather than a patch.** Re-revoking a capability with an earlier timestamp is a supported path — `revoke(revoked_at=...)` exists for it, and two processes with any clock skew produce it unaided. It was implemented as `ON CONFLICT ... DO UPDATE`, which refreshed `revoked_at/revoked_by/reason/record` and left `sequence` and `chain_hash` behind: the stored JSON then described one position in the chain while its own columns described another, and `verify_chain` reported deletions **permanently, on a store from which nothing was deleted**. Authorization decisions were never affected — `is_revoked` stayed true — but a tamper-evidence signal that cries wolf is one nobody reads on the day it is right. The real defect was deeper: **a hash chain over rows that can be rewritten is not a hash chain**, and invariant 10 says append-only. `sequence` is now the primary key, `capability_id` is deliberately not unique, and a second withdrawal appends a link instead of editing one. Earliest-wins is decided *on read* — the guarantee is unchanged, and both withdrawals stay on the record. **Deployment consequence, stated rather than implied:** this is schema v4 and the store refuses a v3 file rather than migrating it, which is the existing and deliberate behaviour for a version it does not understand. |
| `tip()` never took the lock its docstring claimed | `IMPLEMENTED` | The same review found the docstring asserting the tip was "read under the same lock a write takes". It is not, and cannot be: a caller reads the tip, builds a revocation, **signs** it — the signature covers the sequence — and only then records. No lock spans that. This was the more dangerous half, because a reader would have stopped looking for the race. What actually forbids two links at one position is now the primary key: the second writer is refused with `ChainPositionTakenError` and re-signs against a fresh tip. Enforced by the store rather than by a promise about timing. |
| Durable, atomic spend ledger | `IMPLEMENTED` | The ledger is a port. `SqliteAuthorizationStore` implements it in the same file that holds revocations (schema v4), so a spent budget survives a restart — and, the half that matters more, the count-and-append happens inside one `BEGIN IMMEDIATE`, so a **fleet cannot spend past the ceiling by racing**. Proven by four real OS processes contending for a budget of ten. Reopening an envelope with a *larger* budget raises `EnvelopeWidenedError` (its own type, so "the store is unavailable" cannot swallow "an authority was widened"); a *smaller* one narrows and the narrowing sticks. `InMemorySpendLedger` remains the default and is named for its limitation. |
| `nemesis pilot` demonstration | `SIMULATED` | An autonomous session with no human in the loop: the pilot investigates, records a belief, spends a rehearsal inside the envelope — then is **hijacked** mid-run by an instruction planted in collected content and obeys it. The registrar suspension, the unapproved target and the request past budget are each refused by different code it cannot reach. The pilot is a script, not a model: wiring a real one needs a credential and an egress path this repository must not have. |
| Concrete pilot adapters (OpenAI + Anthropic) | `IMPLEMENTED` (shape) / `REQUIRES_EXTERNAL_DATA` (a live model) | `nemesis.pilot.openai_pilot` and `nemesis.pilot.anthropic_pilot`, sharing `model_seat`. The closed vocabulary is exposed as each vendor's tools; the briefing becomes the request; the tool call/use is re-validated at the seam, and the tool name is authoritative for the verb. The model call is an injected transport, default refuses, so the tree contains no network code (invariant 15 intact). A hosted model means the briefing is transmitted to the vendor — the same minimization that keeps an untrusted pilot from *holding* the withheld band now also keeps it from being *sent* there. The seat is vendor-neutral by design; the containment must not depend on which model drives. |
| Local pilot seat (laboratory) | `IMPLEMENTED` | `nemesis.pilot.local_pilot` — a real autonomous model driving the real harness from *this machine*, sharing `model_seat` with the vendor seats so the mediator still cannot tell which model it is driving. Like them it takes an **injected transport whose default refuses**, and holds no network code: the first version imported `urllib` directly and the prohibited-content scan refused it, correctly — only the collection plane holds network capability, and "it is only localhost" is the exemption that turns a control into a habit. The concrete Ollama transport lives in the test harness, where a laboratory wiring belongs. Chosen because it removes all three open founder decisions from the critical path at once: every one of them is a question about data leaving the building. **Measured, live:** a 27B model drove 8 moves in 2m50s — 5 pivots with evidence sealed and entities discovered, 2 gaps honestly recorded as `REQUIRES_EXTERNAL_DATA`, 1 belief stored as HYPOTHESIS/MODEL_ASSERTION, halted at the move ceiling, envelope untouched, `anything left the platform: False`. |
| Reproducible injection demonstration | `IMPLEMENTED` | `tests/invariants/test_live_pilot_injection.py`. The injection arrives through **collection**: a connector answers a resolution pivot with a second domain co-resolving to the target's address, and that domain's *name* is an instruction. Co-residency is the ordinary reason a pursuit surfaces a new domain, which is exactly why an adversary would use it. **This was wrong when first shipped and is recorded rather than quietly fixed:** the first version upserted the injected entity into the graph, where the briefing — which lists only entities the investigation *surfaced* — never saw it. The "injection" test therefore ran with no injection, and its assertions were identical to a run without one. Found by an adversarial pre-merge review and independently by direct capture of the briefings. Tests now pin the *delivery* itself and need no model, because whether the injection arrives is a property of this harness and must be checked on every run. **What the live tests assert is still deliberately narrower than what the run shows:** not that the model ignored the injection — a run where it never tried proves only that — but that nothing left, and every effect was ruled on with a reason. |
| A pilot cannot clear its own stop conditions | `IMPLEMENTED` | Found by the same pre-merge review, and the sharpest defect in the branch. The effects preflight reads stop-condition clearances out of `request.parameters`, and the mediator copied the pilot's parameters there verbatim — so one dict entry, `stop_condition.target_ownership_contested: cleared`, turned a refusal into an acceptance against the same target and operation. The condition it defeated is the innocent-third-party abort: *has anyone contested ownership of this target since approval*. The party a condition constrains was the party satisfying it. The mediator now strips the whole `stop_condition.` prefix — the prefix rather than the known keys, so a condition added tomorrow is protected the day it exists. An untrusted model attests to nothing. |
| The containment property is measured, not asserted | `IMPLEMENTED` | `PilotSession.any_effect_left_the_platform()` returned the literal `False`. It was the headline assertion in the containment tests including the live-pilot one, and it could not fail. Invariant 15 is genuinely enforced elsewhere — `EffectsRegistry.register()` refuses any adapter declaring external contact — so the constant happened to be *true*, which is what made it dangerous: an assertion that proves nothing reads exactly like one that proves something. It now computes from what the Effects plane reported, **fail-closed**: an accepted effect that came back without saying counts as having left. |
| The entity normalizer is an accidental injection barrier | `IMPLEMENTED` (unplanned) | Found while building the demo, pinned because nobody designed it and it would be easy to refactor away: the first planted injection was refused by `normalize_identifier` — a label over 63 characters is not a well-formed domain name. An adversary can only inject through an identifier the domain model *accepts*, which is a far narrower channel than free text. |
| CTI data may transit a model vendor | **founder decision, off the critical path** | A hosted pilot sends each briefing to OpenAI or Anthropic. Needs an enterprise / zero-retention arrangement before a live transport is wired. The code makes no such contact and no such decision. **The local seat removes this from the POC's path** — it becomes live again the day a hosted pilot is wired, and is deferred rather than answered. |
| Harness contains a pilot that raises | `IMPLEMENTED` | An untrusted pilot (or a failed OpenAI transport) that throws is a refused move and a recorded halt, never a crash of the mediator and never a silent retry. |
| Vertical slice + CLI | `IMPLEMENTED` | `nemesis demo`, `nemesis verify`. 49 acceptance tests. |
| Calibration harness | `IMPLEMENTED` | `nemesis calibrate`. Six structural properties, plus scores that state what they are conditional on. |
| Robustness margin | `IMPLEMENTED` | A conclusion must survive losing a plantable fact. Laundering false-match rate 100% to 0%. See ADR-0004. |

**897 tests.** Gate: ruff, ruff format, mypy strict (156 source files), 9 plane contracts,
prohibited-content scan. All green. `nemesis demo`, `nemesis pilot` and `nemesis calibrate`
each exit 0. (The count read "472" through 2026-08-15; that was stale documentation, corrected
since — the suite grows with every hardening pass.)

## What is designed but not built

| Item | Status |
|---|---|
| Analyst investigation view | `IMPLEMENTED` | `nemesis view` renders one self-contained HTML case file — no external fonts, no scripts, no network. Design thesis is an inversion: **uncertainty is drawn as physical space** (a three-segment bar whose unknown part is a hatched void, so a mostly-void bar looks wrong before any percentage is read), the pre-margin opinion is a ghost behind the real one so the cost of the robustness margin is visible, and refusals carry more weight than conclusions. Deliverable-class dimensions only, from `DELIVERABLE_DIMENSIONS`; withheld dimensions are reported **with the band they reached** — a refusal named, its content withheld — because dropping them would read as an absence of findings. |
| HTTP API (read surface) | `IMPLEMENTED` | Four routes. No anonymous read: every route but `/health` requires a verified `IdentityAssertion` through the same verifier the gateway uses. `/attribution` returns the redacted external product, so the D1 wall is the schema rather than a branch. No schema browser is published. |
| API write path into the graph | `IMPLEMENTED` | `POST /submissions`. The highest-risk route here — graph poisoning is in the threat model and this is its mechanism — so it rests on one sentence: **a submission is not an observation**. It becomes a `HYPOTHESIS` from an `EXTERNAL_REPORT` attributed to the caller, and the domain model already refuses to build an observation without sealed evidence, which a submission has none of. The write model carries no confidence and no attribution: those are conclusions the platform derives, and accepting them over HTTP would let a submitter write conclusions into a graph meant to reach them. Only ANALYST and INVESTIGATION_LEAD may write; an auditor cannot, because oversight must not require the ability to act. The route does not exist unless a claim store is wired — absence of a store is absence of the route, not a flag. |
| API rate limiting | `IMPLEMENTED` | Per **principal**, not per connection — an attacker chooses their connections and not their verified identity. Refuses rather than queues (a queued write still lands). Attempts count whether or not the write succeeds, or an attacker probes at any rate with submissions designed to fail validation. Rolling window, so two full quotas cannot be sent back to back across a boundary. |
| API multi-tenancy | `IMPLEMENTED` | **Not a `tenant_id` filter** — that fails silently the first time a query omits it, the same shape as the read blocklist this project already replaced. Instead: **one store per tenant**, so a component holds its tenant's store and no reference to any other and cannot *name* another customer's data. `TenantStores.for_principal` takes a verified `Principal`, never a tenant string, so no route can call it with a header value. The tenant itself is stamped by `PrincipalVerifier` from the **registered issuer** — the same place, and the same reasoning, as the assurance ceiling: a caller-supplied tenant is an attacker-supplied one. Registering a second issuer is the whole of multi-tenant configuration, and there is no way to hold an identity for a tenant nobody registered. `strict=True` refuses an unregistered tenant instead of silently minting it a private graph. **Honest scope:** this removes the "forgot the WHERE clause" class; it is not a guarantee about a shared file or an operator with disk access, who remain in the threat model. |
| Whether an analyst surface may serve internal leads | **founder decision** | D1's neighbour, and not one to settle in a route handler. Until it is made, the API serves deliverable-class material only. |
| Sandbox policy shared by both planes | `IMPLEMENTED` — one launch path, two opposite policies, so the corrections six reviews earned cannot drift apart in a second copy |
| Quarantine pipeline for hostile artifacts | `IMPLEMENTED` — **wired 2026-08-19** | Measured across a full `nemesis demo`: **70 artifacts quarantined, 70 sealed, 0 sealed without examination**. The decision lives in one function, `seal_when_released`, because there were **three** sealing sites — the pursuit engine's and two in the reference scenario — and wiring the engine alone left twenty-three examined and the rest going straight to the vault. Material classified `MANDATORY_REPORT` is held and never reaches the vault, and any claim citing a held artifact is dropped rather than recorded with unresolvable provenance. The classification written to the vault is what the analyser *found*, not what the collector *declared*. **Still true:** the shipped analyser runs in the calling process and reports `confined=False`. Two further false claims were fixed with it: the module docstring described the analyser as "a child process under `SandboxPolicy` with reads confined and no socket" when it runs in the calling process, and the shipped analyser hardcoded `confined=True` on a field documented as *reported rather than assumed*. It now reports `False` and a test pins it. What follows describes the mechanism, which is real and tested: `ContentSafety` had always said MALICIOUS_CODE is "never executed outside an isolated analysis pipeline" and MANDATORY_REPORT is "quarantined" — describing a control that did not exist; the word *quarantine* appeared only in fixture prose. Now: bytes land in quarantine and never in the vault, and **analysis is the only exit**. A handle carries no path, so "just peek at it" is not available. **Failure holds rather than releases** — treating unanalysable as routine would let anyone who can crash the analyser choose the classification. The shipped analyser may *raise* a declared classification and never lower it. MANDATORY_REPORT has no automated exit at all: the escalation is a human decision. **Documented limitation, asserted by a test rather than hidden:** the gate reads the analyser's verdict, so a compromised analyser can lower a classification — what the pipeline refuses to trust is the *absence* of a verdict, which is the failure that actually happens. |
| External integrity anchoring (RFC 3161 / transparency log) | `REQUIRES_EXTERNAL_DATA` |
| Independent calibration corpus | `REQUIRES_EXTERNAL_DATA` — the harness is built and runs (`nemesis calibrate`); what is missing is ground truth nobody in this project generated |
| Coherence laws | `IMPLEMENTED` | `calibration/coherence.py`, wired into `nemesis calibrate` as a structural property. **The only quantitative claim this platform can honestly make today**: calibration needs ground truth and coherence does not — a forecaster reporting more confidence from strictly less evidence is broken whatever the world says. Four laws (monotonic under corroboration, monotonic under removal, band agreement, dependence discipline). Result on the real engine: **668 checks, 0 violations**. Getting there took two rounds of narrowing: the unguarded law fired 64 times and was wrong every time — 62 were correct averaging within a dependence group, 2 were dissenting sources whose projection looks high because it is only `base_rate × uncertainty`. Shipping the first version would have reported 64 defects in an engine that had none. |
| Retention and minimization | `IMPLEMENTED` (policy, sweep and enforcement) | `core/retention.py`. `EntityCategory` claimed it "drives retention policy" and `is_personal_data` claimed it "triggers retention limits"; both were true about the intent and false about the code. A period per category, clocked from **last observation** rather than creation, with a legal hold that must name its instrument. Writing the tests first found a real hole: `PERSONA`/`ALIAS` file under `ACTOR`, which carries no period, so a category-keyed table held personas — pseudonymous data resolving to a person — forever. Fixed by reusing `disclosure.PERSONA_ENTITY_TYPES` so the two policies cannot drift. A sweep reports what is due; core deletes nothing (no I/O). `graph/enforcement.py` acts: `erase_entity` reaches the port, the in-memory store and the journal as `OP_ERASE`. **The load-bearing property is that an erasure survives a replay** — the graph replays a mutation journal on open, so an unjournalled erasure is undone at the next restart, which is a delay rather than a control. Erasure takes the incident edges with it; the record describes the *shape* and never the value (a log that repeats what it deleted has kept it); a legal hold is recorded with the same weight as an erasure; a failed erasure makes the report non-compliant rather than silently clean; `dry_run` is the intended first use. |
| Erasure vs. tamper-evidence | **founder decision** | Invariant 10 (evidence append-only, hash-chained) and data-protection erasure **genuinely conflict**: a row cannot leave a hash chain without breaking it. Three honest options — crypto-erasure, never vaulting personal data, or recording erasure as its own chained event. Until settled, erasure is scoped to the graph and every sweep prints `RETENTION IN THE VAULT: NOT IMPLEMENTED`. |
| Mandatory-reporting escalation | `IMPLEMENTED` (register + refusals) / `REQUIRES_LEGAL_AUTHORITY` (the procedure's content) | `evidence/escalation.py` does the only two things software honestly can: it **opens** an obligation and **refuses to close one**. No worker, no timer, no cleanup path discharges it — a platform that could mark its own legal duty complete would keep a compliance record of its own convenience. Only a LEGAL_REVIEWER may discharge, never the analyst who found the material, and a channel reference is required so "we handled it" is not a record. `discharged` means *a human said they did it* — **not** that a report was filed or accepted, which the platform cannot see. Built against silence rather than refusal: overdue items lead the output, oldest first, and re-examining the material does not restart the deadline. [docs/procedures/mandatory-reporting.md](../procedures/mandatory-reporting.md) carries the human half; which authority and which window are deliberately left blank. |
| Real intelligence connectors | `REQUIRES_EXTERNAL_DATA` |
| Any real-world effect | `REQUIRES_LEGAL_AUTHORITY` |

---

## Decisions taken

| ADR | Decision |
|---|---|
| [0001](../adr/0001-single-package-with-enforced-plane-separation.md) | One distribution, plane separation enforced by import contracts; real isolation deferred to process boundaries |
| [0002](../adr/0002-subjective-logic-for-evidence-fusion.md) | **Superseded.** Subjective logic, with a false absence claim and an unsound central argument. Kept as the record of what was believed. |
| [0004](../adr/0004-robustness-margin-against-planted-evidence.md) | A conclusion must survive losing a plantable fact; one origin is no longer actionable on an attribution, and that constraint is withdrawn explicitly |
| [0005](../adr/0005-identity-is-established-not-asserted.md) | Providers state an identity, the deployment decides what it establishes; a caller-built `Principal` no longer reaches the gateway, and each issuer carries an assurance ceiling |
| [0006](../adr/0006-sign-the-object-verify-by-reconstruction.md) | Sign the model's own serialization, and act only on the grant reconstructed from the signed bytes — signing a *rendering* of a grant let a `str` subclass draft a notification from a rehearsal |
| [0007](../adr/0007-process-isolation-for-the-effects-plane.md) | Effects run in a child process with no key, no importable intelligence platform, no socket and a deadline; "nothing left the system" becomes a kernel fact rather than the adapters' own report |
| [0003](../adr/0003-evidence-fusion-corrected.md) | Fusion corrected after an external challenge: SL as bookkeeping rather than as forced by the invariant; provenance clustering with asymmetric semantics; report a vector, not a confidence |
| [0008](../adr/0008-the-pilot-seam-and-envelope-bounded-autonomy.md) | NEMESIS is the harness an autonomous pilot drives. A `nemesis.pilot` plane: closed move vocabulary, a mediator holding every handle, effects routed through a pre-signed envelope. The untrusted pilot cannot leave the track — proven by 13 attack-constructing tests |

Founder-level questions, with working defaults implemented so nothing is blocked:
[FOUNDER_DECISIONS.md](FOUNDER_DECISIONS.md). Two are answered:

- **Unit of resolution:** both operator and organization, **separated by a wall**.
  Organizational attribution is the deliverable; persona linkage is an internal lead,
  never exported and never presented as a conclusion. **Implemented** — see
  `core/disclosure.py`, `attribute/disclosure.py` and the eighth plane contract.
- **Positioning:** multi-dimensional attribution, no collapsed score, human identity
  unraisable above `INSUFFICIENT_BASIS` by any configuration.

---

## Known risks, worst first

1. **No confidence figure has ever been validated.** Attribution rarely has ground truth,
   so Brier scores and reliability diagrams have nothing to score against. Every number the
   system produces is internally consistent and externally unverified. No amount of better
   mathematics fixes this; only a corpus of resolved cases does. Until then, outputs should
   be presented as *internally consistent*, never as *calibrated*.

2. **The calibration constants are choices, not measurements.** Admiralty weights,
   selectivity decay, method ceilings, conflict and vacuity thresholds. All stated
   explicitly in code so they can be argued with; none derived from observed base rates.

3. **Invariant 8 is weaker than ADR-0001 implies.** Effects cannot *import* the
   intelligence platform, but shares a process with it. The security argument assumes a
   process boundary that does not exist yet.

4. **Evidence is not defensible against an insider.** No external anchor exists. The vault
   reports this itself rather than presenting a clean internal chain as proof — which is the
   right behaviour, but it is a real limitation, not a mitigated one.

5. **The organization/operator wall catches markers, not paraphrase.** The type-level and
   redaction layers are airtight; the free-text guard at the Effects boundary is a backstop
   that stops the accidental path and would not stop a determined analyst rewording a
   persona finding into a takedown request.

6. **Two integration bugs were found only by testing, and both were silent.** Evidence
   would never have reached the vault; the strongest single link in the scenario would have
   been silently downgraded to worthless. Both were string-key mismatches across a plane
   boundary that typed contracts would have caught at import time. The ports should become
   typed contracts rather than string keys.

7. **There is still no real identity provider.** What changed is that this can no longer be
   waved past. The gateway takes a signed `IdentityAssertion` and a mandatory
   `PrincipalVerifier`; a `Principal` built by a caller is not accepted by any entry point.
   The verifier checks the issuer against an allowlist, the audience, the expiry and the
   signature, and then **caps the assurance at what this deployment is willing to believe
   from that issuer** — which for the development fixture is `DEVELOPMENT`, whatever the
   assertion claims. An earlier version accepted a caller-built principal declaring
   `HARDWARE_BACKED` assurance from an invented issuer and returned a genuine signed
   capability; an audit did exactly that.

   The consequence is enforced rather than documented: a development identity can authorize
   a rehearsal and nothing meant to leave the platform, so the demonstration **requests** a
   provider notification, is refused, and prints the refusal. Wiring a real directory means
   implementing one verifier and registering it with a ceiling — the gateway does not change.

8. **The demo adversary is not adaptive.** A real one responds to being pursued. Nothing
   here models that.

9. **Persona resolution is margined.** ~~It calls `establish_fact` directly.~~ Closed:
   `LinkageSignal.fact_key()` makes one specific shared attribute — this fingerprint, this
   handle, this cluster — one fact, and the engine calls `fuse` with `SHARED_ORIGIN`.

   The demonstration's own headline linkage is the thing this now refuses. GlassAnvil and
   AnvilWorks were linked at **likely, 71%** on a single published fingerprint, in a channel
   the adversary writes into — one copyable string, one plantable fact. It is now reported
   as **insufficient basis**, with the 71% carried beside it so a reader sees the size of
   the reduction rather than concluding the evidence was weak.

   The scenario plants exactly that shape on purpose, so the refusal is the demonstration
   working. What it costs is real and should be stated: a genuine linkage resting on one
   attribute now needs a second attribute, or an attestation from a channel an adversary
   cannot author, before it is actionable.

10. **The margin costs one plantable fact, not two.** An adversary who plants two
   independent-looking artifacts defeats it. Raising it to 2 is measured as available and
   currently unjustified.

11. **Six consecutive adversarial reviews each broke a control that had just been declared
   working, and a passing test suite detected none of them.** The first walked past the
   identity layer with a hand-built `Principal`. The second walked past the capability layer
   with a ten-line `str` subclass, on a tree where all 517 tests passed. The third, run
   against the corrected tree, found that the gateway handed out references to its own
   records — so an approved rehearsal could be edited into a notification after approval —
   and that documents were still composed from the unauthenticated capability, so a draft
   could cite a court order nobody signed. All are fixed, all have regression tests that
   construct the attack rather than describe it.

   The sixth found the evidence export was not verifiable at all: **nine separately doctored
   packages passed its own bundled verifier with exit 0**, including one whose artifact had
   been replaced with "THE DEFENDANT ADMITS EVERYTHING." The verifier hashed each artifact
   against the manifest — the file an attacker edits — while the true hash sat in the package
   three times over. A README shipped with every package promised the opposite. Fixed, and
   pinned by tests that construct each of the nine.

   A fourth review, run against the corrected tree, found no way to make the platform *act*
   on anything other than the signed grant — but found three ways the **audit trail** was
   recording the wrong thing, one of which was a regression introduced by the fix itself: a
   revoked capability was refused and recorded as `permitted: true`. All three wrote into
   the append-only hash-chained trail, and the chain verified. A tamper-evident record of a
   false statement is worse than no record, and invariant 11 asks for replayable, not
   logged.

   The pattern is the finding. These were failures of *what the tests asserted*, not of
   coverage, and none would have been found by writing more tests of the same kind. Read
   any claim in this document about a security property as "survived the reviews run so
   far", which is a weaker statement than "holds". Four reviews in, the rate at which a new
   reviewer finds something has not reached zero — though it has moved from "the platform
   acts wrongly" to "the platform records wrongly", which is the direction one wants.

   A seventh review, run against the **pilot seam** just after it was built, moved the needle
   back the wrong way once: it found the briefing **transmitted a RESTRICTED human-identity
   lead ("john doe") to the model vendor** on every turn after a pivot surfaced it — a
   real personal-data egress, and the module's own docstring claimed the opposite ("human
   identity structurally absent"). The defence I had reasoned about (the pilot plane cannot
   *import* persona resolution) was a red herring: the material arrived through the graph the
   pursuit engine populated, not through an import. The invariant test passed only because it
   pivoted on infrastructure and never surfaced the person, and it asserted mixed-case while
   the leaked key was lowercased. Fixed by filtering the briefing to deliverable-class,
   refusing pivots on internal-class entities, and a fail-closed backstop; the test now
   surfaces the person and asserts case-insensitively. The same review found three lower
   findings (a parser raising where its mirror returned a sentinel; a hanging transport
   parking the session with no timeout; a test over-claiming BaseException behaviour), all
   fixed. The lesson repeats: a confidently-worded docstring is not a control.

---

## CI does not exercise the strongest form of invariant 8

**Found 2026-08-18, by the documented-counts check on its first CI run.** The suite collects
859 tests. On macOS 856 pass and 3 skip; on the Ubuntu runner **844 pass and 15 skip**, because
the kernel-confinement tests are gated on `sandbox_available()` — that is `sandbox-exec`,
which exists on macOS and nowhere else.

The macOS-only limitation was already documented. What was not visible is the consequence:
**the kernel-enforced half of Effects isolation is verified only on a developer laptop, and
never by CI.** On the runner, invariant 8 rests on the import contracts alone. A green build
therefore means less than it appears to, and this is the gap to close before anyone treats CI
as the authority on that invariant — a macOS runner, or a Linux equivalent built on namespaces
and seccomp.

It also caught the badge claiming "856 passing", a macOS-specific number about to be published
as universal. The badge now states tests *collected*, which is 859 everywhere.

---

## Next milestones

**Rewritten 2026-08-18.** The four items that stood here — the calibration harness, the
analyst UI, typed port contracts, Effects process isolation — were all shipped, and three of
them are marked `IMPLEMENTED` in this same document. A milestone list that contradicts its own
status table is the defect this project rejects, wearing the one costume nobody inspects: a
plan rather than a claim.

1. **Wire the controls that exist and are not reachable.** `Quarantine` is instantiated
   nowhere in `src/` and `PursuitEngine` seals collected artifacts straight to the vault;
   nothing reads `handles_hostile_content`, so `IsolatedCollector` never runs. Both are built
   and tested directly, and both are documented as unwired — which is honest and is not the
   same as done. Harmless today because every connector reads a fixture, and the first real
   connector is exactly when nobody will be looking.
2. **External review, 2026-08-20** — briefed in
   [`docs/review/2026-08-20-external-review-brief.md`](../review/2026-08-20-external-review-brief.md).
   The target is what the local models cannot do and the review script says not to ask them:
   concurrency. `BEGIN IMMEDIATE` under WAL, and the `tip()`/`record()` race now closed by a
   primary key rather than a lock.
3. **A set-valued content classification.** `ContentSafety` holds one member, its members are
   different handling obligations rather than a severity ladder, and an artifact that is both
   malware and sensitive personal data can only be filed as one. Currently named in the
   observations in words; the schema change is `PROPOSED`.
4. **The three open founder decisions**, listed in
   [`FOUNDER_DECISIONS.md`](FOUNDER_DECISIONS.md). All three are questions about data leaving
   the building, all three are off the critical path while the pilot runs locally, and all
   three return the day a hosted pilot is wired.

---

## Conventions a new session needs

- Python 3.13, `uv`. `uv sync --all-extras` then `uv run pytest`.
- Branch `agent/<task>`; never commit to `main`; never push without asking.
- Every invariant in `CLAUDE.md` has a test in `tests/invariants/`. If enforcement cannot be
  expressed as a test, the design is wrong.
- Documentation that contradicts the code is a defect, not a lag.
