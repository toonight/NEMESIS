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

Classes A and B are the routine case. C and D are the ones the architecture must survive
without depending on anyone behaving well.

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
| A hijacked pilot requests an out-of-envelope effect ("suspend this domain now") | The mediator routes every effect through `registry.execute(request, envelope)`; the pre-signed capability refuses anything it does not authorize. Proven by a test where the pilot does not resist injection — it tries — and nothing leaves. |
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
| Process isolation for dark-web collectors | `IMPLEMENTED` on macOS / `PROPOSED` elsewhere | **Wired 2026-08-19 and measured:** a full reference run puts **6 hostile pivots in a confined child and 0 in the main process** — `separate_process=True`, `mechanism='sandbox-exec'`, `reaches_platform=False`. A connector declaring hostile content without an isolation factory is refused rather than run here. The mechanism is macOS-only and deprecated by Apple, and CI runs Ubuntu, so CI does not exercise it. |
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

## Review triggers

Revisit this document when any of these happens, not on a calendar:

- The first connector talks to something real.
- The first effects adapter can make external contact.
- The first non-synthetic personal data enters the graph.
- NEMESIS is deployed anywhere more than one person can reach.
- Any invariant in CLAUDE.md is proposed for change.
