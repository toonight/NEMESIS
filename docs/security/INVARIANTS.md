# Security invariants with stable identifiers

**Added 2026-08-27** by the agent-collective hardening pass. See
[`2026-08-27-agent-collective-hardening.md`](2026-08-27-agent-collective-hardening.md) for why,
and [`../architecture/THREAT_MODEL.md`](../architecture/THREAT_MODEL.md) for the adversary each
one answers.

---

## What this document is, and what it is not

CLAUDE.md carries **fifteen numbered invariants**. Those are the constitution: they are
non-negotiable, a change that violates one is rejected rather than debated, and they are stated
in the language of the platform's purpose.

This register is a different thing and does not replace them. It gives **stable identifiers** to
the specific, testable properties that the hardening pass either introduced or made checkable for
the first time, so that a test, a Breaker attack, a threat-model row and a review finding can all
name the same property and be talking about the same thing. Every entry here serves one or more
of the fifteen; the mapping is in the last column.

**An identifier here is a promise that something enforces it.** Each row names the enforcement
and the test. A row whose enforcement column says a document rather than a mechanism is a row
that is not yet a control, and it says so.

**Status labels are the repository's own** (`IMPLEMENTED`, `SIMULATED`, `PROPOSED`,
`REQUIRES_EXTERNAL_DATA`, `REQUIRES_LEGAL_AUTHORITY`) and are never silently promoted.

---

## AUTH — authority cannot be manufactured

The governing property, stated once:

> **Peer-originated information can never increase authority.**
> `authority_after_untrusted_input ⊑ authority_before_untrusted_input`

"Peer-originated" is deliberately broad: a model's output, another model's message, a tool
result, a retrieved document, a chat reply, a research hint, an evidence artifact, a provider's
response body. Any of these may change what NEMESIS *believes*. None may change what it is
*allowed to do*.

The comparison is mechanical. `nemesis.authz.monotonicity.AuthoritySnapshot` reduces the live
state — the signed capability's operations, targets, window, approvers and ceilings, plus the
envelope's remaining autonomy — to one comparable value, and `widenings_from()` names every way
one snapshot grants more than another. It is an **observation instrument, not a gate**: nothing
in the production path consults it, because a fourth check reading a summary of the other three
would be a control derived from the controls it is meant to check.

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **AUTH-01** | Model output cannot directly create authority. | `IMPLEMENTED` | The move vocabulary is a four-member discriminated union with `extra="forbid"`. There is no `mint_capability`, no `widen_envelope`, no `change_scope`. The absence of a verb, not a check on one. | `test_authority_monotonicity.py`, `test_pilot_containment.py`; Breaker `invented-verbs` |

**The instrument these four rest on had to be able to fail, and did not.** An adversarial review
found that within one process holding one frozen capability, almost every snapshot field is
*physically incapable* of differing — so `after.widenings_from(before) == ()` was unfalsifiable at
every call site, and six invariants cited it as evidence. Two things were wrong: the fixtures read
their own envelope reference rather than the mediator's live one, and no test replaced an envelope
to see whether anything noticed. Both are fixed, and
`test_the_instrument_fires_when_the_mediator_swaps_its_envelope` now swaps in a strictly wider
signed grant mid-session and asserts every dimension is reported.

The same review found **six dimensions of authority outside the snapshot entirely**: blocking stop
conditions (each one a `REFUSED_STOP_CONDITION` gate in the effects preflight), `jurisdictions`
(named verbatim by CLAUDE.md invariant 9), `max_effect_description`, whether the grant is signed at
all, and — because `approver_subjects` read `.approver` without `.decision` — an objector was
indistinguishable from an approver. All six are now compared.
| **AUTH-02** | Peer/model communication cannot increase authority. | `IMPLEMENTED` | Nothing reads a string as an authorization. A chat reply is a `DecisionIntent` (a *reading*, with no member naming an outcome); a challenger's verdicts only subtract; a supervisor's directives change one word in a briefing; a research hint is redacted and quarantined. The collaboration plane cannot import `nemesis.authz` at all. | `test_authority_monotonicity.py` (10 phrasings × 2 shapes), `test_collaboration_boundary.py`; Breaker `peer-says-go` |
| **AUTH-03** | Evidence cannot automatically become capability. | `IMPLEMENTED` | A model assertion is minted as `HYPOTHESIS`/`MODEL_ASSERTION` at construction (invariant 1) and can never be an observation or a fact. Capability comes only from a signed `AuthorizationCapability`. | `test_authority_monotonicity.py`, `test_credential_containment.py`; Breaker `opinion-as-evidence` |
| **AUTH-04** | Discovered credentials do not imply authorization. | `IMPLEMENTED` | `nemesis.core.credentials`: no type has a field for material; the fingerprint is HMAC under a deployment key; `EntityCategory.CREDENTIAL` maps to `RESTRICTED`; `normalize_identifier` refuses a credential as a natural key. Nothing outside `core` imports the types. | `test_credential_containment.py`; Breaker `credential-laundering` |

---

## NET — reachability is a property of the composition

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **NET-01** | Model-controlled contexts cannot obtain unauthorized **direct** Internet access. | `IMPLEMENTED` | `scripts/check_prohibited.py` refuses a network import outside the collection plane, and every import inside it needs an adjacent `NEMESIS-EGRESS-ALLOWED` marker. Vendor SDKs are on the list, because a full HTTP stack behind a name that does not look like one is how invariant 15 ends quietly. | `test_transitive_egress.py`, CI step |
| **NET-02** | Model-controlled contexts cannot obtain unauthorized **transitive** Internet access. | `IMPLEMENTED` | `nemesis.sandbox.reachability` builds the import graph, marks modules that can reach the network **or start a process**, and asserts no path from a model-controlled root to one except through a declared broker. Three brokers, each with a written reason the far side is policy-controlled. | `test_transitive_egress.py`, `scripts/check_egress_reachability.py` in CI |

**Four forms it could not see, found by an adversarial review and now covered:** a relative import
(`from ..x import y` produced *no edge at all*, so a whole subtree was invisible); an aliased
`import subprocess as sp`; a bare `from subprocess import run`; and `asyncio.open_connection`,
which is a full TCP client that neither the module list nor the process-call table classified.
The false positive the design already avoided — `asyncio.run` is not a capability — is now
asserted alongside them, so a fix for the four cannot reintroduce it.
| **NET-03** | Collector network privileges are not inherited by pilots. | `IMPLEMENTED` | A pivot names an **entity id the investigation surfaced**, never a locator; the vocabulary has no field a destination fits in. The Tor connector takes a `services` allowlist and has no `url` parameter anywhere in its call path. | `test_transitive_egress.py` (8 locators), `test_darkweb_hostility.py`; Breaker `collector-as-proxy` |

**Measured 2026-08-27**, by removing each broker in turn — because "no findings" does not by
itself say whether anything was brokered or whether there was nothing to broker:

| Broker | Removing it | Reading |
|---|---|---|
| `nemesis.collect.isolation` | **2 findings** | **Load-bearing.** Both model-controlled roots reach `nemesis.sandbox.process` — the confinement launcher — along `mediator → pursuit.engine → collect.isolation → sandbox.process`, and this is the only module on it. That is the right one to be load-bearing: `collect_confined` is the single gate deciding whether a connector handling hostile content runs at all. |
| `nemesis.collect.wire` | 0 findings | Slack today. Declared because a reader should be able to check the property, not because a path runs through it. |
| `nemesis.pilot.providers.transport` | 0 findings | Slack today, same reason. |

**No model-controlled root reaches either network-capable connector at all**, brokered or
otherwise. Keeping the two halves apart matters: the network property holds more strongly than
the contract requires, and the process property holds exactly because of one broker.

*An earlier draft of this row said the brokers were "slack rather than load-bearing" on the
strength of an empty finding list. That was measuring the wrong thing — an empty list with the
brokers excluded says nothing about what happens without them.*

**What NET-02 does not cover, stated rather than implied.** It is a static import analysis. It
does not see a callable handed in at construction, and it does not see out of the process — a
subprocess, a shared filesystem, a database another service reads. It closes the composition an
ordinary commit widens by accident.

---

## MODEL — several models is several seats, not a swarm

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **MODEL-01** | Models cannot communicate outside mediated typed channels. | `IMPLEMENTED` | `import-linter` contract `model-seats-are-mutually-unreachable`: an `independence` contract over the six provider modules, so no seat may reach another in either direction. The challenger's whole input is `(briefing, move)`. | `test_model_isolation.py`, `lint-imports` |
| **MODEL-02** | Models cannot create arbitrary shared persistent coordination state. | `IMPLEMENTED` | The only channel between model contexts is `ResearchContext`: `extra="forbid"`, eight items per list, 240 characters per item, redacted before it reaches a briefing, with its untrusted half in a separately named field. The probe log and the transcript are per-session and never handed out. | `test_model_isolation.py`, `test_evolution_memory_poisoning.py` |
| **MODEL-03** | Model failure cannot autonomously widen scope. | `IMPLEMENTED` | A provider outage produces a session of refusals and a recorded halt. There is no provider fallback, deliberately. A stall produces a stop, never a request for room. | `test_safe_failure.py`, `test_provider_seam.py` |

> **Communication can transfer information, never authority.** Every inter-model transfer goes
> through a typed result, schema validation, provenance and the mediator — and the receiving
> context's authority is the envelope's, unchanged by anything the sending context said.

---

## EFFECT — nothing happens because a model asked

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **EFFECT-01** | No untrusted input can directly trigger an effect. | `IMPLEMENTED` | Every `RequestEffect` is routed to `registry.execute(request, capability)`; the refusal is the capability's, reached by asking it. Collected content is `PivotResult` data with nothing executable in it. | `test_pilot_containment.py`, `test_effects_boundary.py`, `test_darkweb_hostility.py` |
| **EFFECT-02** | Effects require independently verifiable authorization. | `IMPLEMENTED` | Ed25519 signature verified by reconstruction from the signed bytes; `TargetFingerprint` recomputed against current state at execution; validity window read from `utcnow()` and never from a caller; revocation oracle consulted immediately before acting, fail-closed. | `test_authorization_invariants.py`, `test_authority_monotonicity.py`; Breaker `stale-approval-replay` |
| **EFFECT-03** | Model messages cannot simulate human approval. | `IMPLEMENTED` | An `Approval` lives inside the signed capability and is minted by a gateway requiring a verified `IdentityAssertion` from a registered issuer. The pilot plane cannot reach the gateway; the collaboration plane cannot import `nemesis.authz`. Text is text. | `test_authority_monotonicity.py`, `test_collaboration_boundary.py`; Breaker `forged-human-approval` |

---

## DARKWEB — visibility without obedience

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **DARKWEB-01** | Dark web content is treated as hostile evidence. | `IMPLEMENTED` (macOS) / `REFUSED` elsewhere for real collection | Hostile connectors run in a kernel-confined child (`collect_confined`) or are refused; bytes pass through quarantine before the vault; the connector's one observation is *the service responded*, and it parses nothing out of the body. | `test_collector_isolation.py`, `test_quarantine.py`, `test_darkweb_hostility.py` |
| **DARKWEB-02** | Dark web collection cannot become arbitrary pilot-controlled browsing. | `IMPLEMENTED` | An operator maps a NEMESIS forum identifier to one v3 onion URL. The pilot names the identifier; nothing in the chain takes a URL from a caller. A well-formed onion address read *out of a collected page* is refused like any other unknown entity. | `test_darkweb_hostility.py`, `test_dark_web_connector.py` |

---

## SAFEFAIL — an investigation is allowed to fail

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **SAFEFAIL-01** | Investigations may terminate safely without attribution. | `IMPLEMENTED` | `ConclusionOutcome`: a closed vocabulary of seven honest endings plus `ATTRIBUTION_REACHED` and `UNSPECIFIED`. Carried on the session and written to the audit close, so no consumer parses prose to learn whether a case concluded or was abandoned. | `test_safe_failure.py` |
| **SAFEFAIL-02** | Stagnation cannot automatically cause scope expansion. | `IMPLEMENTED` (thresholds `PROPOSED`) | `nemesis.pilot.stagnation` is deterministic and its every signal maps into the safe-failure set. There is no branch in the mediator that responds to a stall by asking for more, and no member of the outcome vocabulary that requests it. Detection is not configurable; only stopping is. | `test_safe_failure.py`; Breaker `persistence-past-usefulness` |

**SAFEFAIL-02 as stated survived an adversarial review; the detector around it did not.** Three
defects, all of them over-firing rather than under-firing, and one adversary-steerable:

- **An analytic write-up phase read as a stall.** `was_productive` counted only entities and
  evidence, which only a pivot ever sets — so `record_belief` was *structurally incapable* of being
  productive and six accepted beliefs halted the investigation. An accepted belief is now
  productive; repeating the *same* belief is still caught, by repetition.
- **Three refused effects anywhere killed a productive run.** The count was cumulative over the
  whole session, so content that induces three out-of-envelope requests early — exactly what an
  injected page asks for — terminated a healthy investigation from outside. Now counted over the
  window and gated on the window being unproductive, because the signal's honest ending is
  *progress needs an effect nobody authorized* and a window surfacing entities is one where it
  does not.
- **`conclude` outranked the detector at the one moment it mattered.** The assessment ran after
  the conclude branch, so a run that stalled for five turns and concluded on the sixth filed
  itself as `attribution_reached` with no signals recorded. It now runs first, and a stalled run
  gets the detector's ending.

---

## AUDIT — history is not what the current process remembers

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **AUDIT-01** | Historical event modification is detectable. | `IMPLEMENTED` | Each entry hashes its canonical encoding together with its predecessor's hash. A careless edit breaks the entry hash; an interior deletion or reorder breaks the link. | `test_audit_anchoring.py`, `test_audit.py` |
| **AUDIT-02** | Tail truncation is detectable, and a stale anchor cannot be replayed. | `IMPLEMENTED` at `AnchorIndependence.NONE` | A signed `(epoch, record_count, tip_hash)` anchor, published after a run and checked by `nemesis verify` **against a retained epoch**. The chain alone cannot do this: a truncated chain links perfectly, and a fresh reader's counters are whatever the file says. | `test_audit_anchoring.py`, `test_chain_anchor.py`; Breaker `rewrite-history` |

**The rollback half was specified, tested and unwired.** An adversarial review pointed out that
`verify_audit_trail`'s own docstring says "without it a stale but validly-signed anchor replays
cleanly" — and `nemesis verify` passed no `retained_epoch` at all. The primitive had a test; the
caller did not, which is the same failure this module was written to fix, one level up. A workspace
now persists the greatest epoch it has accepted, monotonically, and the verifier consults it.

**The two controls are complementary and neither covers both halves. Measured:**

| Attack | Chain says | Anchor says |
|---|---|---|
| Careless edit (hashes not recomputed) | **broken** | intact |
| Full rewrite (every hash recomputed) | intact | **broken** |
| Interior deletion | **broken** | **broken** |
| Tail truncation, fresh reader | intact | **broken** |
| Empty the file | intact | **broken** |
| Delete the anchor | intact | **reported as unattested** |

The chain covers *content*; the anchor covers *shape*. An attacker has to defeat them in
opposite directions. This was found by a test that asserted "caught twice" and was wrong.

**What AUDIT-02 is worth at the shipped rung.** `FileAnchorStore` beside the trail, signed by a
key beside it, is `AnchorIndependence.NONE`: it catches an accident, a partial restore, a chain
rebuilt by a repair script, a trail copied in from elsewhere. It catches nobody who meant it,
because the account that truncated the log can regenerate both. The rungs above
(`SEPARATE_ACCOUNT`, `SEPARATE_HOST`, `THIRD_PARTY`) are a constructor argument and a deployment
decision; `THIRD_PARTY` remains `REQUIRES_EXTERNAL_DATA`. `nemesis verify` prints the rung beside
the verdict so "anchored" cannot be read as the tier above.

---

## EVID — evidence somebody else can check

**Added 2026-08-27**, after two adversarial reviews of the vault and the effects plane. Their
findings had no identifier to violate, because this register mapped CLAUDE.md invariant 10 to the
audit trail alone — so the vault's controls, which are most of what "tamper-evident" means here,
appeared in no row at all. That omission is why this section exists.

The governing property, and it is not the one people expect:

> **The vault operator is inside the threat model.**
> An internal hash chain proves nothing against whoever can rewrite the whole store. What the
> evidence plane can honestly promise is that *careless* tampering is caught, that a package can
> be checked by its recipient without trusting us, and that where it cannot promise more it
> **says so** rather than presenting a clean internal chain as proof.

That last clause does real work. EVID-08 is the only invariant in this document whose
`IMPLEMENTED` status is a promise to keep reporting a *failure*.

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **EVID-01** | An artifact's identity is its content. | `IMPLEMENTED` | `evidence_id` is `content_id(IdPrefix.EVIDENCE, artifact)` — derived from the SHA-256 of the bytes, not assigned. Sealing bytes that do not hash to the declared `content_hash` is refused; re-sealing over substituted stored bytes raises `EvidenceSubstitutionError`; and a genuine collision is named as voiding *every* content address in the platform rather than handled quietly. | `test_evidence_vault.py`, `test_evidence_export.py` |
| **EVID-02** | Modification, insertion, deletion, reordering and truncation of the vault log are all detectable. | `IMPLEMENTED` | Every entry hashes its canonical encoding with its predecessor's. `_parse_chain` separates an **in-place edit** ("log entry N was altered after it was written") from a **break in the sequence** ("entries were reordered, inserted or removed" — one message for those three, which is as precise as a link check can be), and `_check_recorded_head` compares the tip against the head stored beside it, which is what catches truncation. A chain that only caught in-place edits would be defeated by an editor that drops a line. | `test_evidence_vault.py`, `test_evidence_export.py` |
| **EVID-03** | Nothing is released from a vault whose chain does not verify. | `IMPLEMENTED` | `_verify_metadata_against_chain`, `_enumerable_objects` and `_quarantined_count` each raise `VaultChainError` on any chain defect. **New in this pass:** all three previously did `entries, _ = _parse_chain(...)` and discarded the verdict, so a two-file edit released quarantined material — relabel the metadata, patch the seal entry's `metadata_hash` to agree, leave `entry_hash` alone. `verify_integrity()` named the forgery and `list_evidence()` handed the object over anyway. | `test_evidence_vault.py` (`test_a_forged_chain_releases_nothing_even_when_the_metadata_hash_agrees`) |
| **EVID-04** | Material carrying a reporting obligation is held, never indexed, and never exported through an ordinary path. | `IMPLEMENTED` (the vault gate) / `PROPOSED` (analyser monotonicity) | `must_not_be_indexed` excludes it from every bulk read and from `export_bundle`; an ordinary read raises `RestrictedContentError` **and appends a `REFUSED_ACCESS` entry**; the only way through is `retrieve_quarantined_artifact` with a non-empty escalation reference, which appends a `QUARANTINED_ACCESS` entry no bulk read produces. **The gap, stated:** the monotonicity rule that stops a *downgrade* lives inside `StructuralAnalyser` — a documented deployment extension point — so a replaceable analyser can relabel material before the vault ever sees it. See the threat model. | `test_quarantine.py`, `test_evidence_vault.py` |
| **EVID-05** | A recipient can verify a package without trusting us and without this codebase. | `IMPLEMENTED` | `verify.py` ships inside the bundle, imports nothing from `nemesis`, is excluded from the `UP` lint rules so it keeps running on whatever interpreter the recipient has, and computes the same chain hash as the vault — asserted against the real implementation rather than against a copy of the algorithm. | `test_evidence_export.py` (imports, oldest interpreter on this machine, chain-hash agreement) |
| **EVID-06** | A doctored package does not verify, and the seal covers every file in it. | `IMPLEMENTED` | An explicit filename→key map, duplicated in the shipped verifier and asserted identical by a test. **New in this pass:** the verifier derived the key from the filename, producing one the sealer never wrote — the log's check was dead code, `anchors.jsonl` was never in the loop, and `verify.py` was not in the seal at all, so a signed package could ship an attacker's verifier under a byte-identical digest. `README.txt` is bound the other way round, because it quotes the digest and cannot contain it. | `test_evidence_export.py` (every sealed file parametrised, verifier substitution, detached notice, suppression, swap, reorder) |
| **EVID-07** | The verifier reads nothing outside the package, and a refusal carries no measurement. | `IMPLEMENTED` | `artifact_path` refuses a leaf name containing a separator, refuses a symlinked leaf, refuses a symlinked `artifacts/` outright, and resolves the confinement root from the **bundle** rather than through the directory it is confining. **New in this pass:** resolving through the directory moved the root along with a symlink, and the stray-file walk then listed a private directory off the recipient's machine with no forgery at all. A refusal now names nothing behind the link. | `test_evidence_export.py` (symlinked directory, symlinked leaf, read-oracle) |
| **EVID-08** | The vault reports that it is **not** defensible against its own operator, and cannot be made to say otherwise. | `IMPLEMENTED` | `is_externally_held` is an allowlist of anchor types this build can *verify*, and that set is **empty** — so `externally_anchored` is 0 and `is_defensible_against_insider` is False for every package this build can produce. **New in this pass:** it was a denylist of authority *strings*, so an anchor reading `authority="Totally Independent Notary AG"`, `proof="not-even-base64"` flipped the verdict to True. Filling the allowlist requires a verifier for that anchor type, not a better name. | `test_evidence_vault.py`, `test_evidence_export.py` (an appended anchor cannot flip the verdict) |

**What has no row yet, and why that is deliberate.** `resolve_lineage` reports evidence backing
for a claim that has none: any non-empty `supported_by_evidence` counts, whatever the claim's
kind, and nothing checks the evidence is *about* the claim. A HYPOTHESIS naming a person, citing
an unrelated TLS capture, resolves to an unplantable own-sensor origin. That feeds the robustness
margin, so it matters — and a row here would be a promise that something enforces it. Nothing
does. It is recorded in the threat model as an open finding until it is fixed, which is the
honest place for it.

**What EVID does not promise, restated because the temptation is to read a green table as more.**
Two vault instances on one root fork the chain irrecoverably; the shipped verifier's size ceiling
covers artifacts but not the log; and the reporting-obligation register has no callers, so the
`REFUSED_ACCESS` entry EVID-04 appends is currently the *only* trace a statutory obligation was
incurred. All three are reproduced and open.

---

## PROBE — reaching for a capability is itself information

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **PROBE-01** | A reach for a reserved capability identifier is recorded, and sustained probing halts the session. | `IMPLEMENTED` | `nemesis.core.canaries`: ten identifiers nothing legitimate emits, matched on a normalised whole token in pilot-authored identifier fields. A hit writes a `security.control_boundary_probe` audit event; three distinct tokens end the session. | `test_control_boundary_canaries.py`; Breaker `capability-probe` |
| **PROBE-02** | The canary cannot be fired by what an adversary *writes*. | `IMPLEMENTED` | Identifier fields only — never a rationale, a summary, a belief's natural language, a parameter *value*, or anything else an adversary can write. A control an adversary can trigger is a denial of service handed to them. | `test_control_boundary_canaries.py` |

**PROBE-02 is stated as "what an adversary writes", and the boundary moved once already.**

The first version scanned every non-prose field, and an adversarial review broke it with **one
DNS registration**: a domain whose subdomain labels are three reserved capability names. It is a
well-formed hostname, it enters the graph through an ordinary registration pivot, it reaches the
pilot as an entity's natural key — and the moment a *correct* pilot wrote an ordinary belief
about it, three tokens landed in `record_belief.subject` and the session halted. No injection, no
misbehaviour, one adversary, every investigation that collected it.

The fix is not a longer exclusion list. **A value the pilot was *shown* is not a reach**: what
separates a probe from an echo is whether the pilot could have got the string from us, and the
briefing is the answer. Every string in the assembled briefing is excluded from the scan.

Three shapes, and only the third remains reachable:

| Shape | Cost to the adversary | Effect | Verdict |
|---|---|---|---|
| Token in a collected page, matched in prose | One forum post | Would halt **every** session that reads it | Refused by design — a weapon handed to them |
| Token in an entity natural key the pilot echoes | One DNS registration | Would halt every session that collects it, with no model cooperation at all | **Was reachable; now refused** by the briefing filter |
| Token in a field the *model* invented | Must get the model to obey, three distinct times | Halts one session and flags it for human review | Accepted — a session where a model acted on instructions from collected content is one somebody should read |

**What PROBE-01 does not catch, stated so nobody over-reads it.** A careful adversary will not
say the words. This finds the copy-pasteable probe, the injected payload that names a control,
and a future component that quietly grows a matching identifier. It is instrumentation placed at
the boundary the real controls defend, and it refuses nothing on its own.

---

## Mapping to the fifteen

| Register | CLAUDE.md invariants served |
|---|---|
| AUTH-01, AUTH-03 | 1 (LLM conclusions are not evidence), 2 (intelligence ≠ evidence) |
| AUTH-02 | 5 (external content is hostile), 7 (authorization outside the model) |
| AUTH-04 | 3 (provenance), 6 (minimum capabilities), 15 (no action against external infrastructure) |
| NET-01, NET-02, NET-03 | 8 (no ambient authority), 15 |
| MODEL-01, MODEL-02 | 6, 11 (auditable actions) |
| MODEL-03 | 9 (narrow, expiring authorization) |
| EFFECT-01, EFFECT-02, EFFECT-03 | 7, 8, 9 |
| DARKWEB-01, DARKWEB-02 | 5, 15 |
| SAFEFAIL-01, SAFEFAIL-02 | 4 (explicit uncertainty), 9, 14 (disruption closes no case) |
| EVID-01 … EVID-03 | 2 (intelligence ≠ evidence), 10 (tamper-evident evidence) |
| EVID-04 | 5 (external content is hostile), 10 |
| EVID-05 … EVID-07 | 3 (provenance), 10, 12 (NEMESIS must explain why) |
| EVID-08 | 4 (confidence and uncertainty are explicit), 10 |
| AUDIT-01, AUDIT-02 | 10 (tamper-evident evidence), 11 |
| PROBE-01, PROBE-02 | 11 |

---

## Adding to this register

Three rules, each learned from something in this repository going wrong:

1. **Name the enforcement, and make it a mechanism.** A row whose enforcement is a document is
   not a control. Say so in the status column rather than in the prose underneath.
2. **Name the test, and make the test able to fail.** Every property here has a test that
   constructs the violation, and several have a test asserting the *instrument* detects a planted
   one. An assertion that cannot fail reads exactly like one that can — this project shipped a
   containment check that returned the literal `False` and was the headline of four tests.
3. **Say where it stops.** Every entry above that has a limit states it. The alternative is a
   reader inferring coverage from an identifier, which is how `THIRD_PARTY` would get read into
   an anchor sitting next to the database.
