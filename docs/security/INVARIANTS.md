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
| **AUTH-02** | Peer/model communication cannot increase authority. | `IMPLEMENTED` | Nothing reads a string as an authorization. A chat reply is a `DecisionIntent` (a *reading*, with no member naming an outcome); a challenger's verdicts only subtract; a supervisor's directives change one word in a briefing; a research hint is redacted and quarantined. The collaboration plane cannot import `nemesis.authz` at all. | `test_authority_monotonicity.py` (10 phrasings × 2 shapes), `test_collaboration_boundary.py`; Breaker `peer-says-go` |
| **AUTH-03** | Evidence cannot automatically become capability. | `IMPLEMENTED` | A model assertion is minted as `HYPOTHESIS`/`MODEL_ASSERTION` at construction (invariant 1) and can never be an observation or a fact. Capability comes only from a signed `AuthorizationCapability`. | `test_authority_monotonicity.py`, `test_credential_containment.py`; Breaker `opinion-as-evidence` |
| **AUTH-04** | Discovered credentials do not imply authorization. | `IMPLEMENTED` | `nemesis.core.credentials`: no type has a field for material; the fingerprint is HMAC under a deployment key; `EntityCategory.CREDENTIAL` maps to `RESTRICTED`; `normalize_identifier` refuses a credential as a natural key. Nothing outside `core` imports the types. | `test_credential_containment.py`; Breaker `credential-laundering` |

---

## NET — reachability is a property of the composition

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **NET-01** | Model-controlled contexts cannot obtain unauthorized **direct** Internet access. | `IMPLEMENTED` | `scripts/check_prohibited.py` refuses a network import outside the collection plane, and every import inside it needs an adjacent `NEMESIS-EGRESS-ALLOWED` marker. Vendor SDKs are on the list, because a full HTTP stack behind a name that does not look like one is how invariant 15 ends quietly. | `test_transitive_egress.py`, CI step |
| **NET-02** | Model-controlled contexts cannot obtain unauthorized **transitive** Internet access. | `IMPLEMENTED` | `nemesis.sandbox.reachability` builds the import graph, marks modules that can reach the network **or start a process**, and asserts no path from a model-controlled root to one except through a declared broker. Three brokers, each with a written reason the far side is policy-controlled. | `test_transitive_egress.py`, `scripts/check_egress_reachability.py` in CI |
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

---

## AUDIT — history is not what the current process remembers

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **AUDIT-01** | Historical event modification is detectable. | `IMPLEMENTED` | Each entry hashes its canonical encoding together with its predecessor's hash. A careless edit breaks the entry hash; an interior deletion or reorder breaks the link. | `test_audit_anchoring.py`, `test_audit.py` |
| **AUDIT-02** | Tail truncation is detectable. | `IMPLEMENTED` at `AnchorIndependence.NONE` | A signed `(epoch, record_count, tip_hash)` anchor, published after a run and checked by `nemesis verify`. The chain alone cannot do this: a truncated chain links perfectly, and a fresh reader's counters are whatever the file says. | `test_audit_anchoring.py`, `test_chain_anchor.py`; Breaker `rewrite-history` |

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

## PROBE — reaching for a capability is itself information

| ID | Property | Status | Enforced by | Tested by |
|---|---|---|---|---|
| **PROBE-01** | A reach for a reserved capability identifier is recorded, and sustained probing halts the session. | `IMPLEMENTED` | `nemesis.core.canaries`: ten identifiers nothing legitimate emits, matched on a normalised whole token in pilot-authored identifier fields. A hit writes a `security.control_boundary_probe` audit event; three distinct tokens end the session. | `test_control_boundary_canaries.py`; Breaker `capability-probe` |
| **PROBE-02** | The canary cannot be fired by what an adversary *writes*. | `IMPLEMENTED` | Identifier fields only — never a rationale, a summary, a belief's natural language, a parameter *value*, or anything else an adversary can write. A control an adversary can trigger is a denial of service handed to them. | `test_control_boundary_canaries.py` |

**PROBE-02 is stated as "what an adversary writes" rather than "by an adversary", and the
distinction is the control.** An adversary who successfully injects the pilot *can* have it put a
reserved token into a parameter key, and sustained probing then ends the session. That is a
different shape from the one refused, and it is arguably the right outcome:

| Shape | Cost to the adversary | Effect | Verdict |
|---|---|---|---|
| Token in a collected page, matched in prose | One forum post | Halts **every** session that reads it, no model cooperation needed | Refused by design — a weapon handed to them |
| Token in a field the *model* chose | Must get the model to obey, three distinct times | Halts one session, and flags it for human review | Accepted — a session where a model acted on instructions from collected content is one somebody should read |

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
