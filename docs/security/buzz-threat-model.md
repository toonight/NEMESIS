# Threat model: the collaboration boundary

Scope: everything that crosses between NEMESIS and a collaboration backend, with Buzz as the
concrete case. Read [`THREAT_MODEL.md`](../architecture/THREAT_MODEL.md) for the platform's own
adversary model and [ADR-0010](../adr/0010-buzz-as-an-optional-collaboration-provider.md) for why
the integration has the shape it has.

Every finding about Buzz below was read from the `block/buzz` source at commit `4baccd5`, not from
its documentation. Where the documentation and the code disagreed, the code is recorded. Where
something is *not* established, this document says so rather than filling the gap.

---

## The boundary, stated once

**Buzz is outside the collection boundary. Everything crossing it inbound is untrusted data, never
instruction** — invariant 5, applied without exception. That holds for a relay the operator hosts
themselves, because a self-hosted relay's database can rewrite `content`, `tags` and `sig` with no
trigger preventing it and no read-path verification catching it.

The only property that survives a hostile relay operator is **the author's own signature over the
event id**. NEMESIS therefore recomputes the id of every inbound event from its own fields — which
detects any modification of content or tags — and reports `author_verified=False` because it does
not ship the BIP-340 implementation needed to check the signature itself. Reporting what was
checked rather than what is hoped is the rule; a field that asserts its own innocence is this
repository's recurring defect shape.

**Outbound is the sharper edge.** NEMESIS publishing into a channel is NEMESIS putting material
somewhere it no longer controls retention, deletion or readership. The controls are therefore at
construction, not at the socket.

---

## What Buzz can be trusted for

| Property | Evidence |
|---|---|
| Delivering bytes with an intact author signature | every stored event carries a BIP-340 signature over a canonical serialization whose hash is the event id; `buzz-core/src/verification.rs` |
| Server-side channel ACL on ordinary message traffic | four independent enforcement sites, all fail-closed: write gate at ingest, historical read scoped in SQL **and** re-checked per row, live fan-out re-checked per recipient |
| Tenant separation by `Host` header | composite PKs `(community_id, id)`, immutability trigger on `channels.community_id` |
| Rate limiting and admission control | Redis-backed, atomic, fail-closed |
| Mandatory authentication | NIP-42 with `auth_required: true` hard-coded; `REQ`/`EVENT`/`COUNT` reject unauthenticated connections |

That is a genuinely good relay. Everything below is about what it is *not*.

---

## Threats

### T1 — Identity

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Stolen agent key** | An agent's nsec transits process environment variables and is forwarded to shell children; the zeroize in `buzz-acp` is labelled best-effort. A stolen key lets an attacker publish as that agent. | A backend key is a *label*. `ActorBinding` has no field granting anything and no method consults one. Authorization needs a `Principal` from a verified `IdentityAssertion` through `PrincipalVerifier`, unreachable from this plane. | The attacker can publish convincing-looking NEMESIS events into a channel and mislead a human reader. **Not mitigated.** Mitigation would be signature verification plus binding to an enrolled key — see G3. |
| **Impersonation of a NEMESIS actor** | Any key may publish; nothing marks a message as ours. | `ActorRegistry.actor_for_backend` returns `None` for an unenrolled key — the honest answer, rather than a plausible guess. | A reader who does not check attribution is fooled. Client-side rendering is not ours to control. |
| **Rogue agent added to a channel** | An agent joins by `kind:9000`, gated by the target's `channel_add_policy` and the NIP-OA owner relation. | It can read the channel and publish into it. It cannot read evidence: the channel carries references, and resolving one requires NEMESIS access control. | It learns the *shape* of an investigation — which cases are open, which operations are proposed. Real, and the reason `visibility` defaults to `RESTRICTED`. |
| **Relay dev-key forgery** | With `BUZZ_REQUIRE_AUTH_TOKEN=false` the relay signs with a hardcoded `0x00…01`. Every dev deployment shares that identity and can forge relay-signed kinds (39000/39001/39002, 44100/44101, 13534). | Set `BUZZ_RELAY_PRIVATE_KEY`. Documented in [`buzz-local-setup.md`](../development/buzz-local-setup.md). | An operator who misconfigures this has a relay whose membership events are forgeable. Buzz's problem; ours to warn about. |

### T2 — Authorization

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Confused deputy: a chat message causes an action** | The central threat. | The plane cannot import `nemesis.authz` — layering plus a `forbidden` contract naming the package, both verified to break on a probe. `DecisionIntent` has no `APPROVED` member. `DecisionIntake.authorizes` is `False` for every input. | **Mitigated structurally.** A future author would have to edit `.importlinter` to introduce this, which is a visible act. |
| **Approval replay** | A captured "APPROVE <digest>" resent later. | The digest covers `responses_close_at`; `intent_from` refuses after it, before parsing. A capability additionally expires (`MAX_CAPABILITY_LIFETIME` 24h) and is bound to `TargetFingerprint`s. | Within the window, a replay of the *same* reply reads the same way — which is correct: it is the same reply. It still authorizes nothing. |
| **Approval substitution: reply approves a different action** | The attack the digest exists for. | The digest covers capability id, operation, every target fingerprint **in order**, risk level and close time. Any change → a different digest → `UNCLEAR`. | A reply quoting a digest the attacker obtained from the channel could be *forged by a stolen key*. It still authorizes nothing (T2 row 1). |
| **Privilege escalation through channel roles** | Buzz roles (`Owner`/`Admin`/`Member`/`Guest`/`Bot`) are relay-side and real. | They are not NEMESIS roles. `nemesis.core.identity.Role` is what the gateway checks, and a backend role cannot become one. | None for authorization. Buzz roles do govern who can read the channel. |
| **Non-member write into a private channel** | Verified: a NIP-OA owner of an agent in the channel may publish kinds 40003, 9005, 9002 and 9008 into a **private** channel without membership — and 9002 can flip `visibility` to `open`. Explicitly designed and tested by Buzz. | NEMESIS publishes kind 9 only, and reads kind 9 only. The carve-out does not let a non-member post a NEMESIS event. | A non-member owner can **delete** or **edit** NEMESIS messages, and can make a private channel public. **Not mitigated, and not mitigable from our side.** Treat channel membership as advisory and never publish anything whose exposure would matter. |

### T3 — Event integrity

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Forgery** | Requires the author's private key. | Not mitigated by us — we do not verify signatures. Event-id recomputation catches modification, not forgery by a key holder. | See G3. |
| **Tampering** | The relay stores `verified: true` on read reconstruction; nothing re-verifies; no trigger prevents `UPDATE events SET content/tags/sig`. | `NostrEvent` recomputes the id at construction and refuses a mismatch. Any change to `content` or `tags` is caught. | A tamperer with database access can recompute the id *and* would then need the author's key to produce a matching signature — which we do not check. So id-only verification catches a careless edit, not a determined one. |
| **Deletion** | Five paths verified: `deleted_at` soft delete; a moderator path deleting another user's event; DB triggers converting soft deletes into `DELETE FROM events` (migrations 0009, 0019); hard delete of superseded parameterized events; `purge_postgres` deleting `events` **and** `audit_log`. | **None, and none is possible.** There is no hash chain, no sequence number and no anchor across Buzz events. | **Deletion is undetectable.** This is the single reason Buzz must never be an evidence or audit store. The record lives in `AppendOnlyAuditTrail` and `FileSystemEvidenceVault`. |
| **Reordering / omission** | Inter-event order rests on client-supplied `created_at`, bounded only by a ±900s ingest drift check. | Every `CollaborationEvent` carries `occurred_at` (when the thing happened, not when it was published) and a `correlation_id`. NEMESIS's own ordering is the audit chain's. | A channel read as a timeline can be wrong. Do not read one as a timeline. |
| **Buzz's own audit chain as a fallback** | SHA-256 `prev_hash` chain in `audit_log`, per community. But: **2 of 11** `AuditAction` variants are ever emitted, `verify_chain` has no caller outside tests, there is no route/CLI/UI to run it, it is not signed, not anchored, and `audit_log` is in `PURGE_SCOPED_TABLES`. | Not used. | Do not cite it as an audit capability. |

### T4 — Prompt injection

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Injection through a channel message** | A channel is human-writable and, in a shared workspace, adversary-reachable. | Nothing reads a channel message as an instruction. `InboundSignal` is a *different type* from `CollaborationEvent`, with no `standing` and no `classification` field, so no function accepts both and no projection can be forged inbound. The reply parser is deliberately crude token matching — a cleverer parser would be a model reading adversary-reachable text and deciding what a human meant. | A human reader can be socially engineered. That is not a software control. |
| **Injection reaching the pilot** | The pilot could in principle be briefed with channel content. | It is not, and cannot be: `nemesis.pilot` cannot import `nemesis.collaboration` (contract `collaboration-holds-no-handles` lists `nemesis.pilot`; the layers contract places the plane below it). `Briefing` is built by the mediator from the investigation, capped at 50 deliverable-class entities, with markers redacted in the three adversary-influenced fields. | **Mitigated structurally.** |
| **Agent-to-agent injection** | A foreign agent in the channel publishing text a NEMESIS component reads. | Same mitigation: signals become `DecisionIntake` records and nothing else. There is no path from a signal to a `Claim`. | An injection payload is preserved byte-identical in the record — deliberately, as the collection plane preserves hostile artifacts. A test asserts it survives and becomes no assertion. |
| **Poisoned memory** | NEMESIS has no channel-derived memory. | No path exists to write one. | None today. Any future inbound-ingest path must go through `nemesis.collect` with quarantine, not through this plane. |

### T5 — Data security

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Evidence leakage** | Channel content is plaintext at rest, with the operator's retention and deletion. | `CollaborationEvent` has **no field** that can hold an artifact. Material travels as a `Reference` whose scheme is a closed enum and whose parts are refused if they contain a path separator. | A reference reveals that an artifact exists and which case it belongs to. Judged acceptable; the alternative is publishing nothing, which defeats collaboration. |
| **Persona linkage / human-identity leakage** | Founder decision D1: internal leads never leave. | The model validator refuses to construct any event above `DisclosureClass.DELIVERABLE`. `scan_for_internal_material` runs over the summary, event type, uncertainty note and every payload value. | The scan catches markers, **not paraphrase**. An analyst rewording an internal finding into a summary would not be stopped. Stated in `ARCHITECTURE.md` for the effects boundary; it applies identically here. |
| **Credentials in messages** | Someone pastes a key into a channel. | `scripts/check_prohibited.py` scans the repository, not a channel. Out of scope for this plane. | Not mitigated. An operator control. |
| **Investigation targets disclosed** | Event payloads name domains and addresses. | That is the point of the channel; those are `DELIVERABLE`-class by `ENTITY_DISCLOSURE`. | Anyone with channel access learns what is being investigated. `visibility` defaults to `RESTRICTED`; enable `BUZZ_REQUIRE_RELAY_MEMBERSHIP`. |

### T6 — Supply chain

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Compromised transport library** | The operator supplies it. | NEMESIS ships none, so the attack surface is not in this repository. The `BuzzTransport` Protocol receives only already-projected, already-redacted events and returns receipts. | A malicious transport learns everything published to it. It learns nothing else: the plane holds no platform handle. |
| **Compromised relay** | Assumed hostile throughout this document. | Publish references, not content. Never treat the relay as a record. | Covered above. |
| **Compromised Buzz plugin / MCP server** | `buzz-dev-mcp` exposes a `shell` tool described as running "at the operator's trust level, like bash itself", and `buzz-acp` auto-approves every `session/request_permission` with `allow_once`. | Not used by NEMESIS. Nothing here spawns or talks to an ACP harness. | If an operator runs a Buzz agent on the same host as NEMESIS, that agent has shell. **That is a host-level compromise and this plane cannot mitigate it.** Do not co-locate. |
| **Compromised agent harness** | Same. | Same. | Same. |

### T7 — Multi-agent failure

| Threat | Reality | Mitigation | Residual |
|---|---|---|---|
| **Hallucination amplification** | A model's assertion republished until it reads as established. | `standing_of_claim()` derives the standing from the claim, whose kind was fixed at construction. A `MODEL_ASSERTION` derivation can never be an `OBSERVATION`. Republishing a hypothesis republishes a hypothesis. | A human reading five hypothesis-labelled messages may still over-weight them. Labelling is what software can do. |
| **Circular confirmation** | Five feeds reselling one upstream reading as five confirmations. | `provenance_cluster()` in `core/fusion.py` resolves resellers to their origin and refuses to read missing lineage as independence; `independent_source_count` is reported separately from `total_sources`. Publishing does not create sources. | A channel is not a source and cannot become one — no path from `InboundSignal` to `Claim`. |
| **Collusion between agents** | NEMESIS has one model seat. | `STANDING_ACTORS` lists four actors, one of them a model. There is no agent-to-agent delegation type and no sub-delegation of `AutonomyEnvelope`. | Not applicable today. Would need re-modelling if a second seat is ever added. |
| **Cascading error** | One wrong event drives the next decision. | Collaboration events drive nothing. Nothing in the platform reads them. | None from this plane. |
| **False attribution** | The platform-level threat. | Attribution is multi-dimensional with no collapsed score; a channel projection carries the dimensions or no number at all. `confidence` is nullable so a vacuous opinion publishes nothing rather than 0.5. | Unchanged by this plane. |

---

## Gaps, named

- **G1 — No signature verification of inbound events.** `author_verified` is always `False`. Event
  ids *are* recomputed, so content and tag modification is caught. Closing this needs the BIP-340
  dependency ADR-0010 declines to add; when an operator supplies an `EventSigner`, a verifying
  counterpart is the natural extension. `PROPOSED`.
- **G2 — The disclosure guard catches markers, not paraphrase.** Identical to the effects boundary,
  and stated in `ARCHITECTURE.md`. Unchanged by this work.
- **G3 — A stolen backend key can publish convincing NEMESIS-shaped events.** Mitigated for
  *authorization* (it grants nothing) and not for *misleading a human reader*. Closing it needs G1
  plus rejecting any event whose author key is not enrolled in `ActorRegistry`.
- **G4 — CLOSED.** `CollaborationPublisher` (`src/nemesis/collaboration/publisher.py`) records
  every publication attempt, channel open, actor binding, signal read and decision reading into
  the hash-chained trail. The plane still cannot import `nemesis.audit`: it takes a
  `PublicationRecorder` (`src/nemesis/ports/storage.py`) — one method, `record`, and no `query`,
  so a compromised collaboration path can write what it published and cannot read the platform's
  history of everything else. `AppendOnlyAuditTrail` satisfies it structurally, so a caller passes
  the trail it already has and no adapter exists to keep in step. Refusals are recorded **before**
  the exception propagates, and an audit-write failure stops the publisher rather than being
  swallowed. `tests/invariants/test_collaboration_audit.py` pins it, including by tampering with a
  publication entry and asserting the chain reports the break.

  What it does **not** close: an entry holds the event's content-addressed id and its integrity
  hash, not its content, so the trail proves *which* event was published without holding a second
  copy of what it said. The excerpt of a human's reply **is** kept, because the reply itself lives
  on a backend whose retention is not ours. And this trail is anchored no better than any other —
  see G6.
- **G5 — Buzz's non-member edit carve-out.** A NIP-OA agent owner can edit or delete NEMESIS
  messages in a private channel and can flip its visibility. Not mitigable from our side.
- **G6 — Nothing here improves evidence defensibility.** `SealedExport.is_defensible_against_operator`
  (`evidence/export.py:185`) is `False` for every package this build produces, and the reason is
  narrower than "no anchoring exists". The vault's anchoring *is* wired: `slice/scenario.py:1832`
  calls `vault.record_anchor(LocalHeadSigner.generate().anchor(head))`. But the only anchor NEMESIS
  can mint carries `LOCAL_ANCHOR_AUTHORITY = "nemesis"`, which
  `IntegrityAnchor.is_externally_held` (`core/evidence.py:117`) rejects by name — so
  `externally_anchored` stays 0 and the property is `False` by construction rather than by
  omission. Separately, the *authorization*-side machinery (`AnchorRegistry`, `FileAnchorStore`,
  `AnchorVerifier`, `verify_against_anchor` in `authz/anchor.py`) has **no caller in `src/`** — only
  `tests/invariants/test_chain_anchor.py` — so the audit trail, the revocation chain and the spend
  ledger carry no anchor at all. Closing either needs an authority outside NEMESIS: RFC 3161
  timestamping or a transparency log. Larger and more valuable than this work, and independent of
  Buzz.

  *This entry was wrong in its first draft* — it said the machinery was unwired, which is true of
  the `authz` half and false of the vault half. Corrected after reading the call sites.

---

## Configuration recommendations

For an investigation deployment, in priority order:

1. `BUZZ_RELAY_PRIVATE_KEY` set. Never run with the hardcoded dev key.
2. `BUZZ_REQUIRE_RELAY_MEMBERSHIP=true` and `BUZZ_PUBKEY_ALLOWLIST=true`. Both default to `false`,
   which admits any authenticated pubkey.
3. Every channel `RESTRICTED`. It is the default in `ChannelDescriptor`; do not override it.
4. Relay on infrastructure the investigation owns. Never `buzz.xyz` for a real case.
5. NEMESIS and any Buzz agent harness on **different hosts**. See T6.
6. Buzz credentials in the operator's secret store, never in this repository. `.env` is ignored
   here and no `.env.example` claims otherwise.
