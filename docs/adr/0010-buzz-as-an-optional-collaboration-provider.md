# ADR-0010: A collaboration plane, and Buzz as one provider in it that ships unwired

- **Status:** accepted
- **Date:** 2026-08-22
- **Deciders:** founding architect, founder
- **Plane:** collaboration (new), core (two additions), audit (one move)
- **Reversibility:** high, and deliberately kept that way. `nemesis.collaboration` is additive:
  nothing above it imports it except a demonstration, nothing below it knows it exists, and the
  five contracts that were extended to name it would simply lose a line. Deleting the plane
  removes a capability and breaks nothing that investigates, authorizes or seals. The two core
  additions — `ActionRisk`/`OPERATION_RISK` and the `ActorKind` move — are the only parts that
  would outlive it, and both stand on their own.

## Context

The proposal was to evaluate [Block's Buzz](https://github.com/block/buzz) as "the
collaboration/control plane and signed event backbone for NEMESIS agents and human
investigators": channels, threads, signed events, agent identities, workflow events, audit
history, and approvals.

Two weeks of reconnaissance across both repositories produced eighteen agent reports and six
adversarial verification passes whose job was to *refute* the claims the design would rest on.
Four of the six came back refuted or imprecise, and each one moved the design.

**Buzz's relay is genuinely good, and it is a relay.** It speaks plain NIP-01 over a WebSocket
with five verbs (`EVENT`, `REQ`, `COUNT`, `CLOSE`, `AUTH`) and no Buzz-private framing; NIP-29
groups give it real channels; NIP-42 authentication is mandatory and properly implemented;
channel membership is enforced server-side in four independent places, all fail-closed, in Rust,
outside any model. A Go CLI is a documented working client, which is direct evidence the wire is
not language-coupled. Self-hosting is a real Compose bundle and a real Helm chart. This is a
solid piece of infrastructure and the reason this ADR says yes to anything at all.

**Its agent and workflow layer is not what a security control can rest on.** The verification
pass on approval gates came back `REFUTED` with the mechanism quoted: `finalize_run` intercepts
any run that reaches an approval gate and marks it **`Failed`** with the error code
`approval_not_supported`. `create_approval` has no production caller; nothing emits the
kind-46010 event that three separate consumers already subscribe to; `RunStatus::WaitingApproval`
is never written by any code, so the grant, deny and resume handlers are unreachable. And the
parts that *are* built would not fit even if they ran: an approval binds to
`(workflow_id, run_id, step_index)` and never to a hash of the action, the target or the
workflow definition, and granting resumes every remaining step against a definition re-fetched
at resume time. The approval record itself is an unsigned SQL row owned by the relay.

**Buzz's event store is not append-only.** The claim that it could serve as a tamper-evident log
came back `REFUTED` with five deletion paths quoted: a `deleted_at` soft delete, a moderator path
that soft-deletes another user's event, two database triggers that convert a soft delete into
`DELETE FROM events`, a hard delete of superseded parameterized events, and a community purge
whose table list contains both `events` *and* `audit_log`. No trigger prevents an `UPDATE` of
`content`, `tags` or `sig`, and signatures are verified only at ingest, never on read. There is
no hash chain, no sequence, no external anchor; inter-event order rests on a client-supplied
`created_at` bounded only by a ±900s drift check. Content modification is detectable to a client
that re-verifies. **Deletion, omission and reordering are not detectable at all.**

**Private channels are an access list over plaintext.** Channel messages and DMs are stored
unencrypted; NIP-44 encryption exists for five other kinds and not for these. The ACL is real and
well-built, and it keeps out other workspace members. It does not keep out the operator, and the
operator is in NEMESIS's threat model by construction (invariant 10). There is also a designed,
tested carve-out: the NIP-OA "owning human" of an agent in a channel may publish kinds 40003,
9005, 9002 and 9008 into a **private** channel without being a member — and 9002 can flip
`visibility` to open.

**A Python client is possible, with two corrections.** The transport claim came back `IMPRECISE`.
The load-bearing half survived: plain JSON text frames, no Buzz-specific handshake, no protobuf,
no Rust-only step. Two parts did not. Ed25519 will not work — every event goes through BIP-340
Schnorr over secp256k1, which the `cryptography` dependency NEMESIS already has does **not**
provide. And `auth_required: true` is hard-coded with a five-second deadline, so "just open a
socket and publish" understates a timed handshake.

**And the most useful finding was about NEMESIS, not Buzz.** Two claims were refuted at home. A
new top-level package under `src/nemesis/` is *ungoverned by default*: the verification pass
created `nemesis.collaboration`, made it import all nine planes at once, and `lint-imports`
reported `10 kept, 0 broken` — then made `nemesis.core` import it, and the contract literally
named "Core domain model depends on nothing internal" still reported KEPT. The nine `forbidden`
contracts are deny-lists keyed by explicit module name, and the `layers` contract ignores modules
it does not list. A clean linter run on new top-level code is evidence of absent coverage, not of
compliance. Separately: NEMESIS already has a canonical, hash-chained event envelope
(`AuditEvent`), a complete approval object (`Approval`, `ApprovalRequest`,
`AuthorizationCapability`, `TargetFingerprint`), a full evidence and chain-of-custody model, and
an epistemic taxonomy enforced at construction. Roughly thirty-eight of the forty-five
capabilities the proposal called for were already built.

## Decision

**A collaboration plane, sitting below the platform, with Buzz as one provider whose transport
and signer NEMESIS does not ship.**

### 1. Buzz is an optional provider, not the control plane

`CollaborationProvider` is a Protocol with six members. `LocalCollaborationProvider` — append-only
JSONL in a directory, no network, no credential — is the **default**, and it is the provider every
test runs against. NEMESIS investigates, authorizes and seals with nothing behind the seam.

The word "control plane" is refused deliberately. Buzz carries conversation. Control stays where
it is: the pursuit engine decides pivots, the mediator rules on moves, the gateway mints
authority, the effects registry dispatches. None of them can import this plane.

### 2. Nothing NEMESIS reads from a channel authorizes anything

This is the whole point, and it is enforced by the import graph rather than by a rule.
`nemesis.collaboration` sits below `nemesis.authz` in the layering, and a new contract —
`collaboration-holds-no-handles` — additionally forbids the package from importing `authz`,
`evidence`, `graph`, `collect`, `audit`, `pursuit`, `resolve`, `attribute`, `disrupt`, `effects`,
`pilot`, `api`, `slice` and `cli`. Both were verified to *break* on a probe import, not merely to
pass.

So the strongest object this plane can produce from a human's reply is a `DecisionIntake`, whose
`intent` is drawn from a vocabulary with no `APPROVED` member (`APPEARS_TO_APPROVE`,
`APPEARS_TO_REJECT`, `UNCLEAR`, `REFUSED_EXPIRED`, `REFUSED_CONFLICTING`) and whose `authorizes`
property returns `False` for every input. Turning one into an `Approval` requires the gateway, a
verified `IdentityAssertion` and a `PrincipalVerifier` — none of them reachable from here.

A reply must also quote a 16-hex **proposal digest** covering the capability id, the operation,
every target fingerprint in order, the risk level and the close time. A generic "approved" with
no digest reads as `UNCLEAR`; a digest from a different proposal reads as `UNCLEAR`; a reply after
`responses_close_at` is refused however it is worded. That is the requirement that a chat "yes"
must not authorize a later action, made mechanical.

### 3. Evidence stays out of the channel, structurally

`CollaborationEvent` has no field that can hold an artifact. Material travels as a `Reference`
rendering to `evidence://case-2026-000123/evd_sha256-…`, whose scheme is a closed enum and whose
parts are refused if they contain a path separator. Every event is classified, and the model
validator refuses to construct anything above `DisclosureClass.DELIVERABLE` — the wall is at
construction, not at the socket, because a checked-on-send design leaves an object in existence
for a second, unchecked send path to pick up. The internal-marker scan from `core/disclosure.py`
runs over the summary, the event type, the uncertainty note and every payload value.

### 4. The epistemic ladder is reused, not re-derived

`EpistemicStanding` maps onto the existing `ClaimKind` lattice rather than duplicating it, and
`standing_of_claim()` is the only sanctioned way to obtain a standing for a claim — a publication
path cannot label a hypothesis an observation on the way out any more than a caller can on the way
in. Three members exist that are deliberately *not* claim kinds, because they are not assertions
about the world: `RECOMMENDATION`, `DECISION`, `AUTHORIZED_ACTION`. And `EVIDENCE` is deliberately
**not** a standing: evidence is a separate object reachable from a claim, and adding it here would
let a channel message present itself as one (invariant 2).

### 5. The transport and the signer are Protocols NEMESIS does not implement

This is the decision that will look strange without the reason, so it is stated twice.

`scripts/check_prohibited.py` fails the build on an import of any of thirty-odd network modules —
`httpx`, `websockets`, `socket`, and every vendor SDK that carries an HTTP stack behind a name
that does not look like one — from anywhere outside `nemesis.collect`, where it additionally
requires an adjacent `NEMESIS-EGRESS-ALLOWED` marker. That is the mechanical form of invariant 15.
A collaboration plane holding a WebSocket client would either violate that check or require
weakening it, and weakening a security control so that a feature fits is the move this repository
exists to refuse.

The second reason is BIP-340. Buzz verifies Schnorr signatures over secp256k1. `cryptography>=44`
provides Ed25519 and secp256k1 ECDSA and does not provide BIP-340 — measured, not assumed. The
options were a binary dependency in a project with three runtime dependencies, or a curve
implementation vendored into a security-sensitive tree. Neither is NEMESIS's to choose on an
operator's behalf.

So: `BuzzTransport` and `EventSigner` are injected Protocols. `UnwiredBuzzTransport` and
`UnwiredEventSigner` ship, and they raise with the reason and a pointer to this ADR.
`BuzzCollaborationProvider.is_wired` reports the posture so a deployment can assert it rather than
infer it from whether messages appear. **The entire wire format is real and tested** — NIP-01
serialization, event-id derivation, tag ordering, NIP-29 channel creation, NIP-42 authentication,
the relay's `OK` message vocabulary — and nothing sends it.

This mirrors ADR-0009 exactly, where five provider seats ship and no transport is wired.

### 6. Buzz identity labels a message; it grants nothing

`ActorBinding` records that a NEMESIS actor publishes under a backend key. There is no field on
it that could grant anything and no method that consults one before allowing anything. The reverse
lookup returns `None` for an unenrolled key, because the interesting case is a message from a key
nobody accounted for and the honest answer there is "I do not know who that is".

`STANDING_ACTORS` lists **four** actors, not the ten a multi-agent design would assume, because
four is how many exist. NEMESIS has exactly one seat for a model (ADR-0008) and everything else is
deterministic Python. Enrolling nine identities that no code drives would put nine names in a
channel that never speak.

### 7. Failure isolation is an outbox, and durability comes before delivery

`Outbox.enqueue()` writes the intention to disk before anything is attempted, keyed by the event's
content-derived id. Delivery is a separate, retryable step with exponential backoff, a bounded
attempt count, a dead-letter state that keeps the record and its reason, and a circuit breaker
that stops calling a backend that keeps failing. The publish-then-enqueue-on-failure alternative
loses exactly the events worth keeping, because a process dying mid-investigation is the situation
somebody will later want the channel to explain.

### 8. Two additions to `core`, and one thing moved

`ActionRisk` (0–4) and `OPERATION_RISK` give the risk vocabulary a human governance process is
written in. It is a **derived, checked** classification, not a parallel one: an import-time check
refuses to load if the table is not total over `OperationClass`, if any member of
`IRREVERSIBLE_OPERATIONS` is classified below `HIGH_IMPACT`, or if any operation without an adapter
is classified below `SENSITIVE_EXTERNAL`. A classification that can drift away from the enforcement
it describes is worse than none, because it is the one people read.

`ActorKind` moved from `nemesis.audit.trail` to `nemesis.core.identity`, and the audit trail
re-exports it so every existing import keeps working. Two planes that cannot see each other now
need it; the alternative was a second four-member enum, which is the shape of defect where a value
is `"agent"` in one plane and `"AGENT"` in the other and nothing compares equal at the boundary.

## Consequences

**What this buys.** A human-facing surface with the epistemic distinctions intact — a reader of a
channel can tell an observation from a model's hypothesis from a recommendation from an authorized
action, because the standing rides in the envelope and was derived from the claim rather than
typed by whoever wrote the message. An approval flow that can be exercised end to end in CI,
because the local provider is a real provider. And a Buzz integration that is complete enough to
be reviewed, tested and argued about before anybody decides to point it at a relay.

**What it costs.** `BuzzCollaborationProvider` cannot reach a relay as shipped, and that will
surprise someone. It is documented in the class docstring, in the two `Unwired*` error messages,
in `docs/development/buzz-local-setup.md` and here. The `is_wired` property exists so the surprise
happens at a `False` rather than at an empty channel.

**What it does not buy, stated so nobody discovers it later.** Publishing to a relay does not make
anything defensible. Buzz's store is mutable and purgeable, its audit chain is unverified,
unanchored, incomplete (two of eleven action types are ever emitted) and itself purgeable, and no
ordering proof spans its events. A channel is a place to talk about an investigation. The record of
the investigation is the hash-chained audit trail and the sealed vault, and the gap that would make
*those* defensible against their own operator is an **externally held** anchor. The vault already
records one on every run (`slice/scenario.py:1832`), but it is minted by `LocalHeadSigner` and
carries `authority = "nemesis"`, which `IntegrityAnchor.is_externally_held` rejects by name — so
`is_defensible_against_operator` is `False` by construction, not by omission. The authorization-side
machinery (`AnchorRegistry`, `FileAnchorStore`, `verify_against_anchor`) has no caller in `src/` at
all, so the audit trail and the spend ledger carry no anchor of any kind. Closing either needs an
authority outside NEMESIS — RFC 3161 timestamping or a transparency log. That is a larger and more
valuable piece of work than this one, and it is orthogonal to Buzz.

**On ACP.** Buzz's Agent Client Protocol harness is a hand-rolled JSON-RPC-over-stdio client for
spawning agent subprocesses, at a self-declared `protocolVersion: 2` that squats ahead of the
upstream RFD. It also auto-approves every `session/request_permission` with `allow_once`, and pairs
with a dev MCP server whose `shell` tool "runs at the operator's trust level, like bash itself".
NEMESIS's pilot seam is the opposite design: a closed four-verb vocabulary, a mediator holding
every handle, and refusal by absence of a verb. Adapting NEMESIS to ACP would mean replacing a
control that works with one that auto-approves, and is refused. If a future deployment wants a Buzz
agent to *drive* NEMESIS, the correct shape is that agent proposing moves through the existing
`AutonomousPilot` Protocol, where the mediator rules on every one — not ACP reaching into the
platform.

## Alternatives considered

**Make Buzz the default provider.** Rejected. It would make an optional dependency mandatory in
practice, and every test would then need a relay or a mock of one — at which point the local
provider exists anyway, but as test scaffolding rather than as a supported mode.

**Put the integration in `nemesis.collect` as an inbound connector.** This was the recommendation
of the reconnaissance synthesis, and it is a good design for a *different question*: it needs zero
import-linter edits and inherits six enforcement mechanisms free, because the collection plane is
already the one place network capability is permitted. It was rejected because the requirement is
bidirectional collaboration with humans, and modelling that as intelligence collection would put
NEMESIS's own approval requests into the plane whose entire premise is that its contents are
adversary-written. Collecting *from* a Buzz relay as a threat-intelligence source remains a
sensible future connector, and it belongs there rather than here.

**Use Buzz's workflow approval gates.** Rejected on the evidence above: they mark the run failed.

**Add `coincurve` and ship a working transport.** Rejected for this change, not forever. It is a
one-line dependency addition and a two-hundred-line transport, and the reason to defer is that
turning on egress is a founder decision about invariant 15 rather than an engineering convenience.
The seam is shaped so that decision costs one class.

**Vendor the BIP-340 reference implementation.** Rejected. It is about 120 lines of Python and it
would work. It also puts private-key arithmetic in a tree whose threat model includes the operator,
for the sake of avoiding a dependency the operator probably already has.

## Enforcement

| Property | Enforced by |
|---|---|
| The plane cannot reach authorization or evidence | `collaboration-holds-no-handles`, verified to break on a probe |
| `core` cannot import the plane | `core-is-independent`, extended and verified to break |
| Effects cannot publish (exfiltration path) | `effects-no-ambient-authority`, extended |
| A collector cannot publish | `collectors-cannot-act`, extended |
| The vault cannot publish | `evidence-vault-isolation`, extended |
| A pilot seat cannot publish | `provider-adapters-hold-no-handles`, extended |
| Layer position (above `ports`, below everything) | `layers` contract |
| No network module anywhere in the plane | `scripts/check_prohibited.py`, plus a runtime test over the loaded module graph |
| Nothing above `DELIVERABLE` is publishable | `CollaborationEvent` model validator |
| A message never authorizes | `DecisionIntake.authorizes`, `DecisionIntent` vocabulary, import contract |
| The risk table agrees with what the code enforces | import-time check in `core/authorization.py` |

## References

- [ADR-0008](0008-the-pilot-seam-and-envelope-bounded-autonomy.md) — the pilot seam and why
  authority lives outside the model
- [ADR-0009](0009-provider-neutral-pilot-seats.md) — the provider pattern this ADR copies,
  including shipping seats with no transport
- [`docs/architecture/buzz-integration.md`](../architecture/buzz-integration.md) — the integration map
- [`docs/security/buzz-threat-model.md`](../security/buzz-threat-model.md) — the threat model for
  this boundary
- [`docs/development/buzz-local-setup.md`](../development/buzz-local-setup.md) — how an operator
  wires it
