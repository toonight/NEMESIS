# NEMESIS architecture

A living document. It describes what is built, not what is intended — where the two differ,
that is a defect. Component status carries the labels defined in `CLAUDE.md`.

For what currently works, see [PROJECT_STATE.md](PROJECT_STATE.md). For why a decision was
made, see [`docs/adr/`](../adr/). For what the adversary is assumed to do, see
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## The shape of the thing

```
                    ┌──────────────────────────────────────────┐
   attack signal ──▶│  PLANE 1  COLLECTION      (hostile)      │
                    │  connectors, fixtures, quarantine        │
                    └────────────────┬─────────────────────────┘
                                     │ claims + evidence + artifacts
                                     ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │  PLANE 2  PURSUIT         (control)                               │
     │  investigation state, hypotheses, pivot selection, budget         │
     └───┬────────────────────┬───────────────────────┬──────────────────┘
         │ entities/edges     │ claims                │ artifacts
         ▼                    ▼                       ▼
   ┌───────────┐      ┌───────────────┐      ┌──────────────────┐
   │  PLANE 3  │      │  CLAIM STORE  │      │  PLANE 6         │
   │  GRAPH    │      │  append-only  │      │  EVIDENCE VAULT  │
   │  temporal │      │               │      │  tamper-evident  │
   └─────┬─────┘      └───────┬───────┘      └────────┬─────────┘
         │                    │                       │
         ▼                    ▼                       │
   ┌──────────────┐   ┌──────────────┐                │
   │  PLANE 5     │   │  PLANE 7     │◀───────────────┘
   │  RESOLVE     │──▶│  ATTRIBUTE   │
   │  (internal)  │   │  5 dimensions│
   └──────────────┘   └──────┬───────┘
                             ▼
                      ┌──────────────┐
                      │  PLANE 8     │  proposes; cannot execute
                      │  DISRUPT     │
                      └──────┬───────┘
                             ▼
                      ┌──────────────────────────────────┐
                      │  PLANE 9  AUTHORIZATION GATEWAY  │
                      │  human approval, Ed25519, expiry │
                      └──────┬───────────────────────────┘
                             │ one signed capability, per operation
                             ▼
                      ┌──────────────────────────────────┐
                      │  PLANE 10  EFFECTS   (isolated)  │
                      │  no ambient authority            │
                      └──────┬───────────────────────────┘
                             ▼
                      ┌──────────────┐
                      │  PLANE 11    │──▶ back to PURSUE
                      │  RESURGENCE  │
                      └──────────────┘

  AUDIT TRAIL spans everything. Hash-chained, append-only, records denials as
  carefully as approvals.
```

The arrows that *do not* exist are as load-bearing as the ones that do. Effects has no
arrow back into the graph, the vault or the collection plane. Collection has no arrow to
Effects, Authorization or Disruption. Both absences are enforced by `import-linter`
contracts in CI, not by convention.

---

## Why the planes are separated the way they are

Trust level, not functional grouping. Two components sit in different planes when a
compromise of one must not become a compromise of the other.

| Plane | Trust | What a compromise would mean |
|---|---|---|
| Collection | **Hostile** | Handles adversary-written content by definition. Assume it is compromised. |
| Effects | **Isolated** | Reaches the outside world. Must not be an exfiltration path *out* of an investigation. |
| Evidence | **Evidence** | Its own operator is in the threat model. |
| Graph, claims | Data | Revisable; poisoning is expected and must leave a trace. |
| Pursuit, disrupt, authz | Control | Decides what happens next. |
| Core | — | Pure. No I/O, no internal dependencies. |

The collection plane holds hostile content and the effects plane holds outward reach. If
those two could talk, planted content could steer a real-world action — which is the single
worst outcome this architecture exists to prevent. They are separated by import contracts and
will eventually be separated by process boundaries.

---

## The five ideas the design rests on

Everything else is consequence.

### 1. Standing is structural, not a field

A claim is an observation, a fact, an inference, a correlation, a hypothesis or an
attribution — and the difference is enforced at construction. A model cannot produce an
observation, whatever the calling code says. A conclusion never outranks its weakest
premise, so a chain of individually defensible steps cannot launder a guess into a
certainty. That laundering is how confident, wrong attribution actually happens.

### 2. Confidence must distinguish ignorance from conflict

A scalar cannot. "Nobody looked" and "two credible sources disagree" are both 0.5, and the
second is the one that should stop an operation. Subjective-logic opinions keep them apart:
vacuity is `u = 1`, conflict is balance with low uncertainty. Anything vacuous reports
`INSUFFICIENT_BASIS` rather than a probability band, so a prior is never dressed as a
finding. See [ADR-0002](../adr/0002-subjective-logic-for-evidence-fusion.md).

### 3. A pivot is worth what it discriminates, capped by the method that found it

Two independent questions, and conflating them is a specific, common error.

*Selectivity*: how many entities share this attribute? Two domains on an IP hosting four
others is strong; the same relation on a CDN address hosting 41,700 is noise. Uncounted
populations weigh **zero**, never a default.

*Method reliability*: how often does this technique link things that are not related?
Cryptographic identity is uncapped — a private key is not shared by accident. Wallet
clustering caps at 0.60; mixers defeat it by design. Stylometry caps at 0.30 and is never
decisive alone.

The edge takes the lesser. A perfectly selective attribute matched by a fallible technique
is still a fallible link, and the explanation says which of the two is limiting — because a
weak attribute needs a better pivot while a weak method needs corroboration of a *different
kind*.

### 4. Sources are counted by origin, not by name

Cumulative fusion accumulates evidence, which is correct for independent sources and
catastrophic otherwise: five feeds reselling one upstream would look like five
confirmations. `provenance_cluster()` resolves resellers and mirrors back to their origin, and refuses to read missing lineage as independence;
weighted fusion applies within a group, cumulative across groups. `independent_source_count`
is reported separately from `total_sources`, because the second is what gets mistaken for
corroboration.

### 5. Authority is an object, not a state

Nothing in Effects can act without a signed capability naming the operation, the targets
*and the state those targets were in when approved*. The Effects plane verifies the Ed25519
signature itself and asks a revocation oracle whether the grant still stands, failing closed
if it cannot get an answer — it trusts neither its caller nor the object it was handed. If a domain is transferred between
approval and execution, the fingerprint stops matching and the operation fails closed. An
agent cannot mint one; issuance needs a private key that lives outside the agent execution
plane. Every capability expires.

The same reasoning applies one level up, to the humans in the chain. An approver is also an
object rather than a state: the gateway takes a **signed identity assertion** and a mandatory
`PrincipalVerifier`, not a `Principal` its caller constructed. The verifier decides what an
assertion establishes — issuer allowlist, audience, expiry, signature — and then caps the
assurance at the **ceiling this deployment registered for that issuer**. An issuer states;
the relying side decides. That split is why the only provider we have, a local fixture
registered at `DEVELOPMENT`, cannot authorize anything meant to leave the platform even if
it signs an assertion claiming otherwise.

---

## Component map

**Truth pass 2026-08-19.** This table had drifted, and the drift was measured rather than
suspected: an external reviewer read it faithfully and produced four recommendations for things
already built — a write path, tenant-isolation tests, a pilot circuit-breaker, a `propose`
timeout. That is this repository's own rejected defect, documentation contradicting code, in its
most expensive form: it no longer misleads only the next engineer, it wastes an outside
reviewer's attention. Every row below was re-checked against the code on that date.

| Module | Plane | Status |
|---|---|---|
| `core/` | — | `IMPLEMENTED` — domain model, no I/O, no internal deps |
| `ports/` | — | `IMPLEMENTED` — protocols only |
| `collect/` | 1 | `IMPLEMENTED` — seven fixture connectors plus one opt-in, allowlisted Tor snapshot connector; the demo remains simulated |
| `pursuit/` | 2 | `IMPLEMENTED` — deterministic rule policy |
| `graph/` | 3 | `IMPLEMENTED` — in-memory temporal store |
| — dark-web ops | 4 | `IMPLEMENTED` snapshot / `SIMULATED` demo — `collect_confined` routes hostile connectors through `IsolatedCollector`; the real Tor connector is bounded to configured v3 onion services and fails closed without kernel confinement |
| `resolve/` | 5 | `IMPLEMENTED` — refuses human identity structurally |
| `evidence/` | 6 | `IMPLEMENTED` — hash-chained, head signed; no external anchor. **Measured 2026-08-19:** deleting a chain's *newest* row is undetected — the same blind spot the revocation and spend chains carry, since nothing follows the tail. Interior edits are caught, by the per-record signature rather than by the chaining |
| `attribute/` | 7 | `IMPLEMENTED` — five dimensions, no collapsed score |
| `disrupt/` | 8 | `IMPLEMENTED` — proposes what it cannot execute |
| `authz/` | 9 | `IMPLEMENTED` — Ed25519, dual control, offline verify, verified identity assertions with per-issuer assurance ceilings |
| `effects/` | 10 | `SIMULATED` — simulation and drafting only |
| — resurgence | 11 | `SIMULATED` — fixtures exist; no standing monitor |
| `pilot/` | — | `IMPLEMENTED` — the seat and the limiter an external autonomous pilot drives; closed move vocabulary, a mediator holding every handle, effects routed through the pre-signed envelope (ADR-0008). |
| `pilot/providers/` | — | `IMPLEMENTED` (shape), **unconfirmed on the wire** — five seats (OpenAI, Anthropic, xAI, Gemini, Ollama) plus a generic OpenAI-compatible one, behind one canonical tool suite and a frozen registry. An `import-linter` contract forbids anything here from importing the mediator or any platform plane. No transport ships wired (ADR-0009). |
| `pilotbench/` | — | `IMPLEMENTED` harness / `SIMULATED` corpus — eight adversarial scenarios and a two-tier report: control-plane properties that stand alone, and agreement with a corpus we wrote that does not. |
| `sandbox/` | — | `IMPLEMENTED` — one confinement launch path, two opposite policies |
| `audit/` | — | `IMPLEMENTED` — hash-chained, denials recorded, single-writer enforced |
| `calibration/` | — | `IMPLEMENTED` (structural) — coherence laws that need no ground truth. **Not** empirical: no confidence figure has been scored against a resolved case, and no corpus exists |
| `ui/` | — | `IMPLEMENTED` — the analyst view, uncertainty visible by default, filtered to DELIVERABLE-class material |
| `cli/` | — | `IMPLEMENTED` — `demo`, `pilot`, `verify`, `view`, `corpus`, `calibrate`, `providers`, `pilot-preview`, `pilotbench` |
| `slice/` | — | `IMPLEMENTED` — the end-to-end reference scenario and the pilot session it drives |
| `api/` | — | `IMPLEMENTED` — **five** routes, not four, and one of them writes: `POST /submissions` admits an outside claim as a HYPOTHESIS from EXTERNAL_REPORT, never an observation, rate-limited per principal. Multi-tenancy is one store per tenant, stamped from the registered issuer, with eight isolation tests. **Honest scope:** the write path is isolated per tenant; the read routes still serve one investigation view to every tenant |

---

## Agent topology — and where the pilot fits

The most important thing to understand about this design: **NEMESIS is not the pilot.** It is
the harness an autonomous frontier-model pilot drives — the car and the limiter (ADR-0008).
The brain is external and untrusted; NEMESIS is the part that must not be a model, because the
part that enforces the limits cannot be one an adversary steers with the content it writes.

So the topology is deliberately small, and smaller than the brief's list of sixteen agent
roles suggested. Internal components are deterministic Python, not agents. There is exactly one
seat for a model, and it is the pilot's — mediated move by move.

**Which model sits in the seat is configuration.** Five providers are registered — OpenAI,
Anthropic, xAI, Google Gemini and a local model through Ollama — plus a generic seat for any
other OpenAI-compatible endpoint. There is no vendor branch anywhere in investigation logic: a
registry resolves a provider key to a seat and fails closed on a name it does not know. The four
verbs are rendered into each vendor's dialect from **one** canonical suite that no adapter can
enumerate, and an `import-linter` contract naming the *package* keeps every adapter — including
ones nobody has written yet — from importing the mediator, the engine, the graph, the vault or
the audit sink. A shared transport shape is never a shared identity: xAI is recorded as xAI.
See ADR-0009 and [`docs/pilot/MULTI_PROVIDER.md`](../pilot/MULTI_PROVIDER.md).

**The pilot is untrusted, and the seam contains it (`nemesis.pilot`).** The pilot receives a
read-only briefing and proposes a move from a closed four-verb vocabulary; the `PilotMediator`
holds every handle it does not — the engine, the graph, the capability envelope, the effects
registry — validates each move, and carries out only the permitted part. Authority escalation
is contained by the *absence of a verb*; acting outside the envelope is refused by the
capability the mediator routes to; a belief is minted only as `HYPOTHESIS`/`MODEL_ASSERTION`.
The session is replayable though the pilot is not.

**The pivot selection policy is not an LLM either.** `PursuitPolicy` is a deterministic rule
policy, because invariant 11 requires replayability: the same state must yield the same
decisions. It is the *reference driver* the pilot seam sits above — the pilot chooses pivots
through `execute_pivot`, the policy chooses them through `step`, and both run the same
enforcement. Collected content influences *what is in the graph*, never *what decides next*.

Where models are used, their output is a `Claim` of kind `INFERENCE` or `HYPOTHESIS`,
carrying the model identifier, and it can never be an observation or a fact.

---

## Extension points, declared and unimplemented

Interfaces exist with no implementation behind them, so the architecture is ready without
the development environment becoming an offensive platform:

- Operation classes beyond the four MVP adapters — registrar suspension, hosting
  termination, sinkholing, domain seizure, judicial packages. Declared in
  `OperationClass`, absent from `MVP_IMPLEMENTED_OPERATIONS`, and the registry returns
  `REFUSED_NO_ADAPTER`. Marked `REQUIRES_LEGAL_AUTHORITY`. Two tests act as tripwires.
- `AnchorProvider` for RFC 3161 timestamping or a transparency log.
- Provider-specific intelligence connectors beyond the bounded Tor snapshot adapter.

The planner deliberately proposes options NEMESIS may not perform. A planner limited to what
it can execute silently narrows every investigation to whatever happens to be built.

---

## What this architecture does not yet do

Stated here rather than discovered later:

- **Effects process isolation is macOS-only, and its mechanism is deprecated.** ADR-0007 runs
  each operation in a child under `sandbox-exec`, which denies sockets and confines reads —
  and which exists on no other platform and is on Apple's deprecation path. On Linux, where
  this would actually deploy, invariant 8 falls back to static import contracts, which
  constrain the import graph and cannot stop a subprocess, a socket through an allowed
  dependency, or a mounted path. CI runs on Ubuntu and therefore **never exercises the
  kernel-enforced form at all**. Landlock or a seccomp-bpf wrapper is the direction; neither
  is built. The real Tor connector therefore refuses to run on platforms without the
  kernel-enforced collector boundary; fixtures may still use process-only isolation.
- No external integrity anchor exists, so evidence is not defensible against an insider. The
  vault reports this itself — and the same gap is now measured in the revocation and spend
  chains, where deleting the newest row is undetected and, if a later honest write follows,
  becomes an unrecoverable history rewrite. See `THREAT_MODEL.md` for the anchor contract and
  for why no placement of it defeats the modelled adversary on a single-user laptop.
- **`external_contact_made` and `is_defensible_against_insider` are flags the code sets about
  itself.** On macOS the sandbox corroborates the first; elsewhere nothing does. A field that
  asserts its own innocence is the recurring shape of defect in this codebase — three were
  found and fixed on 2026-08-18 alone — and these two remain.
- The organization/operator wall is built, but its free-text guard at the Effects boundary
  catches a marker rather than an idea: a determined analyst paraphrasing a persona finding
  into a takedown request would not be stopped.
- No confidence figure has been validated against a known-correct answer, and none can be
  until resolved cases exist.
