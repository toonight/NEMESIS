# NEMESIS — Project Rules

**N**etworked **E**ngine for **M**alicious **E**ntity **S**urveillance, **I**dentification & **S**uppression.

Autonomous cyber-adversary pursuit, attribution and disruption-planning platform.
`DETECT → PURSUE → ATTRIBUTE → DISRUPT → WATCH → REAPPEARANCE → PURSUE`

Machine-speed investigation. Human-authorized effects. Evidence-backed attribution.
Persistent adversary memory.

**What NEMESIS is:** the framework an autonomous frontier-model pilot drives — the car, the
écurie, and above all the limiter that keeps the pilot inside the track. The pilot is the
brain and is *external and untrusted*; NEMESIS is the part that must not be a model, because
the part that enforces the limits cannot be one an adversary steers with the content it
writes. Autonomy of an *effect* lives inside a pre-signed capability envelope. See ADR-0008.

---

## Non-negotiable invariants

These survive every architectural evolution. A change that violates one is rejected,
not debated. Each is enforced by a test in `tests/invariants/` — if you cannot express
the enforcement as a test, the design is wrong.

1. **LLM conclusions are not evidence.** A model assertion is a `Claim` of kind
   `INFERENCE` or `HYPOTHESIS`, never an `EvidenceObject`.
2. **Intelligence and evidence are distinct objects.** The Intelligence Graph admits
   speculation. The Evidence Graph admits only traceable material. They never merge.
3. **Every material claim has provenance.** No claim without a resolvable derivation
   chain back to collected artifacts or a named human.
4. **Confidence and uncertainty are explicit.** Never a bare boolean, never a single
   unexplained number. Attribution confidence is multi-dimensional by construction.
5. **External content is hostile by default.** Anything crossing the collection boundary
   is untrusted data, never instruction.
6. **Agents get minimum necessary capabilities.** Tool access is granted per-agent-role,
   denied by default, and enforced outside the model.
7. **Real-world effects require authorization outside the model.** No effect executes
   because an agent asked for it.
8. **Effects have no ambient authority.** The Effects plane holds no standing credentials
   and no network reach it was not handed for one specific, expiring operation.
9. **Authorization is narrowly scoped and expires.** Capabilities bind to target
   fingerprints, operation class, jurisdiction and a hard expiry.
10. **Evidence is tamper-evident.** Append-only, hash-chained, externally anchored.
    The vault operator is in the threat model.
11. **All meaningful agent and human actions are auditable.** Replayable, not just logged.
12. **NEMESIS must explain why it connected two entities.** Machine-readable and
    human-readable, on demand, for every edge.
13. **An adversary will try to poison attribution.** Deception is a modelled hypothesis,
    not an afterthought.
14. **A takedown is followed by resurgence monitoring.** Disruption closes no case.
15. **The MVP never acts against external infrastructure.** No scanning, no probing,
    no unsolicited contact. The sole egress is a fetch of specific URLs from an
    operator-supplied allowlist, off by default with no endpoint shipped, confined by the
    kernel and marked `NEMESIS-EGRESS-ALLOWED`. Everything else is synthetic.

## Boundary discipline

Every artifact, doc, API response and log line must make its epistemic status explicit.
Use exactly these labels — they are load-bearing, not decoration:

| Label | Meaning |
|---|---|
| `IMPLEMENTED` | Code exists, tests pass, behaviour is real |
| `SIMULATED` | Code exists, returns synthetic data by design |
| `PROPOSED` | Designed, not built |
| `REQUIRES_EXTERNAL_DATA` | Blocked on a licensed/commercial source |
| `REQUIRES_LEGAL_AUTHORITY` | Blocked on authorization we do not and may not have |

Never silently promote something from one label to a stronger one. Changing a label is
a documented event.

## Language

All repository artifacts in **English**: code, comments, docs, commit messages, branch
names, test names, ADRs, schemas, identifiers. Conversation with the founder is in French.

## Architecture invariants

- **Plane separation is physical, not conventional.** Control / data / agent-execution /
  collection / dark-web / evidence / effects planes have distinct trust levels. Code in
  one plane does not import code from another except through a declared interface package.
- **The domain model has no I/O.** `src/nemesis/core` depends on nothing but the
  standard library and Pydantic. Storage, network and LLM access live behind ports.
- **Adapters are replaceable.** Every external intelligence source implements a connector
  interface. Swapping a simulated connector for a licensed one must not touch domain code.
- **Prompts are not security boundaries.** If a property matters, enforce it in code that
  the model cannot reach: schema validation, capability checks, egress policy, sandboxing.
- **Time is first-class.** Graph relationships are bitemporal (valid time + transaction
  time). "When did we learn this" and "when was this true" are different questions and
  both must be answerable.

## Engineering conventions

- Python 3.13, `uv` workspace. Ruff (lint + format), mypy `strict`, pytest.
- Type annotations are mandatory in `src/`. `Any` requires a comment justifying it.
- Tests: TDD for domain logic. Every invariant above has a test. Every bug fix starts
  with a failing test.
- Commits: Conventional Commits. Work on `agent/<task>` branches, never on `main`.
- Do not push to a remote, open a PR, or install global packages without asking.
- ADRs for decisions that are expensive to reverse: `docs/adr/NNNN-title.md`.
  Superseded ADRs are marked superseded, never deleted.
- Keep `docs/architecture/PROJECT_STATE.md` current. It is how the next session finds
  its bearings. Documentation that contradicts the code is a defect.

## Hard prohibitions in this repository

Not "discouraged" — these must not exist in the codebase:

- Any code path that scans, probes, connects to, authenticates against or modifies
  infrastructure not owned by us. Connectors talk to fixtures or licensed APIs only.
- Autonomous purchasing, financial transactions, impersonation, or engagement with
  criminal personas.
- Exploitation, persistence, credential attacks, malware deployment, destructive remote
  capability — including "just for testing".
- Real secrets in the tree. `.env` is ignored; `.env.example` is the contract.
- Weakening or skipping a test to make a build pass.

Extension points for future legally authorized capability are declared as interfaces with
no implementation, and documented as `REQUIRES_LEGAL_AUTHORITY`.

## Where to look

| Question | File |
|---|---|
| What exists and what works right now | `docs/architecture/PROJECT_STATE.md` |
| How the system is shaped | `docs/architecture/ARCHITECTURE.md` |
| Why a decision was made | `docs/adr/` |
| What the threat model assumes | `docs/architecture/THREAT_MODEL.md` |
