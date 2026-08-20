# ADR-0001: Single Python package with statically enforced plane separation

- **Status:** accepted
- **Date:** 2026-08-15
- **Deciders:** founding architect
- **Plane:** all
- **Reversibility:** moderate — splitting into distributions later is mechanical; the
  import contracts are what would have to be re-expressed, and they would survive.

## Context

The security model requires separate planes with different trust levels: control, data,
agent execution, collection, dark-web, evidence, effects. Invariant 8 in particular
requires that the Effects plane hold no ambient authority — it must not be able to reach
the intelligence platform even if an adapter is compromised.

The question is what enforces that separation. Three mechanisms are available, and they
are not equivalent:

1. **Convention and code review.** Zero cost, zero guarantee. A junior engineer adds one
   import and the boundary is gone with nobody noticing.
2. **Separate distributions** (one `pyproject.toml` per plane). A plane cannot import what
   is not in its dependency list. Strong, and expensive: eleven packages, eleven version
   numbers, a release dance for every cross-cutting change, and painful local development
   at exactly the stage where iteration speed matters most.
3. **Separate processes.** The strongest boundary — separate credentials, separate network
   namespace, separate memory. Also the most operationally involved.

Additionally: NEMESIS is at the stage where getting a working vertical slice matters more
than getting a perfect package graph. A structure that slows the first milestone in
exchange for a guarantee we can obtain another way is a bad trade.

## Decision

**One distribution, `nemesis`, with `src/nemesis/<plane>/` modules, and plane separation
enforced statically by `import-linter` contracts in CI.**

Seven contracts, each encoding a numbered invariant:

| Contract | Enforces |
|---|---|
| `core-is-independent` | The domain model imports nothing internal |
| `core-has-no-io` | The domain model touches no socket, no database, no subprocess |
| `effects-no-ambient-authority` | Effects cannot import graph, collect, pursuit, resolve, attribute, disrupt, evidence (invariant 8) |
| `collectors-cannot-act` | Collectors cannot import effects, authz, disrupt (invariant 6) |
| `analysis-has-no-network` | Resolution and attribution cannot import collect or effects |
| `evidence-vault-isolation` | The vault depends only on core and ports (invariant 10) |
| `layers` | Overall directional layering |

Supplemented by `scripts/check_prohibited.py`, which fails the build on any import of a
network client outside the collection plane — backing invariant 15 in CI rather than in a
prompt.

**Where a real boundary is needed, it is a process boundary, not a packaging one.** The
Effects plane and the dark-web collectors will run as separate processes with separate
credentials and separate network policy. That is a stronger guarantee than any packaging
arrangement, and it is the one the threat model actually asks for. The module structure is
designed so that extraction is mechanical: those planes communicate through declared
interfaces in `nemesis.ports`, never through direct calls into other planes.

## Alternatives considered

**Eleven separate distributions.** Rejected. It provides the same *static* guarantee as
import-linter for substantially more friction, and it does not provide the runtime
guarantee — a package boundary does not stop a compromised adapter from reading a
credential that the process already holds. Since the runtime boundary has to exist anyway
for the planes that matter, the packaging boundary buys little. Worth revisiting if
NEMESIS is ever distributed as separately licensed components.

**Convention plus code review.** Rejected outright. CLAUDE.md's own rule is that prompts
and documentation are not security boundaries; the same applies to review discipline. A
boundary that depends on someone remembering is not a boundary.

**A monolith with no enforced structure, refactored later.** Rejected. Plane separation is
cheap to establish now and expensive to retrofit, because by then the violating imports
exist and each one is someone's working code.

## Consequences

### Positive

- Boundary violations fail CI with a named contract, not a review comment.
- Local development stays a single `uv sync`.
- Contracts are readable as a security document: `.importlinter` states what may not reach
  what, and why, in one screen.

### Negative / accepted costs

- The static guarantee holds only for imports. Dynamic dispatch, `importlib`, or a shared
  global registry could route around it. Mitigated by the process boundary for the planes
  where it matters, not by hoping nobody does it.
- Everything shares one virtualenv, so a dependency pulled in for one plane is importable
  from all of them. `check_prohibited.py` covers the specific case that matters (network
  clients); the general case is not covered.
- One version number for the whole platform.

### Residual risk

A future contributor adds a plane and forgets to add contracts for it. Mitigation: the
`layers` contract enumerates planes explicitly, so a new plane that is not listed also is
not layered, and its first cross-plane import is likely to break an existing contract.
Not airtight. A periodic review of `.importlinter` against the module tree is warranted.

## Verification status

- `import-linter` 2.1 behaviour verified locally: 7 contracts, 7 kept, and deliberately
  broken imports were confirmed to fail the check.
- `check_prohibited.py` verified against the current tree (no findings) — but it is a
  coarse pattern matcher and says so in its own output. It is not a secret scanner.
- **Unverified assumption:** that process-level isolation for Effects and dark-web
  collectors will be implemented before either plane does anything real. This ADR's
  security argument depends on it. Until then, invariant 8 rests on the static contract
  alone, which is weaker than claimed here.

## Revisit when

- A plane needs to be separately licensed, separately deployed, or separately audited.
- The static contract is routed around in practice.
- Effects gains its first adapter that makes external contact — at that point the process
  boundary stops being a plan and becomes a prerequisite.
