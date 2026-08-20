# Security policy

NEMESIS is a security product that assumes its own adversaries will eventually study it.
This file says what we defend, what we knowingly do not defend yet, and how to tell us
about something we have missed.

## Status

Pre-release, single-tenant, **simulated only**. No deployment processes untrusted external
data, and no component can act on infrastructure we do not own. That is a property of the
code, not a policy: every connector reads a fixture, and CI fails the build on a network
import outside the collection plane.

There is therefore no supported version and no security-update channel yet.

## Reporting

Open a **private security advisory** through GitHub, or contact the maintainer directly.
Please do not open a public issue for anything that would be exploitable in a real
deployment.

Useful reports include the invariant you believe is broken (they are numbered in
[`CLAUDE.md`](CLAUDE.md)) and, ideally, code that demonstrates it. A finding that has been
executed is worth considerably more than one that has been reasoned about — roughly two
thirds of the plausible-sounding findings raised against this codebase during development
did not survive being run.

## What we consider a vulnerability

Anything that breaks one of the fifteen invariants. In particular:

| Class | Why it matters |
|---|---|
| An agent obtaining or minting an authorization capability | Invariant 7: no effect happens because a model asked |
| Effects reaching the graph, vault or collection plane | Invariant 8: a compromised adapter must not be an exfiltration path |
| A stale approval executing against a changed target | The control that stops an action landing on a transferred domain |
| Evidence substitution or deletion that `verify_integrity()` misses | Invariant 10 |
| Making the platform name a natural person | The single most damaging thing this system could do |
| Inflating attribution confidence without new evidence | Provenance laundering, duplicate-source leverage, base-rate manipulation |
| Collected content changing what the engine *does* rather than what it *knows* | Invariant 5: external content is data, never instruction |

The last two are the interesting ones and the reason this file exists. NEMESIS can be
attacked without being broken into: an adversary who cannot get in can still win by making
it believe the wrong thing, and that outcome is worse than an outage because it is
invisible and it gets acted on.

## What is knowingly not defended yet

Listed so nobody reports them as discoveries, and so nobody mistakes them for solved:

- **Process isolation is macOS-only, and its mechanism is deprecated.** Effects operations
  and hostile-content collectors *do* run in confined child processes — measured, not
  asserted: a full reference run puts every dark-web pivot in a child with
  `separate_process=True`, `reaches_platform=False`. But the enforcement is `sandbox-exec`,
  which exists on no other platform and is on Apple's deprecation path, and CI runs Ubuntu —
  so **CI never exercises the kernel-enforced form at all**. Elsewhere invariant 8 falls back
  to static import contracts, which constrain an import graph and stop no subprocess or
  socket. Landlock or seccomp-bpf is the direction; neither is built.
- **Insider tampering, and the rollback it enables.** No external anchor exists. The vault
  reports `is_defensible_against_insider = False` itself rather than implying integrity it
  does not have — and the same boundary is now *measured* on the authorization store:
  deleting the newest revocation is undetected, deleting the newest debit restores spent
  autonomy, and deleting the store file resets the budget entirely. Three strict `xfail`
  tests pin exactly where the line falls. Hash chains prove adjacency and signatures prove
  authenticity of surviving records; neither proves freshness or completeness.
- **Revocation forgery is caught; revocation *suppression* is not.** Revocations are signed
  by the issuing key and chained, so a withdrawal nobody minted is refused on `not signed by
  the issuing authority` — an attacker who rewrites a row and recomputes every hash
  downstream is still caught, because forging one needs the Ed25519 key. What remains is the
  other direction: deleting the newest link is invisible, and `verify_chain` must actually be
  run — a store nobody checks is a chain nobody reads.
- **Quarantine decides what may pass; it does not yet decide where parsing happens.**
  Collected bytes now go through quarantine before the vault — measured at 70 artifacts
  quarantined and 70 sealed in a reference run, with material carrying a reporting
  obligation held and never sealed. But the shipped analyser runs in the calling process and
  reports `confined=False`. Nothing opens untrusted documents today because collectors are
  fixtures; a deployment wiring a real source supplies an analyser that runs under a real
  sandbox.
- **Tool and MCP supply chain.** An agent's tools are trusted implicitly.
- **Confidence calibration.** No figure the system produces has been validated against a
  known-correct answer, and none can be until a corpus of resolved cases exists.

Full detail, including the attack classes each control is meant to stop, is in
[`THREAT_MODEL.md`](docs/architecture/THREAT_MODEL.md).

## Scope limits

This repository contains no offensive capability and we will not accept contributions that
add any. Operation classes requiring lawful authority exist as declared interfaces with no
implementation, and two tests act as tripwires on that boundary. If you have a use case
that needs one implemented, that is a conversation about legal authority and jurisdiction
before it is a pull request.
