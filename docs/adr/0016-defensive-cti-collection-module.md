# ADR-0016: A defensive-CTI collection module wrapping the local `cti-toolkit`

- Status: accepted (with one founder decision left open — see below)
- Date: 2026-09-14
- Supersedes: none
- Related: ADR-0007 (process isolation), the D-egress entry in `FOUNDER_DECISIONS.md`,
  invariants 1, 5, 6, 13, 15; the CTI register in `docs/security/INVARIANTS.md`

## Context

A defensive team runs a local CTI toolkit alongside NEMESIS (`~/cti-toolkit`): a local model
(CyberTiel-Coder, MLX) for triage and RAG, a knowledge base of crawled dark-web actor cards
(`kb/actor-*.md`), and passive-collection scripts. This is **defensive OSINT** — passively
observing what threat actors have *already published* about a monitoring subject (ransomware DLS
posts, onion listings, forum/market pages). The subject needs no authorization because it is never
contacted; this is the collection plane's existing "operator-allowlisted, kernel-confined,
off-by-default egress" pattern, extended, not the offensive `redteam` path.

The question was how to admit that toolkit's capabilities into NEMESIS without breaking the
invariants, and without duplicating what the collection plane already covers.

## Decision

Four modules under `nemesis.collect` (the only plane holding network capability), each modelled on
the existing real connectors and adapters rather than on `SimulatedConnector`:

1. **`ransomlook.py` — `RansomLookConnector`.** A new sibling egress connector for the RansomLook
   aggregator (`www.ransomlook.io`). RansomLook is a genuinely distinct source from ransomware.live
   — a different maintainer, dataset, and response shape (`GET /api/group/<name>` returns a
   two-element `[group, posts]` array, verified against the project's own API source). It reuses
   `PivotType.THREAT_INTEL_LOOKUP` over `EntityType.THREAT_ACTOR`, the pinned-host + injectable
   transport + `NEMESIS-EGRESS-ALLOWED` pattern, and the `collect_confined` path. Each post becomes
   a *third-party report of an adversary's own claim* (`TARGETED`, hostile, deception-assessed),
   never a confirmed compromise. Off by default, wired into no registry.

2. **`cti_kb.py` — `parse_cti_kb`.** The KB-card sibling of `parse_deepdarkcti`: operator KB cards
   (untrusted text, no I/O, no fetch) become reviewable `OnionService` *candidates* for
   `TorOnionConnector`'s allowlist. Every onion is re-validated through the v3-checksum gate; cards
   carrying embedded credentials or naming illegal content are dropped and counted; leak-site
   candidates are `MANDATORY_REPORT`. A proposal, never an allowlist and never a reach.

3. **`cybertiel.py` — `ingest_model_assessment` / `triage_row_to_assessment`.** The local model's
   *output* (produced out of process; the model SDKs are never imported) enters as a
   `Claim` of kind `HYPOTHESIS`/`INFERENCE`, `derivation=MODEL_ASSERTION`, with `model_identifier`
   set and a `DeceptionAssessment` attached. Invariant 1 in `Claim`'s validator makes it impossible
   for this to become an observation or fact. A human-identity subject or object is refused.

4. **`cti_safety.py`.** The one shared helper: an illegal-content indicator so a record can be
   escalated to `MANDATORY_REPORT` and held.

The `TorOnionConnector` and `RansomwareLiveConnector` are **reused** where they already cover a
capability (onion snapshots, ransomware.live victim claims); the module adds only what is genuinely
new.

## Two decisions worth recording, because they cut against the task as written

### Credentials are handled by *not storing free text*, not by redaction in this plane

The brief asked the collectors to run stored excerpts through
`nemesis.core.credentials.redact_credential_material()` and to represent credentials as
`CredentialIndicator`s. Invariant **AUTH-04** — enforced by
`test_credential_containment.py::test_nothing_in_the_platform_consumes_a_credential_indicator` —
forbids any module but `core/entities.py` from importing `nemesis.core.credentials`, so that
"discovery" of a credential cannot be quietly wired to "use". `CLAUDE.md` forbids weakening that
test to make the work pass.

So the module takes the **stronger** guarantee the existing connectors already rely on: it never
stores adversary-authored free text in a human- or model-readable field. A victim name is a
normalized node key; a connector summary is a fixed template; the description is scanned for
illegal content but never stored; the model's free-text rationale is not carried into the graph at
all — only the structured assessment is. You cannot leak what you never store. Representing a
discovered credential as a keyed `CredentialIndicator` remains the engine's job behind the
independent authorization path AUTH-04 protects; a connector that one day collects real credential
*material* would extend AUTH-04 deliberately rather than reach around it. **This is flagged for the
founder**: if you want credential representation inside the collect plane, AUTH-04 must be widened
on purpose, with a test, not silently.

### A third egress connector sharpens the open "sole egress" question

Invariant 15 speaks of "the **sole** egress". There are now **three** opt-in egress connectors (Tor
onion, ransomware.live, RansomLook), all on the same disciplined mechanism class — operator-approved
target, off by default, confined by the kernel, `NEMESIS-EGRESS-ALLOWED`, wired into no registry.
The runtime *posture* is unchanged: nothing egresses unless an operator turns it on under
confinement. But the literal count moved again, and RansomLook (like ransomware.live) pins a host
while letting the pilot choose the actor queried. This is the exact tension the **D-egress** entry
in `FOUNDER_DECISIONS.md` opened; this ADR does not resolve it and does not amend invariant 15.

## Consequences

- The defensive team can drive RansomLook, feed the Tor allowlist from KB cards, and fold the local
  model's triage into the graph — all inside the confinement and epistemic boundaries.
- No default command or repository test contacts the network; the new connector ships with no
  endpoint wired and no live CI test, exactly like its two siblings.
- Two founder decisions are made visible rather than pre-empted: whether to widen AUTH-04 for
  in-plane credential representation, and the "sole egress" wording under a third connector.

## Status label

`IMPLEMENTED` for the connector and adapters (code exists, tests pass), with real collection
`REQUIRES_LEGAL_AUTHORITY` and, on non-macOS hosts, `REFUSED` for want of kernel confinement.
