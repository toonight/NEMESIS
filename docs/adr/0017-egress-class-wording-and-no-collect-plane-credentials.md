# ADR-0017: Invariant 15 reworded to "one disciplined egress class"; no collect-plane credentials

- Status: accepted
- Date: 2026-09-16
- Decides: the two founder decisions ADR-0016 surfaced (D-egress, D-credentials in `FOUNDER_DECISIONS.md`)
- Related: invariant 15 (CLAUDE.md), invariant AUTH-04 (`docs/security/INVARIANTS.md`), ADR-0016

## Context

ADR-0016 added a third opt-in egress connector (RansomLook) and, in doing so, surfaced two questions
it deliberately did not answer, recording them in `FOUNDER_DECISIONS.md`:

1. **D-egress.** Invariant 15 spoke of "the **sole** egress ... a fetch of specific URLs from an
   operator-supplied allowlist". Three egress connectors now exist, and two of them (the OSINT
   tracker readers) pin a *host* while letting the pilot choose the actor queried within it. Did
   "sole" mean a hard cap of one connector, and was a host-pin an acceptable "allowlist"?
2. **D-credentials.** Invariant AUTH-04 keeps `nemesis.core.credentials` importable by exactly one
   module, so the collection plane cannot redact or represent a discovered credential. Should
   AUTH-04 be widened to let a connector mint a keyed `CredentialIndicator`?

Both are founder decisions because they touch non-negotiable invariants, which are amended only
deliberately and with test coverage — never silently.

## Decision

### 1. Invariant 15 reworded — one disciplined egress *class*, host-pin allowed

"Sole egress" meant one disciplined egress *mechanism class*, not one connector. Invariant 15 now
reads (CLAUDE.md):

> **The MVP never acts against external infrastructure.** No scanning, no probing, no unsolicited
> contact. All egress belongs to one disciplined class — operator-approved, off by default with no
> endpoint shipped, kernel-confined and marked `NEMESIS-EGRESS-ALLOWED` — a bounded fetch of a
> pre-approved allowlist. Several connectors may instantiate that class; each pins its reach (a
> specific onion URL, or a single host whose public API is queried within it) and none is wired
> into a default registry. Everything else is synthetic.

The previous wording was:

> The sole egress is a fetch of specific URLs from an operator-supplied allowlist, off by default
> with no endpoint shipped, confined by the kernel and marked `NEMESIS-EGRESS-ALLOWED`. Everything
> else is synthetic.

What changed is only the wording; **the runtime posture and its enforcement are unchanged.** A
host-pin (e.g. `www.ransomlook.io`, queried only over its public API within that pinned host) is an
accepted allowlist form alongside per-target onion allowlisting, because a public tracker's targets
cannot be pre-enumerated.

### 2. AUTH-04 unchanged — the collection plane represents no credentials

AUTH-04 stays exactly as written. The collection plane does **not** import `nemesis.core.credentials`,
does not redact, and does not mint a `CredentialIndicator`. The posture is the stronger structural
guarantee the connectors already rely on: never store adversary-authored free text, so there is
nothing to redact and nothing to represent. Credential representation, if a future connector ever
collects real credential *material*, remains the engine's job behind AUTH-04's authorization path —
and would require a deliberate AUTH-04 amendment with its own test. This question is **closed, not
deferred.**

## Why this is not a weakening

The reworded invariant preserves every hard clause of the original: no scanning/probing/unsolicited
contact; egress only through an operator-approved, off-by-default, kernel-confined,
`NEMESIS-EGRESS-ALLOWED` allowlisted fetch; everything else synthetic. It adds two clarifications the
founder decided — several connectors on one class, and host-pin as an allowlist form — neither of
which relaxes what the platform may reach.

## Enforcement (unchanged, and it still holds)

Nothing in the invariant's enforcement depended on the word "sole", so no test changed behaviour:

- `scripts/check_prohibited.py` — network clients only inside `nemesis.collect`, each next to a
  `NEMESIS-EGRESS-ALLOWED` marker.
- `tests/invariants/test_transitive_egress.py` — every network-capable module is under
  `nemesis.collect`; no unbrokered path from a model-controlled root to egress.
- `tests/planes/test_collect.py` — every connector in the default set (`simulated_connectors()`) is
  simulated, so a real connector added to it fails; every collected fixture evidence is simulated.
- `tests/invariants/test_cti_collection.py` (CTI-02) — the real RansomLook connector is
  `is_simulated=False`, host-pinned, confined, and absent from the default registry.
- AUTH-04: `tests/invariants/test_credential_containment.py` — `nemesis.core.credentials` is
  imported by exactly `core/entities.py` and nowhere else.

## Consequences

- `FOUNDER_DECISIONS.md` D-egress and D-credentials are marked ANSWERED/RESOLVED, pointing here.
- Prose that paraphrased "sole egress" (in `check_prohibited.py`, `test_transitive_egress.py`,
  `ransomlook.py`, `docs/connectors/ransomlook.md`, ADR-0016) is aligned to the new wording.
- No code behaviour changed; no connector was added, removed, or wired into a default registry.
