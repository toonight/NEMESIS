# RansomLook OSINT connector

**Status:** `IMPLEMENTED`, opt-in, and not exercised against the real aggregator by this
repository. It ships with no endpoint wired into any registry and no live CI test; real collection
is `REQUIRES_LEGAL_AUTHORITY` and, on non-macOS hosts, `REFUSED` for want of kernel confinement.

`RansomLookConnector` reads the public [RansomLook](https://www.ransomlook.io) aggregator for the
victims a threat actor has *claimed* on its leak site. It is the sibling of
[`RansomwareLiveConnector`](../architecture/PROJECT_STATE.md) and is deliberately narrow: it asks
one bounded question over clearnet HTTPS, follows no redirects, accepts only JSON, and bounds both
time and bytes.

## Why a second tracker rather than reusing ransomware.live

RansomLook is a genuinely distinct source, not a base-URL swap:

- a different project and maintainer, scraping an overlapping but not identical set of leak sites;
- a different response shape — `GET /api/group/<name>` returns a two-element array `[group, posts]`
  (the crew's own leak-site `locations`, then the list of claimed-victim posts), verified against
  RansomLook's own API source, not guessed.

It reuses everything reusable: `PivotType.THREAT_INTEL_LOOKUP` over `EntityType.THREAT_ACTOR`, the
pinned-host + injectable-transport + `NEMESIS-EGRESS-ALLOWED` pattern, and the `collect_confined`
isolation path. A defender wants both trackers because they disagree often enough to matter.

## What it observes, and what it does not

Every record is a **third-party report of an adversary's own claim**. The statement is
`threat_actor X TARGETED organization Y`, qualified `content_is_hostile=true`,
`pivot_method=external_reporting`, `reported_by=ransomlook.io`, with a `DeceptionAssessment`
(`adversary_could_plant=True`, `planting_cost=trivial`) on every record. A ransomware crew inflates,
recycles and fabricates victim listings, so "the group said it" is never "the breach happened", and
the connector never promotes a listing into a confirmed compromise. It interprets no free-text field
as instruction (invariant 5): the victim name is a normalized node key, the summary is a fixed
template, and the description is scanned for illegal content but never stored.

`SourceClass.OPEN_SOURCE` with `FAIRLY_RELIABLE` grades the *aggregator's faithful relaying*, not
the crews it relays; the hostility of the content travels in the deception assessment and the
qualifier. `upstream_of_record` is `osint:ransomlook.io`, so a corroboration pass treats it as a
distinct aggregator channel rather than falsely independent of ransomware.live.

## Content safety

Tracker records are `SENSITIVE_PERSONAL_DATA` by default (a victim *listing* is aggregated metadata,
which is how ransomware.live classifies the same thing). A listing whose free text carries an
illegal-content indicator is escalated to `MANDATORY_REPORT` for that record —
`must_not_be_indexed` becomes true, quarantine holds it with no automated exit, and the engine opens
the reporting obligation downstream. The collect plane cannot write the vault (`build_observation`
leaves `vault_locator` unset); no leaked data is stored, because the tracker returns listings, not
dumps.

## Preconditions and construction

1. Written authority to collect from the aggregator and a recorded purpose for the pivot.
2. The optional transport installed: `uv sync --extra darkweb` or `pip install 'nemesis[darkweb]'`.
3. Kernel confinement (macOS `sandbox-exec`); a real hostile connector refuses a plain subprocess.

```python
from datetime import UTC, datetime

from nemesis.collect.ransomlook import RansomLookConnector

connector = RansomLookConnector(as_of=datetime.now(UTC))  # host defaults to www.ransomlook.io
```

Do not call `pivot()` directly in production: route it through `collect_confined()`, which rebuilds
the connector in the isolated worker from non-secret configuration (base URL, timeouts, ceilings —
never credentials). A request uses `PivotType.THREAT_INTEL_LOOKUP`, `EntityType.THREAT_ACTOR`, and
the group name as the entity key; an unsafe key never reaches the transport.

## Deliberate limits

- No content parser ships. The record establishes only that the aggregator reported a listing.
- Host-pinned to `www.ransomlook.io` / `ransomlook.io` over HTTPS; a redirect, a host-swapped final
  URL, a non-JSON body, an unexpected shape, or an oversized response all fail closed.
- No endpoint is wired and no live integration test runs in CI.
- Being a third egress connector, it puts invariant 15's "sole egress" wording under further strain
  — see the **D-egress** entry in `docs/architecture/FOUNDER_DECISIONS.md`. The posture (off by
  default, confined, unwired) is unchanged; the wording is a founder decision.
