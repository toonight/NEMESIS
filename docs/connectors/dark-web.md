# Tor onion snapshot connector

**Status:** implemented, opt-in, and not exercised against a real onion service by this
repository. The default demo still uses `SimulatedDarkWebConnector` exclusively.

`TorOnionConnector` takes bounded snapshots of explicitly authorized version-3 onion
services. It is deliberately not a crawler, a marketplace client, or a global search engine.
It does not authenticate, transact, post, purchase, follow redirects, download attachments, or
interpret page text. Its only claim is that the configured forum or marketplace responded at
the configured onion address at the collection instant.

## Preconditions

1. Written authority to collect the named service and a recorded purpose for the pivot.
2. A local Tor SOCKS listener, normally `socks5://127.0.0.1:9050`.
3. The optional transport installed: `uv sync --extra darkweb` or
   `pip install 'nemesis[darkweb]'`.
4. Kernel confinement. A real hostile connector refuses to fall back to a plain subprocess.
   The repository currently supplies this only through macOS `sandbox-exec`; Linux remains
   unsupported until Landlock/seccomp confinement exists.
5. An explicit `ContentSafety` classification for every target. There is no default because
   choosing `ROUTINE` silently for an unknown criminal service would be a handling decision
   disguised as configuration.

## Construction

```python
from datetime import UTC, datetime
from os import environ

from nemesis.collect.dark_web import OnionService, TorOnionConnector
from nemesis.core.entities import EntityType
from nemesis.core.evidence import ContentSafety

connector = TorOnionConnector(
    services=(
        OnionService(
            name="authorized-forum",
            entity_type=EntityType.FORUM,
            # Supply an authorized v3 address at deployment; never commit it here.
            url=environ["NEMESIS_AUTHORIZED_ONION_URL"],
            content_safety=ContentSafety.SENSITIVE_PERSONAL_DATA,
        ),
    ),
    as_of=datetime.now(UTC),
)
```

Pass the connector through the ordinary `ConnectorRegistry` and pursuit path. Do not call
`pivot()` directly in production: `collect_confined()` is the shared decision that rebuilds
the connector in the isolated worker. The allowlist, proxy address, timeout and byte ceiling
cross that pipe as non-secret configuration; credentials are rejected from both target and
proxy URLs.

The corresponding request uses `PivotType.DARK_WEB_SNAPSHOT`, the configured entity type and
the configured logical name. An unlisted name fails before the network transport is called.

## What is preserved

- the raw response body, capped at 2 MiB by default and 5 MiB at the hard maximum (leaving
  room for base64 and provenance inside the worker's 8 MiB output ceiling);
- the exact onion URL, HTTP status, media type, Tor proxy and collection instant in provenance;
- a `WEB_PAGE_SNAPSHOT` evidence object, marked non-simulated and non-redistributable;
- a direct observation linking the forum or marketplace to its onion service address;
- an explicit deception assessment saying the service operator controls every returned byte.

Only `text/html`, `application/xhtml+xml` and `text/plain` are accepted. Redirects,
attachments, compressed bodies, clearnet URLs, v2 onion addresses, invalid v3 checksums,
credential-bearing URLs, remote SOCKS proxies and oversized responses fail closed.

## Deliberate limits

- No content parser ships. The page can establish reachability, not authorship, identity,
  ownership, truth, or marketplace activity.
- No credential or session support exists. Adding one changes both the authorization and
  sanctions posture and requires a separate design review.
- No real endpoint is included and no live integration test runs in CI.
- `StructuralAnalyser` still reports `confined=False`; quarantine is a release gate, not a
  sandboxed content-analysis implementation. The connector itself avoids parsing the body,
  but a deployment adding a parser must supply a confined analyser.
- Real collection makes external contact and may create legal, privacy, sanctions and
  mandatory-reporting obligations. Code cannot decide that authority for its operator.
