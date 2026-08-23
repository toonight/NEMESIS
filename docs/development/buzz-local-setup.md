# Standing up a Buzz relay, and pointing NEMESIS at it

**Status:**
`IMPLEMENTED` — the Buzz wire format (NIP-01 event ids, NIP-29 groups, NIP-42 auth events,
the relay's `OK`-prefix vocabulary), `nemesis.collaboration.providers.buzz`.
`IMPLEMENTED` — the local filesystem provider, which is the default and needs no setup.
`REQUIRES_EXTERNAL_DATA` — a reachable relay. **NEMESIS ships no transport and no signer.**
As shipped, `BuzzCollaborationProvider` cannot open a socket and cannot produce a signature.
Every byte it would send is constructed, validated and tested; nothing sends them.

Nothing in this repository has ever contacted a Buzz relay. Read the whole of the NEMESIS
half of this document as *correct in shape and unconfirmed on the wire*.

---

## What you are actually turning on

NEMESIS does not need a collaboration backend. The pursuit engine runs, the pilot flies, the
gateway authorizes and the vault seals with nothing behind this plane — see the module
docstring of `src/nemesis/collaboration/base.py`, which states the property the interface
exists to preserve. Turning on Buzz gives you one thing: NEMESIS's projected events land in
a chat room humans can read, and replies to an approval request come back as *readings of
untrusted text*.

It gives you nothing else, and in particular it does not give the relay any authority. A
message in a channel never becomes an authorization; see
[the trust model](../security/agent-trust-model.md) and `DecisionIntake.authorizes` in
`src/nemesis/collaboration/approvals.py`, which returns `False` unconditionally.

For *why* the plane is shaped this way, read
[ADR-0010](../adr/0010-buzz-as-an-optional-collaboration-provider.md) and
[the integration overview](../architecture/buzz-integration.md). This document is the
operator recipe; those two are the decision and the shape.

---

## Part 1 — a self-hosted Buzz relay

Ground truth below is taken from the `block/buzz` source and its `deploy/compose/compose.yml`.

### Services and ports

| Service | Image | Purpose |
|---|---|---|
| `relay` | `ghcr.io/block/buzz:main` | the relay itself |
| `postgres` | `postgres:17-alpine` | event storage |
| `redis` | `redis:7-alpine` | ephemeral state |
| `minio` | MinIO | S3-compatible media store |
| `mc` bucket init | MinIO client | one-shot job that creates the bucket and exits |

The relay listens on **`:3000`** (`BUZZ_BIND_ADDR`), serves health on **`:8080`**
(`/_readiness`) and Prometheus metrics on **`:9102`**.

### Environment

**Required — the stack will not come up without them:**

```
POSTGRES_PASSWORD
REDIS_PASSWORD
BUZZ_S3_ACCESS_KEY
BUZZ_S3_SECRET_KEY
```

**Optional:**

| Variable | Default | Notes |
|---|---|---|
| `BUZZ_S3_BUCKET` | `buzz-media` | |
| `BUZZ_AUTO_MIGRATE` | `false` | leave off in anything you care about; run migrations deliberately |
| `BUZZ_HTTP_PORT` | — | the HTTP bridge port |

### The dev relay key is a real deployment hazard — read this one

`BUZZ_RELAY_PRIVATE_KEY` **must be set in production**. If it is unset and
`BUZZ_REQUIRE_AUTH_TOKEN=false`, the relay falls back to a **hardcoded development key,
`0x00…01`**.

Stated plainly: *every* Buzz deployment left in that configuration shares one relay identity,
and anyone who has ever read the source can forge relay-signed events that your deployment
will accept as the relay's own. For an investigation deployment this is not a
development convenience, it is an unauthenticated write path into the room where your
approval requests live.

Set `BUZZ_RELAY_PRIVATE_KEY` from your secret store, on the first deployment, before anyone
joins the channel.

### Authentication: NIP-42, mandatory

- The relay pushes `["AUTH", <challenge>]` as the **first frame** on the socket.
- You have **5 seconds** to answer before the connection is cancelled.
- The auth event is kind **22242**, and its `created_at` must be within **±60 seconds** of the
  relay's clock.
- The `relay` tag must **normalise-equal** the relay's own configured URL. The relay folds
  `localhost` and `::1` to `127.0.0.1` and strips a trailing slash before comparing.

NEMESIS implements that normalisation itself, in `normalize_relay_url()` in
`src/nemesis/collaboration/providers/buzz/wire.py`, precisely so the tag you send matches the
tag the relay computes. A client that skips it sends a tag that looks correct to a human and
fails the comparison, surfacing as the generic `auth-required: verification failed`.

**Signatures are BIP-340 Schnorr over secp256k1. They are not Ed25519.** This is the single
most common way an integration written from memory fails.

### The two gates you should turn on

Both default to **`false`**:

| Variable | Default | Turn on for an investigation deployment |
|---|---|---|
| `BUZZ_PUBKEY_ALLOWLIST` | `false` | **yes** |
| `BUZZ_REQUIRE_RELAY_MEMBERSHIP` | `false` | **yes** |

Why, concretely. With both off, any keypair that can reach the socket can authenticate and
write. A collaboration channel carrying NEMESIS approval notices is a list of what an
investigation is about to do, against which targets, with a close time — it is targeting
intelligence for the adversary being investigated, and it is an invitation to flood the
channel with plausible-looking replies. The allowlist makes the participant set a decision
somebody made; membership makes channel writes require that decision too.

Neither gate protects the *content*: `ChannelVisibility.RESTRICTED` is enforced by a
server-side access list over plaintext storage, which keeps out other workspace members and
does not keep out the relay operator. `src/nemesis/collaboration/base.py` names this
explicitly, and it is why NEMESIS publishes **references** (`evidence://case/evd_sha256-…`)
rather than material into channels of either visibility.

### Membership

Either with the `buzz-admin` CLI:

```
buzz-admin add-member    --pubkey <hex>
buzz-admin remove-member --pubkey <hex>
buzz-admin list-members
```

…or with NIP-43 admin events, kinds **9030 / 9031 / 9032**.

NEMESIS itself adds channel participants with NIP-29 kind **9000** (`build_add_user`), which
is a different thing: that is group membership inside a channel, not relay membership.

### The HTTP bridge

The relay also exposes `POST /events`, `/query` and `/count`, authenticated with **NIP-98**
(kind **27235**, sent as `Authorization: Nostr <base64 event>`).

This avoids the 5-second socket deadline entirely, which makes it the easier target for a
first transport implementation — a request/response call has no handshake race to lose. It
is a reasonable place to start if your first WebSocket attempt keeps timing out during auth.

### Size caps

| Limit | Value | Advertised via NIP-11? |
|---|---|---|
| Event `content` at ingest | **256 KiB** | no |
| WebSocket frame | **512 KiB** | **yes** |

Only the frame cap is advertised. A well-behaved client can therefore build a frame the relay
accepts, carrying an event the relay rejects. NEMESIS checks the content cap locally —
`MAX_CONTENT_BYTES` in `wire.py` — so you get a useful local error rather than an opaque
`OK false`. (In practice a NEMESIS envelope is nowhere near either cap: `summary` is capped at
2000 characters and payload values at 500.)

---

## Part 2 — the NEMESIS half

### What you must supply

Two Protocols, both declared in
`src/nemesis/collaboration/providers/buzz/transport.py`, both shipped with a refusing default
(`UnwiredBuzzTransport`, `UnwiredEventSigner`):

```python
class EventSigner(Protocol):
    @property
    def public_key_hex(self) -> str: ...  # x-only pubkey, 64 lowercase hex chars
    def sign(self, digest: bytes) -> str: ...  # 32-byte digest in, 128 hex chars out


class BuzzTransport(Protocol):
    async def publish(self, event: Mapping[str, object]) -> PublishOutcome: ...
    async def query(self, filters: Sequence[Mapping[str, object]]) -> RelayQueryResult: ...
    async def health(self) -> bool: ...  # must not raise
```

**Why NEMESIS ships neither.** Invariant 15 confines network capability to the collection
plane behind an explicit `NEMESIS-EGRESS-ALLOWED` marker, and `scripts/check_prohibited.py`
fails the build on an import of any of ~30 network modules (`httpx`, `websockets`, `socket`, …)
from anywhere outside `nemesis.collect`. A collaboration plane holding a WebSocket client
would either break that check or require weakening it. Separately, `cryptography>=44` — the
project's only crypto dependency — provides Ed25519 and secp256k1 ECDSA and **does not provide
BIP-340**, so signing would mean either a new binary dependency or a vendored curve
implementation in a security-sensitive tree.

The consequence is deliberate: the two implementations below **live outside this repository**,
in your own deployment package. Adding them to `src/nemesis/` will fail the prohibited-imports
check, and that is the check working.

### An operator-side signer

> **Operator-side example. This file belongs in your deployment package, not in the NEMESIS
> tree.**

`coincurve` is the usual BIP-340 option in Python. No version is pinned here on purpose —
pick and pin one in your own dependency set, and audit it the way you would audit any code
that holds a private key.

```python
"""nemesis_deploy/buzz_signer.py — operator-supplied. NOT part of the NEMESIS tree."""

from __future__ import annotations

from coincurve import PrivateKey


class CoincurveEventSigner:
    """A BIP-340 Schnorr signer over secp256k1, satisfying nemesis ... transport.EventSigner.

    Holds one identity. The private key never reaches NEMESIS: the plane hands this object a
    32-byte digest and receives hex back, which is the same discipline
    `nemesis.authz.keys.CapabilitySigningKey` applies to the capability key.
    """

    def __init__(self, secret_key_hex: str) -> None:
        self._key = PrivateKey(bytes.fromhex(secret_key_hex))

    @property
    def public_key_hex(self) -> str:
        # Nostr wants the x-only key: the 33-byte compressed form without its parity byte.
        return self._key.public_key.format(compressed=True)[1:].hex()

    def sign(self, digest: bytes) -> str:
        if len(digest) != 32:
            raise ValueError(
                f"a Nostr signing digest is exactly 32 bytes, got {len(digest)}; "
                "pass UnsignedEvent.signing_digest() unmodified"
            )
        return self._key.sign_schnorr(digest).hex()
```

You never compute the digest yourself. `UnsignedEvent.signing_digest()` in `wire.py` does it —
SHA-256 over the ordered NIP-01 array `[0, pubkey, created_at, kind, tags, content]`, with tag
order preserved — so an implementation cannot get NIP-01's serialization rules wrong, because
it never sees them.

### An operator-side transport

> **Operator-side example. This file belongs in your deployment package, not in the NEMESIS
> tree.** It is a skeleton: no reconnection policy, no rate limiting, no metrics. Treat it as
> a starting shape, not a production client.

```python
"""nemesis_deploy/buzz_transport.py — operator-supplied. NOT part of the NEMESIS tree."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable, Mapping, Sequence

import websockets

from nemesis.collaboration.providers.buzz.transport import PublishOutcome, RelayQueryResult
from nemesis.collaboration.providers.buzz.wire import NostrEvent

AUTH_DEADLINE_SECONDS = 5.0  # the relay cancels the connection after this
OK_DEADLINE_SECONDS = 15.0


class WebsocketBuzzTransport:
    """Carries frames to one Buzz relay. Connects per call.

    Per call, not once: `CollaborationProvider` requires that a provider hold no session,
    credential or roster across calls, because a cached one is the ambient authority the
    effects plane is forbidden. A pooled socket is a decision you are making, not one NEMESIS
    made for you — and it reintroduces standing network reach into a long-lived process.
    """

    def __init__(self, relay_url: str) -> None:
        self._relay_url = relay_url
        self._auth_event: Callable[..., NostrEvent] | None = None

    def bind(self, auth_event: Callable[..., NostrEvent]) -> None:
        """Take BuzzCollaborationProvider.auth_event — the builder, not the provider.

        Only the bound method is handed over, so the transport cannot reach the provider's
        signer, its clock or anything else it holds.
        """
        self._auth_event = auth_event

    async def _authenticated(self):
        if self._auth_event is None:
            raise RuntimeError("transport was never bound to an auth-event builder")
        socket = await websockets.connect(self._relay_url, max_size=512 * 1024)
        try:
            # The relay pushes ["AUTH", <challenge>] as the FIRST frame.
            frame = json.loads(await asyncio.wait_for(socket.recv(), AUTH_DEADLINE_SECONDS))
            if not (isinstance(frame, list) and frame and frame[0] == "AUTH"):
                raise RuntimeError(f"expected an AUTH challenge as the first frame, got {frame!r}")
            challenge = frame[1]

            # Build and sign kind 22242. NEMESIS normalises the relay tag and stamps
            # created_at; both must satisfy the relay's +/-60s window and URL comparison.
            event = self._auth_event(challenge=challenge)
            await socket.send(json.dumps(["AUTH", event.to_wire()]))

            reply = json.loads(await asyncio.wait_for(socket.recv(), AUTH_DEADLINE_SECONDS))
            if not (isinstance(reply, list) and reply[0] == "OK" and reply[2] is True):
                raise RuntimeError(f"relay refused authentication: {reply!r}")
            return socket
        except BaseException:
            await socket.close()
            raise

    async def publish(self, event: Mapping[str, object]) -> PublishOutcome:
        socket = await self._authenticated()
        try:
            await socket.send(json.dumps(["EVENT", event]))
            while True:
                frame = json.loads(await asyncio.wait_for(socket.recv(), OK_DEADLINE_SECONDS))
                if isinstance(frame, list) and frame and frame[0] == "OK":
                    _, event_id, accepted, message = (list(frame) + [""])[:4]
                    # Carry the relay's message VERBATIM. Its prefix -- duplicate:,
                    # restricted:, invalid:, auth-required: -- is what the provider
                    # classifies on, and paraphrasing it loses the distinction.
                    return PublishOutcome(
                        accepted=bool(accepted), event_id=str(event_id), message=str(message)
                    )
        finally:
            await socket.close()

    async def query(self, filters: Sequence[Mapping[str, object]]) -> RelayQueryResult:
        socket = await self._authenticated()
        subscription = uuid.uuid4().hex
        events: list[Mapping[str, object]] = []
        reached_end = False
        try:
            await socket.send(json.dumps(["REQ", subscription, *filters]))
            while True:
                frame = json.loads(await asyncio.wait_for(socket.recv(), OK_DEADLINE_SECONDS))
                if not isinstance(frame, list) or not frame:
                    continue
                if frame[0] == "EVENT" and frame[1] == subscription:
                    events.append(frame[2])  # raw wire object; NEMESIS validates it
                elif frame[0] == "EOSE" and frame[1] == subscription:
                    reached_end = True
                    break
                elif frame[0] == "CLOSED" and frame[1] == subscription:
                    break
            await socket.send(json.dumps(["CLOSE", subscription]))
        finally:
            await socket.close()
        return RelayQueryResult(events=tuple(events), reached_end=reached_end)

    async def health(self) -> bool:
        """Must not raise -- CollaborationProvider.health() promises a bool."""
        try:
            socket = await self._authenticated()
        except Exception:
            return False
        await socket.close()
        return True
```

Two contract points worth stating, because getting them wrong changes NEMESIS's behaviour
rather than producing an error:

- `query()` returns **raw wire objects**, not `NostrEvent`. That is deliberate: validating
  inside the transport would let the transport decide what a well-formed event is. NEMESIS
  parses on its own side of the boundary, where a malformed event becomes an `UNPARSEABLE`
  inbound signal instead of an exception in your HTTP client.
- `reached_end` must be `False` if the relay never sent `EOSE`. It means "the answer was
  truncated", and a caller must not read absence as absence.
- `publish()` and `query()` may raise. `BuzzCollaborationProvider.publish` turns an arbitrary
  exception into a `REFUSED_UNAVAILABLE` receipt and `poll` returns an empty sequence.
  `health()` must not raise.

### The NIP-42 handshake, as a sequence

What a transport must perform, in order, for every connection:

1. Open the WebSocket to the relay URL.
2. Read the **first** frame. It is `["AUTH", <challenge>]`.
3. Call `provider.auth_event(challenge=challenge)`. That method
   (`src/nemesis/collaboration/providers/buzz/provider.py`) builds a kind-22242 event with
   `("relay", normalize_relay_url(relay_url))` and `("challenge", challenge)` tags, stamps
   `created_at` from the provider's clock, computes the NIP-01 id and signs it through your
   `EventSigner`. It raises `ProviderConfigurationError` if no `relay_url` was configured.
4. Send `["AUTH", <the signed event as a wire dict>]` **immediately**. The 5-second deadline
   started at step 2.
5. Read the `["OK", <id>, true|false, <message>]` reply. Only after `true` may you send
   `EVENT` or `REQ`.

The split exists because the handshake belongs to whoever owns the socket, while the event's
construction belongs in NEMESIS where it is tested with no relay, no network and no credential.

### Wiring it together

```python
import os

from nemesis.collaboration.providers.buzz.provider import BuzzCollaborationProvider

from nemesis_deploy.buzz_signer import CoincurveEventSigner
from nemesis_deploy.buzz_transport import WebsocketBuzzTransport

relay_url = os.environ["NEMESIS_BUZZ_RELAY_URL"]  # e.g. ws://127.0.0.1:3000

transport = WebsocketBuzzTransport(relay_url)
signer = CoincurveEventSigner(os.environ["NEMESIS_BUZZ_SECRET_KEY"])

provider = BuzzCollaborationProvider(relay_url=relay_url, transport=transport, signer=signer)
transport.bind(provider.auth_event)

assert provider.is_wired  # False if either Protocol was left at its default
```

`is_wired` exists so a deployment can *assert* its posture rather than infer it from whether
messages appear. `relay_url` has no default and no environment fallback inside NEMESIS —
an endpoint picked up from an unset variable is an endpoint nobody chose.

`nemesis.collaboration.providers.registry.build_provider("buzz", relay_url=…, transport=…,
signer=…)` is the equivalent by name, and fails closed on a name it does not recognise: a
deployment that typed `buzzz` gets `UnknownCollaborationProviderError`, not a silent fallback
to writing files.

---

## Running with the local provider instead — the default, no setup at all

```python
from nemesis.collaboration.providers.registry import build_provider

provider = build_provider("local", root="/var/lib/nemesis/collaboration")
```

or directly:

```python
from nemesis.collaboration.providers.local import LocalCollaborationProvider

provider = LocalCollaborationProvider("/var/lib/nemesis/collaboration")
```

This is not a stub. Projected events keep their epistemic standing, approval notices carry
their proposal digest, inbound replies are read as decision intents, and all of it is durable.
It happens in a directory instead of a chat room: one append-only JSONL file per channel under
`channels/`, one per channel under `inbox/`.

`LocalCollaborationProvider.deliver_inbound()` is the local analogue of a human typing in a
chat window — that is how the approval flow is exercised end to end in CI without a relay.
`published(channel_key)` reads a channel back.

The local provider reaches no network and holds no credential, and has no configuration that
could give it either. It is the mode every test runs in, and the honest offline mode: the
simulation is a *different object* rather than a flag on the remote provider that somebody can
forget to set.

### What the CLI gives you

```
nemesis collab-providers        # the backend table, printed from the registry itself
nemesis collaborate [--workspace DIR]
```

`nemesis collaborate` runs the whole flow — channels opened, events published with their
standing intact, an approval notice with its digest, replies read back as decision intents —
and stops at the authorization boundary. It is synthetic throughout and contacts nothing:
`run_collaboration_demonstration` in `src/nemesis/collaboration/demonstration.py` constructs a
`LocalCollaborationProvider` directly. The point of the run is what it refuses to do at the end.

`nemesis collab-providers` prints `PROVIDERS` from the registry, so the table cannot drift from
the code.

**There is no CLI flag that selects the Buzz provider, and no configuration file for one.**
`nemesis collaborate` is hardcoded to the local provider, and `build_provider` has no caller in
`src/` outside its own module. Pointing NEMESIS at a relay is something a composition root
writes in Python, using the wiring shown above. Do not document it to your operators as a
setting.

---

## Troubleshooting

| Symptom | What it usually is | NEMESIS-side status |
|---|---|---|
| `auth-required: verification failed` | Clock skew: the auth event's `created_at` is outside the relay's ±60s window. Check NTP on **both** ends first — it is the most common cause and the least visible. | `REFUSED_UNAUTHENTICATED` |
| `auth-required: verification failed` | Wrong `relay` tag: your URL does not normalise-equal the relay's configured URL. `localhost` and `::1` fold to `127.0.0.1`, trailing slash stripped. Compare `normalize_relay_url(your_url)` against the relay's config, not against what you typed. | `REFUSED_UNAUTHENTICATED` |
| `auth-required: verification failed` | Your pubkey is not on `BUZZ_PUBKEY_ALLOWLIST` (if you enabled it, as recommended). The relay does not distinguish this from the other two in its message. | `REFUSED_UNAUTHENTICATED` |
| `restricted: unknown event kind` | You minted a kind outside the relay's ingest map. NEMESIS never does — a collaboration event travels as an ordinary NIP-29 kind-9 group message. If you see this, something outside `wire.py` built the event. | `REFUSED_REJECTED` |
| `restricted: not a channel member` | The publishing key was never added to the group. Add it with NIP-29 kind 9000 (`build_add_user`), or via `buzz-admin` / NIP-43 for relay membership. Note these are two different memberships. | `REFUSED_REJECTED` |
| `duplicate:` | **This is a success.** The relay already holds this event id. That is exactly what a content-addressed identifier is for, and a retry landing here has done its job. | `DUPLICATE` — `receipt.succeeded` is `True`, and the outbox marks the record `DELIVERED` |
| HTTP **404** on the WebSocket upgrade | The `Host` header does not map to a configured community. You are reaching the relay process but not any workspace it serves. Check the vhost/community mapping, and that your client sends the `Host` the relay expects — an IP literal often will not. | transport exception → `REFUSED_UNAVAILABLE` (retryable) |
| `TransportNotWiredError` / `SignerNotWiredError` | No transport or no signer was injected. This **raises**, deliberately: a quiet "unavailable" would be indistinguishable from an outage, and the difference is a deployment that believes it is publishing and is not. | raises — not a receipt |
| Nothing published for ten minutes, no errors | The outbox circuit breaker is open. `outbox.breaker.describe()` says since when, after how many consecutive failures, and when it will retry. | `Outbox.due()` returns `()` while open |
| An event stuck, then gone quiet | It exhausted its attempts (default 6, exponential backoff from 5s to 900s) and moved to `DEAD_LETTER`. It is still on disk with the last failure's detail: `outbox.dead_letters()`. | `DEAD_LETTER` |

---

## Secrets

**Never in source, prompts, messages, git, logs or tests.** The Nostr secret key, the Postgres
and Redis passwords, and the S3 credentials are environment variables read at the composition
root, and nothing else.

- This repository has **no `.env.example`** today. `.gitignore` ignores `.env` and `.env.*`
  while un-ignoring `.env.example`, so the slot exists and the file does not. Any Buzz
  credentials belong in **your own secret store** — the operator's vault, the orchestrator's
  secret mechanism — not in a template committed here.
- The private key never enters the collaboration plane. Your `EventSigner` holds it; NEMESIS
  hands that object a 32-byte digest and receives hex. Same discipline as
  `nemesis.authz.keys.CapabilitySigningKey`.
- Do not log the signed event wholesale while debugging. The `sig` field is not secret, but
  the habit of dumping wire frames is how the adjacent `AUTH` frame ends up in a log too.
- A relay identity is an identity: rotating the Nostr key changes who the workspace sees, and
  `ActorRegistry` will refuse to rebind an actor to a second key
  (`DuplicateBindingError`) rather than make a week of channel history read as two
  participants who are one.

---

## See also

- `src/nemesis/collaboration/base.py` — the provider seam, and the four verbs deliberately
  absent from it.
- `src/nemesis/collaboration/providers/buzz/wire.py` — the four relay constraints the format
  is built around, each with the silent failure it would otherwise cause.
- `src/nemesis/collaboration/outbox.py` — durability, backoff, dead letters, circuit breaker.
- [ADR-0010](../adr/0010-buzz-as-an-optional-collaboration-provider.md) — why a collaboration
  backend is a provider rather than a dependency, and why the transport ships unwired.
- [`docs/architecture/buzz-integration.md`](../architecture/buzz-integration.md) — the shape of
  the integration, the channel topology, and what is deliberately not built.
- [`docs/security/agent-trust-model.md`](../security/agent-trust-model.md) — why a signed
  message in a channel is not an authorization.
- `tests/invariants/test_collaboration_boundary.py` — the four properties this plane is held
  to, asserted rather than described.
