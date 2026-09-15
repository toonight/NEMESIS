"""A real, deliberately narrow OSINT connector for the RansomLook aggregator.

``ransomlook.io`` is a public, open-source ransomware-intelligence aggregator (a genuinely
distinct project from ``ransomware.live``: a different maintainer, a different dataset, and a
different response shape). It scrapes ransomware leak sites and republishes, per group, the
victims each crew has *claimed*. This connector asks one bounded question of its public API —
"which victims has this threat actor claimed?" — over clearnet HTTPS, follows no redirects,
accepts only a JSON response, and bounds both time and bytes.

**Why a second tracker rather than reusing**
:class:`~nemesis.collect.ransomware_live.RansomwareLiveConnector`.
The two aggregators scrape overlapping but not identical sets of leak sites and disagree often
enough that a defender wants both; and RansomLook's route returns a different structure —
``GET {base}/group/<name>`` yields a two-element array ``[group, posts]`` where ``group`` carries
the crew's own leak-site ``locations`` and ``posts`` is the list of claimed-victim entries. Parsing
that faithfully is why this is a sibling and not a base-URL swap. It reuses everything that can be
reused: the same ``PivotType.THREAT_INTEL_LOOKUP`` over ``EntityType.THREAT_ACTOR``, the same
pinned-host + injectable-transport + ``NEMESIS-EGRESS-ALLOWED`` pattern, and the same confinement
path. Only the host and the response parsing differ.

**What it observes, and what it does not.** Every record it emits is a *third-party report of an
adversary's own claim*. The statement is ``threat_actor X TARGETED organization Y``, qualified as
external reporting and as hostile content, with a
:class:`~nemesis.core.claims.DeceptionAssessment` on every record: a ransomware crew inflates,
recycles and fabricates victim listings, so "the group said it" is never "the breach happened".
The connector interprets none of the free-text fields as instruction (invariant 5) and never
promotes a listing into a confirmed compromise. The victim name is a normalized node key and the
statement prose is a fixed template — no adversary text reaches a human-readable claim field — but,
exactly as ransomware.live does, a few **bounded** adversary field values (the listed group, the
reported date) are kept as :class:`~nemesis.core.claims.Statement` qualifiers, stored as data and
marked ``content_is_hostile``. Every adversary field that is preserved or stored — the title, the
description, and those qualifier values — is scanned for illegal content, and a match classifies the
record :attr:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT`, which the quarantine holds
with no automated exit.

**The channel is trusted more than the content.** ``SourceClass.OPEN_SOURCE`` with
``FAIRLY_RELIABLE`` grades *the aggregator's faithful relaying*, not the crews whose posts it
relays — the hostility of the content is carried by the deception assessment and the
``content_is_hostile`` qualifier, exactly as the dark-web and ransomware.live connectors separate
the two.

Like its siblings this is real external collection and is **off by default**: no endpoint is wired
into any registry, the response is treated as adversary-controlled material, and the connector
refuses to run outside kernel confinement (:func:`~nemesis.collect.isolation.collect_confined`). It
ships as one more instance of the operator-allowlisted, confined, ``NEMESIS-EGRESS-ALLOWED`` egress
pattern rather than as a new kind of reach — see ``docs/architecture/FOUNDER_DECISIONS.md`` on the
"sole egress" wording, which a third egress connector puts under further strain.

Install the optional transport with ``pip install 'nemesis[darkweb]'`` (the same ``httpx`` extra) —
tests inject an inert transport and never contact the network.
"""

from __future__ import annotations

import importlib.util
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Final, Protocol

# NEMESIS-EGRESS-ALLOWED: URL parsing supports the collection plane's pinned OSINT host.
from urllib.parse import SplitResult, quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from nemesis.collect.base import (
    QUALIFIER_HOSTILE_CONTENT,
    QUALIFIER_PIVOT_METHOD,
    QUALIFIER_QUOTED_VERBATIM,
    ObservationRecord,
    build_observation,
    connector_actor_id,
)
from nemesis.collect.cti_safety import contains_illegal_indicator
from nemesis.core.claims import Claim, DeceptionAssessment, Statement
from nemesis.core.entities import EntityType, NormalizationError, normalize_identifier
from nemesis.core.evidence import ArtifactKind, ContentSafety, EvidenceObject
from nemesis.core.provenance import (
    CollectionMethod,
    SourceClass,
    SourceDescriptor,
    SourceReliability,
)
from nemesis.core.relationships import PivotMethod, RelationType
from nemesis.core.temporal import TemporalExtent
from nemesis.ports.collection import (
    ConnectorCapabilities,
    IntelligenceConnector,
    PivotRequest,
    PivotResult,
    PivotType,
)

CONNECTOR_VERSION: Final = "0.1.0"
DEFAULT_BASE_URL: Final = "https://www.ransomlook.io/api"
DEFAULT_TIMEOUT_SECONDS: Final = 30.0
DEFAULT_MAX_RESPONSE_BYTES: Final = 4 * 1_024 * 1_024
MAX_TIMEOUT_SECONDS: Final = 120.0
# The worker's stdout ceiling is 8 MiB and the binary-safe JSON pipe expands artifacts by
# 4/3. Five MiB leaves room for the per-record evidence, claims and framing at the hard limit.
MAX_RESPONSE_BYTES: Final = 5 * 1_024 * 1_024
DEFAULT_MAX_RECORDS: Final = 500
# Hosts the aggregator is actually served from. Pinned so a redirect or a poisoned base URL
# cannot move the collection to a host nobody approved.
_ALLOWED_HOSTS: Final = frozenset({"www.ransomlook.io", "ransomlook.io"})
_JSON_MEDIA_TYPES: Final = frozenset({"application/json", "text/json"})
_GROUP_LABEL: Final = re.compile(r"^[a-z0-9](?:[a-z0-9 ._-]{0,126}[a-z0-9])?$")
_MAX_FIELD_CHARS: Final = 512


class RansomLookConfigurationError(ValueError):
    """The connector configuration would broaden or obscure its network authority."""


class RansomLookTransportError(RuntimeError):
    """A bounded fetch could not produce a JSON snapshot."""


def _base_url(value: str) -> SplitResult:
    """Validate the aggregator base URL, pinned to the ransomlook.io host over HTTPS."""
    parsed = urlsplit(value)
    if parsed.scheme != "https":
        raise RansomLookConfigurationError("the OSINT base URL must use https")
    if parsed.username is not None or parsed.password is not None:
        raise RansomLookConfigurationError("credentials are forbidden in the base URL")
    if parsed.query or parsed.fragment:
        raise RansomLookConfigurationError("the base URL may contain only host and path")
    if parsed.hostname not in _ALLOWED_HOSTS:
        raise RansomLookConfigurationError(
            f"host must be one of {sorted(_ALLOWED_HOSTS)}; a different host is a different "
            "trust boundary and must be declared as its own connector"
        )
    if parsed.port not in {None, 443}:
        raise RansomLookConfigurationError("only the standard https port is accepted")
    return parsed


def _clip(value: object) -> str | None:
    """Reduce one untrusted feed field to a bounded string, or drop it."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text[:_MAX_FIELD_CHARS]


def _posts_of(parsed: object) -> list[object] | None:
    """Extract the posts list from a RansomLook ``/group/<name>`` response.

    The route returns ``[group, posts]``: a two-element array whose second element is the list of
    claimed-victim posts. For a group it does not track, RansomLook returns ``[[], {}]`` — an empty
    result, which is "we looked and found nothing" (an empty list of posts), not a malformed shape.
    Anything else — a bare object, a one-element array, a second element that is neither a list nor
    that empty-dict sentinel — is unrecognised and yields ``None`` so the caller records a failed
    pivot rather than reading meaning into a structure it does not recognise.
    """
    if not isinstance(parsed, list) or len(parsed) != 2:
        return None
    posts = parsed[1]
    if isinstance(posts, list):
        return posts
    if isinstance(posts, dict) and not posts:
        return []  # the untracked-group sentinel: an empty success, not a failure
    return None


class FetchedFeed(BaseModel):
    """The bounded response facts the transport hands to the connector."""

    model_config = ConfigDict(frozen=True)

    url: str
    status_code: int = Field(ge=100, le=599)
    media_type: str
    body: bytes


class RansomLookTransport(Protocol):
    async def fetch(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> FetchedFeed: ...

    async def health(self, base_url: str, *, timeout_seconds: float) -> bool: ...


class HttpxRansomLookTransport:
    """HTTPS to the pinned OSINT host, loaded lazily so core keeps no network dependency."""

    async def fetch(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> FetchedFeed:
        try:
            # NEMESIS-EGRESS-ALLOWED: the only outbound client, bounded to the pinned host.
            import httpx
        except ModuleNotFoundError as exc:
            raise RansomLookTransportError(
                "the OSINT transport is not installed; install 'nemesis[darkweb]'"
            ) from exc

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": f"NEMESIS/{CONNECTOR_VERSION} authorized-osint-snapshot",
        }
        try:
            async with (
                httpx.AsyncClient(
                    timeout=timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    headers=headers,
                ) as client,
                client.stream("GET", url) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise RansomLookTransportError(
                        "redirect refused: the pinned OSINT host cannot delegate network "
                        "authority to its response"
                    )
                if not 200 <= response.status_code < 300:
                    raise RansomLookTransportError(
                        f"OSINT host returned HTTP {response.status_code}"
                    )

                media_type = response.headers.get("content-type", "").partition(";")[0].lower()
                if media_type not in _JSON_MEDIA_TYPES:
                    raise RansomLookTransportError(
                        f"content type {media_type or '<missing>'!r} is not a JSON snapshot"
                    )
                content_encoding = response.headers.get("content-encoding", "identity").lower()
                if content_encoding not in {"", "identity"}:
                    raise RansomLookTransportError(
                        f"encoded response {content_encoding!r} refused; the preserved bytes "
                        "must match the declared JSON media type"
                    )

                raw_length = response.headers.get("content-length")
                if raw_length is not None:
                    try:
                        announced = int(raw_length)
                    except ValueError as exc:
                        raise RansomLookTransportError(
                            "invalid Content-Length from OSINT host"
                        ) from exc
                    if announced > max_response_bytes:
                        raise RansomLookTransportError(
                            f"response announces {announced} bytes, past the "
                            f"{max_response_bytes}-byte ceiling"
                        )

                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_raw():
                    size += len(chunk)
                    if size > max_response_bytes:
                        raise RansomLookTransportError(
                            f"response passed the {max_response_bytes}-byte ceiling"
                        )
                    chunks.append(chunk)
                return FetchedFeed(
                    url=str(response.url),
                    status_code=response.status_code,
                    media_type=media_type,
                    body=b"".join(chunks),
                )
        except RansomLookTransportError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            raise RansomLookTransportError(
                f"OSINT fetch failed ({type(exc).__name__}): {exc}"
            ) from exc

    async def health(self, base_url: str, *, timeout_seconds: float) -> bool:
        """Report whether the transport *could* run — availability, not remote reachability.

        Deliberately opens no socket. The connector refuses direct network collection outside
        ``collect_confined``, so probing the remote host from a health check would be exactly the
        unconfined egress path that refusal exists to prevent. This validates the pinned base URL
        and whether the ``httpx`` transport is installed, and touches no network.
        """
        del timeout_seconds
        try:
            _base_url(base_url)
        except RansomLookConfigurationError:
            return False
        return importlib.util.find_spec("httpx") is not None


class RansomLookConnector:
    """Ask the RansomLook aggregator which victims a threat actor has claimed."""

    def __init__(
        self,
        *,
        as_of: datetime,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_records: int = DEFAULT_MAX_RECORDS,
        content_safety: ContentSafety = ContentSafety.SENSITIVE_PERSONAL_DATA,
        transport: RansomLookTransport | None = None,
        _inside_isolated_worker: bool = False,
    ) -> None:
        if as_of.tzinfo is None:
            raise RansomLookConfigurationError("as_of must be timezone-aware")
        self._base = _base_url(base_url)
        self._base_url = base_url
        if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise RansomLookConfigurationError(
                f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS} seconds"
            )
        if not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise RansomLookConfigurationError(
                f"response ceiling must be between 1 and {MAX_RESPONSE_BYTES} bytes"
            )
        if not 1 <= max_records <= DEFAULT_MAX_RECORDS:
            raise RansomLookConfigurationError(
                f"record ceiling must be between 1 and {DEFAULT_MAX_RECORDS}"
            )

        self._as_of = as_of
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_records = max_records
        self._content_safety = content_safety
        self._transport_was_injected = transport is not None
        self._transport = transport or HttpxRansomLookTransport()
        self._inside_isolated_worker = _inside_isolated_worker
        self._actor = connector_actor_id("ransomlook-osint", CONNECTOR_VERSION)

        self._capabilities = ConnectorCapabilities(
            name="ransomlook-osint",
            version=CONNECTOR_VERSION,
            source=SourceDescriptor(
                source_class=SourceClass.OPEN_SOURCE,
                identifier="ransomlook.io public aggregator (v1 API)",
                reliability=SourceReliability.FAIRLY_RELIABLE,
            ),
            supported_pivots=frozenset({PivotType.THREAT_INTEL_LOOKUP}),
            supported_entity_types=frozenset({EntityType.THREAT_ACTOR}),
            is_simulated=False,
            handles_hostile_content=True,
            isolation_factory="nemesis.collect.ransomlook:ransomlook_connector",
            isolation_config={
                "base_url": base_url,
                "timeout_seconds": str(timeout_seconds),
                "max_response_bytes": str(max_response_bytes),
                "max_records": str(max_records),
                "content_safety": content_safety.value,
            },
            cost_per_call=3.0,
            rate_limit_per_minute=20,
            # Victim identities are sensitive third-party data; do not fold them into an
            # export to another party by default. The constraint travels with the data.
            redistribution_permitted=False,
        )

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return self._capabilities

    @property
    def as_of(self) -> datetime:
        return self._as_of

    def _failed(self, request: PivotRequest, error: str) -> PivotResult:
        return PivotResult(
            request=request,
            connector_name=self._capabilities.name,
            observations=(),
            evidence=(),
            error=error,
        )

    def _group_url(self, actor: str) -> str:
        return f"{self._base_url.rstrip('/')}/group/{quote(actor, safe='')}"

    async def pivot(self, request: PivotRequest) -> PivotResult:
        if not self._capabilities.can_answer(request):
            return self._failed(
                request,
                f"{self._capabilities.name} does not answer {request.pivot_type.value} "
                f"for {request.entity_type.value}",
            )
        if not self._inside_isolated_worker and not self._transport_was_injected:
            return self._failed(
                request,
                "real OSINT collection must run through collect_confined; direct network "
                "collection is refused because no kernel confinement was observed",
            )
        try:
            actor = normalize_identifier(request.entity_type, request.entity_key)
        except NormalizationError as exc:
            return self._failed(request, f"unusable entity key: {exc}")
        if not _GROUP_LABEL.fullmatch(actor):
            return self._failed(
                request,
                "threat-actor key contains characters unsafe to place in a request path",
            )

        url = self._group_url(actor)
        try:
            feed = await self._transport.fetch(
                url,
                timeout_seconds=self._timeout_seconds,
                max_response_bytes=self._max_response_bytes,
            )
        except (RansomLookTransportError, OSError, TimeoutError, ValueError) as exc:
            return self._failed(request, f"could not collect OSINT snapshot: {exc}")

        try:
            returned = _base_url(feed.url)
        except RansomLookConfigurationError as exc:
            return self._failed(request, f"transport returned an invalid final URL: {exc}")
        if returned.hostname not in _ALLOWED_HOSTS:
            return self._failed(
                request,
                "transport returned a different host; refused outside the pinned OSINT origin",
            )
        if not 200 <= feed.status_code < 300:
            return self._failed(request, f"OSINT host returned HTTP {feed.status_code}")
        if feed.media_type not in _JSON_MEDIA_TYPES:
            return self._failed(request, f"content type {feed.media_type!r} is not a JSON snapshot")
        if len(feed.body) > self._max_response_bytes:
            return self._failed(
                request, f"response passed the {self._max_response_bytes}-byte ceiling"
            )

        try:
            parsed = json.loads(feed.body)
        except (json.JSONDecodeError, ValueError) as exc:
            return self._failed(request, f"OSINT response was not valid JSON: {exc}")
        posts = _posts_of(parsed)
        if posts is None:
            return self._failed(
                request,
                "OSINT response was not a RansomLook [group, posts] array of victim records",
            )

        observations: list[Claim] = []
        evidence: list[EvidenceObject] = []
        artifacts: dict[str, bytes] = {}
        seen: set[str] = set()
        truncated = False
        for item in posts:
            record = self._observation_for(request, actor, url, feed.status_code, item)
            if record is None:
                continue  # a malformed item is dropped, never counted as "more we could not carry"
            ev, obs = record
            if ev.evidence_id in seen:
                continue
            # The cap is checked only once a *valid* record is in hand, so trailing malformed
            # items do not raise a false `truncated` — an absence within a truncated result means
            # nothing, and mislabelling a complete result as truncated hides evidence of absence.
            if len(observations) >= self._max_records or len(observations) >= request.max_results:
                truncated = True
                break
            seen.add(ev.evidence_id)
            evidence.append(ev)
            observations.append(obs)
            artifacts[ev.evidence_id] = self._record_bytes(item)

        return PivotResult(
            request=request,
            connector_name=self._capabilities.name,
            observations=tuple(observations),
            evidence=tuple(evidence),
            artifacts=artifacts,
            truncated=truncated,
        )

    @staticmethod
    def _record_bytes(item: object) -> bytes:
        return json.dumps(item, sort_keys=True, separators=(",", ":"), default=str).encode()

    def _observation_for(
        self,
        request: PivotRequest,
        actor: str,
        url: str,
        status_code: int,
        item: object,
    ) -> tuple[EvidenceObject, Claim] | None:
        if not isinstance(item, dict):
            return None
        raw_victim = _clip(item.get("post_title"))
        if raw_victim is None:
            return None
        try:
            victim = normalize_identifier(EntityType.ORGANIZATION, raw_victim)
        except NormalizationError:
            return None
        listed_group = _clip(item.get("group_name"))
        discovered = _clip(item.get("discovered"))
        description = _clip(item.get("description"))

        # A listing whose free text names illegal content is held, not indexed: the escalation
        # dominates the connector's ordinary victim-data classification. The engine opens the
        # reporting obligation downstream; this plane cannot, and does not try to. Every
        # adversary-authored field that is preserved or stored — the title, the description, and
        # the group/date values kept as qualifiers — is scanned, not just the title.
        record_safety = self._content_safety
        scanned = " ".join(
            field for field in (raw_victim, description, listed_group, discovered) if field
        )
        if contains_illegal_indicator(scanned):
            record_safety = ContentSafety.MANDATORY_REPORT

        qualifiers = {
            QUALIFIER_PIVOT_METHOD: PivotMethod.EXTERNAL_REPORTING.value,
            QUALIFIER_HOSTILE_CONTENT: "true",
            QUALIFIER_QUOTED_VERBATIM: "false",
            "reported_by": "ransomlook.io",
        }
        if listed_group is not None:
            qualifiers["listed_group"] = listed_group
        if discovered is not None:
            qualifiers["reported_discovered"] = discovered

        artifact = self._record_bytes(item)
        method = CollectionMethod(
            collector_name=self._capabilities.name,
            collector_version=self._capabilities.version,
            parameters={
                "pivot_type": request.pivot_type.value,
                "entity_type": request.entity_type.value,
                "entity_key": actor,
                "osint_url": url,
                "http_status": str(status_code),
                "media_type": "application/json",
                "redirects": "refused",
                "max_response_bytes": str(self._max_response_bytes),
                "as_of": self._as_of.isoformat(),
            },
            is_simulated=False,
            # IsolatedCollector replaces this with the mechanism it actually observed after
            # the worker exits. The connector cannot truthfully name its own outer sandbox.
            sandbox_profile=None,
        )
        source = SourceDescriptor(
            source_class=SourceClass.OPEN_SOURCE,
            identifier="ransomlook.io public aggregator (v1 API)",
            reliability=SourceReliability.FAIRLY_RELIABLE,
            upstream_of_record="osint:ransomlook.io",
            handling_restrictions=("no redistribution",),
        )
        obs_record = ObservationRecord(
            artifact=artifact,
            artifact_kind=ArtifactKind.STRUCTURED_FEED_RECORD,
            statement=Statement(
                subject=f"{EntityType.THREAT_ACTOR.value}:{actor}",
                predicate=RelationType.TARGETED.value,
                obj=f"{EntityType.ORGANIZATION.value}:{victim}",
                qualifiers=qualifiers,
                natural_language=(
                    f"RansomLook reports that the group {actor} posted an organization as a "
                    "victim on its leak site. This records a third-party report of an "
                    "adversary's own claim; it does not establish that a compromise occurred "
                    "or that the named organization was in fact breached."
                ),
            ),
            extent=TemporalExtent.at(self._as_of),
            media_type="application/json",
            content_safety=record_safety,
            # A fixed template, carrying no adversary free text: the victim is a normalized node
            # key in `obj` and the description is scanned for illegal content but never stored, so
            # nothing an adversary authored rides into a human-readable field (invariant 5).
            summary=(
                f"Aggregated leak-site claim by {actor}; preserved as a feed record, not "
                "interpreted as a confirmed compromise"
            ),
            deception=DeceptionAssessment(
                adversary_could_plant=True,
                planting_cost="trivial",
                benefits_from_belief=(
                    "a ransomware crew inflates, recycles or fabricates victim listings to "
                    "project capability and pressure targets",
                ),
            ),
            notes=(
                "This claim establishes only that a public aggregator reported a leak-site "
                "listing. It does not establish that the breach happened, who authored the "
                "post, or that any named organization was affected."
            ),
        )
        return build_observation(
            record=obs_record,
            source=source,
            method=method,
            collected_at=self._as_of,
            asserted_by=self._actor,
            reason=request.reason,
        )

    async def health(self) -> bool:
        return await self._transport.health(
            self._base_url, timeout_seconds=min(self._timeout_seconds, 2.0)
        )


def ransomlook_connector(
    as_of: str, config: Mapping[str, str] | None = None
) -> IntelligenceConnector:
    """Reconstruct the connector in the isolated worker from non-secret configuration."""
    supplied = dict(config or {})
    expected = {
        "base_url",
        "timeout_seconds",
        "max_response_bytes",
        "max_records",
        "content_safety",
    }
    if set(supplied) != expected:
        raise RansomLookConfigurationError(
            f"isolated OSINT connector config must contain exactly {sorted(expected)}"
        )
    try:
        return RansomLookConnector(
            as_of=datetime.fromisoformat(as_of),
            base_url=supplied["base_url"],
            timeout_seconds=float(supplied["timeout_seconds"]),
            max_response_bytes=int(supplied["max_response_bytes"]),
            max_records=int(supplied["max_records"]),
            content_safety=ContentSafety(supplied["content_safety"]),
            _inside_isolated_worker=True,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RansomLookConfigurationError(
            f"isolated OSINT connector configuration is invalid: {exc}"
        ) from exc


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "FetchedFeed",
    "HttpxRansomLookTransport",
    "RansomLookConfigurationError",
    "RansomLookConnector",
    "RansomLookTransport",
    "RansomLookTransportError",
    "ransomlook_connector",
]
