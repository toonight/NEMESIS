"""A real, deliberately narrow Tor connector for allowlisted onion services.

This is not a dark-web crawler and it is not a global search engine.  A deployment supplies
an explicit mapping from a NEMESIS forum or marketplace identifier to one version-3 onion
URL.  The connector may fetch only those URLs, follows no redirects, accepts only textual
responses, and bounds both time and bytes.  Its one observation is intentionally modest:
the configured service responded at that onion address at the collection instant.

The response body is hostile material.  It is returned byte-for-byte as a web-page snapshot,
never interpreted as instruction and never parsed into identity claims.  The collection path
runs this connector through :func:`nemesis.collect.isolation.collect_confined`; configuration
crosses the worker pipe as non-secret data so the child can reconstruct the same allowlist.

Install the optional transport with ``pip install 'nemesis[darkweb]'`` (or
``uv sync --extra darkweb``) and run a Tor SOCKS listener on ``127.0.0.1:9050``.  Tests inject
an inert transport and never contact Tor or an onion service.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Final, Protocol, Self

# NEMESIS-EGRESS-ALLOWED: URL parsing supports the collection plane's explicit onion allowlist.
from urllib.parse import SplitResult, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.collect.base import (
    QUALIFIER_HOSTILE_CONTENT,
    QUALIFIER_PIVOT_METHOD,
    QUALIFIER_QUOTED_VERBATIM,
    ObservationRecord,
    build_observation,
    connector_actor_id,
)
from nemesis.core.claims import DeceptionAssessment, Statement
from nemesis.core.entities import EntityType, NormalizationError, normalize_identifier
from nemesis.core.evidence import ArtifactKind, ContentSafety
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
DEFAULT_TOR_PROXY: Final = "socks5://127.0.0.1:9050"
DEFAULT_TIMEOUT_SECONDS: Final = 30.0
DEFAULT_MAX_RESPONSE_BYTES: Final = 2 * 1_024 * 1_024
MAX_CONFIGURED_SERVICES: Final = 32
MAX_TIMEOUT_SECONDS: Final = 120.0
# The worker's stdout ceiling is 8 MiB and the binary-safe JSON pipe expands artifacts by
# 4/3. Five MiB leaves more than a MiB for evidence, claims and framing at the hard limit.
MAX_RESPONSE_BYTES: Final = 5 * 1_024 * 1_024
_ONION_LABEL: Final = re.compile(r"^[a-z2-7]{56}$")
_ONION_CHECKSUM_PREFIX: Final = b".onion checksum"
_TEXT_MEDIA_TYPES: Final = frozenset({"text/html", "text/plain", "application/xhtml+xml"})


class DarkWebConfigurationError(ValueError):
    """The connector configuration would broaden or obscure its network authority."""


class DarkWebTransportError(RuntimeError):
    """A bounded fetch could not produce a textual snapshot."""


def _onion_url(value: str) -> SplitResult:
    """Validate one v3 onion URL, including the address checksum."""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise DarkWebConfigurationError("an onion service URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise DarkWebConfigurationError("credentials are forbidden in an onion service URL")
    if parsed.fragment:
        raise DarkWebConfigurationError("fragments are local browser state, not collection URLs")
    if parsed.hostname is None or not parsed.hostname.endswith(".onion"):
        raise DarkWebConfigurationError("only explicit .onion services may be configured")
    if parsed.port not in {None, 80, 443}:
        raise DarkWebConfigurationError("onion service ports are limited to 80 and 443")

    label = parsed.hostname.removesuffix(".onion").lower()
    if not _ONION_LABEL.fullmatch(label):
        raise DarkWebConfigurationError("only 56-character version-3 onion addresses are accepted")
    try:
        decoded = base64.b32decode(label.upper())
    except ValueError as exc:
        raise DarkWebConfigurationError("the onion address is not valid base32") from exc
    public_key, checksum, version = decoded[:32], decoded[32:34], decoded[34:]
    expected = hashlib.sha3_256(_ONION_CHECKSUM_PREFIX + public_key + version).digest()[:2]
    if version != b"\x03" or checksum != expected:
        raise DarkWebConfigurationError("the onion address has an invalid v3 checksum")
    return parsed


def _tor_proxy(value: str) -> SplitResult:
    """Accept only an unauthenticated loopback SOCKS proxy.

    Remote proxies and credentials would move the trust boundary into configuration without
    naming who operates it.  A deployment needing a remote gateway should add that boundary as
    an explicit adapter rather than silently widening this one.
    """
    parsed = urlsplit(value)
    if parsed.scheme != "socks5":
        raise DarkWebConfigurationError("the Tor proxy must use socks5://")
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise DarkWebConfigurationError("the Tor SOCKS proxy must be on loopback")
    if parsed.username is not None or parsed.password is not None:
        raise DarkWebConfigurationError("proxy credentials must not cross the collector pipe")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise DarkWebConfigurationError("the Tor proxy URL may contain only host and port")
    if parsed.port is None:
        raise DarkWebConfigurationError("the Tor proxy URL must name its port")
    return parsed


class OnionService(BaseModel):
    """One operator-approved collection target."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=256)
    entity_type: EntityType
    url: str = Field(min_length=1, max_length=2048)
    content_safety: ContentSafety
    """Chosen explicitly by the operator for this target; there is no safe universal default."""

    @model_validator(mode="after")
    def _validate_target(self) -> Self:
        if self.entity_type not in {EntityType.FORUM, EntityType.MARKETPLACE}:
            raise ValueError("an onion snapshot target must be a forum or marketplace")
        _onion_url(self.url)
        normalize_identifier(self.entity_type, self.name)
        return self

    @property
    def onion_host(self) -> str:
        host = _onion_url(self.url).hostname
        assert host is not None
        return host.lower()

    @property
    def key(self) -> tuple[EntityType, str]:
        return self.entity_type, normalize_identifier(self.entity_type, self.name)


class FetchedPage(BaseModel):
    """The bounded response facts the transport hands to the connector."""

    model_config = ConfigDict(frozen=True)

    url: str
    status_code: int = Field(ge=100, le=599)
    media_type: str
    body: bytes


class OnionTransport(Protocol):
    async def fetch(
        self,
        url: str,
        *,
        proxy_url: str,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> FetchedPage: ...

    async def health(self, proxy_url: str, *, timeout_seconds: float) -> bool: ...


class HttpxOnionTransport:
    """HTTP over Tor SOCKS, loaded lazily so the core package keeps no network dependency."""

    async def fetch(
        self,
        url: str,
        *,
        proxy_url: str,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> FetchedPage:
        try:
            # NEMESIS-EGRESS-ALLOWED: the only outbound client, bounded to the validated onion URL.
            import httpx
        except ModuleNotFoundError as exc:
            raise DarkWebTransportError(
                "the dark-web transport is not installed; install 'nemesis[darkweb]'"
            ) from exc

        headers = {
            "Accept": "text/html, application/xhtml+xml, text/plain;q=0.9",
            "Accept-Encoding": "identity",
            "User-Agent": f"NEMESIS/{CONNECTOR_VERSION} authorized-onion-snapshot",
        }
        try:
            async with (
                httpx.AsyncClient(
                    proxy=proxy_url,
                    timeout=timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    headers=headers,
                ) as client,
                client.stream("GET", url) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise DarkWebTransportError(
                        "redirect refused: a configured onion target cannot delegate "
                        "network authority to its response"
                    )
                if not 200 <= response.status_code < 300:
                    raise DarkWebTransportError(
                        f"onion service returned HTTP {response.status_code}"
                    )

                media_type = response.headers.get("content-type", "").partition(";")[0].lower()
                if media_type not in _TEXT_MEDIA_TYPES:
                    raise DarkWebTransportError(
                        f"content type {media_type or '<missing>'!r} is not a textual snapshot"
                    )
                if "attachment" in response.headers.get("content-disposition", "").lower():
                    raise DarkWebTransportError(
                        "attachment responses are not opened by this connector"
                    )
                content_encoding = response.headers.get("content-encoding", "identity").lower()
                if content_encoding not in {"", "identity"}:
                    raise DarkWebTransportError(
                        f"encoded response {content_encoding!r} refused; the preserved "
                        "bytes must match the declared textual media type"
                    )

                raw_length = response.headers.get("content-length")
                if raw_length is not None:
                    try:
                        announced = int(raw_length)
                    except ValueError as exc:
                        raise DarkWebTransportError(
                            "invalid Content-Length from onion service"
                        ) from exc
                    if announced > max_response_bytes:
                        raise DarkWebTransportError(
                            f"response announces {announced} bytes, past the "
                            f"{max_response_bytes}-byte ceiling"
                        )

                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_raw():
                    size += len(chunk)
                    if size > max_response_bytes:
                        raise DarkWebTransportError(
                            f"response passed the {max_response_bytes}-byte ceiling"
                        )
                    chunks.append(chunk)
                return FetchedPage(
                    url=str(response.url),
                    status_code=response.status_code,
                    media_type=media_type,
                    body=b"".join(chunks),
                )
        except DarkWebTransportError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            raise DarkWebTransportError(f"Tor fetch failed ({type(exc).__name__}): {exc}") from exc

    async def health(self, proxy_url: str, *, timeout_seconds: float) -> bool:
        parsed = _tor_proxy(proxy_url)
        assert parsed.hostname is not None and parsed.port is not None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(parsed.hostname, parsed.port), timeout=timeout_seconds
            )
        except (OSError, TimeoutError):
            return False
        del reader
        writer.close()
        await writer.wait_closed()
        return True


class TorOnionConnector:
    """Snapshot explicitly allowlisted onion services through a local Tor SOCKS proxy."""

    def __init__(
        self,
        *,
        services: tuple[OnionService, ...],
        as_of: datetime,
        proxy_url: str = DEFAULT_TOR_PROXY,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: OnionTransport | None = None,
        _inside_isolated_worker: bool = False,
    ) -> None:
        if as_of.tzinfo is None:
            raise DarkWebConfigurationError("as_of must be timezone-aware")
        if not services:
            raise DarkWebConfigurationError("at least one onion service must be allowlisted")
        if len(services) > MAX_CONFIGURED_SERVICES:
            raise DarkWebConfigurationError(
                f"at most {MAX_CONFIGURED_SERVICES} onion services may be configured"
            )
        _tor_proxy(proxy_url)
        if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise DarkWebConfigurationError(
                f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS} seconds"
            )
        if not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise DarkWebConfigurationError(
                f"response ceiling must be between 1 and {MAX_RESPONSE_BYTES} bytes"
            )

        indexed = {service.key: service for service in services}
        if len(indexed) != len(services):
            raise DarkWebConfigurationError("two onion services normalize to the same target")

        self._services = indexed
        self._as_of = as_of
        self._proxy_url = proxy_url
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._transport_was_injected = transport is not None
        self._transport = transport or HttpxOnionTransport()
        self._inside_isolated_worker = _inside_isolated_worker
        self._actor = connector_actor_id("tor-onion-snapshot", CONNECTOR_VERSION)

        serialized = json.dumps(
            [service.model_dump(mode="json") for service in services],
            sort_keys=True,
            separators=(",", ":"),
        )
        self._capabilities = ConnectorCapabilities(
            name="tor-onion-snapshot",
            version=CONNECTOR_VERSION,
            source=SourceDescriptor(
                source_class=SourceClass.DARK_WEB,
                identifier="operator-allowlisted onion services via local Tor",
                reliability=SourceReliability.CANNOT_BE_JUDGED,
            ),
            supported_pivots=frozenset({PivotType.DARK_WEB_SNAPSHOT}),
            supported_entity_types=frozenset(service.entity_type for service in services),
            is_simulated=False,
            handles_hostile_content=True,
            isolation_factory="nemesis.collect.dark_web:tor_onion_connector",
            isolation_config={
                "services": serialized,
                "proxy_url": proxy_url,
                "timeout_seconds": str(timeout_seconds),
                "max_response_bytes": str(max_response_bytes),
            },
            cost_per_call=4.0,
            rate_limit_per_minute=6,
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
                "real onion collection must run through collect_confined; direct network "
                "collection is refused because no kernel confinement was observed",
            )
        try:
            target = normalize_identifier(request.entity_type, request.entity_key)
        except NormalizationError as exc:
            return self._failed(request, f"unusable entity key: {exc}")
        service = self._services.get((request.entity_type, target))
        if service is None:
            return self._failed(
                request,
                "target is not in this connector's explicit onion-service allowlist",
            )

        try:
            page = await self._transport.fetch(
                service.url,
                proxy_url=self._proxy_url,
                timeout_seconds=self._timeout_seconds,
                max_response_bytes=self._max_response_bytes,
            )
        except (DarkWebTransportError, OSError, TimeoutError, ValueError) as exc:
            return self._failed(request, f"could not collect onion snapshot: {exc}")

        try:
            returned = _onion_url(page.url)
        except DarkWebConfigurationError as exc:
            return self._failed(request, f"transport returned an invalid final URL: {exc}")
        if returned.hostname != service.onion_host:
            return self._failed(
                request,
                "transport returned a different onion service; refused outside the allowlist",
            )
        if not 200 <= page.status_code < 300:
            return self._failed(request, f"onion service returned HTTP {page.status_code}")
        if page.media_type not in _TEXT_MEDIA_TYPES:
            return self._failed(
                request, f"content type {page.media_type!r} is not a textual snapshot"
            )
        if len(page.body) > self._max_response_bytes:
            return self._failed(
                request,
                f"response passed the {self._max_response_bytes}-byte ceiling",
            )

        method = CollectionMethod(
            collector_name=self._capabilities.name,
            collector_version=self._capabilities.version,
            parameters={
                "pivot_type": request.pivot_type.value,
                "entity_type": request.entity_type.value,
                "entity_key": target,
                "onion_url": service.url,
                "http_status": str(page.status_code),
                "media_type": page.media_type,
                "tor_proxy": self._proxy_url,
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
            source_class=SourceClass.DARK_WEB,
            identifier=f"onion service {service.onion_host}",
            reliability=SourceReliability.CANNOT_BE_JUDGED,
            upstream_of_record=f"onion:{service.onion_host}",
            handling_restrictions=("no redistribution",),
        )
        record = ObservationRecord(
            artifact=page.body,
            artifact_kind=ArtifactKind.WEB_PAGE_SNAPSHOT,
            statement=Statement(
                subject=f"{request.entity_type.value}:{target}",
                predicate=RelationType.HOSTED_ON.value,
                obj=f"{EntityType.TOR_INFRASTRUCTURE.value}:{service.onion_host}",
                qualifiers={
                    QUALIFIER_PIVOT_METHOD: PivotMethod.DIRECT_OBSERVATION.value,
                    QUALIFIER_HOSTILE_CONTENT: "true",
                    QUALIFIER_QUOTED_VERBATIM: "false",
                    "http_status": str(page.status_code),
                    "onion_url": service.url,
                },
                natural_language=(
                    f"The allowlisted {request.entity_type.value} {target} responded at its "
                    "configured version-3 onion service through Tor. This records "
                    "reachability only; no page content was interpreted."
                ),
            ),
            extent=TemporalExtent.at(self._as_of),
            media_type=page.media_type,
            content_safety=service.content_safety,
            summary=(
                f"Bounded snapshot of allowlisted {request.entity_type.value} {target}; "
                "content preserved but not interpreted"
            ),
            deception=DeceptionAssessment(
                adversary_could_plant=True,
                planting_cost="trivial",
                benefits_from_belief=("the onion service operator controls every returned byte",),
            ),
            notes=(
                "This claim establishes only that the configured endpoint responded. It does "
                "not establish who operated it, who authored its content, or that any content "
                "was true."
            ),
        )
        evidence, observation = build_observation(
            record=record,
            source=source,
            method=method,
            collected_at=self._as_of,
            asserted_by=self._actor,
            reason=request.reason,
        )
        return PivotResult(
            request=request,
            connector_name=self._capabilities.name,
            observations=(observation,),
            evidence=(evidence,),
            artifacts={evidence.evidence_id: page.body},
        )

    async def health(self) -> bool:
        return await self._transport.health(
            self._proxy_url, timeout_seconds=min(self._timeout_seconds, 2.0)
        )


def tor_onion_connector(
    as_of: str, config: Mapping[str, str] | None = None
) -> IntelligenceConnector:
    """Reconstruct the connector in the isolated worker from non-secret configuration."""
    supplied = dict(config or {})
    expected = {"services", "proxy_url", "timeout_seconds", "max_response_bytes"}
    if set(supplied) != expected:
        raise DarkWebConfigurationError(
            f"isolated Tor connector config must contain exactly {sorted(expected)}"
        )
    try:
        raw_services = json.loads(supplied["services"])
        if not isinstance(raw_services, list):
            raise TypeError("services is not a list")
        services = tuple(OnionService.model_validate(item) for item in raw_services)
        return TorOnionConnector(
            services=services,
            as_of=datetime.fromisoformat(as_of),
            proxy_url=supplied["proxy_url"],
            timeout_seconds=float(supplied["timeout_seconds"]),
            max_response_bytes=int(supplied["max_response_bytes"]),
            _inside_isolated_worker=True,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DarkWebConfigurationError(
            f"isolated Tor connector configuration is invalid: {exc}"
        ) from exc


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_TOR_PROXY",
    "DarkWebConfigurationError",
    "DarkWebTransportError",
    "FetchedPage",
    "HttpxOnionTransport",
    "OnionService",
    "OnionTransport",
    "TorOnionConnector",
    "tor_onion_connector",
]
