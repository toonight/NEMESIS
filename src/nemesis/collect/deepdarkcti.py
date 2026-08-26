"""Turn a deepdarkCTI index file into *candidate* onion-allowlist entries for review.

``fastfire/deepdarkCTI`` publishes large Markdown tables of dark-web CTI sources — one row
per ransomware leak site, forum or market, with the onion address embedded as a Markdown
link. This module parses one such table (text an **operator supplies at runtime**, never
vendored into this repository) into validated :class:`~nemesis.collect.dark_web.OnionService`
candidates that an operator can then review and approve for
:class:`~nemesis.collect.dark_web.TorOnionConnector`.

What it deliberately does **not** do:

- **It never fetches anything.** This is pure text-to-structure. Whether any candidate is
  ever collected from is a separate, operator-gated, kernel-confined act (invariant 15). The
  output is a *proposal*, not an allowlist and not a reach.
- **It never carries credentials.** deepdarkCTI rows sometimes include a ``User:Password``
  column and occasionally credentials in a URL. Those are dropped and counted, never emitted:
  NEMESIS does not authenticate against anyone's infrastructure, and a candidate that arrived
  with credentials attached is exactly the kind of thing to strip at the boundary.
- **It never trusts the index.** The file is untrusted external content (invariant 5). Every
  onion address is re-validated through the connector's own v3-checksum gate, malformed and
  dead-shaped rows are dropped with a counted reason, and nothing is interpreted as
  instruction.

The report is honest about what it discarded — "we dropped N rows and why" is a finding, not
noise, because a silently shortened allowlist is an allowlist nobody can audit.
"""

from __future__ import annotations

import re
from typing import Final

from pydantic import BaseModel, ConfigDict, ValidationError

from nemesis.collect.dark_web import (
    DarkWebConfigurationError,
    OnionService,
)
from nemesis.core.entities import EntityType, NormalizationError, normalize_identifier
from nemesis.core.evidence import ContentSafety

MAX_ROWS: Final = 20_000
"""A hard ceiling on rows processed, so a hostile or accidental multi-megabyte file cannot
turn parsing into a denial of service."""

MAX_NAME_CHARS: Final = 200
"""Below :attr:`OnionService.name`'s own 256 limit, leaving room for a mirror discriminator."""

_ALLOWED_ENTITY_TYPES: Final = frozenset({EntityType.FORUM, EntityType.MARKETPLACE})

# A v3 onion URL anywhere in a row: markdown link target or bare. Credentials, if present,
# are captured by the separate _CREDENTIALS probe and cause the candidate to be dropped.
_ONION_URL: Final = re.compile(
    r"https?://(?:[^/@\s|)\]<>\"']+@)?[a-z2-7]{56}\.onion(?::\d+)?(?:/[^\s|)\]<>\"']*)?",
    re.IGNORECASE,
)
_MARKDOWN_LINK: Final = re.compile(r"\[([^\]]{1,300})\]\(\s*([^)\s]+)\s*\)")
_CREDENTIALS: Final = re.compile(r"https?://[^/@\s]+:[^/@\s]+@", re.IGNORECASE)
_ONLINE: Final = re.compile(r"\b(online|up|active)\b", re.IGNORECASE)
_OFFLINE: Final = re.compile(r"\b(offline|down|dead|inactive)\b", re.IGNORECASE)


class DeepDarkCtiParseError(ValueError):
    """The parse arguments themselves are unusable (not: a bad row, which is dropped)."""


class DeepDarkCtiReport(BaseModel):
    """Candidate onion services extracted from one deepdarkCTI table, and what was discarded.

    Every ``dropped_*`` counter has a reason, and the totals reconcile: ``rows_seen`` equals
    ``accepted`` plus every drop counter. An allowlist that quietly loses entries is worse
    than one that fails loudly, so the arithmetic is part of the contract and a test pins it.
    """

    model_config = ConfigDict(frozen=True)

    candidates: tuple[OnionService, ...]
    rows_seen: int
    accepted: int
    dropped_no_onion: int
    dropped_invalid_onion: int
    dropped_offline: int
    dropped_duplicate: int
    dropped_bad_name: int
    credentials_dropped: int
    """Rows carrying credentials (in a ``User:Password`` column or embedded in a URL). The
    onion, if otherwise valid, is still discarded here — a candidate is never emitted with
    authentication material attached."""

    def render(self) -> str:
        return (
            f"{self.accepted} candidate onion service(s) from {self.rows_seen} row(s); "
            f"dropped {self.dropped_no_onion} without an onion, {self.dropped_invalid_onion} "
            f"invalid, {self.dropped_offline} offline, {self.dropped_duplicate} duplicate, "
            f"{self.dropped_bad_name} unnamed; {self.credentials_dropped} carried credentials "
            "and were refused."
        )


def _row_status(row: str) -> str:
    """Best-effort ONLINE/OFFLINE reading; the index maintainer's column is not authoritative."""
    if _OFFLINE.search(row):
        return "offline"
    if _ONLINE.search(row):
        return "online"
    return "unknown"


def _row_name(row: str, cells: list[str]) -> str | None:
    """The group/site name: the first markdown link's text, else the first non-empty cell."""
    link = _MARKDOWN_LINK.search(row)
    if link is not None:
        text = link.group(1).strip()
        if text:
            return text[:MAX_NAME_CHARS]
    for cell in cells:
        stripped = re.sub(r"[\[\]()]", "", cell).strip()
        if stripped:
            return stripped[:MAX_NAME_CHARS]
    return None


def _iter_table_rows(markdown: str) -> list[str]:
    """Data rows of any Markdown table in the text: lines starting with '|', minus header
    and separator rows. Non-table prose is ignored rather than misread."""
    rows: list[str] = []
    for raw in markdown.splitlines():
        line = raw.strip()
        if not line.startswith("|") or line.count("|") < 2:
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        joined = " ".join(cells).lower()
        if set(line) <= {"|", "-", ":", " "}:  # separator row
            continue
        if "onion" not in line.lower() and ("name" in joined and "status" in joined):
            continue  # header row
        rows.append(line)
    return rows


def parse_deepdarkcti(
    markdown: str,
    *,
    entity_type: EntityType = EntityType.MARKETPLACE,
    content_safety: ContentSafety = ContentSafety.MANDATORY_REPORT,
    include_offline: bool = False,
    max_rows: int = MAX_ROWS,
) -> DeepDarkCtiReport:
    """Parse one deepdarkCTI Markdown table into reviewable :class:`OnionService` candidates.

    ``markdown`` is the text of an operator-supplied index file — this function performs no
    I/O and no network access. ``entity_type`` must be a forum or a marketplace (the only
    targets an onion snapshot may name); a leak site is recorded as a marketplace by default.
    ``content_safety`` defaults to ``MANDATORY_REPORT`` because a leak site holds stolen
    victim data. Offline entries are dropped unless ``include_offline`` is set.

    The result never contains credentials, never contains an unvalidated onion address, and
    never contains two services that normalize to the same allowlist key.
    """
    if entity_type not in _ALLOWED_ENTITY_TYPES:
        raise DeepDarkCtiParseError(
            "an onion snapshot target must be a forum or marketplace; "
            f"{entity_type.value} cannot be an allowlist candidate"
        )
    if max_rows < 1:
        raise DeepDarkCtiParseError("max_rows must be positive")

    candidates: list[OnionService] = []
    used_keys: set[tuple[EntityType, str]] = set()
    seen_hosts: set[str] = set()
    rows_seen = 0
    no_onion = invalid = offline = duplicate = bad_name = creds = 0

    for row in _iter_table_rows(markdown)[:max_rows]:
        rows_seen += 1
        cells = [c.strip() for c in row.strip("|").split("|")]

        onion_urls = _ONION_URL.findall(row)
        if not onion_urls:
            no_onion += 1
            continue
        if _CREDENTIALS.search(row) or _row_has_credential_cell(cells):
            creds += 1
            continue
        if not include_offline and _row_status(row) == "offline":
            offline += 1
            continue

        name = _row_name(row, cells)
        if name is None:
            bad_name += 1
            continue

        service = _first_valid_service(
            name, onion_urls, entity_type, content_safety, used_keys, seen_hosts
        )
        if service is None:
            # Some onion was present but none survived validation, dedup or naming.
            if any(_host_of(url) in seen_hosts for url in onion_urls):
                duplicate += 1
            else:
                invalid += 1
            continue

        candidates.append(service)
        used_keys.add(service.key)
        seen_hosts.add(service.onion_host)

    return DeepDarkCtiReport(
        candidates=tuple(candidates),
        rows_seen=rows_seen,
        accepted=len(candidates),
        dropped_no_onion=no_onion,
        dropped_invalid_onion=invalid,
        dropped_offline=offline,
        dropped_duplicate=duplicate,
        dropped_bad_name=bad_name,
        credentials_dropped=creds,
    )


def _row_has_credential_cell(cells: list[str]) -> bool:
    """A non-empty ``User:Password`` column (deepdarkCTI's third column, when present)."""
    if len(cells) < 3:
        return False
    cell = cells[2].strip()
    if not cell or cell in {"-", "n/a", "none"}:
        return False
    # A bare "user:pass" shape, not a Tox id or a URL that happens to contain a colon.
    return bool(re.fullmatch(r"[^\s:/@]{1,64}:[^\s:/@]{1,128}", cell))


def _host_of(url: str) -> str:
    match = re.search(r"([a-z2-7]{56}\.onion)", url, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _first_valid_service(
    name: str,
    onion_urls: list[str],
    entity_type: EntityType,
    content_safety: ContentSafety,
    used_keys: set[tuple[EntityType, str]],
    seen_hosts: set[str],
) -> OnionService | None:
    """Build an :class:`OnionService` from the first onion in the row that validates, is not
    already seen, and can be given a collision-free allowlist key. None if nothing survives.
    """
    for url in onion_urls:
        if _host_of(url) in seen_hosts:
            continue
        candidate_name = name
        for attempt in range(2):
            try:
                service = OnionService(
                    name=candidate_name,
                    entity_type=entity_type,
                    url=url,
                    content_safety=content_safety,
                )
            except (ValidationError, DarkWebConfigurationError, NormalizationError):
                break  # this url is invalid; try the next onion in the row
            if service.key in used_keys:
                # Same name, different host (a mirror or a namesake). Disambiguate once.
                if attempt == 0:
                    candidate_name = f"{name} [{service.onion_host[:8]}]"[:MAX_NAME_CHARS]
                    continue
                break
            return service
    return None


def candidate_summary(report: DeepDarkCtiReport) -> list[str]:
    """One human-readable line per accepted candidate: name, onion host and safety label.

    Deliberately not the onion URL path or any credential — the minimum an operator needs to
    decide whether to approve a target, and nothing that reads as a directory of live links.
    """
    return [
        f"{service.entity_type.value}: {normalize_identifier(service.entity_type, service.name)} "
        f"-> {service.onion_host} [{service.content_safety.value}]"
        for service in report.candidates
    ]


__all__ = [
    "DeepDarkCtiParseError",
    "DeepDarkCtiReport",
    "candidate_summary",
    "parse_deepdarkcti",
]
