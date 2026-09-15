"""Turn operator CTI knowledge-base cards into *candidate* onion-allowlist entries for review.

The ``cti-toolkit`` a defensive team runs alongside NEMESIS keeps a knowledge base of Markdown
cards (``kb/actor-*.md``): one per crawled dark-web actor, each carrying the actor's name, a
category, its live ``.onion`` address(es) and a scrubbed excerpt. This module parses those cards
(text an **operator supplies at runtime**, never vendored into this repository) into validated
:class:`~nemesis.collect.dark_web.OnionService` candidates an operator can review and approve for
:class:`~nemesis.collect.dark_web.TorOnionConnector`.

It is the KB-shaped sibling of :func:`~nemesis.collect.deepdarkcti.parse_deepdarkcti`, and it keeps
that module's discipline exactly:

- **It never fetches anything.** Pure text-to-structure. Whether any candidate is ever collected
  from is a separate, operator-gated, kernel-confined act (invariant 15). The output is a
  *proposal*, not an allowlist and not a reach.
- **It never carries credentials.** A card is untrusted external content (invariant 5); if any of
  its onion addresses embeds ``user:password@`` authentication material the whole card is dropped
  and counted, never emitted. NEMESIS authenticates against nobody's infrastructure.
- **It never trusts the card.** Every onion address is re-validated through the connector's own
  v3-checksum gate, malformed and unnamed cards are dropped with a counted reason, and nothing in
  the free text is interpreted as instruction.
- **It refuses to propose an illegal-content site.** A card whose text carries an illegal-content
  indicator is dropped and counted rather than turned into a collection target: material that must
  be reported is not material to add to a monitoring allowlist.

Every accepted candidate is classified :attr:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT`
by default, because a ransomware leak site holds stolen victim data;
:attr:`~nemesis.core.evidence.EvidenceObject.must_not_be_indexed` follows from that. One candidate
is emitted per card (the first onion that validates), which keeps the reconciling arithmetic a
single sum; a card's additional mirror addresses are for the operator to add explicitly, or to
recover from the raw ``deepdarkCTI`` index through
:func:`~nemesis.collect.deepdarkcti.parse_deepdarkcti`, which counts at the row level.

The report is honest about what it discarded — "we dropped N cards and why" is a finding, not
noise, because a silently shortened allowlist is an allowlist nobody can audit.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from pydantic import BaseModel, ConfigDict, ValidationError

from nemesis.collect.cti_safety import contains_illegal_indicator
from nemesis.collect.dark_web import DarkWebConfigurationError, OnionService
from nemesis.core.entities import EntityType, NormalizationError, normalize_identifier
from nemesis.core.evidence import ContentSafety

MAX_CARDS: Final = 20_000
"""A hard ceiling on cards processed, so a hostile or accidental multi-megabyte input cannot turn
parsing into a denial of service."""

MAX_NAME_CHARS: Final = 200
"""Below :attr:`OnionService.name`'s own 256 limit, leaving room for a mirror discriminator."""

_ALLOWED_ENTITY_TYPES: Final = frozenset({EntityType.FORUM, EntityType.MARKETPLACE})

_ONION_URL: Final = re.compile(
    r"https?://(?:[^/@\s|)\]<>\"']+@)?[a-z2-7]{56}\.onion(?::\d+)?(?:/[^\s|)\]<>\"']*)?",
    re.IGNORECASE,
)
_CREDENTIALS: Final = re.compile(r"https?://[^/@\s]+:[^/@\s]+@", re.IGNORECASE)
_HEADING: Final = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
_FRONTMATTER_TITLE: Final = re.compile(r"^title:\s*(.+?)\s*$", re.MULTILINE)
# The gen_kb_from_intel card heading is "# NAME — category"; the category is the tail after the
# last em dash (the generator's separator) or hyphen. A card without one keeps the whole heading
# as its name and is classified as a marketplace by default.
_CATEGORY_TO_ENTITY: Final[dict[str, EntityType]] = {
    "forum": EntityType.FORUM,
    "hacking_forum": EntityType.FORUM,
    "cybercrime_forum": EntityType.FORUM,
    "market": EntityType.MARKETPLACE,
    "markets": EntityType.MARKETPLACE,
    "ransomware_gang": EntityType.MARKETPLACE,
    "maas": EntityType.MARKETPLACE,
    "rat": EntityType.MARKETPLACE,
    "others": EntityType.MARKETPLACE,
}


class CtiKbParseError(ValueError):
    """The parse arguments themselves are unusable (not: a bad card, which is dropped)."""


class CtiKbReport(BaseModel):
    """Candidate onion services extracted from operator KB cards, and what was discarded.

    Every ``dropped_*`` counter has a reason and the totals reconcile: ``cards_seen`` equals
    ``accepted`` plus every drop counter, because exactly one candidate is emitted per card. An
    allowlist that quietly loses entries is worse than one that fails loudly, so the arithmetic is
    part of the contract and a test pins it.
    """

    model_config = ConfigDict(frozen=True)

    candidates: tuple[OnionService, ...]
    cards_seen: int
    accepted: int
    dropped_no_onion: int
    dropped_invalid_onion: int
    dropped_duplicate: int
    dropped_bad_name: int
    credentials_dropped: int
    """Cards whose onion address embedded ``user:password@`` material. The card is discarded whole —
    a candidate is never emitted with authentication material attached."""

    illegal_content_dropped: int
    """Cards whose free text carried an illegal-content indicator. Not proposed for collection: a
    site that must be reported is not a site to add to a monitoring allowlist."""

    def render(self) -> str:
        return (
            f"{self.accepted} candidate onion service(s) from {self.cards_seen} card(s); "
            f"dropped {self.dropped_no_onion} without an onion, {self.dropped_invalid_onion} "
            f"invalid, {self.dropped_duplicate} duplicate, {self.dropped_bad_name} unnamed; "
            f"{self.credentials_dropped} carried credentials and {self.illegal_content_dropped} "
            "carried an illegal-content indicator, both refused."
        )


def _card_name_and_category(card: str) -> tuple[str | None, str]:
    """The actor name and its category token from a card's ``# NAME — category`` heading.

    Falls back to the frontmatter ``title`` (with the generator's trailing descriptor stripped) so
    a card written without the heading still yields a name. The category defaults to empty, which
    the caller maps to a marketplace.
    """
    heading = _HEADING.search(card)
    if heading is not None:
        text = heading.group(1)
        # Split on the em dash the generator uses, or a spaced hyphen, taking the tail as category.
        for separator in ("—", " - "):
            if separator in text:
                name, _, category = text.rpartition(separator)
                return (name.strip()[:MAX_NAME_CHARS] or None), category.strip().lower()
        return text.strip()[:MAX_NAME_CHARS] or None, ""

    title = _FRONTMATTER_TITLE.search(card)
    if title is not None:
        # Titles read "NAME — crawled dark-web actor profile"; keep only the NAME.
        name = re.split(r"\s*—\s*", title.group(1), maxsplit=1)[0].strip()
        return (name[:MAX_NAME_CHARS] or None), ""
    return None, ""


def _entity_type_for(category: str) -> EntityType:
    return _CATEGORY_TO_ENTITY.get(category, EntityType.MARKETPLACE)


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
    """Build an :class:`OnionService` from the first onion in the card that validates, is not
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
                break  # this url is invalid; try the next onion in the card
            if service.key in used_keys:
                if attempt == 0:
                    candidate_name = f"{name} [{service.onion_host[:8]}]"[:MAX_NAME_CHARS]
                    continue
                break
            return service
    return None


def parse_cti_kb(
    cards: Iterable[str],
    *,
    content_safety: ContentSafety = ContentSafety.MANDATORY_REPORT,
    max_cards: int = MAX_CARDS,
) -> CtiKbReport:
    """Parse operator KB cards into reviewable :class:`OnionService` candidates.

    ``cards`` is an iterable of the *text* of operator-supplied ``kb/*.md`` cards — this function
    performs no I/O and no network access. ``content_safety`` defaults to
    :attr:`~nemesis.core.evidence.ContentSafety.MANDATORY_REPORT` because a leak site holds stolen
    victim data; the entity type (forum vs marketplace) is inferred from each card's category.

    The result never contains credentials, never contains an unvalidated onion address, never
    contains two services that normalize to the same allowlist key, and never contains a candidate
    for a site whose card names illegal content.
    """
    if content_safety not in {
        ContentSafety.SENSITIVE_PERSONAL_DATA,
        ContentSafety.LEGALLY_RESTRICTED,
        ContentSafety.MANDATORY_REPORT,
    }:
        raise CtiKbParseError(
            "a KB collection target must be classified as at least sensitive personal data; "
            f"{content_safety.value} understates a criminal leak site"
        )
    if max_cards < 1:
        raise CtiKbParseError("max_cards must be positive")

    candidates: list[OnionService] = []
    used_keys: set[tuple[EntityType, str]] = set()
    seen_hosts: set[str] = set()
    cards_seen = 0
    no_onion = invalid = duplicate = bad_name = creds = illegal = 0

    for card in list(cards)[:max_cards]:
        cards_seen += 1

        if contains_illegal_indicator(card):
            illegal += 1
            continue

        onion_urls = _ONION_URL.findall(card)
        if not onion_urls:
            no_onion += 1
            continue
        if _CREDENTIALS.search(card):
            creds += 1
            continue

        name, category = _card_name_and_category(card)
        if name is None:
            bad_name += 1
            continue

        service = _first_valid_service(
            name, onion_urls, _entity_type_for(category), content_safety, used_keys, seen_hosts
        )
        if service is None:
            if any(_host_of(url) in seen_hosts for url in onion_urls):
                duplicate += 1
            else:
                invalid += 1
            continue

        candidates.append(service)
        used_keys.add(service.key)
        seen_hosts.add(service.onion_host)

    return CtiKbReport(
        candidates=tuple(candidates),
        cards_seen=cards_seen,
        accepted=len(candidates),
        dropped_no_onion=no_onion,
        dropped_invalid_onion=invalid,
        dropped_duplicate=duplicate,
        dropped_bad_name=bad_name,
        credentials_dropped=creds,
        illegal_content_dropped=illegal,
    )


def candidate_summary(report: CtiKbReport) -> list[str]:
    """One human-readable line per accepted candidate: name, onion host and safety label.

    Deliberately not the onion URL path or any credential — the minimum an operator needs to decide
    whether to approve a target, and nothing that reads as a directory of live links.
    """
    return [
        f"{service.entity_type.value}: {normalize_identifier(service.entity_type, service.name)} "
        f"-> {service.onion_host} [{service.content_safety.value}]"
        for service in report.candidates
    ]


__all__ = [
    "CtiKbParseError",
    "CtiKbReport",
    "candidate_summary",
    "parse_cti_kb",
]
