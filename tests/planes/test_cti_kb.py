"""The KB-card allowlist adapter: operator knowledge cards -> reviewable onion candidates.

The properties mirror the deepdarkCTI parser's contract, adapted to the ``kb/actor-*.md`` card
shape: pure text-to-structure with no I/O, credentials and illegal-content cards refused and
counted, every onion re-validated through the connector's v3 gate, leak sites classified
MANDATORY_REPORT, and a reconciling count so a silently shortened allowlist cannot pass.
"""

from __future__ import annotations

import pytest

from nemesis.collect.cti_kb import CtiKbParseError, candidate_summary, parse_cti_kb
from nemesis.core.entities import EntityType
from nemesis.core.evidence import ContentSafety

# Valid version-3 onion addresses (correct checksums), generated for these tests only.
ONION_A = "3e7lo3ebsgrjp5wsb6msvoiqrvmrn4mxmtkepmoevgjxqew5ksnftmid.onion"
ONION_B = "tsjzr4ps375ezeomrnqmbxllcabz6y3bn75qjyhsuoreg23refrwx7qd.onion"
ONION_C = "rahxmwfdoibcndn7un7bszd2fdo3af4qbrnz3aepoyrxk72sbfdnboid.onion"


def _card(name: str, category: str, onion: str, *, extra: str = "") -> str:
    return (
        "---\n"
        f"id: actor-{name.lower().replace(' ', '-')}\n"
        f"title: {name} — crawled dark-web actor profile\n"
        "---\n\n"
        f"# {name} — {category}\n\n"
        f"- Live onion/site(s): http://{onion}\n"
        f"- Leak dump present on site: yes | referenced onions: 3\n"
        f"{extra}"
    )


def test_a_ransomware_card_becomes_a_mandatory_report_marketplace_candidate() -> None:
    report = parse_cti_kb([_card("Brain Cipher", "ransomware_gang", ONION_A)])

    assert report.cards_seen == 1
    assert report.accepted == 1
    service = report.candidates[0]
    assert service.entity_type is EntityType.MARKETPLACE
    assert service.onion_host == ONION_A
    assert service.content_safety is ContentSafety.MANDATORY_REPORT


def test_a_forum_card_is_classified_as_a_forum() -> None:
    report = parse_cti_kb([_card("CryptBB", "forum", ONION_B)])
    assert report.candidates[0].entity_type is EntityType.FORUM


def test_a_card_with_no_onion_is_dropped_and_counted() -> None:
    card = "---\ntitle: X — profile\n---\n\n# X — forum\n\n- Live onion/site(s): (none live)\n"
    report = parse_cti_kb([card])
    assert report.accepted == 0
    assert report.dropped_no_onion == 1


def test_a_card_whose_onion_embeds_credentials_is_refused() -> None:
    card = _card("Creds Market", "markets", ONION_A).replace(
        f"http://{ONION_A}", f"http://user:pass@{ONION_A}"
    )
    report = parse_cti_kb([card])
    assert report.accepted == 0
    assert report.credentials_dropped == 1


def test_a_card_naming_illegal_content_is_refused() -> None:
    report = parse_cti_kb([_card("Bad Site", "markets", ONION_A, extra="- Sections seen: CSAM\n")])
    assert report.accepted == 0
    assert report.illegal_content_dropped == 1
    assert report.candidates == ()


def test_an_invalid_onion_checksum_is_dropped() -> None:
    bogus = "a" * 56 + ".onion"
    report = parse_cti_kb([_card("Bad Onion", "markets", bogus)])
    assert report.accepted == 0
    assert report.dropped_invalid_onion == 1


def test_two_cards_on_the_same_host_collapse_to_one() -> None:
    report = parse_cti_kb(
        [_card("Site One", "markets", ONION_A), _card("Site Two", "markets", ONION_A)]
    )
    assert report.accepted == 1
    assert report.dropped_duplicate == 1


def test_the_counts_reconcile() -> None:
    cards = [
        _card("Alpha", "ransomware_gang", ONION_A),
        _card("Beta", "forum", ONION_B),
        _card("Gamma", "markets", ONION_C),
        "# NoOnion — forum\n\n- nothing here\n",
        _card("Illegal", "markets", ONION_A, extra="- note: csam bundle\n"),
    ]
    report = parse_cti_kb(cards)
    assert report.cards_seen == 5
    assert report.cards_seen == (
        report.accepted
        + report.dropped_no_onion
        + report.dropped_invalid_onion
        + report.dropped_duplicate
        + report.dropped_bad_name
        + report.credentials_dropped
        + report.illegal_content_dropped
    )


def test_cards_beyond_the_cap_are_reported_not_silently_dropped() -> None:
    cards = [
        _card("Alpha", "markets", ONION_A),
        _card("Beta", "markets", ONION_B),
        _card("Gamma", "markets", ONION_C),
    ]
    report = parse_cti_kb(cards, max_cards=2)
    assert report.cards_seen == 2  # only the examined cards
    assert report.cards_over_cap == 1  # the unlooked-at remainder is surfaced, not hidden
    # The reconciliation still holds over the examined cards.
    assert report.cards_seen == (
        report.accepted
        + report.dropped_no_onion
        + report.dropped_invalid_onion
        + report.dropped_duplicate
        + report.dropped_bad_name
        + report.credentials_dropped
        + report.illegal_content_dropped
    )
    assert "not examined" in report.render()


def test_a_too_weak_content_safety_is_refused() -> None:
    with pytest.raises(CtiKbParseError):
        parse_cti_kb([_card("X", "markets", ONION_A)], content_safety=ContentSafety.ROUTINE)


def test_candidate_summary_hides_the_url_path_and_shows_the_host() -> None:
    report = parse_cti_kb([_card("Brain Cipher", "ransomware_gang", ONION_A)])
    lines = candidate_summary(report)
    assert len(lines) == 1
    assert ONION_A in lines[0]
    assert "mandatory_report" in lines[0]
    assert "http://" not in lines[0]
