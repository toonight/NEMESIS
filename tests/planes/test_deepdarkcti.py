"""The deepdarkCTI index parser, exercised on a synthetic table.

No real onion address appears here: the fixtures generate valid v3 addresses so the parser's
checksum gate is tested against real cryptography, and the table is shaped like
``fastfire/deepdarkCTI``'s ``ransomware_gang.md`` (Name | Status | User:Password | channel |
RSS) without reproducing its live-link directory.

The parser is pure text-to-structure: these tests open no socket and the module imports no
network client. What they pin is the boundary — credentials never survive, unvalidated or
dead-shaped onions are dropped with a counted reason, the arithmetic reconciles, and every
accepted candidate is a valid, allowlist-ready OnionService.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

import pytest

from nemesis.collect.dark_web import TorOnionConnector
from nemesis.collect.deepdarkcti import (
    DeepDarkCtiParseError,
    candidate_summary,
    parse_deepdarkcti,
)
from nemesis.core.entities import EntityType
from nemesis.core.evidence import ContentSafety

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


def _v3(seed: bytes) -> str:
    public_key = hashlib.sha256(seed).digest()[:32]
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode().lower() + ".onion"


A, B, C, D, E, F = (_v3(seed) for seed in (b"a", b"b", b"c", b"d", b"e", b"f"))
BAD_CHECKSUM = "a" * 56 + ".onion"  # well-shaped label, wrong v3 checksum

TABLE = f"""\
Some prose before the table is ignored.

| Name | Status | User:Password | Tox ID or other channel | RSS Feed |
| ---- | ------ | ------------- | ----------------------- | -------- |
| [SynthLock](http://{A}/) | ONLINE |  | Tox:ABC - https://t.me/x |  |
| [GhostLeak](http://{B}/data) | Online | admin:hunter2 |  |  |
| [OldGang](http://{C}/) | Offline |  |  |  |
| [BadChecksum](http://{BAD_CHECKSUM}/) | ONLINE |  |  |  |
| [TelegramOnly](https://t.me/nogroup) | ONLINE |  |  |  |
| [DupOfSynthLock](http://{A}/mirror) | ONLINE |  |  |  |
| [CredInUrl](http://root:toor@{D}/) | ONLINE |  |  |  |
| [TwinGang](http://{E}/) | ONLINE |  |  |  |
| [TwinGang](http://{F}/) | ONLINE |  |  |  |
"""


def test_a_clean_table_yields_validated_candidates() -> None:
    report = parse_deepdarkcti(TABLE)

    # Accepted: SynthLock (A), TwinGang (E), TwinGang-mirror (F). Everything else is dropped.
    assert report.accepted == 3
    hosts = {service.onion_host for service in report.candidates}
    assert hosts == {A, E, F}
    assert all(service.entity_type is EntityType.MARKETPLACE for service in report.candidates)
    assert all(
        service.content_safety is ContentSafety.MANDATORY_REPORT for service in report.candidates
    )


def test_the_arithmetic_reconciles() -> None:
    report = parse_deepdarkcti(TABLE)
    total = (
        report.accepted
        + report.dropped_no_onion
        + report.dropped_invalid_onion
        + report.dropped_offline
        + report.dropped_duplicate
        + report.dropped_bad_name
        + report.credentials_dropped
    )
    assert total == report.rows_seen == 9


def test_credentials_never_survive_whether_in_a_url_or_a_column() -> None:
    report = parse_deepdarkcti(TABLE)
    # GhostLeak (column) and CredInUrl (URL) both carried credentials.
    assert report.credentials_dropped == 2
    blob = repr(report.candidates) + "\n".join(candidate_summary(report))
    assert "hunter2" not in blob
    assert "root:toor" not in blob
    assert "admin:" not in blob
    # The credentialed onions (B and D) are absent from the accepted set.
    hosts = {service.onion_host for service in report.candidates}
    assert B not in hosts and D not in hosts


def test_dead_shaped_and_offline_and_linkless_rows_are_dropped_with_reasons() -> None:
    report = parse_deepdarkcti(TABLE)
    assert report.dropped_invalid_onion == 1  # BadChecksum
    assert report.dropped_offline == 1  # OldGang
    assert report.dropped_no_onion == 1  # TelegramOnly
    assert report.dropped_duplicate == 1  # DupOfSynthLock reuses A


def test_offline_entries_can_be_kept_when_asked() -> None:
    kept = parse_deepdarkcti(TABLE, include_offline=True)
    assert kept.dropped_offline == 0
    assert kept.accepted == 4  # OldGang (C) now included
    assert C in {service.onion_host for service in kept.candidates}


def test_a_name_collision_is_disambiguated_not_dropped() -> None:
    report = parse_deepdarkcti(TABLE)
    twins = [s for s in report.candidates if s.name.startswith("TwinGang")]
    assert len(twins) == 2
    assert {s.onion_host for s in twins} == {E, F}
    # Distinct allowlist keys, so a connector will accept both.
    assert twins[0].key != twins[1].key


def test_candidates_are_allowlist_ready_for_the_connector() -> None:
    report = parse_deepdarkcti(TABLE)
    connector = TorOnionConnector(services=report.candidates, as_of=NOW)
    assert connector.capabilities.is_simulated is False
    assert len(connector.capabilities.supported_entity_types) >= 1


def test_the_summary_shows_host_and_safety_but_no_url_path_or_secret() -> None:
    lines = candidate_summary(parse_deepdarkcti(TABLE))
    assert lines
    for line in lines:
        assert ".onion" in line
        assert "mandatory_report" in line
        assert "/mirror" not in line and "/data" not in line  # no path
        assert "@" not in line  # no credentials


def test_forum_is_an_acceptable_target_type() -> None:
    report = parse_deepdarkcti(TABLE, entity_type=EntityType.FORUM)
    assert report.accepted == 3
    assert all(s.entity_type is EntityType.FORUM for s in report.candidates)


def test_a_non_onion_target_type_is_refused() -> None:
    with pytest.raises(DeepDarkCtiParseError, match="forum or marketplace"):
        parse_deepdarkcti(TABLE, entity_type=EntityType.THREAT_ACTOR)


def test_an_empty_or_prose_only_document_is_an_empty_report() -> None:
    report = parse_deepdarkcti("no tables here\njust prose\n")
    assert report.rows_seen == 0
    assert report.accepted == 0
    assert report.candidates == ()


def test_the_row_ceiling_bounds_a_hostile_file() -> None:
    row = f"| [X](http://{A}/) | ONLINE |  |  |  |\n"
    flood = "| Name | Status | User:Password | c | r |\n| - | - | - | - | - |\n" + row * 50
    report = parse_deepdarkcti(flood, max_rows=10)
    assert report.rows_seen == 10
