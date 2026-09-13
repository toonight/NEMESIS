"""Operation PAPER SWARM — acceptance tests for the sealed, verifiable PaperCut run.

Offline and deterministic: the default fixture profile author stands in for the local pilot,
so these run in CI with no model. The opt-in live-Ollama counterpart is in
``tests/planes/test_papercut_live_pilot.py``.

What they defend:
- the workspace a fresh reader opens verifies (vault + audit chains, anchor sound);
- human identity is a name-free HYPOTHESIS, never a naming, and cannot reach an external product;
- the plantable nationality does not survive into an organizational finding;
- disruption is proposed and never executable here;
- nothing left the platform.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from nemesis.attribute.dimensions import AttributionDimension, IdentityDisposition
from nemesis.attribute.disclosure import redact_for_disclosure
from nemesis.audit.trail import AppendOnlyAuditTrail
from nemesis.authz.anchor import (
    FileAnchorStore,
    local_anchor_authority,
    registered_authorities,
)
from nemesis.authz.audit_anchor import (
    ANCHOR_FILE,
    ANCHOR_PUBLIC_KEY_FILE,
    retained_epoch,
    verify_audit_trail,
)
from nemesis.authz.keys import CapabilityVerifyingKey
from nemesis.collect.fixtures.papercut import paper_swarm_observations
from nemesis.core.confidence import ConfidenceBand
from nemesis.evidence.vault import FileSystemEvidenceVault
from nemesis.slice.papercut import run_paper_swarm

pytestmark = pytest.mark.invariant

HIGH_BANDS = frozenset(
    {ConfidenceBand.LIKELY, ConfidenceBand.VERY_LIKELY, ConfidenceBand.ALMOST_CERTAIN}
)


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("paper-swarm")
    run_paper_swarm(workspace=root)
    return root


def test_a_fresh_reader_verifies_the_sealed_package(workspace: Path) -> None:
    """The whole point of 'sealed': a different process, not the one that wrote it, validates it."""

    async def _check() -> tuple[bool, bool, bool]:
        vault_report = await FileSystemEvidenceVault(workspace / "vault").verify_integrity()
        chain = await AppendOnlyAuditTrail(workspace / "audit.jsonl").verify()
        verifier = CapabilityVerifyingKey.load(workspace / ANCHOR_PUBLIC_KEY_FILE)
        anchor = await verify_audit_trail(
            AppendOnlyAuditTrail(workspace / "audit.jsonl"),
            store=FileAnchorStore(workspace / ANCHOR_FILE),
            authorities=registered_authorities(local_anchor_authority(verifier)),
            retained_epoch=retained_epoch(workspace),
        )
        return vault_report.is_intact, chain.intact, anchor.sound

    vault_intact, chain_intact, anchor_sound = asyncio.run(_check())
    assert vault_intact
    assert chain_intact
    assert anchor_sound


def test_every_observation_is_sealed(workspace: Path) -> None:
    result = run_paper_swarm(workspace=workspace / "reseal-probe")
    assert result.sealed_objects == len(paper_swarm_observations())
    assert result.vault_chain_intact
    assert result.audit_chain_intact


def test_human_identity_is_a_name_free_hypothesis_not_a_naming() -> None:
    result = run_paper_swarm()
    human = result.attribution.for_dimension(AttributionDimension.HUMAN_IDENTITY)

    assert human.identity_disposition is IdentityDisposition.HYPOTHESIS
    assert result.attribution.names_a_person is False
    assert any("hypothesis" in warning.casefold() for warning in human.warnings)


def test_the_human_identity_hypothesis_cannot_reach_an_external_product() -> None:
    result = run_paper_swarm()
    product = redact_for_disclosure(result.attribution)

    shipped = {item.dimension for item in product.dimensions}
    withheld = {item.dimension for item in product.withheld}
    assert AttributionDimension.HUMAN_IDENTITY in withheld
    assert AttributionDimension.HUMAN_IDENTITY not in shipped
    assert product.names_a_person is False
    # The profile text itself must not ride out in the product.
    assert "human-in-the-loop" not in product.model_dump_json()


def test_the_plantable_nationality_does_not_become_an_organizational_finding() -> None:
    """The CIS do-not-hit list is trivially plantable; it must be inverted, not believed."""
    result = run_paper_swarm()
    organization = result.attribution.for_dimension(AttributionDimension.ORGANIZATION)

    assert organization.band not in HIGH_BANDS
    # The engine records the "planted to mislead" reading rather than crediting the tell.
    assert any(alt.is_deception_hypothesis for alt in organization.alternatives)


def test_disruption_is_proposed_and_never_executable_here() -> None:
    result = run_paper_swarm()
    by_operation = {option.operation.value: option for option in result.disruption.options}

    assert "hosting_termination" in by_operation
    assert (
        by_operation["hosting_termination"].implementation_status.value
        == "REQUIRES_LEGAL_AUTHORITY"
    )
    # The drafting operations are implemented (drafted, not sent), never a live effect.
    assert by_operation["provider_notification"].implementation_status.value == "IMPLEMENTED"
    assert by_operation["takedown_request_draft"].implementation_status.value == "IMPLEMENTED"


def test_nothing_left_the_platform() -> None:
    result = run_paper_swarm()
    assert result.any_external_contact is False


def test_the_run_states_what_it_does_not_reach() -> None:
    result = run_paper_swarm()
    assert "No natural person is identified" in result.actor_gap
    assert "REQUIRES_EXTERNAL_DATA" in result.actor_gap
