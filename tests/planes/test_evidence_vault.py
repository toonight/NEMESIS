"""Tamper tests for the filesystem evidence vault.

Invariant 10 puts the vault operator inside the threat model, so a happy-path test proves
nothing here. Every test below damages the store the way a person with write access would
— rewriting artifact bytes, editing a log line, cutting the tail off the chain, deleting a
file, substituting evidence, relabelling quarantined material — and asserts that the damage
is named rather than absorbed.

The last group asserts the limit honestly: the chain the vault computes itself does not
make it defensible against the person who computes it, and an anchor we signed ourselves
does not change that.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from nemesis.core.evidence import ArtifactKind, ContentSafety, EvidenceObject, IntegrityAnchor
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    CustodyAction,
    CustodyEvent,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
)
from nemesis.core.temporal import TemporalExtent
from nemesis.evidence.anchoring import LocalHeadSigner
from nemesis.evidence.vault import (
    ArtifactCorruptedError,
    ArtifactHashMismatchError,
    ContentSafetyConflictError,
    EvidenceSubstitutionError,
    FileSystemEvidenceVault,
    MetadataCorruptedError,
    RestrictedContentError,
    VaultChainError,
    VaultEntryKind,
    compute_entry_hash,
)

T0 = datetime(2026, 3, 2, 8, 14, tzinfo=UTC)
COLLECTOR = new_id(IdPrefix.ACTOR)
QUARANTINED = [ContentSafety.MANDATORY_REPORT, ContentSafety.LEGALLY_RESTRICTED]


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Drive one vault call to completion.

    The vault is ``async`` because the port declares it so; its critical sections are
    synchronous and guarded by a ``threading.Lock``, so a fresh event loop per call is safe.
    """
    return asyncio.run(coroutine)


def _provenance() -> ProvenanceChain:
    return ProvenanceChain(
        collection_id=new_id(IdPrefix.COLLECTION),
        source=SourceDescriptor(source_class=SourceClass.INTERNET_SCAN, identifier="fixture-pdns"),
        method=CollectionMethod(
            collector_name="fixture-passive-dns",
            collector_version="1.0",
            parameters={"query": "acme-invoice-portal.example"},
            is_simulated=True,
        ),
        collected_at=T0,
        custody=(
            CustodyEvent(
                action=CustodyAction.SEALED,
                actor=COLLECTOR,
                occurred_at=T0,
                reason="sealed on collection",
            ),
        ),
    )


def _evidence(artifact: bytes, *, safety: ContentSafety = ContentSafety.ROUTINE) -> EvidenceObject:
    return EvidenceObject.seal(
        artifact=artifact,
        artifact_kind=ArtifactKind.DNS_RECORD,
        provenance=_provenance(),
        observed_extent=TemporalExtent.at(T0),
        content_safety=safety,
    )


def _vault(tmp_path: Path) -> FileSystemEvidenceVault:
    return FileSystemEvidenceVault(tmp_path / "vault")


def _sealed(
    tmp_path: Path, artifact: bytes = b"A 198.51.100.23"
) -> tuple[FileSystemEvidenceVault, EvidenceObject]:
    vault = _vault(tmp_path)
    evidence = _evidence(artifact)
    run(vault.seal(evidence, artifact))
    return vault, evidence


def _overwrite(path: Path, payload: bytes) -> None:
    """Write over a file the vault made read-only.

    The operator owns these files and can restore the mode at will, which is the point of
    the threat model rather than a gap in the test.
    """
    path.chmod(0o600)
    path.write_bytes(payload)


# --- corruption of the artifacts ---------------------------------------------


def test_rewritten_artifact_bytes_are_caught(tmp_path: Path) -> None:
    vault, evidence = _sealed(tmp_path)
    _overwrite(vault.root / "objects" / evidence.evidence_id, b"A 203.0.113.45")

    report = run(vault.verify_integrity())

    assert report.artifacts_corrupted == (evidence.evidence_id,)
    assert report.artifacts_verified == 0
    assert not report.is_intact
    # The chain itself is untouched: the report must not blame the log for a bad artifact.
    assert report.hash_chain_intact


def test_a_deleted_artifact_is_caught(tmp_path: Path) -> None:
    vault, evidence = _sealed(tmp_path)
    (vault.root / "objects" / evidence.evidence_id).unlink()

    report = run(vault.verify_integrity())

    assert report.artifacts_missing == (evidence.evidence_id,)
    assert not report.is_intact


def test_a_file_slipped_into_the_store_is_reported(tmp_path: Path) -> None:
    vault, _ = _sealed(tmp_path)
    (vault.root / "objects" / ("evd_sha256-" + "0" * 64)).write_bytes(b"never sealed")

    report = run(vault.verify_integrity())

    # Every link can verify and the store still hold material that entered it without
    # extending the chain.
    assert report.hash_chain_intact
    assert report.unlogged_artifacts
    assert not report.is_intact


# --- corruption of the chain --------------------------------------------------


def test_a_doctored_log_line_is_caught(tmp_path: Path) -> None:
    vault, evidence = _sealed(tmp_path)
    run(vault.retrieve_artifact(evidence.evidence_id, accessed_by="analyst-1", reason="review"))
    log = vault.root / "log.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["actor"] = "somebody-else"
    lines[1] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = run(vault.verify_integrity())

    assert not report.hash_chain_intact
    assert any("altered after it was written" in defect for defect in report.log_defects)


def test_a_truncated_log_is_caught(tmp_path: Path) -> None:
    vault, evidence = _sealed(tmp_path)
    run(vault.retrieve_artifact(evidence.evidence_id, accessed_by="analyst-1", reason="review"))
    log = vault.root / "log.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text(lines[0] + "\n", encoding="utf-8")

    report = run(vault.verify_integrity())

    # Every remaining link is genuine, so truncation is invisible from inside the chain.
    # Only the separately recorded head says how long the chain used to be.
    assert not report.hash_chain_intact
    assert any("removed from the end of the log" in defect for defect in report.log_defects)


def test_the_vault_refuses_to_extend_a_chain_that_does_not_verify(tmp_path: Path) -> None:
    vault, evidence = _sealed(tmp_path)
    log = vault.root / "log.jsonl"
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    entry["reason"] = "sealed under a different pretext"
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    # Appending would give the corruption a fresh, valid-looking tip; handing that tip to
    # an anchoring authority would launder it with someone else's credibility.
    with pytest.raises(VaultChainError):
        run(vault.head())
    with pytest.raises(VaultChainError):
        run(vault.retrieve_artifact(evidence.evidence_id, accessed_by="analyst-1", reason="review"))


# --- sealing ------------------------------------------------------------------


def test_seal_refuses_bytes_that_do_not_hash_to_the_declared_content_hash(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)
    evidence = _evidence(b"A 198.51.100.23")

    with pytest.raises(ArtifactHashMismatchError):
        run(vault.seal(evidence, b"A 203.0.113.45"))

    # Nothing may be left behind by a refused seal, or the store holds an object the chain
    # never committed to.
    assert run(vault.verify_integrity()).objects_checked == 0
    assert not list((vault.root / "objects").iterdir())


def test_resealing_identical_bytes_is_a_no_op(tmp_path: Path) -> None:
    artifact = b"A 198.51.100.23"
    vault, evidence = _sealed(tmp_path, artifact)

    again = run(vault.seal(evidence, artifact))

    entries = run(vault.log_entries())
    assert [entry.kind for entry in entries] == [VaultEntryKind.SEAL]
    assert again.evidence_id == evidence.evidence_id
    assert run(vault.verify_integrity()).is_intact


def test_resealing_over_substituted_stored_bytes_fails_loudly(tmp_path: Path) -> None:
    artifact = b"A 198.51.100.23"
    vault, evidence = _sealed(tmp_path, artifact)
    _overwrite(vault.root / "objects" / evidence.evidence_id, b"A 203.0.113.45")

    # The stored copy was replaced after sealing. Overwriting it with the genuine bytes
    # would repair the evidence and erase the fact that it had been substituted.
    with pytest.raises(EvidenceSubstitutionError, match="replaced after sealing"):
        run(vault.seal(evidence, artifact))
    assert (vault.root / "objects" / evidence.evidence_id).read_bytes() == b"A 203.0.113.45"


def test_reseal_may_not_relabel_material_already_in_the_vault(tmp_path: Path) -> None:
    artifact = b"forum post asserting a real name"
    vault = _vault(tmp_path)
    quarantined = _evidence(artifact, safety=ContentSafety.MANDATORY_REPORT)
    run(vault.seal(quarantined, artifact))
    relabelled = _evidence(artifact, safety=ContentSafety.ROUTINE)
    assert relabelled.evidence_id == quarantined.evidence_id

    with pytest.raises(ContentSafetyConflictError, match="mandatory_report"):
        run(vault.seal(relabelled, artifact))

    stored = run(vault.get(quarantined.evidence_id))
    assert stored is not None
    assert stored.content_safety is ContentSafety.MANDATORY_REPORT


# --- access -------------------------------------------------------------------


def test_retrieving_an_artifact_records_who_read_it_and_why(tmp_path: Path) -> None:
    artifact = b"A 198.51.100.23"
    vault, evidence = _sealed(tmp_path, artifact)

    returned = run(
        vault.retrieve_artifact(
            evidence.evidence_id, accessed_by="analyst-1", reason="drafting the referral"
        )
    )

    assert returned == artifact
    access = [entry for entry in run(vault.log_entries()) if entry.kind is VaultEntryKind.ACCESS]
    assert len(access) == 1
    assert access[0].actor == "analyst-1"
    assert access[0].reason == "drafting the referral"
    assert access[0].evidence_id == evidence.evidence_id
    # An unrecorded read is a chain-of-custody gap; a recorded one must not break the chain.
    assert run(vault.verify_integrity()).is_intact


def test_reading_a_corrupted_artifact_is_refused_and_the_refusal_is_recorded(
    tmp_path: Path,
) -> None:
    vault, evidence = _sealed(tmp_path)
    _overwrite(vault.root / "objects" / evidence.evidence_id, b"A 203.0.113.45")

    with pytest.raises(ArtifactCorruptedError):
        run(vault.retrieve_artifact(evidence.evidence_id, accessed_by="analyst-1", reason="review"))

    kinds = [entry.kind for entry in run(vault.log_entries())]
    assert VaultEntryKind.REFUSED_ACCESS in kinds


# --- quarantined material -----------------------------------------------------


@pytest.mark.parametrize("safety", QUARANTINED)
def test_quarantined_material_reaches_no_bulk_or_export_path(
    tmp_path: Path, safety: ContentSafety
) -> None:
    vault = _vault(tmp_path)
    routine_bytes = b"A 198.51.100.23"
    restricted_bytes = b"content carrying a reporting obligation"
    routine = _evidence(routine_bytes)
    restricted = _evidence(restricted_bytes, safety=safety)
    run(vault.seal(routine, routine_bytes))
    run(vault.seal(restricted, restricted_bytes))

    listed = run(vault.list_evidence())
    bundle = run(vault.export_bundle(requested_by="analyst-1", reason="referral package"))

    assert [obj.evidence_id for obj in listed] == [routine.evidence_id]
    assert [entry.evidence_id for entry in bundle.entries] == [routine.evidence_id]
    assert bundle.withheld_restricted == 1
    # The recipient must know the package is partial and must not learn what was withheld,
    # so the identifier may not appear anywhere in the serialized bundle either.
    assert restricted.evidence_id not in bundle.model_dump_json()


@pytest.mark.parametrize("safety", QUARANTINED)
def test_an_ordinary_read_of_quarantined_material_is_refused_and_conspicuous(
    tmp_path: Path, safety: ContentSafety
) -> None:
    vault = _vault(tmp_path)
    artifact = b"content carrying a reporting obligation"
    restricted = _evidence(artifact, safety=safety)
    run(vault.seal(restricted, artifact))

    with pytest.raises(RestrictedContentError):
        run(
            vault.retrieve_artifact(
                restricted.evidence_id, accessed_by="analyst-1", reason="curiosity"
            )
        )
    with pytest.raises(RestrictedContentError, match="escalation_reference"):
        run(
            vault.retrieve_quarantined_artifact(
                restricted.evidence_id,
                accessed_by="analyst-1",
                reason="escalation",
                escalation_reference="   ",
            )
        )

    released = run(
        vault.retrieve_quarantined_artifact(
            restricted.evidence_id,
            accessed_by="counsel-2",
            reason="statutory escalation",
            escalation_reference="ESC-2026-0041",
        )
    )

    assert released == artifact
    kinds = [entry.kind for entry in run(vault.log_entries())]
    assert kinds.count(VaultEntryKind.REFUSED_ACCESS) == 1
    assert kinds.count(VaultEntryKind.QUARANTINED_ACCESS) == 1


def test_relabelled_metadata_is_caught_and_never_enumerated(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    artifact = b"content carrying a reporting obligation"
    restricted = _evidence(artifact, safety=ContentSafety.MANDATORY_REPORT)
    run(vault.seal(restricted, artifact))
    metadata_path = vault.root / "metadata" / f"{restricted.evidence_id}.json"
    record = json.loads(metadata_path.read_text(encoding="utf-8"))
    record["content_safety"] = ContentSafety.ROUTINE.value
    _overwrite(metadata_path, json.dumps(record).encode())

    report = run(vault.verify_integrity())

    # The artifact is untouched; only the handling classification was rewritten. That is
    # the edit that moves quarantined material into an export, so the chain commits a
    # metadata hash and every release path must consult it.
    assert report.artifacts_corrupted == ()
    assert report.metadata_corrupted == (restricted.evidence_id,)
    assert not report.is_intact
    with pytest.raises(MetadataCorruptedError):
        run(vault.get(restricted.evidence_id))
    with pytest.raises(MetadataCorruptedError):
        run(vault.list_evidence())
    with pytest.raises(MetadataCorruptedError):
        run(vault.export_bundle(requested_by="analyst-1", reason="referral package"))


# --- anchors, and what they are worth ------------------------------------------


def test_a_locally_signed_anchor_does_not_make_the_vault_defensible(tmp_path: Path) -> None:
    vault, _ = _sealed(tmp_path)
    signer = LocalHeadSigner.generate()
    anchor = signer.anchor(run(vault.head()))
    run(vault.record_anchor(anchor))

    report = run(vault.verify_integrity())

    assert signer.verifies(anchor)
    assert not anchor.is_externally_held
    assert report.is_intact
    assert report.anchors_verified == 1
    # An anchor we signed ourselves is held by someone the threat model already includes.
    assert report.externally_anchored == 0
    assert not report.is_defensible_against_insider


def test_no_anchor_this_build_can_produce_closes_the_insider_gap(tmp_path: Path) -> None:
    """The claim the platform must be *unable* to make falsely, asserted as unmakeable.

    **This test enshrined the hole it was named for.** It recorded an anchor with
    ``proof="SIMULATED-token"`` and asserted ``is_defensible_against_insider`` was True — and it
    passed, because ``is_externally_held`` was a denylist of authority *strings*: anything not
    called "nemesis", "self" or "internal" counted as external. An adversarial review flipped the
    verdict to YES with ``authority="Totally Independent Notary AG"`` and
    ``proof="not-even-base64"``. Nothing validated either field.

    A string somebody typed decided whether this platform claimed its evidence was defensible
    against itself. That is the single claim it most needs to be unable to make falsely, and
    `export.py` says as much: "False for every package this build can produce."

    So the check is now an allowlist of anchor types this build can actually *verify*, and that
    set is empty. The assertion inverted with it, and inverting it is the point: a test that can
    only be made to pass by implementing a real verifier is a test that cannot be satisfied by
    typing a better authority name.
    """
    vault, _ = _sealed(tmp_path)
    head = run(vault.head())
    for authority, proof in (
        ("synthetic-timestamping-authority", "SIMULATED-token"),
        ("Totally Independent Notary AG", "not-even-base64"),
        ("some-transparency-log", "x" * 64),
    ):
        run(
            vault.record_anchor(
                IntegrityAnchor(
                    anchor_type="rfc3161_timestamp_token",
                    anchored_at=T0,
                    authority=authority,
                    proof=proof,
                    covers_hash=head,
                )
            )
        )

    report = run(vault.verify_integrity())

    assert report.anchors_verified == 3, "the anchors were not recorded; this tests nothing"
    assert report.externally_anchored == 0, (
        "an unvalidated authority string was counted as an external anchor"
    )
    assert not report.is_defensible_against_insider


def test_making_an_anchor_external_requires_a_verifier_and_not_a_better_name() -> None:
    """The allowlist is empty, and what filling it costs is stated rather than left implied."""
    from nemesis.core.evidence import VERIFIED_ANCHOR_TYPES

    assert frozenset() == VERIFIED_ANCHOR_TYPES, (
        "an anchor type was allowlisted. That is a commitment to two things: a verifier that "
        "validates `proof` against the named authority, and a registry mapping an authority to "
        "the key that authenticates it. Without both, this restores the defect the allowlist "
        "replaced."
    )


def test_an_anchor_over_a_head_this_chain_never_had_is_refused(tmp_path: Path) -> None:
    vault, _ = _sealed(tmp_path)
    signer = LocalHeadSigner.generate()
    foreign = signer.anchor("f" * 64)

    # Such an anchor belongs to another vault, or is proof the chain was already rewritten.
    # Storing it would let a later verification "confirm" a head that no longer exists.
    with pytest.raises(VaultChainError, match="not a head this chain ever had"):
        run(vault.record_anchor(foreign))


def test_an_anchor_catches_a_rewrite_the_chain_alone_cannot(tmp_path: Path) -> None:
    vault, evidence = _sealed(tmp_path)
    signer = LocalHeadSigner.generate()
    run(vault.record_anchor(signer.anchor(run(vault.head()))))

    # The careless tamperer edits a line; this one recomputes the entry hash and the
    # recorded head, so nothing inside the store disagrees with anything else.
    log = vault.root / "log.jsonl"
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    entry["actor"] = "somebody-else"
    entry["entry_hash"] = compute_entry_hash(
        sequence=entry["sequence"],
        kind=VaultEntryKind(entry["kind"]),
        previous_entry_hash=entry["previous_entry_hash"],
        evidence_id=entry["evidence_id"],
        content_hash=entry["content_hash"],
        metadata_hash=entry["metadata_hash"],
        recorded_at=datetime.fromisoformat(entry["recorded_at"]),
        actor=entry["actor"],
        reason=entry["reason"],
    )
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    _overwrite(
        vault.root / "head.json",
        json.dumps({"sequence": entry["sequence"], "head": entry["entry_hash"]}).encode(),
    )

    report = run(vault.verify_integrity())

    assert evidence.evidence_id == entry["evidence_id"]
    assert not report.hash_chain_intact
    assert any("the chain was rewritten" in defect for defect in report.log_defects)
