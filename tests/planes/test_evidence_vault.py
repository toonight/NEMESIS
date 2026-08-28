"""Tamper tests for the filesystem evidence vault.

Invariant 10 puts the vault operator inside the threat model, so a happy-path test proves
nothing here. Every test below damages the store the way a person with write access would
— rewriting artifact bytes, editing a log line, cutting the tail off the chain, deleting a
file, substituting evidence, relabelling quarantined material — and asserts that the damage
is named rather than absorbed.

The last group asserts the limit honestly: the chain the vault computes itself does not
make it defensible against the person who computes it, and an anchor we signed ourselves
does not change that.

Covers **EVID-01** (an artifact's identity is its content), **EVID-02** (modification,
insertion, deletion and reordering each detectable and distinctly reported), **EVID-03**
(nothing is released from a chain that does not verify), **EVID-04** (quarantined material is
held, never indexed, and its refusal is itself recorded) and **EVID-08** (the vault reports that
it is not defensible against its own operator, and cannot be made to say otherwise) from
`docs/security/INVARIANTS.md`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import threading
from collections import Counter
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
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


def test_a_forged_chain_releases_nothing_even_when_the_metadata_hash_agrees(
    tmp_path: Path,
) -> None:
    """EVID-03. The construction the neighbouring test does not perform.

    ``test_relabelled_metadata_is_caught_and_never_enumerated`` edits the metadata file alone, so
    the committed ``metadata_hash`` stops matching and the release paths refuse on *that*. An
    adversarial review did the two-file version: relabel the metadata **and** patch the seal
    entry's ``metadata_hash`` to agree, leaving ``entry_hash`` untouched.

    The chain caught it — ``verify_integrity()`` named the entry precisely — and
    ``list_evidence()`` handed the object over anyway, summary included, because every reader
    parsed the chain and discarded the verdict: ``entries, _ = _parse_chain(...)``, in three
    places. Checking a metadata hash against a log line already known to be forged is not a
    check; it is a check read out of a compromised source.

    That is *below* this module's stated position — "careless tampering is caught" — because the
    operator here recomputed nothing beyond one field.
    """
    vault = _vault(tmp_path)
    artifact = b"content carrying a reporting obligation"
    restricted = _evidence(artifact, safety=ContentSafety.MANDATORY_REPORT)
    run(vault.seal(restricted, artifact))

    metadata_path = vault.root / "metadata" / f"{restricted.evidence_id}.json"
    record = json.loads(metadata_path.read_text(encoding="utf-8"))
    record["content_safety"] = ContentSafety.ROUTINE.value
    relabelled = json.dumps(record).encode()
    _overwrite(metadata_path, relabelled)

    # Make the log agree with the forgery, without recomputing the entry hash.
    log_path = vault.root / "log.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    forged = []
    for line in lines:
        entry = json.loads(line)
        if entry.get("evidence_id") == restricted.evidence_id and "metadata_hash" in entry:
            entry["metadata_hash"] = hashlib.sha256(relabelled).hexdigest()
        forged.append(json.dumps(entry, separators=(",", ":"), sort_keys=True))
    _overwrite(log_path, ("\n".join(forged) + "\n").encode())

    report = run(vault.verify_integrity())
    assert not report.is_intact, "the chain no longer notices the forgery; this tests nothing"
    assert report.log_defects, report

    # Every release path refuses, and refuses on the chain rather than on the metadata hash —
    # which now agrees, which was the whole point of the construction.
    for release in (
        lambda: run(vault.list_evidence()),
        lambda: run(vault.get(restricted.evidence_id)),
        lambda: run(vault.export_bundle(requested_by="analyst-1", reason="referral")),
    ):
        with pytest.raises(VaultChainError):
            release()


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


# --- two writers on one root ---------------------------------------------------


def _seal_batch(root: Path, tag: str, count: int) -> Counter[str]:
    """Seal `count` artifacts through a vault instance of this thread's own.

    A separate instance is the point: the vault's mutex is per-instance, so two of them on
    one root are exactly as unsynchronised as two processes are, and cost a thread instead
    of a fork to demonstrate.
    """
    vault = FileSystemEvidenceVault(root)
    outcomes: Counter[str] = Counter()
    for index in range(count):
        artifact = f"{tag}-{index}".encode()
        try:
            run(vault.seal(_evidence(artifact), artifact))
            outcomes["sealed"] += 1
        except Exception as exc:  # recorded rather than raised: the shape matters
            outcomes[type(exc).__name__] += 1
    return outcomes


def test_two_vaults_on_one_root_do_not_fork_the_chain(tmp_path: Path) -> None:
    """THE FAILURE THAT LOOKS LIKE AN ATTACK AND IS AN ACCIDENT.

    The mutex was a `threading.Lock` on the instance, `_append` read the tip and wrote with
    nothing held across the two, and `_write_atomic` used one fixed `.partial` name per
    target. Measured before the fix, 3 runs out of 3: two entries claim sequence 0, and from
    the second write onward **every** seal fails for the life of the store — `_chain_tip()`
    raises, so no seal, no recorded read and no anchor can ever be appended again.

    The report it produced was the worst part. `entries were reordered, inserted or removed`
    is the sentence a tamper-evident store exists to be able to say, and here it was
    describing two honest writers and a missing lock.
    """
    root = tmp_path / "vault"
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_seal_batch, root, tag, 20) for tag in ("A", "B")]
        outcomes = [future.result() for future in futures]

    failures = {kind: n for outcome in outcomes for kind, n in outcome.items() if kind != "sealed"}
    assert not failures, f"concurrent seals failed: {failures}"
    assert sum(outcome["sealed"] for outcome in outcomes) == 40

    sequences = [
        json.loads(line)["sequence"]
        for line in (root / "log.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert sorted(sequences) == list(range(40)), (
        f"the chain forked: duplicate sequences "
        f"{sorted(s for s, n in Counter(sequences).items() if n > 1)}"
    )

    report = run(_vault(tmp_path).verify_integrity())
    assert report.is_intact, report.log_defects


def test_a_later_writer_still_works_after_concurrent_ones(tmp_path: Path) -> None:
    """The store must remain writable, which is the property the fork destroyed.

    Distinct from the assertion above on purpose: a chain can verify and still be one whose
    tip nothing can build on, and it is the second that ends an investigation.
    """
    root = tmp_path / "vault"
    with ThreadPoolExecutor(max_workers=2) as pool:
        [future.result() for future in [pool.submit(_seal_batch, root, tag, 10) for tag in "AB"]]

    artifact = b"written after the concurrent ones"
    run(FileSystemEvidenceVault(root).seal(_evidence(artifact), artifact))


def test_a_forked_chain_is_named_as_concurrency_rather_than_as_an_edit(tmp_path: Path) -> None:
    """The harm the lock does not undo: a store already forked, and the sentence about it.

    `entries were reordered, inserted or removed` is what a tamper-evident store exists to be
    able to say, and for as long as two writers could race it was routinely saying it about an
    accident. An operator who reads that about a missing lock either hunts an intruder who was
    never there, or learns to discount the message — and the second is worse.

    The signature is exact: two entries at the same sequence, built on the same predecessor.
    The report says so *and* says it is forgeable, because a shape anyone who can write the log
    can write on purpose lowers suspicion and does not clear it.
    """
    vault, _ = _sealed(tmp_path)
    log = vault.root / "log.jsonl"
    first = json.loads(log.read_text(encoding="utf-8").splitlines()[0])

    # A sibling of entry 0: same sequence, same predecessor, its own honest hash — exactly
    # what a second writer that had read the same tip would have appended.
    sibling = dict(first)
    sibling["reason"] = "sealed by the other writer"
    sibling["entry_hash"] = compute_entry_hash(
        sequence=sibling["sequence"],
        kind=VaultEntryKind(sibling["kind"]),
        previous_entry_hash=sibling["previous_entry_hash"],
        evidence_id=sibling["evidence_id"],
        content_hash=sibling["content_hash"],
        metadata_hash=sibling["metadata_hash"],
        recorded_at=datetime.fromisoformat(sibling["recorded_at"]),
        actor=sibling["actor"],
        reason=sibling["reason"],
    )
    log.write_text(json.dumps(first) + "\n" + json.dumps(sibling) + "\n", encoding="utf-8")

    report = run(vault.verify_integrity())

    assert not report.hash_chain_intact
    assert any("signature two concurrent writers leave" in d for d in report.log_defects), (
        f"the fork was reported only as an edit: {report.log_defects}"
    )
    assert any("forgeable" in d for d in report.log_defects), (
        "a shape anyone who can write the log can write must not read as exculpatory"
    )


def test_a_package_is_read_from_one_snapshot_not_from_two_reads(tmp_path: Path) -> None:
    """The fork argument, one level up, where an adversarial pass found it still standing.

    A package used to be assembled from `export_bundle()` and then `log_entries()` — two
    acquisitions, so an honest concurrent writer landed in the gap and the manifest named a
    head the shipped log no longer ended at. That pair is exactly what the package's own
    `verify.py` checks, and its answer is not "stale": it is `the bundle and its log describe
    different vaults`, which tells a recipient the evidence was doctored. Measured on the
    two-call form, 120 exports against one concurrent sealer: 10 disagreed with themselves.

    The writer is real and the assertion that it ran is part of the test — a quiet writer
    would make this pass while proving nothing.
    """
    root = tmp_path / "vault"
    seed = FileSystemEvidenceVault(root)
    for index in range(3):
        artifact = f"seed-{index}".encode()
        run(seed.seal(_evidence(artifact), artifact))

    stop = threading.Event()

    def keep_sealing() -> None:
        vault = FileSystemEvidenceVault(root)
        index = 0
        while not stop.is_set():
            artifact = f"concurrent-{index}".encode()
            index += 1
            run(vault.seal(_evidence(artifact), artifact))

    log = root / "log.jsonl"
    before = len(log.read_text().splitlines())
    writer = threading.Thread(target=keep_sealing, daemon=True)
    writer.start()
    try:
        reader = FileSystemEvidenceVault(root)
        for _ in range(40):
            bundle, entries, _anchors = run(
                reader.export_snapshot(requested_by="analyst-1", reason="disclosure")
            )
            assert entries, "the snapshot came back with no chain at all"
            assert bundle.vault_head == entries[-1].entry_hash, (
                "the manifest names a head the log it ships beside does not end at; the "
                "recipient's own verifier reads that as two different vaults"
            )
    finally:
        stop.set()
        writer.join(timeout=10)

    after = len(log.read_text().splitlines())
    assert after > before + 5, (
        f"the concurrent writer only added {after - before} entries, so the window this test "
        "exists to close was never actually open"
    )


def test_a_vault_on_read_only_media_can_still_be_verified(tmp_path: Path) -> None:
    """Verifying a store you were handed must not require write access to it.

    The first version of the inter-process lock took `LOCK_EX` in every critical section,
    including the read-only ones, and `LOCK_EX` needs the lock file opened for append. So
    `verify_integrity` — whose own docstring says it never raises — raised `PermissionError`
    on a vault copied to read-only media, which is precisely the forensic workflow the vault
    exists to support: somebody hands you a package and you check it without touching it.

    Readers hold `LOCK_SH` instead. It still excludes writers, which is all a consistent read
    needs, and it does not require the store to be writable.
    """
    source = tmp_path / "vault"
    vault = FileSystemEvidenceVault(source)
    for index in range(3):
        artifact = f"handed-over-{index}".encode()
        run(vault.seal(_evidence(artifact), artifact))

    handed_over = tmp_path / "read-only" / "vault"
    shutil.copytree(source, handed_over)
    for path in sorted(handed_over.rglob("*"), reverse=True):
        path.chmod(0o400 if path.is_file() else 0o500)
    handed_over.chmod(0o500)

    try:
        report = run(FileSystemEvidenceVault(handed_over).verify_integrity())
        assert report.is_intact, report.log_defects
        assert report.artifacts_verified == 3
    finally:
        # Restored so pytest's tmp_path cleanup can remove it.
        handed_over.chmod(0o700)
        for path in sorted(handed_over.rglob("*"), reverse=True):
            path.chmod(0o700)


def test_a_reader_does_not_need_the_lock_file_to_exist(tmp_path: Path) -> None:
    """A store with no usable lock file is read without one, deliberately.

    The lock exists to exclude a concurrent writer. A root that cannot supply one is a root
    nothing is writing to either, and refusing to verify would mean an operator can be handed
    a vault they cannot check — the failure this module exists to prevent, arrived at by way
    of the control meant to help.
    """
    root = tmp_path / "vault"
    vault = FileSystemEvidenceVault(root)
    artifact = b"sealed before the lock file went missing"
    run(vault.seal(_evidence(artifact), artifact))

    (root / ".lock").unlink()

    report = run(FileSystemEvidenceVault(root).verify_integrity())
    assert report.is_intact, report.log_defects


# --- a seal interrupted between its writes -------------------------------------


def _interrupted_seal(
    root: Path, artifact: bytes, monkeypatch: pytest.MonkeyPatch
) -> EvidenceObject:
    """Seal until the files are down and the chain entry is not, as a crash would leave it."""
    vault = FileSystemEvidenceVault(root)
    evidence = _evidence(artifact)

    def die(_self: Any, **_kwargs: Any) -> None:
        raise RuntimeError("the process died before the chain entry was written")

    with monkeypatch.context() as patched:
        patched.setattr(FileSystemEvidenceVault, "_append", die)
        with pytest.raises(RuntimeError):
            run(vault.seal(evidence, artifact))
    return evidence


def test_a_retry_after_an_interrupted_seal_finishes_it_instead_of_reporting_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE HALF THAT LIED.

    `seal` is three writes — artifact, metadata, chain entry — and the files land first. Its
    idempotent-retry path then keyed on the *metadata*, which is precisely the half that
    survives a crash at `_append`. So a retry saw metadata, returned the stored object, and
    told the caller the evidence was sealed while it had no chain entry and never would get
    one: `get()` refused it, and `write_sealed_export` refused the whole vault from then on.

    The retry now asks the chain, which is the half that decides, and completes the seal.
    """
    root = tmp_path / "vault"
    seed = b"already sealed"
    run(FileSystemEvidenceVault(root).seal(_evidence(seed), seed))

    artifact = b"interrupted between the metadata and the chain"
    evidence = _interrupted_seal(root, artifact, monkeypatch)

    entries = run(FileSystemEvidenceVault(root).log_entries())
    assert not any(e.evidence_id == evidence.evidence_id for e in entries), (
        "the fixture did not actually interrupt anything"
    )

    run(FileSystemEvidenceVault(root).seal(evidence, artifact))

    entries = run(FileSystemEvidenceVault(root).log_entries())
    assert any(
        e.evidence_id == evidence.evidence_id and e.kind is VaultEntryKind.SEAL for e in entries
    ), "the retry returned success and the evidence is still unchained"
    assert run(FileSystemEvidenceVault(root).get(evidence.evidence_id)) is not None
    report = run(FileSystemEvidenceVault(root).verify_integrity())
    assert report.is_intact, report.log_defects


def test_an_interrupted_seal_is_named_as_one_rather_than_as_an_unlogged_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A power cut must not produce the report an intruder would.

    `unlogged_artifacts` is documented as the signature of slipping a file into the store
    without logging it. A crash mid-seal put its two files there, so the store accused itself
    of tampering over an interruption — the same defect as a fork reading as an edit, in the
    other direction. The files are still a defect and still block an export; they are simply
    the *recoverable* one, and the report says which.
    """
    root = tmp_path / "vault"
    seed = b"already sealed"
    run(FileSystemEvidenceVault(root).seal(_evidence(seed), seed))
    evidence = _interrupted_seal(root, b"interrupted", monkeypatch)

    report = run(FileSystemEvidenceVault(root).verify_integrity())

    assert not report.is_intact, "an unchained artifact must still stop an export"
    assert evidence.evidence_id in report.interrupted_seals
    assert not report.unlogged_artifacts, (
        f"a recoverable interruption was reported as an unaccounted file: "
        f"{report.unlogged_artifacts}"
    )
