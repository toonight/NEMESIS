"""A filesystem evidence vault: append-only, hash-chained, and honest about its limits.

Invariant 10 puts the vault operator inside the threat model, which decides the shape of
everything here. An insider with write access to the store can recompute any hash chain we
compute ourselves — the chain below is not a defence against that person and this module
does not pretend otherwise. What it does buy:

- **Accidental corruption is caught.** A truncated write, a bad disk, a script that
  rewrote a file: all detected, with the affected object named.
- **Careless tampering is caught.** Editing a log line, deleting an artifact, dropping the
  tail of the log, or slipping a file into the store without logging it all leave a
  detectable mark, because each requires repairing more state than is obvious.
- **Deliberate rewriting by the operator is *not* caught** by anything in this file. Only
  an anchor held by someone else closes that gap, which is why
  :meth:`FileSystemEvidenceVault.record_anchor` exists and why
  :attr:`VaultIntegrityReport.is_defensible_against_insider` stays False until an
  externally held anchor is recorded. See :mod:`nemesis.evidence.anchoring`.

Four files make up the store:

``log.jsonl``
    The chain. One JSON entry per line, each committing to its predecessor's hash. Seals
    and reads are both entries: an unrecorded read is a chain-of-custody gap someone will
    ask about in the one proceeding where it matters.
``head.json``
    The tip (sequence and hash), rewritten on every append. A chain that has had its tail
    cut off still verifies internally — every remaining link is genuine — so truncation is
    only visible against a record of where the chain used to end.
``objects/``
    Artifact bytes, one file per evidence id, written read-only.
``metadata/``
    The serialized :class:`~nemesis.core.evidence.EvidenceObject`, byte-for-byte as it was
    hashed into the chain.
``anchors.jsonl``
    Anchors recorded over past heads.

The log entry commits to a hash of the metadata as well as of the artifact. The artifact
alone would leave the handling classification unchained, and relabelling
``MANDATORY_REPORT`` content as ``ROUTINE`` is exactly the edit that moves quarantined
material into an export.

Status: `IMPLEMENTED`.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nemesis.core.evidence import (
    SHA256_HEX,
    ArtifactKind,
    EvidenceObject,
    IntegrityAnchor,
)
from nemesis.core.ids import EvidenceId
from nemesis.core.provenance import CustodyAction
from nemesis.core.temporal import utcnow
from nemesis.ports.storage import VaultIntegrityReport

GENESIS_HASH: Final = "0" * 64
"""The predecessor of the first entry. A distinguished value rather than ``None`` so the
hash of entry zero is computed by the same code as every other entry."""

_EVIDENCE_ID_RE: Final = re.compile(r"\Aevd_sha256-([0-9a-f]{64})\Z")
"""The shape of an evidence id, anchored with ``\\A``/``\\Z`` rather than ``^``/``$``.

``$`` matches before a trailing newline in Python, so ``"evd_sha256-" + "a"*64 + "\\n"``
passed and came back with the newline attached. Not exploitable for traversal — the
character class admits no separator — and pydantic's own validator refuses it upstream, so
this was the last line of a defence that held by accident. An adversarial review pointed
out that a control which is sound only because something else refused first is the pattern
this repository keeps finding in itself.
"""

_ARTIFACT_MODE: Final = 0o400
"""Artifacts are written read-only. This stops a stray script, not the operator — the
operator owns the file and can chmod it back, which is the point of the threat model."""


# --------------------------------------------------------------------------------------
# Failures
# --------------------------------------------------------------------------------------


class VaultError(Exception):
    """Base class for every way the vault refuses."""


class ArtifactHashMismatchError(VaultError):
    """The bytes offered do not hash to the object's ``content_hash``.

    Either the caller assembled the object from one artifact and passed another, or the
    bytes were damaged between collection and sealing. Both make the object undefendable,
    so neither is stored.
    """


class EvidenceSubstitutionError(VaultError):
    """An evidence id already in the vault has been offered with different bytes.

    Evidence ids are content-addressed, so this cannot happen by accident. It means either
    the stored copy was replaced after sealing, or SHA-256 produced a collision. The first
    is evidence substitution; the second would invalidate every content address in the
    platform. Neither is resolved by overwriting.
    """


class ContentSafetyConflictError(VaultError):
    """A re-seal presents the same bytes under a different handling classification.

    Re-sealing never overwrites stored metadata, so the attempted relabelling has no
    effect — but it is refused loudly rather than ignored, because moving material out of
    ``MANDATORY_REPORT`` is how quarantined content reaches an export.
    """


class RestrictedContentError(VaultError):
    """An ordinary read was attempted against quarantined material.

    ``MANDATORY_REPORT`` and ``LEGALLY_RESTRICTED`` bytes leave the vault only through
    :meth:`FileSystemEvidenceVault.retrieve_quarantined_artifact`, which demands an
    escalation reference. The refusal is recorded in the chain.
    """


class EvidenceNotFoundError(VaultError):
    """No such evidence id in this vault."""


class ArtifactCorruptedError(VaultError):
    """The stored bytes no longer hash to the sealed content hash."""


class MetadataCorruptedError(VaultError):
    """The stored metadata no longer hashes to the value committed in the chain."""


class VaultChainError(VaultError):
    """The log cannot be read, or its tip disagrees with the recorded head.

    Raised by the operations that would *extend* the chain, and by :meth:`head`. Appending
    to a chain we cannot verify would give the corruption a fresh, valid-looking tip, and
    handing that tip to an anchoring authority would launder it with external credibility.
    """


class MalformedEvidenceIdError(VaultError):
    """An identifier that is not a well-formed evidence id was used as a store key.

    Every id becomes a path component. Validating the shape here is what keeps a
    hand-built id from addressing a file outside the vault root.
    """


# --------------------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------------------


class VaultEntryKind(StrEnum):
    """What an entry in the chain records."""

    SEAL = "seal"
    ACCESS = "access"
    QUARANTINED_ACCESS = "quarantined_access"
    """A read of ``MANDATORY_REPORT`` or ``LEGALLY_RESTRICTED`` material, under a named
    escalation reference. Conspicuous by construction."""

    REFUSED_ACCESS = "refused_access"
    """A read the vault declined: quarantined material through the ordinary path, or an
    artifact that failed its hash check. A refused read is an event, not a non-event."""


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class VaultLogEntry(BaseModel):
    """One link in the chain.

    ``recorded_at`` and ``actor`` are the seal time and the sealer on a
    :attr:`VaultEntryKind.SEAL` entry, and the read time and the reader on an access
    entry. One entry shape rather than two keeps the chain a single sequence, which is
    what makes "was anything inserted between these two events?" answerable.

    The entry hash is deliberately *not* checked by a validator. Verification must be able
    to parse a doctored line in order to report what is wrong with it; a line that refuses
    to load tells an operator only that something is broken.
    """

    model_config = ConfigDict(frozen=True)

    sequence: Annotated[int, Field(ge=0)]
    kind: VaultEntryKind
    previous_entry_hash: SHA256_HEX
    evidence_id: EvidenceId
    content_hash: SHA256_HEX
    metadata_hash: SHA256_HEX
    recorded_at: datetime
    actor: Annotated[str, Field(min_length=1)]
    reason: Annotated[str, Field(min_length=1)]
    entry_hash: SHA256_HEX

    def expected_hash(self) -> str:
        """Recompute this entry's hash from its own contents."""
        return compute_entry_hash(
            sequence=self.sequence,
            kind=self.kind,
            previous_entry_hash=self.previous_entry_hash,
            evidence_id=self.evidence_id,
            content_hash=self.content_hash,
            metadata_hash=self.metadata_hash,
            recorded_at=self.recorded_at,
            actor=self.actor,
            reason=self.reason,
        )

    @property
    def is_intact(self) -> bool:
        return self.entry_hash == self.expected_hash()


def compute_entry_hash(
    *,
    sequence: int,
    kind: VaultEntryKind,
    previous_entry_hash: str,
    evidence_id: str,
    content_hash: str,
    metadata_hash: str,
    recorded_at: datetime,
    actor: str,
    reason: str,
) -> str:
    """Hash one link over its predecessor and its own contents.

    The timestamp is normalized to UTC before encoding so that an entry written by a
    process with a different local timezone hashes identically after a round trip through
    the log file.
    """
    return hashlib.sha256(
        _canonical(
            {
                "sequence": sequence,
                "kind": kind.value,
                "previous_entry_hash": previous_entry_hash,
                "evidence_id": evidence_id,
                "content_hash": content_hash,
                "metadata_hash": metadata_hash,
                "recorded_at": recorded_at.astimezone(UTC).isoformat(),
                "actor": actor,
                "reason": reason,
            }
        )
    ).hexdigest()


class AnchorRecord(BaseModel):
    """An anchor, bound to the sequence at which the head it covers was the tip."""

    model_config = ConfigDict(frozen=True)

    sequence: Annotated[int, Field(ge=0)]
    anchor: IntegrityAnchor


# --------------------------------------------------------------------------------------
# Reports and exports
# --------------------------------------------------------------------------------------


class FileSystemVaultIntegrityReport(VaultIntegrityReport):
    """A :class:`VaultIntegrityReport` with the detail a filesystem store can supply.

    The port's report says *whether* the chain holds. An operator handed
    ``hash_chain_intact=False`` and nothing else cannot act on it, so the defects are
    named here. The extra fields are additions, never reinterpretations: a consumer typed
    against the port still reads the same booleans and counts.
    """

    log_defects: tuple[str, ...] = ()
    """Human-readable reasons the chain failed, in log order."""

    metadata_corrupted: tuple[EvidenceId, ...] = ()
    """Objects whose stored metadata no longer matches the hash committed in the chain —
    the artifact may be untouched while its handling classification was rewritten."""

    unlogged_artifacts: tuple[str, ...] = ()
    """Files in the store that no entry accounts for. Every link may verify and the store
    still hold material that entered it without extending the chain."""

    anchors_verified: int = 0
    """Anchors whose covered head still matches the chain at that sequence."""

    @property
    def is_intact(self) -> bool:
        """Whether nothing is wrong, which is stricter than the port's version.

        The base class knows only about the chain and the artifacts. Rewritten metadata
        and unaccounted-for files are defects it has no field for, and reporting a vault
        as intact while either is true would be the report lying by omission.
        """
        return super().is_intact and not self.metadata_corrupted and not self.unlogged_artifacts


class EvidenceExportEntry(BaseModel):
    """One object in an export manifest: what it is and how to check it.

    Carries hashes, not bytes. Material leaves the vault only through
    :meth:`FileSystemEvidenceVault.retrieve_artifact`, so that every byte handed out is a
    recorded read rather than a side effect of assembling a package.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: EvidenceId
    artifact_kind: ArtifactKind
    content_hash: SHA256_HEX
    size_bytes: Annotated[int, Field(ge=0)]
    media_type: str
    vault_locator: str
    admissibility_defects: tuple[str, ...]
    """Why this object would fail to be defended, if anything. Exported alongside it so a
    recipient is never handed material whose weaknesses only we can see."""


class EvidenceExportBundle(BaseModel):
    """A manifest of what the vault holds and may release."""

    model_config = ConfigDict(frozen=True)

    created_at: datetime
    requested_by: str
    reason: str
    vault_head: SHA256_HEX
    entries: tuple[EvidenceExportEntry, ...]

    withheld_restricted: int = 0
    """How many objects were withheld for their handling classification. A count and never
    an identifier: the recipient must know the package is not everything, and must not
    learn what was kept back."""


# --------------------------------------------------------------------------------------
# The vault
# --------------------------------------------------------------------------------------


class FileSystemEvidenceVault:
    """An append-only, hash-chained evidence store rooted at a directory.

    Satisfies :class:`~nemesis.ports.storage.EvidenceVault`. Every method is ``async``
    because the port declares it; the implementation is synchronous, and holds a
    ``threading.Lock`` rather than an ``asyncio.Lock`` across its critical sections. The
    critical sections contain no awaits, and an asyncio primitive would bind the vault to
    whichever event loop touched it first — a needless failure mode for an object built at
    composition time and used by whatever runs next.

    **That mutex alone was not enough, and the gap was measured rather than argued.** It is
    per *instance*, so two vaults on one root — two processes, or two objects in one process —
    were entirely unsynchronised, while ``_append`` reads the chain tip and then writes with
    nothing held across the two. Two writers both build on sequence *n*, both write *n+1*, and
    ``_chain_tip`` refuses the log from then on: no seal, no recorded read and no anchor can
    ever be appended again. Measured 3 runs of 3 before the fix, 78 of 80 seals lost, and the
    sentence it produced was ``entries were reordered, inserted or removed`` — the sentence a
    tamper-evident store exists to be able to say, describing two honest writers and a missing
    lock. Every critical section now takes :meth:`_exclusive`, which holds the mutex *and* an
    ``flock`` on a file beside the log.

    No state is cached in memory. The chain tip is re-derived from the log on every
    operation that needs it, which costs a full read per append and is the right trade at
    the scale this adapter targets: a cached tip that disagrees with the file is precisely
    the class of bug a tamper-evident store cannot afford. A production vault would keep
    an index and verify it against the log rather than trust it.
    """

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._objects = self._root / "objects"
        self._metadata = self._root / "metadata"
        self._log_path = self._root / "log.jsonl"
        self._head_path = self._root / "head.json"
        self._anchors_path = self._root / "anchors.jsonl"
        self._lock_path = self._root / ".lock"
        self._lock = threading.Lock()

        self._objects.mkdir(parents=True, exist_ok=True)
        self._metadata.mkdir(parents=True, exist_ok=True)

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold the store against every other writer, in this process and outside it.

        Two locks because there are two races and one primitive answers each. The mutex
        serialises threads sharing *this* object; the ``flock`` serialises everything else,
        which is what the mutex could never see — a second instance in this process is as
        unsynchronised as a second process, and both were.

        Taken around the whole critical section rather than around the write, because the race
        is a read-modify-write: the tip is read, an entry is built on it, and the entry is
        appended. A lock held only across the append serialises the writes and lets both of
        them build on the same tip, which is the same fork arriving more tidily.

        ``fcntl`` rather than a lock directory or an atomic create: the kernel releases it when
        the holder dies, so a crash mid-append leaves a log to repair rather than a store
        nobody can open. POSIX-only, and imported at module scope on purpose — this package is
        macOS and Linux, and a platform that silently ran without the second lock would keep
        exactly the defect this method exists to close.
        """
        # Opened per section rather than held for the object's life: an `flock` belongs to an
        # open file description, so a fresh descriptor each time keeps the lock's scope
        # identical to the block it guards.
        with self._lock, self._lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @property
    def root(self) -> Path:
        return self._root

    # -- the port -----------------------------------------------------------------------

    async def seal(self, evidence: EvidenceObject, artifact: bytes) -> EvidenceObject:
        """Store an artifact and its metadata, extending the chain.

        Refuses bytes that do not hash to the object's ``content_hash``, and refuses a
        re-seal whose stored copy differs from the bytes offered. Re-sealing identical
        bytes is a no-op that returns the *stored* object: the stored metadata wins, so a
        re-seal cannot be used to relabel material already in the vault.
        """
        if not evidence.verify_artifact(artifact):
            raise ArtifactHashMismatchError(
                f"{evidence.evidence_id} declares content_hash {evidence.content_hash} but "
                f"the bytes offered hash to {hashlib.sha256(artifact).hexdigest()}"
            )

        with self._exclusive():
            existing = self._read_metadata(evidence.evidence_id)
            if existing is not None:
                self._reject_conflicting_reseal(existing, evidence, artifact)
                return existing

            locator = f"objects/{evidence.evidence_id}"
            sealed = evidence.model_copy(update={"vault_locator": locator})
            # Relative, so the vault survives being moved or restored to another path.
            # An absolute locator baked into sealed metadata makes the metadata wrong the
            # first time the store is copied, and the metadata is hashed into the chain.
            payload = sealed.model_dump_json().encode()

            actor, reason = _sealer_of(sealed)
            self._write_atomic(self._artifact_path(sealed.evidence_id), artifact)
            self._write_atomic(self._metadata_path(sealed.evidence_id), payload)
            self._append(
                kind=VaultEntryKind.SEAL,
                evidence_id=sealed.evidence_id,
                content_hash=sealed.content_hash,
                metadata_hash=hashlib.sha256(payload).hexdigest(),
                actor=actor,
                reason=reason,
            )
            return sealed

    async def get(self, evidence_id: EvidenceId) -> EvidenceObject | None:
        """Return the sealed metadata, or ``None`` if this vault never held it.

        Verifies the metadata against the hash committed in the chain and raises rather
        than returning a doctored record. A store that quietly serves rewritten metadata
        is worse than one that refuses: the caller has no way to know.
        """
        with self._exclusive():
            stored = self._read_metadata(evidence_id)
            if stored is None:
                return None
            self._verify_metadata_against_chain(evidence_id)
            return stored

    async def retrieve_artifact(
        self, evidence_id: EvidenceId, *, accessed_by: str, reason: str
    ) -> bytes:
        """Return the sealed bytes, recording who read them, when and why.

        Refuses quarantined material: ``MANDATORY_REPORT`` and ``LEGALLY_RESTRICTED``
        content leaves only through :meth:`retrieve_quarantined_artifact`. The refusal is
        itself appended to the chain.
        """
        return self._read_artifact(
            evidence_id,
            accessed_by=accessed_by,
            reason=reason,
            escalation_reference=None,
        )

    async def verify_integrity(self) -> FileSystemVaultIntegrityReport:
        """Walk the whole chain and every artifact.

        Never raises. A store too damaged to read is a finding to report, not an error to
        propagate — the caller asked what is wrong with it.
        """
        with self._exclusive():
            lines = self._read_log_lines()
            entries, defects = _parse_chain(lines)
            defects.extend(self._check_recorded_head(entries))
            anchors_verified, external_anchors, anchor_defects = self._check_anchors(entries)
            defects.extend(anchor_defects)

            sealed = _sealed_in_order(entries)
            missing: list[str] = []
            corrupted: list[str] = []
            metadata_corrupted: list[str] = []
            verified = 0

            for evidence_id, entry in sealed.items():
                artifact_path = self._artifact_path(evidence_id)
                if not artifact_path.is_file():
                    missing.append(evidence_id)
                elif hashlib.sha256(artifact_path.read_bytes()).hexdigest() != entry.content_hash:
                    corrupted.append(evidence_id)
                else:
                    verified += 1

                # A missing record and a rewritten one are one finding: in both cases the
                # object's handling classification is no longer the one the chain committed
                # to, which is what decides whether the material may be released.
                metadata_path = self._metadata_path(evidence_id)
                if (
                    not metadata_path.is_file()
                    or hashlib.sha256(metadata_path.read_bytes()).hexdigest() != entry.metadata_hash
                ):
                    metadata_corrupted.append(evidence_id)

            return FileSystemVaultIntegrityReport(
                checked_at=utcnow(),
                objects_checked=len(sealed),
                hash_chain_intact=not defects,
                artifacts_verified=verified,
                artifacts_missing=tuple(missing),
                artifacts_corrupted=tuple(corrupted),
                externally_anchored=external_anchors,
                log_defects=tuple(defects),
                metadata_corrupted=tuple(metadata_corrupted),
                unlogged_artifacts=tuple(self._unlogged_files(set(sealed))),
                anchors_verified=anchors_verified,
            )

    async def head(self) -> str:
        """The current tip of the chain, suitable for handing to an anchoring authority.

        Refuses when the log and the recorded head disagree. Anchoring the tip of a store
        that is already inconsistent would attach an outside party's credibility to
        whatever the inconsistency was.
        """
        with self._exclusive():
            _, tip = self._chain_tip()
            return tip

    # -- beyond the port ----------------------------------------------------------------

    async def retrieve_quarantined_artifact(
        self,
        evidence_id: EvidenceId,
        *,
        accessed_by: str,
        reason: str,
        escalation_reference: str,
    ) -> bytes:
        """Return bytes of quarantined material, under a named escalation.

        The vault cannot tell whether a caller is the lawful escalation path, so it does
        not try. What it can do is make the read impossible to perform through the
        ordinary interface and impossible to perform unnoticed: this method exists, is
        separately named, demands a reference to the escalation it serves, and appends a
        :attr:`VaultEntryKind.QUARANTINED_ACCESS` entry that no bulk read produces.
        """
        if not escalation_reference.strip():
            raise RestrictedContentError(
                "quarantined material may only be read under a named escalation; "
                "escalation_reference must not be empty"
            )
        return self._read_artifact(
            evidence_id,
            accessed_by=accessed_by,
            reason=reason,
            escalation_reference=escalation_reference,
        )

    async def list_evidence(
        self, *, artifact_kind: ArtifactKind | None = None
    ) -> tuple[EvidenceObject, ...]:
        """Every object the vault may enumerate, in seal order.

        Quarantined material is absent and there is no argument that brings it back. The
        exclusion is a property of the method rather than a rule callers are asked to
        remember, because the caller who forgets is the one assembling a package for
        someone outside the organization.
        """
        with self._exclusive():
            objects = self._enumerable_objects()
        if artifact_kind is None:
            return objects
        return tuple(obj for obj in objects if obj.artifact_kind is artifact_kind)

    async def export_bundle(self, *, requested_by: str, reason: str) -> EvidenceExportBundle:
        """A manifest of releasable objects, with the vault head that covers them.

        Quarantined material is excluded and counted. The count is reported so a recipient
        knows the package is partial; the identifiers are not, because naming what was
        withheld defeats withholding it.
        """
        with self._exclusive():
            _, tip = self._chain_tip()
            releasable = self._enumerable_objects()
            withheld = self._quarantined_count()

        return EvidenceExportBundle(
            created_at=utcnow(),
            requested_by=requested_by,
            reason=reason,
            vault_head=tip,
            entries=tuple(
                EvidenceExportEntry(
                    evidence_id=obj.evidence_id,
                    artifact_kind=obj.artifact_kind,
                    content_hash=obj.content_hash,
                    size_bytes=obj.size_bytes,
                    media_type=obj.media_type,
                    vault_locator=obj.vault_locator or "",
                    admissibility_defects=tuple(defect.value for defect in obj.admissibility()),
                )
                for obj in releasable
            ),
            withheld_restricted=withheld,
        )

    async def record_anchor(self, anchor: IntegrityAnchor) -> AnchorRecord:
        """Bind an anchor to the sequence whose head it covers.

        Refuses an anchor over a head this chain never had: such an anchor either belongs
        to another vault or is proof that the chain has already been rewritten, and
        storing it would let a later verification "confirm" a head that no longer exists.
        """
        with self._exclusive():
            entries, defects = _parse_chain(self._read_log_lines())
            if defects:
                raise VaultChainError(
                    "refusing to record an anchor against a chain that does not verify: "
                    + "; ".join(defects)
                )
            sequence = next(
                (e.sequence for e in entries if e.entry_hash == anchor.covers_hash), None
            )
            if sequence is None:
                raise VaultChainError(
                    f"anchor covers head {anchor.covers_hash} which is not a head this "
                    "chain ever had"
                )
            record = AnchorRecord(sequence=sequence, anchor=anchor)
            self._append_line(self._anchors_path, record.model_dump_json().encode())
            return record

    async def anchors(self) -> tuple[AnchorRecord, ...]:
        with self._exclusive():
            return self._read_anchors()

    async def log_entries(self) -> tuple[VaultLogEntry, ...]:
        """The chain as parsed, defects and all.

        Exposed for audit and for tests. Returns what the file says rather than what it
        should say: entries whose hash does not recompute come back unchanged, so a caller
        can see the doctored line rather than a sanitized version of it.
        """
        with self._exclusive():
            entries, _ = _parse_chain(self._read_log_lines())
            return tuple(entries)

    # -- internals ----------------------------------------------------------------------

    def _read_artifact(
        self,
        evidence_id: str,
        *,
        accessed_by: str,
        reason: str,
        escalation_reference: str | None,
    ) -> bytes:
        with self._exclusive():
            stored = self._read_metadata(evidence_id)
            if stored is None:
                raise EvidenceNotFoundError(f"{evidence_id} is not held by this vault")
            metadata_hash = self._verify_metadata_against_chain(evidence_id)

            quarantined = stored.must_not_be_indexed
            if quarantined and escalation_reference is None:
                self._append(
                    kind=VaultEntryKind.REFUSED_ACCESS,
                    evidence_id=evidence_id,
                    content_hash=stored.content_hash,
                    metadata_hash=metadata_hash,
                    actor=accessed_by,
                    reason=f"refused: {stored.content_safety.value} — {reason}",
                )
                raise RestrictedContentError(
                    f"{evidence_id} is classified {stored.content_safety.value} and cannot be "
                    "read through the ordinary path; use retrieve_quarantined_artifact with an "
                    "escalation reference"
                )

            path = self._artifact_path(evidence_id)
            if not path.is_file():
                self._append(
                    kind=VaultEntryKind.REFUSED_ACCESS,
                    evidence_id=evidence_id,
                    content_hash=stored.content_hash,
                    metadata_hash=metadata_hash,
                    actor=accessed_by,
                    reason=f"refused: artifact missing from the store — {reason}",
                )
                raise EvidenceNotFoundError(
                    f"{evidence_id} is sealed but its artifact is missing from the store"
                )

            artifact = path.read_bytes()
            if not stored.verify_artifact(artifact):
                # Recorded before raising: a read that found corrupted evidence is one of
                # the few events in this log anybody will ever go looking for.
                self._append(
                    kind=VaultEntryKind.REFUSED_ACCESS,
                    evidence_id=evidence_id,
                    content_hash=stored.content_hash,
                    metadata_hash=metadata_hash,
                    actor=accessed_by,
                    reason=f"refused: stored bytes fail their hash — {reason}",
                )
                raise ArtifactCorruptedError(
                    f"{evidence_id} was sealed with content_hash {stored.content_hash} but the "
                    f"stored bytes hash to {hashlib.sha256(artifact).hexdigest()}"
                )

            if escalation_reference is not None:
                kind = VaultEntryKind.QUARANTINED_ACCESS
                recorded_reason = f"{reason} [escalation: {escalation_reference}]"
            else:
                kind = VaultEntryKind.ACCESS
                recorded_reason = reason

            self._append(
                kind=kind,
                evidence_id=evidence_id,
                content_hash=stored.content_hash,
                metadata_hash=metadata_hash,
                actor=accessed_by,
                reason=recorded_reason,
            )
            return artifact

    def _reject_conflicting_reseal(
        self, stored: EvidenceObject, incoming: EvidenceObject, artifact: bytes
    ) -> None:
        """Decide whether a re-seal is the same evidence or an attempt to change it."""
        path = self._artifact_path(stored.evidence_id)
        on_disk = path.read_bytes() if path.is_file() else b""

        if hmac.compare_digest(on_disk, artifact):
            if incoming.content_safety is not stored.content_safety:
                raise ContentSafetyConflictError(
                    f"{stored.evidence_id} is sealed as {stored.content_safety.value} and was "
                    f"re-offered as {incoming.content_safety.value}. The stored classification "
                    "stands; the attempt is refused rather than ignored because relabelling "
                    "out of quarantine is how restricted material reaches an export."
                )
        else:
            if hashlib.sha256(on_disk).hexdigest() == stored.content_hash:
                raise EvidenceSubstitutionError(
                    f"{stored.evidence_id}: two different byte sequences hash to "
                    f"{stored.content_hash}. This is a SHA-256 collision, and every content "
                    "address in the platform is void until it is explained."
                )
            raise EvidenceSubstitutionError(
                f"{stored.evidence_id}: the copy in the store hashes to "
                f"{hashlib.sha256(on_disk).hexdigest()}, not to the sealed content_hash "
                f"{stored.content_hash}. The stored artifact was replaced after sealing; "
                "the vault will not overwrite it."
            )

    def _verify_metadata_against_chain(self, evidence_id: str) -> str:
        """Return the metadata hash, having checked it against the chain.

        **The chain's own verdict is now fatal here.** Every reader in this class parsed the
        chain and threw the defects away — ``entries, _ = _parse_chain(...)`` in three places —
        so a two-file edit released quarantined material: flip ``content_safety`` in the
        metadata, set the seal entry's ``metadata_hash`` to match, and leave ``entry_hash``
        alone. ``verify_integrity()`` named the forgery precisely ("log entry 0 was altered
        after it was written"); ``list_evidence()`` handed the object over anyway, summary
        included.

        That is *below* this module's stated position — "careless tampering is caught" — because
        the operator here recomputed nothing. Checking a metadata hash against a log line already
        known to be forged is not a check; it is a check being read out of a compromised source.
        """
        entries, defects = _parse_chain(self._read_log_lines())
        if defects:
            raise VaultChainError(
                f"the vault log does not verify, so nothing may be released from it: {defects[0]}"
            )
        sealed = _sealed_in_order(entries).get(evidence_id)
        if sealed is None:
            raise EvidenceNotFoundError(
                f"{evidence_id} has metadata in the store but no seal entry in the chain"
            )
        actual = hashlib.sha256(self._metadata_path(evidence_id).read_bytes()).hexdigest()
        if actual != sealed.metadata_hash:
            raise MetadataCorruptedError(
                f"{evidence_id}: stored metadata hashes to {actual} but the chain committed "
                f"{sealed.metadata_hash}. The record was rewritten after sealing."
            )
        return actual

    def _enumerable_objects(self) -> tuple[EvidenceObject, ...]:
        entries, defects = _parse_chain(self._read_log_lines())
        if defects:
            raise VaultChainError(
                f"the vault log does not verify, so nothing may be enumerated from it: {defects[0]}"
            )
        objects: list[EvidenceObject] = []
        for evidence_id in _sealed_in_order(entries):
            stored = self._read_metadata(evidence_id)
            if stored is None:
                continue
            # The classification that keeps quarantined material out of a bulk read lives in
            # the metadata, so enumerating from an unverified copy would let one edited file
            # move MANDATORY_REPORT content into an export. That edit is exactly what the
            # chain commits a metadata hash for; not checking it here wastes the commitment.
            self._verify_metadata_against_chain(evidence_id)
            if not stored.must_not_be_indexed:
                objects.append(stored)
        return tuple(objects)

    def _quarantined_count(self) -> int:
        entries, defects = _parse_chain(self._read_log_lines())
        if defects:
            raise VaultChainError(
                f"the vault log does not verify, so its quarantine count means nothing: "
                f"{defects[0]}"
            )
        return sum(
            1
            for evidence_id in _sealed_in_order(entries)
            if (stored := self._read_metadata(evidence_id)) is not None
            and stored.must_not_be_indexed
        )

    def _unlogged_files(self, sealed: set[str]) -> list[str]:
        """Files in the store that no seal entry accounts for.

        The suffix is stripped **only in the metadata directory**, which is the only one that
        writes ``.json``. Stripping it in both let an unlogged file hide in the object store by
        wearing the suffix: ``evd_sha256-<64 hex>.json`` in ``objects/`` had its name reduced to
        a sealed id and passed, so 54 unlogged bytes sat in the store while
        ``verify_integrity()`` reported intact and ``write_sealed_export`` proceeded.

        An object's name must therefore *be* a sealed id exactly, not merely reduce to one.
        """
        found: list[str] = []
        for directory in (self._objects, self._metadata):
            strip_suffix = directory is self._metadata
            for path in sorted(directory.iterdir()):
                if not path.is_file():
                    continue
                name = path.name.removesuffix(".json") if strip_suffix else path.name
                if name not in sealed:
                    found.append(f"{directory.name}/{path.name}")
        return found

    def _check_recorded_head(self, entries: list[VaultLogEntry]) -> list[str]:
        """Compare the chain's tip with the head written beside it.

        Every remaining link of a truncated chain is genuine, so truncation is invisible
        from inside the chain. The recorded head is the only thing that says how long it
        used to be — and an operator who truncates can rewrite it too, which is why this
        catches accidents and careless tampering and nothing more.
        """
        expected_sequence = len(entries) - 1
        expected_head = entries[-1].entry_hash if entries else GENESIS_HASH

        if not self._head_path.is_file():
            if entries:
                return ["the recorded head is missing while the log holds entries"]
            return []

        try:
            recorded = json.loads(self._head_path.read_text(encoding="utf-8"))
            recorded_sequence = int(recorded["sequence"])
            recorded_head = str(recorded["head"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return [f"the recorded head is unreadable: {exc}"]

        defects: list[str] = []
        if recorded_sequence > expected_sequence:
            defects.append(
                f"the log ends at sequence {expected_sequence} but the recorded head is at "
                f"{recorded_sequence}: {recorded_sequence - expected_sequence} entr"
                f"{'y was' if recorded_sequence - expected_sequence == 1 else 'ies were'} "
                "removed from the end of the log"
            )
        elif recorded_sequence < expected_sequence:
            defects.append(
                f"the log holds entries up to sequence {expected_sequence} but the recorded "
                f"head is at {recorded_sequence}: entries were appended without updating the "
                "head, or the head was rolled back"
            )
        elif recorded_head != expected_head:
            defects.append(
                f"the recorded head {recorded_head} does not match the chain tip {expected_head}"
            )
        return defects

    def _check_anchors(self, entries: list[VaultLogEntry]) -> tuple[int, int, list[str]]:
        verified = 0
        external = 0
        defects: list[str] = []
        for record in self._read_anchors():
            if record.anchor.is_externally_held:
                external += 1
            if record.sequence >= len(entries):
                defects.append(
                    f"an anchor covers sequence {record.sequence} but the log now ends at "
                    f"{len(entries) - 1}: the chain was truncated below an anchored point"
                )
            elif entries[record.sequence].entry_hash != record.anchor.covers_hash:
                defects.append(
                    f"the chain at sequence {record.sequence} hashes to "
                    f"{entries[record.sequence].entry_hash} but was anchored as "
                    f"{record.anchor.covers_hash}: the chain was rewritten"
                )
            else:
                verified += 1
        return verified, external, defects

    def _chain_tip(self) -> tuple[int, str]:
        """The sequence and hash the next entry must build on.

        Cross-checks the log against the recorded head and refuses on disagreement rather
        than picking one. Extending a chain whose two records of its own tip disagree
        buries the disagreement under a valid-looking new entry.
        """
        entries, defects = _parse_chain(self._read_log_lines())
        if defects:
            raise VaultChainError("the log does not verify: " + "; ".join(defects))
        head_defects = self._check_recorded_head(entries)
        if head_defects:
            raise VaultChainError("; ".join(head_defects))
        if not entries:
            return -1, GENESIS_HASH
        return entries[-1].sequence, entries[-1].entry_hash

    def _append(
        self,
        *,
        kind: VaultEntryKind,
        evidence_id: str,
        content_hash: str,
        metadata_hash: str,
        actor: str,
        reason: str,
    ) -> VaultLogEntry:
        previous_sequence, previous_hash = self._chain_tip()
        sequence = previous_sequence + 1
        recorded_at = utcnow()
        entry = VaultLogEntry(
            sequence=sequence,
            kind=kind,
            previous_entry_hash=previous_hash,
            evidence_id=evidence_id,
            content_hash=content_hash,
            metadata_hash=metadata_hash,
            recorded_at=recorded_at,
            actor=actor,
            reason=reason,
            entry_hash=compute_entry_hash(
                sequence=sequence,
                kind=kind,
                previous_entry_hash=previous_hash,
                evidence_id=evidence_id,
                content_hash=content_hash,
                metadata_hash=metadata_hash,
                recorded_at=recorded_at,
                actor=actor,
                reason=reason,
            ),
        )
        self._append_line(self._log_path, entry.model_dump_json().encode())
        self._write_atomic(
            self._head_path,
            _canonical({"sequence": entry.sequence, "head": entry.entry_hash}),
            read_only=False,
        )
        return entry

    def _read_log_lines(self) -> list[str]:
        if not self._log_path.is_file():
            return []
        text = self._log_path.read_text(encoding="utf-8")
        return [line for line in text.splitlines() if line.strip()]

    def _read_anchors(self) -> tuple[AnchorRecord, ...]:
        if not self._anchors_path.is_file():
            return ()
        records: list[AnchorRecord] = []
        for line in self._anchors_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(AnchorRecord.model_validate_json(line))
        return tuple(records)

    def _read_metadata(self, evidence_id: str) -> EvidenceObject | None:
        path = self._metadata_path(evidence_id)
        if not path.is_file():
            return None
        return EvidenceObject.model_validate_json(path.read_bytes())

    def _artifact_path(self, evidence_id: str) -> Path:
        return self._objects / _safe_key(evidence_id)

    def _metadata_path(self, evidence_id: str) -> Path:
        return self._metadata / f"{_safe_key(evidence_id)}.json"

    @staticmethod
    def _append_line(path: Path, payload: bytes) -> None:
        with path.open("ab") as handle:
            handle.write(payload + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _write_atomic(path: Path, payload: bytes, *, read_only: bool = True) -> None:
        """Write through a temporary file so a crash cannot leave a half-written record.

        A partially written artifact is indistinguishable from a corrupted one, and would
        put the vault into a state that reports tampering where there was only a power cut.
        """
        # Unique per writer. One fixed `.partial` name per target meant two writers shared a
        # scratch file: measured, one `replace()`d it out from under the other, which then
        # failed with `FileNotFoundError` on a path it had itself just written. The suffix
        # stays in the same directory, because `replace()` is only atomic within one.
        temporary = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(8)}.partial")
        with temporary.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(_ARTIFACT_MODE if read_only else 0o600)
        temporary.replace(path)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _safe_key(evidence_id: str) -> str:
    """Validate an evidence id before it becomes a path component."""
    if not _EVIDENCE_ID_RE.match(evidence_id):
        raise MalformedEvidenceIdError(
            f"{evidence_id!r} is not a well-formed evidence id and will not be used as a store key"
        )
    return evidence_id


def _sealer_of(evidence: EvidenceObject) -> tuple[str, str]:
    """Who is recorded as having sealed this, and why.

    Taken from the custody chain rather than from an argument, so the chain and the
    provenance cannot tell two different stories about the same act. An object with no
    custody chain is already inadmissible; the vault records that it could not name a
    sealer instead of inventing one.
    """
    for event in reversed(evidence.provenance.custody):
        if event.action is CustodyAction.SEALED:
            return event.actor, event.reason
    if evidence.provenance.custody:
        last = evidence.provenance.custody[-1]
        return last.actor, last.reason
    return (
        f"collection:{evidence.provenance.collection_id}",
        "sealed with no custody chain recorded",
    )


def _parse_chain(lines: list[str]) -> tuple[list[VaultLogEntry], list[str]]:
    """Parse and verify the chain, returning what was read and what is wrong with it."""
    entries: list[VaultLogEntry] = []
    defects: list[str] = []
    previous = GENESIS_HASH

    for index, line in enumerate(lines):
        try:
            entry = VaultLogEntry.model_validate_json(line)
        except ValidationError as exc:
            defects.append(
                f"log line {index} is not a readable vault entry "
                f"({exc.error_count()} validation error(s)); the chain cannot be followed "
                "past it"
            )
            break

        if entry.sequence != index:
            defects.append(
                f"log line {index} claims sequence {entry.sequence}: entries were "
                "reordered, inserted or removed"
            )
            if entries and (
                entry.sequence == entries[-1].sequence
                and entry.previous_entry_hash == entries[-1].previous_entry_hash
            ):
                # Two entries at the same sequence, built on the same tip. That is what two
                # unsynchronised writers leave behind, and saying so matters: the sentence
                # above is the one a tamper-evident store exists to be able to say, and before
                # `_exclusive` existed it was routinely describing an accident. An operator who
                # reads "reordered, inserted or removed" about a missing lock either hunts an
                # intruder who was never there or, worse, learns to discount the message.
                #
                # It **lowers** suspicion; it does not clear it. Anyone who can write the log
                # can write this shape deliberately, so it is a hypothesis to check against the
                # deployment's own record of what was running, never a verdict.
                defects.append(
                    f"log entries {index - 1} and {index} both claim sequence "
                    f"{entry.sequence} and both build on {entry.previous_entry_hash}: this is "
                    "the signature two concurrent writers leave, not evidence of an edit. "
                    "Confirm against what was running before treating it as tampering — the "
                    "shape is forgeable. See docs/procedures/vault-chain-recovery.md"
                )
        if entry.previous_entry_hash != previous:
            defects.append(
                f"log entry {entry.sequence} links to {entry.previous_entry_hash} but its "
                f"predecessor hashes to {previous}"
            )
        if not entry.is_intact:
            defects.append(
                f"log entry {entry.sequence} was altered after it was written: it carries "
                f"{entry.entry_hash} but its contents hash to {entry.expected_hash()}"
            )

        previous = entry.entry_hash
        entries.append(entry)

    return entries, defects


def _sealed_in_order(entries: list[VaultLogEntry]) -> dict[str, VaultLogEntry]:
    """The seal entry for each evidence id, in the order it was first sealed."""
    sealed: dict[str, VaultLogEntry] = {}
    for entry in entries:
        if entry.kind is VaultEntryKind.SEAL and entry.evidence_id not in sealed:
            sealed[entry.evidence_id] = entry
    return sealed
