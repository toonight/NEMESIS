"""Writing an evidence package somebody else can check.

Until now ``export_bundle`` returned a manifest *object*: a list of identifiers and hashes,
in memory, in this process. That is a description of evidence, not a package of it. Nothing
in it could be handed to a lawyer, a regulator or an opposing expert, and nothing in it could
be checked by anyone who does not run NEMESIS.

This module writes the package. A directory, self-contained, containing the artifacts
themselves, the hash chain that covers them, the anchors such as they are, a manifest, a
notice, and — the part that makes it worth anything — a **standalone verifier that imports
nothing from this codebase** and recomputes every hash from the bytes on disk.

The reason the verifier matters is invariant 10: the vault operator is inside the threat
model. A package whose integrity can only be confirmed by the software of the party that
produced it establishes that our arithmetic agrees with itself. The recipient has to be able
to do the checking, on their own machine, with a program short enough to read first.

**What an export is careful not to claim.** Every link in the chain is recomputable from its
contents, which is exactly what makes it checkable and equally what lets whoever holds the
vault rebuild the whole thing. Only an anchor held by a party that is not us breaks that
circle, and external anchoring is `REQUIRES_EXTERNAL_DATA` here — an RFC 3161 authority is a
system we do not own, and invariant 15 forbids the MVP from contacting one. So every export
this platform can currently produce carries ``DEFENSIBLE AGAINST THE OPERATOR: NO``, in the
notice and in the verifier's own output. That is the finding, not a disclaimer to be tucked
into an appendix.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization

from nemesis.core.canonical import canonical_bytes
from nemesis.core.temporal import utcnow
from nemesis.evidence import standalone_verifier
from nemesis.evidence.anchoring import LocalHeadSigner
from nemesis.evidence.vault import (
    AnchorRecord,
    EvidenceExportBundle,
    FileSystemEvidenceVault,
    VaultError,
    VaultLogEntry,
)

SEAL_FILE: Final = "seal.json"
MANIFEST_FILE: Final = "manifest.json"
LOG_FILE: Final = "vault-log.jsonl"
ANCHORS_FILE: Final = "anchors.jsonl"
ARTIFACTS_DIR: Final = "artifacts"
VERIFIER_FILE: Final = "verify.py"
NOTICE_FILE: Final = "README.txt"

NOTICE: Final = """\
NEMESIS evidence export
=======================

Created:   {created_at}
Requested: {requested_by}
Reason:    {reason}

Objects:   {object_count} exported, {withheld} withheld as restricted
Vault head at export: {vault_head}

PACKAGE SEAL: {seal_digest}

    Obtain this string from us through a channel that is NOT this package — a phone call, a
    letterhead, a signed email — and compare it. That comparison needs no software and no
    cryptography, and it is the only check here that does not run on data the sender
    controls. `verify.py` prints the same string.

{seal_finding}


HOW TO CHECK THIS WITHOUT TRUSTING US
-------------------------------------

    python3 verify.py

`verify.py` imports nothing from NEMESIS and uses only the Python standard library. Read it
before you run it — it is about two hundred lines. It recomputes every artifact's SHA-256
from the bytes in `artifacts/`, recomputes every link of the hash chain in `vault-log.jsonl`
from that link's own contents, checks that the chain has no gap and no reordering, and checks
that the chain ends at the head named in `manifest.json`.


WHAT THIS PACKAGE ESTABLISHES
-----------------------------

That the artifacts are the ones the manifest describes, and that the log covering them is an
unbroken chain ending where it says it does. If any byte of any artifact changed, or any
entry was edited, inserted, removed or reordered, `verify.py` says so and names the entry.


WHAT THIS PACKAGE DOES NOT ESTABLISH
------------------------------------

{anchor_finding}

This matters more than the paragraph above it. Every link in this chain is recomputable from
its own contents. That is what makes the chain checkable, and it is equally what lets whoever
operates the vault recompute the entire chain after changing something. Nothing inside a
package can distinguish an honest chain from one rebuilt by its operator; only an anchor held
by a third party at a time it could not have anticipated can do that.

NEMESIS does not currently obtain such an anchor. Doing so means sending a digest to a
timestamping authority or a transparency log — a system we do not own — and this build makes
no external contact by design. The interface for it exists and has no implementation.

Treat this package as evidence of care in handling, not as proof against the party that
handled it.


ALSO NOT ESTABLISHED
--------------------

* That the *content* of any artifact is true. A sealed artifact is one whose bytes have not
  changed since sealing; it is not a vouched-for fact.
* That the collection was lawful, complete, or unbiased in what it went looking for.
* Anything about material withheld from this package. {withheld} object(s) were withheld as
  restricted, and they are counted rather than named, because naming them would defeat
  withholding them.{dropped}
"""

DROPPED_NOTICE: Final = (
    "\n\n* {count} object(s) could not be read at export time and are absent from this "
    "package: {names}. They remain in the vault's log, so a reader comparing the log's seals "
    "with this manifest will see the difference — which is why this paragraph exists rather "
    "than a silently shorter package."
)

SIGNED_SEAL: Final = (
    "    This package is signed by key {key_id}. `verify.py` checks that signature if the\n"
    "    `cryptography` package is available on your machine, and says so plainly when it\n"
    "    is not. A signature by our key establishes that nothing changed between us and\n"
    "    you. It establishes nothing against us."
)

UNSIGNED_SEAL: Final = (
    "    THIS PACKAGE IS NOT SIGNED. Anyone who has held it could have rebuilt its chain\n"
    "    and recomputed this seal — not only the party that produced it. The digest above\n"
    "    is still worth comparing out of band; it is all you have."
)

NO_EXTERNAL_ANCHOR: Final = (
    "THIS PACKAGE CARRIES NO EXTERNALLY HELD ANCHOR, so it does not establish that its\n"
    "chain was not rebuilt by whoever holds the vault."
)

EXTERNAL_ANCHOR_PRESENT: Final = (
    "This package carries {count} anchor record(s) naming an authority other than this\n"
    "platform. NOTHING HERE ESTABLISHES THAT ANY OF THEM IS INDEPENDENT OF US: an anchor\n"
    "inside a package is as editable as the package, and this build validates neither the\n"
    "authority named nor the proof offered. Check them with the anchoring authority\n"
    "directly, or treat this package as unanchored."
)


@dataclass(frozen=True)
class SealedExport:
    """Where the package was written and what it does — and does not — support."""

    path: Path
    object_count: int
    withheld_restricted: int
    vault_head: str
    log_entries: int
    externally_anchored: int
    seal_digest: str = ""
    """One 64-character string standing for the whole package.

    Give this to the recipient through a channel that is not the package. Comparing it needs
    no cryptography and no tooling, and it is the only check in the whole arrangement that
    does not run on data the sender controls."""

    signed_by: str | None = None

    @property
    def is_defensible_against_operator(self) -> bool:
        """False for every package this build can produce, and it says so on its face."""
        return self.externally_anchored > 0

    def render(self) -> str:
        return (
            f"{self.object_count} object(s) at {self.path}; head {self.vault_head[:16]}…; "
            f"{'externally anchored' if self.externally_anchored else 'NO EXTERNAL ANCHOR'}"
        )


SEALED_FILES: Final[dict[str, str]] = {
    MANIFEST_FILE: "manifest_sha256",
    LOG_FILE: "log_sha256",
    ANCHORS_FILE: "anchors_sha256",
    VERIFIER_FILE: "verify_sha256",
}
"""Which file each digest in the seal covers, as an explicit map.

**The map is the fix.** The verifier used to derive the key from the filename —
``name.split(".")[0].replace("-", "_") + "_sha256"`` — which turns ``vault-log.jsonl`` into
``vault_log_sha256``, a key ``_seal_document`` never wrote. The lookup returned ``None``, the
comparison was skipped, and the log's digest check was dead code. Only ``manifest.json``
happened to round-trip.

Measured before the fix: in a **signed** package, replacing `vault-log.jsonl` wholesale,
rewriting `README.txt`, deleting an exhibit and substituting an eleven-line `verify.py` that
prints a clean verdict left the seal digest byte-identical and the genuine ``check_seal()``
returning ``VERIFIED`` with no findings.

The worst omission was not a mis-keying at all: ``verify.py`` was absent from the document
entirely — **the program the notice instructs the recipient to run.** A seal that does not cover
the verifier is a seal a recipient checks with a program the seal does not vouch for.

``README.txt`` is deliberately **not** here, and the reason is structural rather than an
oversight: the notice quotes the seal digest, so sealing it would require the digest of a
document containing that digest. It is bound the non-circular way instead — the verifier checks
that the digest the notice *quotes* is the digest it *computes*, so a notice detached from its
package is caught even though its prose is not covered.

A dict rather than string-munging, because a name derived from another name is a name that can
be derived wrongly, and this one was for a year.
"""


def _seal_document(
    *,
    vault_head: str,
    manifest: bytes,
    log: bytes,
    anchors: bytes,
    verifier: bytes,
    artifacts: int,
) -> dict[str, object]:
    """What a signature over this package covers, and what a recipient can read aloud.

    Digests of every file in the package plus the head and the object count, so one
    64-character string stands for the whole package. That string is the practical control: a
    recipient who obtains it from us through a channel that is not the package — a phone call,
    a letterhead, a signed email — can compare it without any cryptography at all.

    "Every file" is load-bearing and was not true until an adversarial review measured it. See
    :data:`SEALED_FILES`.
    """
    return {
        "version": 2,
        "vault_head": vault_head,
        "artifact_count": artifacts,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "log_sha256": hashlib.sha256(log).hexdigest(),
        "anchors_sha256": hashlib.sha256(anchors).hexdigest(),
        "verify_sha256": hashlib.sha256(verifier).hexdigest(),
    }


async def write_sealed_export(
    vault: FileSystemEvidenceVault,
    destination: Path,
    *,
    requested_by: str,
    reason: str,
    signer: LocalHeadSigner | None = None,
) -> SealedExport:
    """Write a self-contained, independently verifiable evidence package.

    Refuses to write anything if the vault does not verify. A package assembled from a vault
    whose own chain is broken would carry a manifest asserting integrity the source does not
    have, and the recipient's verifier would then either confirm a lie or — worse — fail in a
    way that looks like damage in transit.

    ``destination`` must not already exist. Overwriting an export in place would let a second
    run silently replace a package somebody has already been given a hash of.

    ``signer`` binds the package to a key. Without it, nothing here is signed, and a review
    pointed out what that costs: the chain is recomputable from its own contents, so **any
    holder** — a courier, an opposing party, anyone downstream — can rebuild the whole thing,
    not merely the operator the notice warns about. Signing moves that boundary to where the
    notice already claims it is. It does not move it further: a signature by our key says
    nothing to anyone worried about *us*, which is why the verdict stays ``NO``.
    """
    integrity = await vault.verify_integrity()
    if not integrity.is_intact:
        raise VaultNotExportableError(
            "refusing to export from a vault that does not verify: "
            # Every defect category, not just the chain. The first version joined
            # `log_defects` alone, so the most likely failure — a corrupted artifact —
            # produced "refusing to export from a vault that does not verify: ." and named
            # nothing at all.
            + (_defects(integrity) or "the vault reports itself as not intact")
            + ". A package is a claim about integrity, and this vault cannot support one."
        )

    if destination.exists():
        raise VaultNotExportableError(
            f"{destination} already exists; refusing to overwrite an export somebody may "
            "already hold a hash of"
        )

    bundle = await vault.export_bundle(requested_by=requested_by, reason=reason)
    entries = await vault.log_entries()
    anchors = await vault.anchors()

    # Assembled beside the destination and moved into place at the end, so a failure
    # anywhere below leaves nothing that looks like a package.
    staging = destination.parent / f".{destination.name}.partial"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    (staging / ARTIFACTS_DIR).mkdir()

    dropped: list[str] = []
    exported = 0
    for item in bundle.entries:
        try:
            artifact = await vault.retrieve_artifact(
                item.evidence_id, accessed_by=requested_by, reason=f"evidence export: {reason}"
            )
        except (VaultError, OSError) as exc:
            # `VaultError` is what the vault actually raises. The first version caught
            # `LookupError`/`PermissionError`/`OSError`, none of which any vault refusal
            # derives from, so an object withdrawn between the manifest and the copy escaped
            # this function mid-write and left a directory that looked like an export with
            # no manifest, no verifier and no notice — and which could never be re-exported
            # at that path, because the (correct) overwrite guard refuses it.
            dropped.append(f"{item.evidence_id}: {type(exc).__name__}")
            continue
        (staging / ARTIFACTS_DIR / item.evidence_id).write_bytes(artifact)
        exported += 1

    written = {path.name for path in (staging / ARTIFACTS_DIR).iterdir()}
    manifest = bundle.model_copy(
        update={"entries": tuple(item for item in bundle.entries if item.evidence_id in written)}
    )

    _write_manifest(staging, manifest)
    _write_jsonl(staging / LOG_FILE, entries)
    _write_jsonl(staging / ANCHORS_FILE, anchors)
    shutil.copyfile(standalone_verifier.__file__, staging / VERIFIER_FILE)

    seal = _seal_document(
        vault_head=manifest.vault_head,
        manifest=(staging / MANIFEST_FILE).read_bytes(),
        log=(staging / LOG_FILE).read_bytes(),
        anchors=(staging / ANCHORS_FILE).read_bytes(),
        verifier=(staging / VERIFIER_FILE).read_bytes(),
        artifacts=exported,
    )
    seal_bytes = canonical_bytes(seal)
    seal_digest = hashlib.sha256(seal_bytes).hexdigest()
    envelope: dict[str, object] = dict(seal)
    if signer is not None:
        envelope["key_id"] = signer.key_id
        envelope["public_key_pem"] = signer.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        envelope["signature"] = base64.b64encode(signer.sign_bytes(seal_bytes)).decode()
    (staging / SEAL_FILE).write_text(json.dumps(envelope, indent=2, sort_keys=True))

    external = sum(1 for record in anchors if record.anchor.is_externally_held)
    (staging / NOTICE_FILE).write_text(
        NOTICE.format(
            created_at=utcnow().isoformat(),
            requested_by=requested_by,
            reason=reason,
            object_count=exported,
            withheld=bundle.withheld_restricted,
            vault_head=manifest.vault_head,
            seal_digest=seal_digest,
            seal_finding=(
                SIGNED_SEAL.format(key_id=signer.key_id) if signer is not None else UNSIGNED_SEAL
            ),
            anchor_finding=(
                EXTERNAL_ANCHOR_PRESENT.format(count=external) if external else NO_EXTERNAL_ANCHOR
            ),
            # Named, not silently omitted. A shorter package with no explanation is a package
            # whose recipient cannot tell deletion in transit from an export that could not
            # read what it promised.
            dropped=(
                DROPPED_NOTICE.format(count=len(dropped), names=", ".join(dropped))
                if dropped
                else ""
            ),
        )
    )

    # Into place only now. Everything above happened in a staging directory, so a failure
    # anywhere leaves no directory that looks like a package.
    staging.rename(destination)

    return SealedExport(
        path=destination,
        object_count=exported,
        withheld_restricted=bundle.withheld_restricted,
        vault_head=manifest.vault_head,
        log_entries=len(entries),
        externally_anchored=external,
        seal_digest=seal_digest,
        signed_by=signer.key_id if signer is not None else None,
    )


class VaultNotExportableError(RuntimeError):
    """The vault cannot support the claim an export would make on its behalf."""


def _defects(integrity: object) -> str:
    """Every defect the integrity report carries, whatever category it landed in."""
    named = (
        "log_defects",
        "artifacts_corrupted",
        "artifacts_missing",
        "metadata_corrupted",
        "unlogged_artifacts",
    )
    found: list[str] = []
    for field in named:
        values = getattr(integrity, field, ())
        if values:
            found.append(f"{field}: {', '.join(str(v) for v in tuple(values)[:5])}")
    return "; ".join(found)


def _write_manifest(destination: Path, manifest: EvidenceExportBundle) -> None:
    (destination / MANIFEST_FILE).write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True)
    )


def _write_jsonl(path: Path, records: tuple[VaultLogEntry, ...] | tuple[AnchorRecord, ...]) -> None:
    """One record per line, in order.

    The log is written in its own order rather than sorted: the sequence *is* the evidence,
    and a reader who re-sorted it would destroy the property the chain exists to carry.
    """
    path.write_text("".join(f"{record.model_dump_json()}\n" for record in records))
