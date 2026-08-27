"""The verifier that travels inside an evidence export, and imports nothing from NEMESIS.

An export is worth what its recipient can check **without us**. A manifest we produce,
describing hashes we computed, verified by a tool we ship and control, establishes only that
our arithmetic is self-consistent. Invariant 10 puts the vault operator in the threat model,
so the recipient has to be able to do the checking themselves.

This file is copied verbatim into every export directory as ``verify.py``. It uses the
standard library only and avoids anything newer than Python 3.9, so ``python3 verify.py``
works on a machine that has never heard of this project — including one whose only
interpreter is whatever its operating system shipped. It is also short enough to read before
running, which is the point: a recipient who checks our claims with our code has moved the
trust rather than removed it, and the only answer to that is a program you can audit in a
few minutes.

**What the first version got catastrophically wrong.** It hashed each artifact against the
``content_hash`` field of the manifest — the same file an attacker edits. A review changed an
artifact to read "THE DEFENDANT ADMITS EVERYTHING.", patched the manifest to match, and got
``INTERNALLY CONSISTENT: YES``. The true hash was sitting in the package three times: in the
content-addressed ``evidence_id``, in the log's ``seal`` entry, and in the manifest. Two of
the three went unread. Eight further doctorings passed the same way — every artifact deleted,
one document suppressed, the chain rebuilt wholesale, ``manifest.json`` replaced by ``{}``.

The rule that follows, and that this file now obeys everywhere: **the log is the authority
inside a package; the manifest is an index.** The log is a hash chain, so editing it shows.
Anything the manifest says is checked against the log and against the bytes, never trusted.

**What it still cannot establish, and says so in its own output.** That the chain was not
rebuilt wholesale by whoever holds the vault — or by anyone who held the package afterwards,
because nothing here is signed. Only an anchor held by a party that is not us breaks that
circle, and an anchor carried *inside* a package can never establish its own independence.
So the verdict is ``DEFENSIBLE AGAINST THE OPERATOR: NO``, unconditionally, and anchors are
reported as something to check with the anchoring party rather than as something this
program can accept.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEAL = "seal.json"
MANIFEST = "manifest.json"
LOG = "vault-log.jsonl"
ANCHORS = "anchors.jsonl"
ARTIFACTS = "artifacts"

GENESIS = "0" * 64
NOTICE = "README.txt"
VERIFIER = "verify.py"

SEALED_FILES = {
    MANIFEST: "manifest_sha256",
    LOG: "log_sha256",
    ANCHORS: "anchors_sha256",
    VERIFIER: "verify_sha256",
}
"""Which seal key covers which file. Must match `export.SEALED_FILES`; a test asserts it does.

Duplicated rather than imported because this file ships inside the bundle and runs on the
recipient's interpreter with no `nemesis` package available. The duplication is the price of
that, and the test is what keeps the two from drifting — which is exactly what happened when the
key was derived from the filename instead of written down.
"""

SEAL_ENTRY = "seal"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
CHUNK = 1024 * 1024


def canonical(payload: dict[str, Any]) -> bytes:
    """The vault's canonical JSON encoding, reproduced exactly.

    If this ever diverges from the vault's, every chain check fails closed and loudly rather
    than passing on a different definition of "same bytes".
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_time(value: str) -> datetime:
    """ISO-8601, including the trailing ``Z`` that interpreters before 3.11 will not parse."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def entry_hash(entry: dict[str, Any]) -> str:
    """Recompute one link from its own contents, including its predecessor."""
    recorded = parse_time(entry["recorded_at"]).astimezone(timezone.utc)
    return hashlib.sha256(
        canonical(
            {
                "sequence": entry["sequence"],
                "kind": entry["kind"],
                "previous_entry_hash": entry["previous_entry_hash"],
                "evidence_id": entry["evidence_id"],
                "content_hash": entry["content_hash"],
                "metadata_hash": entry["metadata_hash"],
                "recorded_at": recorded.isoformat(),
                "actor": entry["actor"],
                "reason": entry["reason"],
            }
        )
    ).hexdigest()


def digest_of(path: Path) -> str:
    """SHA-256 of a file, read in chunks, after refusing anything that is not an ordinary one.

    Streaming rather than ``read_bytes`` because the size is the sender's claim until it is
    measured: a package declaring 20 bytes and shipping 300 MB put 327 MB into a reviewer's
    verifier before any check ran.
    """
    with path.open("rb") as handle:
        digest = hashlib.sha256()
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def read_jsonl(path: Path) -> list[Any]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def artifact_path(bundle: Path, evidence_id: str) -> Path | None:
    """Resolve an artifact, or refuse the name outright.

    The identifier comes from the sender and is used to build a path on the recipient's
    machine. Unconfined, it is a file-existence and SHA-256 oracle for anything readable:
    a review put ``/etc/hosts`` in a manifest and had the verifier print its digest, then
    did the same with ``../`` twenty times over. Recipients are told to run this and usually
    send the output back.
    """
    if not evidence_id or "/" in evidence_id or "\\" in evidence_id or evidence_id in (".", ".."):
        return None
    directory = bundle / ARTIFACTS
    # The root is resolved from the BUNDLE, not through the directory. Resolving
    # `(bundle / ARTIFACTS)` moved the root along with a symlinked `artifacts/`, so the
    # confinement check compared a path against itself and passed. An adversarial review shipped
    # a package whose `artifacts/` pointed at a directory on the recipient's machine and had this
    # program hash and name the files in it.
    if directory.is_symlink():
        return None
    try:
        root = bundle.resolve() / ARTIFACTS
        candidate = directory / evidence_id
        resolved = candidate.resolve()
    except OSError:
        return None
    if resolved.parent != root or candidate.is_symlink() or not candidate.is_file():
        return None
    return candidate


def embedded_hash(evidence_id: str) -> str | None:
    """The hash inside a content-addressed id, which is a third witness to the same fact."""
    _, _, tail = evidence_id.partition("sha256-")
    return tail if len(tail) == 64 and all(c in "0123456789abcdef" for c in tail) else None


def verify(bundle: Path) -> tuple[bool, list[str]]:
    """Return (internally consistent, findings). Defensibility is decided in :func:`main`."""
    findings: list[str] = []

    manifest_path = bundle / MANIFEST
    if not manifest_path.exists():
        return False, ["no {} in {}".format(MANIFEST, bundle)]
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict):
        return False, ["{} is not an object".format(MANIFEST)]

    entries = read_jsonl(bundle / LOG)
    if not entries:
        return False, ["{} is empty or missing; there is no chain to check".format(LOG)]

    # 1. The chain first, because everything below is checked against it.
    previous = GENESIS
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            findings.append("entry {}: not an object".format(position))
            continue
        missing = {
            "sequence",
            "kind",
            "previous_entry_hash",
            "evidence_id",
            "content_hash",
            "metadata_hash",
            "recorded_at",
            "actor",
            "reason",
            "entry_hash",
        } - set(entry)
        if missing:
            findings.append("entry {}: missing {}".format(position, sorted(missing)))
            continue
        if entry["sequence"] != position:
            findings.append(
                "entry {}: sequence is {}; the chain has a gap or was reordered".format(
                    position, entry["sequence"]
                )
            )
        if entry["previous_entry_hash"] != previous:
            findings.append(
                "entry {}: claims predecessor {}…, but the previous entry hashes to {}…".format(
                    position, str(entry["previous_entry_hash"])[:16], previous[:16]
                )
            )
        if entry["entry_hash"] != entry_hash(entry):
            findings.append(
                "entry {}: stored hash does not match its contents — this link was edited "
                "after it was written".format(position)
            )
        previous = entry["entry_hash"]

    # 2. The head must be named, and must be the tip. An empty string is not "nothing to
    #    check": it was the one thing binding the manifest to the chain, and blanking it let
    #    a review truncate the log and still pass.
    head = manifest.get("vault_head")
    if not isinstance(head, str) or len(head) != 64:
        findings.append("the manifest names no usable vault_head, so nothing binds it to this log")
    elif head != entries[-1]["entry_hash"]:
        findings.append(
            "the manifest names head {}…, the log ends at {}… — the bundle and its log "
            "describe different vaults".format(head[:16], str(entries[-1]["entry_hash"])[:16])
        )

    # 3. What the LOG says was sealed. This, not the manifest, is the authority.
    sealed: dict[str, str] = {}
    for entry in entries:
        if isinstance(entry, dict) and entry.get("kind") == SEAL_ENTRY:
            sealed[entry["evidence_id"]] = entry["content_hash"]

    listed = manifest.get("entries")
    if not isinstance(listed, list):
        findings.append("the manifest lists no entries; there is nothing here it describes")
        listed = []

    seen: set[str] = set()
    for item in listed:
        if not isinstance(item, dict) or "evidence_id" not in item:
            findings.append("a manifest entry is not an object with an evidence_id")
            continue
        evidence_id = item["evidence_id"]
        seen.add(evidence_id)

        if evidence_id not in sealed:
            findings.append(
                "{}: exported but never sealed in this log; nothing here says when or by "
                "whom".format(evidence_id)
            )
            continue

        # Three independent witnesses to one fact: the chained log entry, the
        # content-addressed identifier, and the manifest field. They must agree, and the
        # bytes must agree with them. Checking the bytes against the manifest alone — which
        # is what this did — is checking the attacker's copy against itself.
        truth = sealed[evidence_id]
        embedded = embedded_hash(evidence_id)
        if embedded is not None and embedded != truth:
            findings.append(
                "{}: the identifier embeds {}… but the log sealed {}…".format(
                    evidence_id, embedded[:16], truth[:16]
                )
            )
        declared = str(item.get("content_hash", ""))
        if declared and declared != truth:
            findings.append(
                "{}: the manifest claims {}… but the log sealed {}… — the manifest was "
                "edited".format(evidence_id, declared[:16], truth[:16])
            )

        path = artifact_path(bundle, evidence_id)
        if path is None:
            findings.append(
                "{}: no ordinary file for it in {}/ (missing, a symlink, or a name that "
                "escapes the bundle)".format(evidence_id, ARTIFACTS)
            )
            continue
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            findings.append(
                "{}: {} bytes, beyond what this verifier will read".format(evidence_id, size)
            )
            continue
        actual = digest_of(path)
        if actual != truth:
            findings.append(
                "{}: content hashes to {}… but the log sealed {}… — this artifact is not "
                "the one that was sealed".format(evidence_id, actual[:16], truth[:16])
            )
        if "size_bytes" in item and int(item["size_bytes"]) != size:
            findings.append("{}: size differs from the manifest".format(evidence_id))

    # 4. Both directions. A package can be gutted by *removing* things, and a check that only
    #    walks the manifest cannot see what is no longer in it.
    #
    #    **The manifest's own number must not balance the log's equation.** This used to read
    #    `len(sealed) != len(seen) + withheld`, where `withheld` is a *manifest* field — the
    #    attacker's own copy. An adversarial review popped one entry, deleted its artifact and
    #    incremented `withheld_restricted` by one: `verify()` returned True with zero findings,
    #    and the program printed "nothing was added or removed" about a package one exhibit
    #    short. That breaks this module's own stated rule — the log is the authority inside a
    #    package and the manifest is an index.
    #
    #    The log cannot distinguish withheld from deleted, so it is no longer asked to. A
    #    shortfall is reported as a shortfall, and the withholding claim is reported as
    #    something this program cannot check. A recipient who needs it checked compares the
    #    object count against the one in the notice they were given out of band.
    shortfall = len(sealed) - len(seen)
    if shortfall > 0:
        withheld = manifest.get("withheld_restricted", 0)
        withheld = withheld if isinstance(withheld, int) and withheld >= 0 else 0
        findings.append(
            "the log seals {} object(s) and {} are present. The manifest says {} were withheld "
            "as restricted, and THIS PROGRAM CANNOT CHECK THAT: the count is a manifest field, "
            "so a package with objects removed in transit looks identical to one with objects "
            "lawfully withheld. Confirm the number with the sender through a channel that is "
            "not this package.".format(len(sealed), len(seen), withheld)
        )
    elif shortfall < 0:
        findings.append(
            "the package holds {} object(s) the log does not seal; it was added to after it "
            "was written.".format(-shortfall)
        )

    directory = bundle / ARTIFACTS
    if directory.is_symlink():
        # Reported without listing what is behind it. The stray-file walk leaked a full
        # directory listing off the recipient's machine with no log or manifest forgery at all —
        # it iterated the symlinked directory unconditionally. A refusal must not carry the
        # measurement it refused to make.
        findings.append(
            "{} is a symbolic link, not a directory. This package will not be read: a link "
            "here points this program at files that are not part of it.".format(ARTIFACTS)
        )
    elif directory.is_dir():
        for path in sorted(directory.iterdir()):
            if path.name not in seen:
                findings.append(
                    "{}/{}: present in the package but described by nothing".format(
                        ARTIFACTS, path.name
                    )
                )

    return not findings, findings


def check_seal(bundle: Path) -> tuple[str, str, list[str]]:
    """The package seal: one digest for the whole package, and a signature over it if present.

    Returns ``(digest, verdict, findings)`` where verdict is one of ``VERIFIED``, ``FAILED``,
    ``NOT CHECKED`` or ``ABSENT``. Kept separate from the content checks on purpose: an
    unchecked signature is not a failed one, and reporting a package as inconsistent because
    the recipient's machine lacks a library would teach them to ignore the line that matters.

    Two independent things, and the weaker-looking one is the stronger control.

    The digest is a 64-character string a recipient obtains from the producer through a
    channel that is not the package — a phone call, a letterhead — and compares by eye. It
    needs no software, and it is the only check in this program that does not run on data
    the sender controls.

    The signature needs ``cryptography``, which a recipient may not have. When it is missing
    this says so rather than passing quietly: an unchecked signature is not a checked one,
    and a verifier that blurred the two would be doing the thing this whole file exists to
    avoid.
    """
    findings: list[str] = []
    path = bundle / SEAL
    if not path.exists():
        return (
            "",
            "ABSENT",
            [
                "no {}: this package is not sealed, so nothing binds its parts together "
                "and any holder could have rebuilt it".format(SEAL)
            ],
        )

    mismatched = False
    envelope = json.loads(path.read_text())
    covered = {
        k: v for k, v in envelope.items() if k not in ("key_id", "public_key_pem", "signature")
    }
    payload = canonical(covered)
    digest = hashlib.sha256(payload).hexdigest()

    # An explicit map, not a name derived from a filename. The derivation
    # (`name.split(".")[0].replace("-", "_")`) turned "vault-log.jsonl" into "vault_log_sha256",
    # a key the sealer never wrote, so `claimed` was None and the log's check was dead code —
    # measured: a signed package whose log was replaced wholesale still returned VERIFIED.
    # `verify.py` was not checked at all, which meant a recipient could be running an
    # attacker's verifier under a genuine seal.
    for name, seal_key in sorted(SEALED_FILES.items()):
        path = bundle / name
        if not path.is_file():
            findings.append("{} is missing, so the seal cannot cover it".format(name))
            mismatched = True
            continue
        claimed = covered.get(seal_key)
        if claimed is None:
            findings.append(
                "the seal carries no {} digest, so {} is not covered by it".format(seal_key, name)
            )
            mismatched = True
        elif claimed != hashlib.sha256(path.read_bytes()).hexdigest():
            findings.append(
                "{} does not match the digest this package was sealed with".format(name)
            )
            mismatched = True

    # The notice quotes the seal digest, so it cannot be inside the seal. Binding it the other
    # way round costs nothing and catches a notice detached from its package.
    notice = bundle / NOTICE
    if notice.is_file() and digest not in notice.read_text(encoding="utf-8", errors="replace"):
        findings.append(
            "{} does not quote this package's seal digest; the notice belongs to a different "
            "package or was rewritten".format(NOTICE)
        )
        mismatched = True

    # Deliberately NOT an early return. The first version short-circuited here, and an existing
    # test caught what that cost: mutating `seal.json` moves the computed digest, the notice no
    # longer quotes it, and the recipient was told "the notice does not quote this digest" while
    # never being told the far stronger fact that **the signature does not verify**. A verifier
    # must report the strongest true statement, not the first one it reaches, so the content
    # findings are kept and the signature is evaluated regardless.
    signature = envelope.get("signature")
    if not signature:
        findings.append(
            "THIS PACKAGE IS NOT SIGNED, so any holder could have rebuilt it — a courier, an "
            "opposing party, anyone it passed through — not only the party that produced it. "
            "The seal digest above is still worth comparing out of band; it is all there is."
        )
        return digest, "FAILED" if mismatched else "ABSENT", findings

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        return (
            digest,
            "FAILED" if mismatched else "NOT CHECKED (no `cryptography` on this machine)",
            findings,
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = load_pem_public_key(str(envelope["public_key_pem"]).encode())
        if not isinstance(key, Ed25519PublicKey):
            # Named rather than accepted: the scheme is part of what was agreed, and a
            # package arriving under a different one is a package whose producer changed
            # something they did not say they changed.
            raise ValueError("the seal key is not Ed25519")
        key.verify(base64.b64decode(str(signature)), payload)
    except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
        findings.append(
            "THE SEAL SIGNATURE DOES NOT VERIFY ({}): this package was altered after it was "
            "signed, or was signed by a different key".format(type(exc).__name__)
        )
        return digest, "FAILED", findings
    return digest, "FAILED" if mismatched else "VERIFIED", findings


def anchor_note(bundle: Path) -> str:
    """See :func:`_anchor_note`. Wrapped so a damaged file cannot follow a verdict with a stack.

    ``anchor_note`` is called after the verdict lines are printed and, until an adversarial
    review pointed it out, outside ``main``'s handler: making ``anchors.jsonl`` a *directory*
    printed ``INTERNALLY CONSISTENT: YES`` and then an ``IsADirectoryError`` traceback. The exit
    status was still 1, so automation failed closed — but a human saw the outcome line this
    program exists to make unambiguous, and grep-based automation keying on that line accepted.
    """
    try:
        return _anchor_note(bundle)
    except OSError as exc:
        return (
            "anchors.jsonl could not be read ({}), so nothing here says whether this package "
            "was anchored at all.".format(type(exc).__name__)
        )


def _anchor_note(bundle: Path) -> str:
    """What the anchors in a package are worth, which is never more than a pointer.

    An anchor carried inside a package cannot establish its own independence: the file is as
    editable as everything else beside it, and a review appended one line naming "Totally
    Independent Notary AG" and flipped the verdict to YES. So this reports and does not
    accept. The only anchor worth anything is one the recipient checks with the party that
    holds it.
    """
    try:
        anchors = read_jsonl(bundle / ANCHORS)
    except ValueError:
        return "anchors.jsonl is present but unreadable."
    if not anchors:
        return (
            "This package carries no anchor at all. Every link in its chain is recomputable "
            "from its own contents, so anyone who has held this package could have rebuilt it."
        )
    return (
        "This package carries {} anchor record(s). Nothing here can establish that any of "
        "them is held by a party independent of the producer — an anchor inside a package is "
        "as editable as the package. Check them with the anchoring authority directly.".format(
            len(anchors)
        )
    )


def main(argv: list[str]) -> int:
    bundle = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent
    digest, seal = "", "NOT CHECKED"
    try:
        consistent, findings = verify(bundle)
        digest, seal, seal_findings = check_seal(bundle)
        findings = findings + seal_findings
        # Only an actual seal FAILURE contradicts the package. Absent and unverifiable are
        # reported on their own line and do not make an otherwise sound package read as
        # doctored — a verifier that cried tampering because the recipient's machine lacks a
        # library, or because nobody signed, would train them to ignore the line that counts.
        consistent = consistent and seal != "FAILED"
    except Exception as exc:
        # A traceback reads as "damage in transit" or "broken tool", and the recipient's
        # correct conclusion — this package cannot be verified — is exactly what gets lost.
        consistent, findings = (
            False,
            ["this package could not be checked: {}: {}".format(type(exc).__name__, exc)],
        )

    print("NEMESIS evidence export — {}".format(bundle))
    print()
    for finding in findings:
        print("  ! {}".format(finding))
    if findings:
        print()
    if digest:
        print("PACKAGE SEAL: {}".format(digest))
        print("  Compare this with the producer through a channel that is not this package.")
        print()
    print("INTERNALLY CONSISTENT:            {}".format("YES" if consistent else "NO"))
    print("PACKAGE SEAL SIGNATURE:           {}".format(seal))
    print("DEFENSIBLE AGAINST THE OPERATOR:  NO")
    print()
    print("  " + anchor_note(bundle))
    print()
    if consistent:
        print(
            "  This package is self-consistent: every artifact hashes to what the chained\n"
            "  log sealed, the log has no gap, edit or reordering, and nothing was added or\n"
            "  removed. That is the strongest statement available from inside a package.\n"
            "  It is NOT proof against the party that produced it, and nothing here is\n"
            "  signed — treat it as evidence of care in handling."
        )
    return 0 if consistent else 1


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main(sys.argv))
