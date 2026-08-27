"""An evidence package is worth what its recipient can check without us.

Invariant 10 puts the vault operator inside the threat model. That makes a package whose
integrity is confirmed only by the producer's software worth very little: it establishes
that our arithmetic agrees with itself, which is exactly what an insider with write access
can arrange.

So the tests here do not ask the vault whether the export is good. They run
``python3 verify.py`` — the standalone verifier that travels inside the package and imports
nothing from this codebase — as a subprocess, against a bundle on disk, and read its verdict.
Then they damage the bundle in each of the ways an adversary would and check that it says so.

The last group is the one that matters most, and it asserts a *refusal to overclaim*: every
package this build can produce says ``DEFENSIBLE AGAINST THE OPERATOR: NO``, because there is
no externally held anchor and every link is recomputable by whoever holds the vault. A test
suite that only checked the happy path would let that sentence quietly disappear.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from nemesis.core.evidence import ArtifactKind, EvidenceObject
from nemesis.core.ids import IdPrefix, new_id
from nemesis.core.provenance import (
    CollectionMethod,
    CustodyEvent,
    ProvenanceChain,
    SourceClass,
    SourceDescriptor,
)
from nemesis.core.temporal import TemporalExtent, utcnow
from nemesis.evidence.export import (
    ARTIFACTS_DIR,
    LOG_FILE,
    MANIFEST_FILE,
    NOTICE_FILE,
    VERIFIER_FILE,
    VaultNotExportableError,
    write_sealed_export,
)
from nemesis.evidence.standalone_verifier import SEALED_FILES as VERIFIER_MAP
from nemesis.evidence.standalone_verifier import check_seal
from nemesis.evidence.vault import FileSystemEvidenceVault

pytestmark = pytest.mark.invariant


def _evidence(artifact: bytes) -> EvidenceObject:
    """Sealed the way a collector seals it, so the export covers a real object."""
    moment = utcnow()
    return EvidenceObject.seal(
        artifact=artifact,
        artifact_kind=ArtifactKind.DOCUMENT,
        provenance=ProvenanceChain(
            collection_id=new_id(IdPrefix.COLLECTION),
            source=SourceDescriptor(
                identifier="export-test-fixture",
                source_class=SourceClass.OWN_SENSOR,
            ),
            method=CollectionMethod(collector_name="export-test-fixture", collector_version="1"),
            collected_at=moment,
            custody=(
                CustodyEvent(
                    actor=new_id(IdPrefix.ACTOR),
                    action="collected",
                    reason="an export test needs something to export",
                ),
            ),
        ),
        observed_extent=TemporalExtent(
            known_from=moment,
            known_until=moment,
            possible_from=moment,
            possible_until=moment,
        ),
        media_type="text/plain",
        summary="synthetic artifact for an export test",
    )


async def _sealed_vault(root: Path, *, count: int = 3) -> FileSystemEvidenceVault:
    vault = FileSystemEvidenceVault(root / "vault")
    for index in range(count):
        artifact = f"synthetic artifact {index}".encode()
        await vault.seal(_evidence(artifact), artifact)
    return vault


def _export(tmp_path: Path, *, count: int = 3) -> Path:
    async def build() -> Path:
        vault = await _sealed_vault(tmp_path, count=count)
        report = await write_sealed_export(
            vault,
            tmp_path / "export",
            requested_by=new_id(IdPrefix.ACTOR),
            reason="disclosure to opposing counsel",
        )
        assert report.object_count == count
        return report.path

    return asyncio.run(build())


def _verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    """Run the package's own verifier, the way a recipient would."""
    return subprocess.run(  # noqa: S603 - fixed command, no shell
        [sys.executable, str(bundle / VERIFIER_FILE), str(bundle)],
        capture_output=True,
        text=True,
        timeout=120,
    )


# --- The package is self-contained and independently checkable ------------------


def test_the_export_is_a_directory_a_recipient_can_take_away(tmp_path: Path) -> None:
    bundle = _export(tmp_path)

    assert (bundle / MANIFEST_FILE).exists()
    assert (bundle / LOG_FILE).exists()
    assert (bundle / VERIFIER_FILE).exists()
    assert (bundle / NOTICE_FILE).exists()
    assert len(list((bundle / ARTIFACTS_DIR).iterdir())) == 3


def test_the_bundled_verifier_imports_nothing_from_this_codebase(tmp_path: Path) -> None:
    """It has to run on a machine that has never heard of NEMESIS.

    Checked against the shipped copy rather than the source module, because the shipped copy
    is the one a recipient runs.
    """
    import ast

    source = (_export(tmp_path) / VERIFIER_FILE).read_text()
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    # Checked by parsing rather than by searching for the word, because the word appears all
    # over its prose — where it belongs, explaining what the recipient is being asked not to
    # trust.
    assert "nemesis" not in imported, f"the shipped verifier imports {sorted(imported)}"

    # `cryptography` is imported lazily, inside the seal check, and its absence is reported
    # rather than fatal — so a recipient who has only the standard library can still run
    # every content check. Asserted as top-level-stdlib-only plus one optional dependency.
    top_level: set[str] = set()
    for node in ast.parse(source).body:
        if isinstance(node, ast.Import):
            top_level.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level.add(node.module.split(".")[0])
    assert top_level <= {
        "__future__",
        "base64",
        "hashlib",
        "json",
        "sys",
        "datetime",
        "pathlib",
        "typing",
    }
    assert imported - top_level <= {"cryptography"}


def test_a_recipient_running_the_verifier_gets_a_pass(tmp_path: Path) -> None:
    done = _verify(_export(tmp_path))

    assert done.returncode == 0, done.stdout + done.stderr
    assert "INTERNALLY CONSISTENT:            YES" in done.stdout


# --- It catches every way the package could be doctored -------------------------


def test_a_changed_artifact_byte_is_caught(tmp_path: Path) -> None:
    bundle = _export(tmp_path)
    artifact = next(iter((bundle / ARTIFACTS_DIR).iterdir()))
    artifact.write_bytes(artifact.read_bytes() + b" and one more word")

    done = _verify(bundle)
    assert done.returncode == 1
    assert "is not the one that was sealed" in done.stdout
    assert "INTERNALLY CONSISTENT:            NO" in done.stdout


def test_a_removed_artifact_is_caught(tmp_path: Path) -> None:
    bundle = _export(tmp_path)
    next(iter((bundle / ARTIFACTS_DIR).iterdir())).unlink()

    done = _verify(bundle)
    assert done.returncode == 1
    assert "no ordinary file for it" in done.stdout


def test_an_edited_log_entry_is_caught(tmp_path: Path) -> None:
    """The link's hash is recomputed from its own contents, so editing it shows."""
    bundle = _export(tmp_path)
    lines = (bundle / LOG_FILE).read_text().splitlines()
    doctored = json.loads(lines[1])
    doctored["reason"] = "a reason nobody gave"
    lines[1] = json.dumps(doctored)
    (bundle / LOG_FILE).write_text("\n".join(lines) + "\n")

    done = _verify(bundle)
    assert done.returncode == 1
    assert "edited after it was written" in done.stdout


def test_a_removed_log_entry_is_caught(tmp_path: Path) -> None:
    """Deleting a link breaks the chain at the next one, which is the point of chaining."""
    bundle = _export(tmp_path)
    lines = (bundle / LOG_FILE).read_text().splitlines()
    (bundle / LOG_FILE).write_text("\n".join(lines[:1] + lines[2:]) + "\n")

    done = _verify(bundle)
    assert done.returncode == 1
    assert "gap or" in done.stdout or "previous entry hashes to" in done.stdout


def test_a_reordered_log_is_caught(tmp_path: Path) -> None:
    bundle = _export(tmp_path)
    lines = (bundle / LOG_FILE).read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    (bundle / LOG_FILE).write_text("\n".join(lines) + "\n")

    done = _verify(bundle)
    assert done.returncode == 1


def test_a_manifest_naming_a_different_head_is_caught(tmp_path: Path) -> None:
    """The manifest and the log must describe the same vault."""
    bundle = _export(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    manifest["vault_head"] = "f" * 64
    (bundle / MANIFEST_FILE).write_text(json.dumps(manifest))

    done = _verify(bundle)
    assert done.returncode == 1
    assert "describe different vaults" in done.stdout


def test_an_object_smuggled_into_the_manifest_is_caught(tmp_path: Path) -> None:
    """Adding an entry the log never covered would be a way to launder an artifact."""
    bundle = _export(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    smuggled = dict(manifest["entries"][0])
    smuggled["evidence_id"] = new_id(IdPrefix.EVIDENCE)
    manifest["entries"].append(smuggled)
    (bundle / MANIFEST_FILE).write_text(json.dumps(manifest))

    done = _verify(bundle)
    assert done.returncode == 1
    assert "never sealed in this log" in done.stdout


# --- And it refuses to overclaim ------------------------------------------------


def test_every_package_this_build_produces_says_it_is_not_defensible(tmp_path: Path) -> None:
    """The sentence that must not quietly disappear.

    External anchoring is `REQUIRES_EXTERNAL_DATA`: an RFC 3161 authority is a system we do
    not own, and invariant 15 forbids contacting one. So there is no externally held anchor,
    every link is recomputable by whoever holds the vault, and the honest verdict is no.
    """
    done = _verify(_export(tmp_path))

    assert done.returncode == 0, "a self-consistent package still passes"
    assert "DEFENSIBLE AGAINST THE OPERATOR:  NO" in done.stdout
    assert "carries no anchor at all" in done.stdout
    assert "could have rebuilt it" in done.stdout


def test_the_notice_states_what_the_package_does_not_establish(tmp_path: Path) -> None:
    notice = (_export(tmp_path) / NOTICE_FILE).read_text()

    assert "WHAT THIS PACKAGE DOES NOT ESTABLISH" in notice
    assert "NO EXTERNALLY HELD ANCHOR" in notice
    assert "evidence of care in handling, not as proof against the party that" in notice
    # The content of an artifact is not vouched for by its bytes being unchanged.
    assert "is not a vouched-for fact" in notice


def test_withheld_material_is_counted_and_not_named(tmp_path: Path) -> None:
    """Naming what was withheld would defeat withholding it."""
    notice = (_export(tmp_path) / NOTICE_FILE).read_text()
    assert "withheld as restricted" in notice
    assert "counted rather than named" in notice


# --- The export refuses when it cannot support its own claim --------------------


def test_a_vault_that_does_not_verify_cannot_be_exported(tmp_path: Path) -> None:
    """A package is a claim about integrity. A broken vault cannot support one.

    The alternative is worse than refusing: the recipient's verifier would either confirm a
    manifest the source cannot back, or fail in a way that reads like damage in transit.
    """

    async def build() -> None:
        vault = await _sealed_vault(tmp_path)
        log = tmp_path / "vault" / "log.jsonl"
        lines = log.read_text().splitlines()
        doctored = json.loads(lines[0])
        doctored["actor"] = "somebody else entirely"
        lines[0] = json.dumps(doctored)
        log.write_text("\n".join(lines) + "\n")

        with pytest.raises(VaultNotExportableError, match="does not verify"):
            await write_sealed_export(
                vault,
                tmp_path / "export",
                requested_by=new_id(IdPrefix.ACTOR),
                reason="disclosure",
            )
        assert not (tmp_path / "export").exists(), "nothing may be written on refusal"

    asyncio.run(build())


def test_an_export_never_silently_replaces_an_earlier_one(tmp_path: Path) -> None:
    """Somebody may already hold a hash of the first one."""
    bundle = _export(tmp_path)

    async def again() -> None:
        vault = FileSystemEvidenceVault(tmp_path / "vault")
        with pytest.raises(VaultNotExportableError, match="already exists"):
            await write_sealed_export(
                vault, bundle, requested_by=new_id(IdPrefix.ACTOR), reason="second attempt"
            )

    asyncio.run(again())


# --- The verifier and the vault must agree on what a hash is --------------------


def test_the_bundled_verifier_computes_the_same_chain_hash_as_the_vault(
    tmp_path: Path,
) -> None:
    """If these ever diverge, every check in the package fails closed and loudly.

    Which is the safe direction, and still worth catching here rather than in a recipient's
    hands: a verifier that disagreed with the vault would call an honest package doctored.
    """
    from nemesis.evidence import standalone_verifier
    from nemesis.evidence.vault import VaultLogEntry

    bundle = _export(tmp_path)
    for line in (bundle / LOG_FILE).read_text().splitlines():
        entry = VaultLogEntry.model_validate_json(line)
        assert standalone_verifier.entry_hash(json.loads(line)) == entry.expected_hash()
        assert entry.is_intact


# --- It has to start on the recipient's interpreter, not ours -------------------


def test_the_verifier_runs_on_the_oldest_interpreter_on_this_machine(tmp_path: Path) -> None:
    """The claim "works on a machine that has never heard of this project" is checkable.

    It was also false. The first version used ``datetime.UTC`` (3.11+) and then
    ``fromisoformat`` on a timestamp ending in ``Z`` (parsed only from 3.11), so the shipped
    verifier crashed on the system Python of the machine it was written on — while the suite
    passed, because the suite ran it with ``sys.executable``.

    Ruff was actively undoing the fix: ``UP017`` rewrites ``timezone.utc`` to ``datetime.UTC``
    for the project's target version, which is a correctness regression for this one file.
    There is a per-file ignore in ``pyproject.toml`` saying so.
    """
    system = Path("/usr/bin/python3")
    if not system.exists():
        pytest.skip("no system interpreter to stand in for a recipient's machine")

    bundle = _export(tmp_path)
    done = subprocess.run(  # noqa: S603 - fixed command, no shell
        [str(system), str(bundle / VERIFIER_FILE), str(bundle)],
        capture_output=True,
        text=True,
        timeout=120,
        # No PYTHONPATH: the recipient does not have this package, and must not need it.
        env={"PATH": "/usr/bin:/bin"},
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert "INTERNALLY CONSISTENT:            YES" in done.stdout
    assert "DEFENSIBLE AGAINST THE OPERATOR:  NO" in done.stdout


# ======================================================================================
# Round four. Nine doctored packages passed the first verifier with exit 0.
#
# The mistake was one sentence long: it hashed each artifact against the manifest's
# `content_hash` — the file an attacker edits — while the true hash sat in the package
# three times over, in the content-addressed id, in the log's seal entry, and in the
# manifest. Two of the three went unread.
#
# The rule now: the log is the authority inside a package, the manifest is an index.
# ======================================================================================


def _doctor(bundle: Path, mutate: object) -> subprocess.CompletedProcess[str]:
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    result = mutate(bundle, manifest)  # type: ignore[operator]
    (bundle / MANIFEST_FILE).write_text(json.dumps(result if result is not None else manifest))
    return _verify(bundle)


def test_an_artifacts_contents_cannot_be_swapped_by_patching_the_manifest(
    tmp_path: Path,
) -> None:
    """The break. Reproduced verbatim, because it is the one that mattered.

    A reviewer replaced a document with "THE DEFENDANT ADMITS EVERYTHING.", patched the
    manifest's hash and size to match, and the recipient's own verifier certified it.
    """

    def swap(bundle: Path, manifest: dict[str, object]) -> None:
        item = manifest["entries"][0]  # type: ignore[index]
        forged = b"THE DEFENDANT ADMITS EVERYTHING."
        (bundle / ARTIFACTS_DIR / item["evidence_id"]).write_bytes(forged)
        item["content_hash"] = hashlib.sha256(forged).hexdigest()
        item["size_bytes"] = len(forged)

    done = _doctor(_export(tmp_path), swap)
    assert done.returncode == 1
    assert "the manifest was edited" in done.stdout or "not the one that was sealed" in done.stdout


def test_every_artifact_cannot_be_deleted_by_emptying_the_manifest(tmp_path: Path) -> None:
    """A gutted package must not certify itself.

    Walking only the manifest means an empty manifest has nothing to walk. The log's seal
    entries are what say how many objects there should be.
    """

    def gut(bundle: Path, manifest: dict[str, object]) -> None:
        for path in (bundle / ARTIFACTS_DIR).iterdir():
            path.unlink()
        manifest["entries"] = []

    done = _doctor(_export(tmp_path), gut)
    assert done.returncode == 1
    assert "Objects were removed from this package" in done.stdout


def test_a_single_document_cannot_be_suppressed_in_transit(tmp_path: Path) -> None:
    """The disclosure case: removing the one exculpatory document and its manifest entry."""

    def suppress(bundle: Path, manifest: dict[str, object]) -> None:
        item = manifest["entries"].pop(0)  # type: ignore[attr-defined]
        (bundle / ARTIFACTS_DIR / item["evidence_id"]).unlink()

    done = _doctor(_export(tmp_path), suppress)
    assert done.returncode == 1
    assert "Objects were removed from this package" in done.stdout


def test_an_empty_manifest_is_not_a_package_with_nothing_to_check(tmp_path: Path) -> None:
    """`manifest.json` replaced by `{}` was the worst case: every check skipped, verdict YES."""
    done = _doctor(_export(tmp_path), lambda bundle, manifest: {})
    assert done.returncode == 1
    assert "no usable vault_head" in done.stdout


def test_blanking_the_head_does_not_disable_the_head_check(tmp_path: Path) -> None:
    """`vault_head: ""` was treated as "nothing to check", so the log could be truncated."""

    def blank(bundle: Path, manifest: dict[str, object]) -> None:
        manifest["vault_head"] = ""
        lines = (bundle / LOG_FILE).read_text().splitlines()
        (bundle / LOG_FILE).write_text(lines[0] + "\n")

    done = _doctor(_export(tmp_path), blank)
    assert done.returncode == 1
    assert "no usable vault_head" in done.stdout


def test_a_file_nobody_described_is_reported(tmp_path: Path) -> None:
    """Reconciliation runs both ways: a package must contain exactly what it says."""
    bundle = _export(tmp_path)
    (bundle / ARTIFACTS_DIR / "a-file-nobody-described").write_bytes(b"x")

    done = _verify(bundle)
    assert done.returncode == 1
    assert "described by nothing" in done.stdout


def test_the_verifier_is_not_a_read_oracle_for_the_recipients_machine(tmp_path: Path) -> None:
    """The evidence_id builds a path on the recipient's machine.

    Unconfined it printed the SHA-256 of /etc/hosts, and `../` twenty times over did the
    same. Recipients are told to run this and usually send the output back.
    """

    # The target is a decoy this test plants, not a real system file. Pointing at /etc/hosts
    # made the assertions depend on the host: its size is a three-digit number on a GitHub
    # runner, and a three-digit substring collides with the hex digests the verifier prints —
    # so the test failed on CI over a coincidence rather than a leak. A decoy gives a
    # distinctive length and a unique marker, which makes every assertion below mean what it
    # says on any machine.
    decoy = tmp_path / "not-part-of-any-package.bin"
    marker = b"RECIPIENT-PRIVATE-DO-NOT-DISCLOSE-"
    decoy.write_bytes(marker + b"\0" * (104729 - len(marker)))

    def traverse(bundle: Path, manifest: dict[str, object]) -> None:
        # The same technique as a real traversal: climb far enough to reach the filesystem
        # root, then descend an absolute path.
        manifest["entries"][0]["evidence_id"] = "../" * 40 + str(decoy).lstrip("/")  # type: ignore[index]

    done = _doctor(_export(tmp_path), traverse)

    assert done.returncode == 1
    # Refused before the path is ever built, because the id is not one the log sealed. The
    # name confinement in `artifact_path` is the second lock on the same door.
    assert "never sealed in this log" in done.stdout
    # What matters either way: nothing about the target leaks. No content, no digest, no size,
    # no confirmation that it exists.
    assert marker.decode() not in done.stdout
    assert hashlib.sha256(decoy.read_bytes()).hexdigest() not in done.stdout
    assert str(decoy.stat().st_size) not in done.stdout
    assert decoy.exists(), "the verifier must not have touched the decoy either"


def test_a_symlinked_artifact_is_refused(tmp_path: Path) -> None:
    """A "self-contained" package must not depend on files outside itself."""
    bundle = _export(tmp_path)
    manifest = json.loads((bundle / MANIFEST_FILE).read_text())
    target = bundle / ARTIFACTS_DIR / manifest["entries"][0]["evidence_id"]
    target.unlink()
    target.symlink_to("/etc/hosts")

    done = _verify(bundle)
    assert done.returncode == 1
    assert "no ordinary file for it" in done.stdout


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("truncated json", '{"entries": '),
        ("a list, not an object", '["not", "an", "object"]'),
        ("not utf-8", "\udcff"),
    ],
    ids=["truncated", "list", "non-utf8"],
)
def test_malformed_input_is_a_finding_not_a_traceback(
    tmp_path: Path, name: str, content: str
) -> None:
    """A traceback reads as "damage in transit" or "broken tool".

    The recipient's correct conclusion — this package cannot be verified — is exactly what
    a stack trace loses. Exit status was already 1 in every case, so automation failed
    closed; the harm was to the human.
    """
    bundle = _export(tmp_path)
    (bundle / MANIFEST_FILE).write_text(content, errors="surrogateescape")

    done = _verify(bundle)
    assert done.returncode == 1
    assert "Traceback" not in done.stdout + done.stderr
    assert "INTERNALLY CONSISTENT:            NO" in done.stdout


def test_an_appended_anchor_cannot_flip_the_defensibility_verdict(tmp_path: Path) -> None:
    """One line naming "Totally Independent Notary AG" turned the verdict to YES.

    An anchor carried *inside* a package cannot establish its own independence — the file is
    as editable as everything beside it. The verdict is now unconditional and anchors are
    reported as something to check with the authority holding them.
    """
    bundle = _export(tmp_path)
    (bundle / "anchors.jsonl").write_text(
        json.dumps(
            {
                "sequence": 1,
                "anchor": {
                    "authority": "Totally Independent Notary AG",
                    "proof": "not-even-base64",
                    "covers_hash": "f" * 64,
                    "is_externally_held": True,
                },
            }
        )
        + "\n"
    )

    done = _verify(bundle)
    assert "DEFENSIBLE AGAINST THE OPERATOR:  NO" in done.stdout
    assert "as editable as the package" in done.stdout


# --- The package seal: what stops any holder rebuilding the chain ---------------


def _signed_export(tmp_path: Path, *, count: int = 3) -> tuple[Path, str]:
    from nemesis.evidence.anchoring import LocalHeadSigner

    async def build() -> tuple[Path, str]:
        vault = await _sealed_vault(tmp_path, count=count)
        report = await write_sealed_export(
            vault,
            tmp_path / "export",
            requested_by=new_id(IdPrefix.ACTOR),
            reason="disclosure to opposing counsel",
            signer=LocalHeadSigner.generate(),
        )
        return report.path, report.seal_digest

    return asyncio.run(build())


def test_an_unsigned_package_says_any_holder_could_have_rebuilt_it(tmp_path: Path) -> None:
    """Without a seal the boundary is not "the operator", it is "anyone who touched this".

    A review made that concrete: the chain is unkeyed, so a courier or an opposing party can
    rebuild it wholesale. The notice claimed the boundary was at the operator.
    """
    done = _verify(_export(tmp_path))

    assert "PACKAGE SEAL SIGNATURE:           ABSENT" in done.stdout
    assert "any holder could have rebuilt it" in done.stdout


def test_a_signed_package_verifies_and_prints_a_digest_to_compare_out_of_band(
    tmp_path: Path,
) -> None:
    """Two controls, and the one needing no software is the one that always works."""
    bundle, digest = _signed_export(tmp_path)
    done = _verify(bundle)

    assert done.returncode == 0, done.stdout + done.stderr
    assert "PACKAGE SEAL SIGNATURE:           VERIFIED" in done.stdout
    assert digest in done.stdout
    assert digest in (bundle / NOTICE_FILE).read_text()


def test_altering_a_signed_package_breaks_its_seal(tmp_path: Path) -> None:
    """Signed or not, the content checks fire; the seal is what a courier cannot forge."""
    bundle, _ = _signed_export(tmp_path)
    seal = json.loads((bundle / "seal.json").read_text())
    seal["artifact_count"] = 99
    (bundle / "seal.json").write_text(json.dumps(seal))

    done = _verify(bundle)
    assert done.returncode == 1
    assert "PACKAGE SEAL SIGNATURE:           FAILED" in done.stdout
    assert "altered after it was signed" in done.stdout


def test_a_recipient_without_cryptography_is_told_so_rather_than_reassured(
    tmp_path: Path,
) -> None:
    """An unchecked signature is not a checked one.

    And it is not a failure either: reporting the package inconsistent because the
    recipient's machine lacks a library would teach them to ignore the line that matters.
    The digest is the fallback, and it needs nothing installed.
    """
    system = Path("/usr/bin/python3")
    if not system.exists():
        pytest.skip("no second interpreter to stand in for a recipient without cryptography")

    # The condition is *constructed*, not assumed. An earlier version ran the system
    # interpreter and trusted that it had no `cryptography` — true on macOS, false on Ubuntu,
    # where it ships as a system package. There the seal verified for real, the branch under
    # test never ran, and CI failed on an assertion about someone else's base image. Shadowing
    # the module makes the import fail deterministically, so this exercises the branch on
    # every platform instead of passing on one and skipping on another.
    shadow = tmp_path / "no-crypto"
    shadow.mkdir()
    (shadow / "cryptography.py").write_text(
        "raise ImportError('shadowed: this test stands in for a recipient without it')\n"
    )

    # And the shadow is proven effective before anything is concluded from it. Without this,
    # a shadow that quietly stopped working would leave the test passing on any machine that
    # happens to lack the library — green for the wrong reason, which is the failure mode this
    # whole file is about.
    blocked = subprocess.run(  # noqa: S603 - fixed command, no shell
        [str(system), "-c", "import cryptography"],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(shadow)},
    )
    assert blocked.returncode != 0, "the shadow did not block the import; the test would be vacuous"

    bundle, digest = _signed_export(tmp_path)
    done = subprocess.run(  # noqa: S603 - fixed command, no shell
        [str(system), str(bundle / VERIFIER_FILE), str(bundle)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(shadow)},
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert "INTERNALLY CONSISTENT:            YES" in done.stdout
    assert "NOT CHECKED" in done.stdout
    assert digest in done.stdout


def test_the_seal_never_makes_the_package_defensible_against_us(tmp_path: Path) -> None:
    """A signature by our key says nothing to anyone worried about us.

    It moves the boundary from "any holder" to "the operator" — which is where the notice
    always claimed it was — and no further. The verdict line stays NO.
    """
    bundle, _ = _signed_export(tmp_path)
    done = _verify(bundle)

    assert "DEFENSIBLE AGAINST THE OPERATOR:  NO" in done.stdout
    assert "establishes nothing against us" in (bundle / NOTICE_FILE).read_text()


# --- the seal covers the package, not one file of it --------------------------------------


def test_the_seal_covers_every_file_in_the_package(tmp_path: Path) -> None:
    """One digest per file, checked against an explicit map rather than a derived name.

    The verifier used to derive the seal key from the filename —
    ``name.split(".")[0].replace("-", "_") + "_sha256"`` — which turns ``vault-log.jsonl`` into
    ``vault_log_sha256``, a key the sealer never wrote. The lookup returned ``None``, the
    comparison was skipped, and the log's digest check was **dead code**. Only ``manifest.json``
    happened to round-trip. ``anchors.jsonl`` was never in the loop, and ``verify.py`` was not in
    the seal document at all.
    """
    from nemesis.evidence.export import SEALED_FILES

    assert SEALED_FILES == VERIFIER_MAP, (
        "the sealer and the shipped verifier disagree about which digest covers which file. "
        "They are separate maps because the verifier ships standalone and cannot import "
        "nemesis; this assertion is what keeps them from drifting, and drift is exactly what "
        "produced the dead-code check."
    )

    bundle = _signed_export(tmp_path)[0]
    seal = json.loads((bundle / "seal.json").read_text())
    for name, key in SEALED_FILES.items():
        assert key in seal, f"{name} has no digest in the seal"
        actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        assert seal[key] == actual, f"the seal's {key} does not match {name} as written"


@pytest.mark.parametrize(
    "target", ["manifest.json", "vault-log.jsonl", "anchors.jsonl", "verify.py"]
)
def test_altering_any_sealed_file_fails_the_seal(tmp_path: Path, target: str) -> None:
    """Each covered file, mutated on its own, must fail. Parametrised so none can go quiet.

    A single test that altered one file would have passed throughout the period when three of
    the four checks were dead.
    """
    bundle = _signed_export(tmp_path)[0]
    before_digest, before_verdict, _ = check_seal(bundle)
    assert before_verdict in {"VERIFIED", "UNSIGNED"}

    path = bundle / target
    path.write_bytes(path.read_bytes() + b"\n# appended by somebody\n")

    digest, verdict, findings = check_seal(bundle)
    assert digest == before_digest, "the seal digest is computed from seal.json and must not move"
    assert verdict == "FAILED", f"altering {target} did not fail the seal: {findings}"
    assert any(target in finding for finding in findings), findings


def test_substituting_the_verifier_fails_the_seal(tmp_path: Path) -> None:
    """The attack that made this a HIGH rather than a tidiness finding.

    ``README.txt`` tells the recipient to run ``verify.py``. Before the fix, ``verify.py`` was
    not covered by the seal — so a signed package could ship an eleven-line program that prints
    a clean verdict, and the *genuine* ``check_seal()`` still returned VERIFIED with a
    byte-identical digest. A seal that does not cover the verifier is a seal the recipient
    checks with a program the seal does not vouch for.
    """
    bundle = _signed_export(tmp_path)[0]
    digest, _, _ = check_seal(bundle)
    (bundle / "verify.py").write_text(
        "import sys\n"
        f"print('PACKAGE SEAL: {digest}')\n"
        "print('INTERNALLY CONSISTENT:            YES')\n"
        "sys.exit(0)\n"
    )
    after_digest, verdict, findings = check_seal(bundle)
    assert after_digest == digest
    assert verdict == "FAILED"
    assert any("verify.py" in finding for finding in findings), findings


def test_a_notice_from_another_package_is_caught(tmp_path: Path) -> None:
    """The notice quotes the seal digest, so it cannot be inside the seal — bind it the other way.

    Sealing ``README.txt`` would require the digest of a document containing that digest. So the
    verifier checks the converse: the digest the notice *quotes* must be the digest it
    *computes*. A notice lifted from a different package, or rewritten to quote a different
    digest, is caught; prose edits that keep the digest are not, and that limit is stated rather
    than papered over.
    """
    bundle = _signed_export(tmp_path)[0]
    (bundle / "README.txt").write_text("Seal: " + "0" * 64 + "\nNothing to see here.\n")
    _, verdict, findings = check_seal(bundle)
    assert verdict == "FAILED"
    assert any("does not quote" in finding for finding in findings), findings


def test_a_missing_sealed_file_is_a_finding_not_a_crash(tmp_path: Path) -> None:
    """Deleting a covered file must be reported, not raise — a crash is a denial of verification."""
    bundle = _signed_export(tmp_path)[0]
    (bundle / "anchors.jsonl").unlink()
    _, verdict, findings = check_seal(bundle)
    assert verdict == "FAILED"
    assert any("anchors.jsonl is missing" in finding for finding in findings), findings
