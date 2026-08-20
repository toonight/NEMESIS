"""Reading is the half of confinement that was never closed.

ADR-0007 gave a confined child no socket and no write outside its job directory, and left the
read side as a blocklist: the workspace and the usual credential directories denied *by name*.
A blocklist stops what somebody thought of, and the ADR said so — then recorded the structural
fix as unavailable: "a read allowlist is the structural fix and aborts CPython on this platform."

Measured on 2026-08-17, that was wrong in a specific way, and the specifics are the finding:

- The abort is **dyld**, not CPython. ``/bin/echo`` dies identically under the same profile, so
  the diagnosis sent anyone who read it looking at the wrong component.
- It aborts because the allowlist was **incomplete**, not because an allowlist cannot work.
  ``(deny file-read-data)`` plus ``(allow file-read-data (subpath "/"))`` runs fine, which
  proves the mechanism and reduces the problem to enumerating paths.
- Two paths were missing, and both are the kind of thing an enumeration loses: ``(literal "/")``
  — the union of every top-level directory is not equivalent to allowing the root, because the
  root is read during path resolution — and the **resolved** interpreter prefix, because
  ``sys.base_prefix`` reported a symlink (``cpython-3.13-…``) while the binary lives in
  ``cpython-3.13.2-…``. That is the same ``/var`` versus ``/private/var`` failure this codebase
  already carries a comment about, one layer up.

These tests run the real profile against the real kernel. The load-bearing one is
`test_a_confined_child_cannot_read_this_platforms_own_source`: a worker that can read the
source it runs inside can find the vault path, the store schema and the shape of every control
meant to contain it.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from nemesis.sandbox.process import SandboxPolicy, sandbox_available

pytestmark = pytest.mark.invariant

needs_sandbox = pytest.mark.skipif(
    not sandbox_available(), reason="kernel-enforced confinement needs macOS sandbox-exec"
)

PROBE = """
import pathlib, sys
target = sys.argv[1]
try:
    pathlib.Path(target).read_bytes()
    print("READ")
except OSError as exc:
    print("DENY", type(exc).__name__)
"""


def _job() -> Path:
    work = Path(tempfile.mkdtemp(prefix="nemesis-readconf-"))
    (work / "job.json").write_text('{"job": 1}')
    (work / "probe.py").write_text(PROBE)
    return work


def _read_under_confinement(target: Path | str, *, confine: bool = True) -> str:
    """Run the probe inside the real profile and report what the kernel allowed."""
    work = _job()
    profile = SandboxPolicy(workdir=work, confine_reads=confine).profile()
    done = subprocess.run(  # noqa: S603 - fixed command, no shell
        [
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            sys.executable,
            "-s",
            "probe.py",
            str(target),
        ],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, f"the confined child died: {done.stderr[:400]}"
    return done.stdout.strip()


# --- The allowlist works at all, which ADR-0007 said it would not ------------


@needs_sandbox
def test_a_python_child_starts_under_a_read_allowlist() -> None:
    """The claim this file overturns.

    If the child cannot start, every assertion below is vacuous — so this runs first and
    proves the mechanism rather than assuming it.
    """
    work = _job()
    profile = SandboxPolicy(workdir=work, confine_reads=True).profile()
    done = subprocess.run(  # noqa: S603
        ["/usr/bin/sandbox-exec", "-p", profile, sys.executable, "-s", "-c", "print('STARTED')"],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, f"CPython aborted under the allowlist: {done.stderr[:400]}"
    assert "STARTED" in done.stdout


@needs_sandbox
def test_the_child_can_still_read_its_own_job() -> None:
    """Confinement that broke the work would be found as an outage, not as a control.

    Runs against *this* job's directory rather than through the helper, which makes its own
    workdir — a child reading a different job's input would prove the opposite of the point.
    """
    work = _job()
    profile = SandboxPolicy(workdir=work, confine_reads=True).profile()
    done = subprocess.run(  # noqa: S603 - fixed command, no shell
        [
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            sys.executable,
            "-s",
            "probe.py",
            str(work / "job.json"),
        ],
        cwd=work,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.stdout.strip() == "READ", done.stderr[:300]


# --- What a compromised worker must not reach --------------------------------


@needs_sandbox
def test_a_confined_child_cannot_read_this_platforms_own_source() -> None:
    """THE TEST THIS FILE EXISTS FOR.

    A worker that can read the source it runs inside can find the vault path, the store schema,
    and the shape of every control meant to contain it. The blocklist never denied this,
    because nobody thinks to deny their own repository.
    """
    source = Path(__file__).resolve().parents[2] / "src" / "nemesis" / "core" / "entities.py"
    assert source.exists(), "the test is pointing at a file that no longer exists"

    assert _read_under_confinement(source).startswith("DENY")


@needs_sandbox
def test_a_confined_child_cannot_read_the_callers_home_directory() -> None:
    """Credentials were denied by name; everything else in a home directory was not."""
    probe_target = Path.home() / ".zsh_history"
    if not probe_target.exists():
        pytest.skip("no shell history on this machine to probe with")
    assert _read_under_confinement(probe_target).startswith("DENY")


@needs_sandbox
def test_the_blocklist_mode_still_leaves_the_source_readable() -> None:
    """The contrast that shows the allowlist is doing something.

    With `confine_reads=False` — the behaviour ADR-0007 shipped — the same child reads this
    platform's source without difficulty. Asserting the *old* behaviour is what makes the new
    assertion meaningful rather than a test of nothing.
    """
    source = Path(__file__).resolve().parents[2] / "src" / "nemesis" / "core" / "entities.py"
    assert _read_under_confinement(source, confine=False) == "READ"


# --- The profile says what it does -------------------------------------------


def test_the_profile_denies_read_data_and_allows_the_root_literal() -> None:
    """A pure-text check, so it runs everywhere and pins the two details that were missing.

    `(literal "/")` is load-bearing: without it the union of top-level directories still
    aborts dyld, silently, with no output at all.
    """
    profile = SandboxPolicy(workdir=Path(tempfile.mkdtemp()), confine_reads=True).profile()

    assert "(deny file-read-data)" in profile
    assert '(literal "/")' in profile


def test_read_confinement_is_off_unless_asked_for() -> None:
    """Newer than the rest of the profile, and the collection plane has not been measured under
    it — so it is opt-in, and this pins that rather than leaving it to a default nobody read."""
    profile = SandboxPolicy(workdir=Path(tempfile.mkdtemp())).profile()
    assert "(deny file-read-data)" not in profile


def test_the_allowlist_carries_the_resolved_interpreter_prefix() -> None:
    """The symlink failure that cost the most time here.

    `sys.base_prefix` reported `cpython-3.13-…` while the binary lives in `cpython-3.13.2-…`;
    allowing the symlink allowed nothing, and the child aborted with no diagnostic.
    """
    profile = SandboxPolicy(workdir=Path(tempfile.mkdtemp()), confine_reads=True).profile()
    resolved = Path(sys.executable).resolve().parent.parent
    assert str(resolved) in profile
