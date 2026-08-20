"""Running something in a process that can do less than this one.

Two planes need this and they need opposite policies, which is the reason it lives here
rather than in either of them.

**Effects** must not reach outward: it is the plane that could touch the world, so its
child is denied a socket and its output is a document. **Collection** is the mirror image —
it is "hostile by definition" (threat model §1), it will one day need the network to fetch
what it collects, and the danger runs *inward*: a parser exploit in a downloaded artifact
must not become reach into the graph, the vault or the signing key.

So the policy is a parameter and the launch is shared. Sharing it is not tidiness: the launch
logic is the part six adversarial reviews have been through, and it earned several corrections
that are easy to lose in a second copy — a process-group kill that refuses to signal its own
group, a bounded read that measures while reading rather than afterwards, an environment built
from nothing, a report that claims nothing before the process exists. A duplicate would drift
from those one commit at a time, exactly as a second implementation of the graph traversal
would have.

`import-linter` puts this beside :mod:`nemesis.core`, below every plane, so both can use it
and it can reach neither.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

SANDBOX_EXEC: Final = Path("/usr/bin/sandbox-exec")

MAX_STDOUT_BYTES: Final = 8 * 1_024 * 1_024
MAX_STDERR_BYTES: Final = 256 * 1_024
REAP_SECONDS: Final = 5.0


def sandbox_available() -> bool:
    """Whether this platform can enforce a profile at all.

    A file-existence check, and that is a known weakness: a future macOS shipping a no-op
    ``sandbox-exec`` would report True with nothing enforced. Recorded in the threat model
    rather than papered over — the honest fix is a positive self-test at startup.
    """
    return sys.platform == "darwin" and SANDBOX_EXEC.exists()


class OutputCeilingError(RuntimeError):
    """The child tried to return more than the parent will hold."""


@dataclass(frozen=True)
class SandboxPolicy:
    """What a confined child may do. Different for every plane that uses one.

    ``allow_network`` is the field that makes this shared rather than copied. Effects sets it
    False and gets the kernel's refusal as a fact it can report. Collection will need it True
    the day a connector fetches something real — and everything *else* denied is precisely
    what makes that safe, because the danger there runs inward.
    """

    workdir: Path
    allow_network: bool = False
    read_denied: tuple[Path, ...] = ()
    deny_mach_services: tuple[str, ...] = (
        "com.apple.coreservices.launchservicesd",
        "com.apple.lsd.mapdb",
        "com.apple.lsd.modifydb",
    )
    """Services that let a confined process have an *unconfined* one started on its behalf.

    A review used ``/usr/bin/open`` to put a process outside the sandbox from inside it —
    a child of ``launchd``, inheriting none of the confinement. `(allow default)` permits
    ``mach-lookup``, so these are denied by name. The list is what was found, not everything
    conceivable.
    """

    confine_reads: bool = False
    """Deny reads by default and allow only an enumerated set, instead of denying by name.

    ``read_denied`` is a **blocklist**: it names the workspace and the usual credential
    directories, and is incomplete by construction — it stops what somebody thought of. This
    flips the default, which is the structural version of the same control: a compromised
    worker can read the interpreter it runs on and its own job directory, and nothing else.

    Off by default because it is newer and because the collection plane has not been measured
    under it. Effects turns it on: that plane holds no legitimate reason to read anything but
    its job.
    """

    read_allowed: tuple[Path, ...] = ()
    """Extra paths a confined child may read, on top of the interpreter and its job.

    Exists because of a tension that only appeared when a real worker ran under
    ``confine_reads``: the worker **is** this package, so it must be able to read the package
    source to import itself. A bare probe under the allowlist cannot read this platform's
    source; the actual Effects worker must, and pretending otherwise produced a profile that
    simply killed the plane. The caller names what it genuinely needs, and the narrowing is
    everything *else*.
    """

    environment: dict[str, str] = field(default_factory=dict)

    def profile(self) -> str:
        """The macOS profile text, with every path resolved.

        ``mkdtemp`` returns a path under ``/var`` that the kernel resolves under
        ``/private/var``, and an unresolved rule matches nothing at all — it failed closed,
        so nothing was exposed, and the child could write nowhere while the report named a
        directory it could not use.
        """
        rules = [
            "(version 1)",
            "(allow default)",
            "(deny file-write*)",
            f'(allow file-write* (subpath "{self.workdir.resolve()}"))',
            '(allow file-write-data (literal "/dev/null") (literal "/dev/stdout") '
            '(literal "/dev/stderr"))',
        ]
        if not self.allow_network:
            rules.insert(2, "(deny network*)")
            # Both resolver services. The Effects plane's own copy of this profile denied the
            # dnsproxy variant and this one did not — the exact drift the module docstring
            # warns a duplicate produces, found when the two were merged.
            rules.append('(deny mach-lookup (global-name "com.apple.mDNSResponder"))')
            rules.append('(deny mach-lookup (global-name "com.apple.mDNSResponder.dnsproxy"))')
        rules += [f'(deny mach-lookup (global-name "{name}"))' for name in self.deny_mach_services]
        rules += [
            f'(deny file-read* (subpath "{Path(path).resolve()}"))'
            for path in self.read_denied
            if Path(path).exists()
        ]
        if self.confine_reads:
            rules += _read_allowlist_rules(self.workdir, self.read_allowed)
        return "\n".join(rules) + "\n"


def _read_allowlist_rules(workdir: Path, extra: tuple[Path, ...] = ()) -> list[str]:
    """Deny reads by default, then allow exactly what a Python child needs plus its job.

    ADR-0007 recorded this as impossible — "a read allowlist is the structural fix and aborts
    CPython on this platform". Measured on 2026-08-17, that was wrong in a specific and useful
    way: the abort is **dyld**, not CPython (``/bin/echo`` dies identically), and it happens
    because the allowlist was incomplete rather than because an allowlist cannot work. Two
    things were missing, and both are the kind of detail an enumeration loses:

    ``(literal "/")`` — the union of every top-level directory is *not* equivalent to allowing
    the root, because the root directory itself is read during path resolution. Allowing
    ``/usr /System /bin /private /dev /Users`` and the interpreter still aborted; adding the
    root turned a silent SIGABRT into dyld's real error message.

    **Resolved interpreter paths.** ``sys.base_prefix`` reported a symlinked directory
    (``cpython-3.13-…``) while the binary lives in the resolved one (``cpython-3.13.2-…``).
    Allowing the symlink allowed nothing — the same ``/var`` versus ``/private/var`` failure
    this module already carries a comment about, one layer up.

    **What it achieves, stated after a real worker ran under it rather than after a probe.**
    The job directory and the interpreter are readable; the evidence vault, the audit trail,
    the caller's SSH key, the shell history and everything else on the machine are not. A bare
    probe also cannot read this platform's source — but the Effects worker *is* this package
    and must import it, so callers pass the package root in ``read_allowed`` and that source
    stays readable to it. Claiming otherwise was an overclaim that survived exactly as long as
    it took to run the real worker, which then could not start at all.

    Honest scope: this is macOS-specific and the allowlist is still an enumeration, just an
    inverted one — a path a future CPython needs and does not have will fail closed and loudly,
    which is the right direction but is an operational cost, not a free win.
    """
    interpreter = Path(sys.executable).resolve()
    allowed = {
        Path("/usr"),
        Path("/System"),
        Path("/bin"),
        Path("/dev"),
        Path("/private/var/db"),  # dyld's caches
        Path("/private/etc"),
        interpreter.parent.parent,  # the venv, or the interpreter's own prefix
        Path(sys.prefix).resolve(),
        Path(sys.base_prefix).resolve(),
        workdir.resolve(),
        *(Path(p).resolve() for p in extra),
    }
    subpaths = " ".join(f'(subpath "{path}")' for path in sorted(allowed))
    return [
        "(deny file-read-data)",
        # `(literal "/")` is load-bearing: without it the union above still aborts dyld.
        f'(allow file-read-data (literal "/") {subpaths})',
    ]


@dataclass(frozen=True)
class SandboxRun:
    """What came back, and what confinement it came back from."""

    stdout: bytes
    stderr: bytes
    mechanism: str
    network_denied: bool
    started: bool
    failure: str | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None


async def run_confined(
    command: list[str],
    *,
    stdin: bytes,
    policy: SandboxPolicy,
    deadline_seconds: float,
    allow_unsandboxed: bool = True,
) -> SandboxRun:
    """Run one command, confined as far as this platform allows, and never longer than the
    deadline.

    Returns a result for every outcome including a crash, a hang and nonsense on stdout. A
    caller that has to catch exceptions to record an outcome is a caller that will one day
    fail to record one.
    """
    sandboxed = sandbox_available()
    if not sandboxed and not allow_unsandboxed:
        return SandboxRun(
            b"",
            b"",
            mechanism="none",
            network_denied=False,
            started=False,
            failure=(
                f"this deployment requires kernel-enforced confinement and {sys.platform!r} "
                "cannot provide it; nothing ran"
            ),
        )

    argv = [str(SANDBOX_EXEC), "-p", policy.profile(), *command] if sandboxed else list(command)
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=policy.workdir,
            env=policy.environment,
            # Its own process group, so the deadline can reach descendants. Without this,
            # `kill()` reached the direct child and `wait()` blocked until the inherited
            # pipes closed — a grandchild holding stdout made a 2s deadline take 90s.
            start_new_session=True,
        )
    except OSError as exc:
        return SandboxRun(
            b"",
            b"",
            mechanism="none",
            network_denied=False,
            started=False,
            failure=f"the child could not be started ({type(exc).__name__}); nothing ran",
        )

    mechanism = "sandbox-exec" if sandboxed else "subprocess"
    try:
        stdout, stderr = await asyncio.wait_for(_collect(process, stdin), timeout=deadline_seconds)
    except (TimeoutError, OutputCeilingError) as exc:
        await terminate(process)
        reason = (
            f"exceeded its {deadline_seconds:g}s deadline"
            if isinstance(exc, TimeoutError)
            else f"tried to return more than {MAX_STDOUT_BYTES} bytes"
        )
        return SandboxRun(
            b"",
            b"",
            mechanism=mechanism,
            network_denied=sandboxed and not policy.allow_network,
            started=True,
            failure=f"the child {reason} and its process group was killed",
        )

    return SandboxRun(
        stdout,
        stderr,
        mechanism=mechanism,
        network_denied=sandboxed and not policy.allow_network,
        started=True,
    )


async def _collect(process: asyncio.subprocess.Process, payload: bytes) -> tuple[bytes, bytes]:
    """Read incrementally, refusing to buffer more than the ceiling.

    ``communicate()`` reads to EOF and only then can anything measure the result, which made
    the ceiling a post-mortem: 600 MiB reached the parent in 0.3 seconds and was met with a
    refusal saying the output had been discarded unread.
    """
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    writer = process.stdin

    async def drain(stream: asyncio.StreamReader, ceiling: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while chunk := await stream.read(64 * 1024):
            total += len(chunk)
            if total > ceiling:
                raise OutputCeilingError
            chunks.append(chunk)
        return b"".join(chunks)

    async def feed() -> None:
        try:
            writer.write(payload)
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # a child that closed stdin is a child that returns nothing usable
        finally:
            writer.close()

    out = asyncio.create_task(drain(process.stdout, MAX_STDOUT_BYTES))
    err = asyncio.create_task(drain(process.stderr, MAX_STDERR_BYTES))
    fed = asyncio.create_task(feed())
    tasks: list[asyncio.Task[Any]] = [out, err, fed]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        # Cancel the siblings rather than leaving one reading a pipe nobody will close: the
        # first version leaked an open read transport on every deadline and every breach.
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return out.result(), err.result()


async def terminate(process: asyncio.subprocess.Process) -> None:
    """Kill the whole process group, and never our own.

    The group is read once and compared against this process's own before anything is
    signalled. Writing this without that check killed the test suite exercising it: if
    ``start_new_session`` has not taken effect, or the pid has been reaped and reused,
    ``getpgid`` answers with *our* group. A kill switch that can fire at its owner is worse
    than no kill switch.
    """
    group: int | None = None
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        group = os.getpgid(process.pid)
    if group is not None and group != os.getpgrp():
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(group, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError, OSError):
        process.kill()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=REAP_SECONDS)
    # Closing the transport is what releases the pipes; `wait()` returns on process exit but
    # leaves a read transport open when nothing reached EOF on it.
    transport = getattr(process, "_transport", None)
    if transport is not None:
        with contextlib.suppress(Exception):
            transport.close()
