"""`handles_hostile_content` must mean something at runtime, not only at construction.

The flag has always existed, and the base connector has always refused to build a
hostile-content collector that does not *declare* a sandbox profile. Declaring one and
running in one are different things, and nothing checked the second — the threat model
carried "opening a malicious document today would happen in the main process" as an open
gap, and the founder's priority list named isolation for Effects **and hostile collectors**.

The danger runs the other way here than in the Effects plane. Effects is what could touch the
world; collection is what the world touches. So the tests below check that a compromised
collector reaches *nothing* — not that it cannot reach outward, which for a real collector
would be the wrong control entirely.

Every connector in this repository reads a fixture, so no hostile bytes are parsed anywhere
today. That is why this is worth building now: ADR-0001 listed the process boundary as an
assumption to be honoured "before it is needed", and a boundary added after the first real
connector is a boundary added after the first real exposure.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from nemesis.collect.base import SimulatedConnector
from nemesis.collect.isolation import IsolatedCollector, requires_isolation
from nemesis.collect.simulated import dark_web_connector, simulated_connectors
from nemesis.collect.worker import FORBIDDEN_PREFIXES
from nemesis.core.entities import EntityType
from nemesis.ports.collection import PivotRequest, PivotType
from nemesis.sandbox.process import SandboxPolicy, sandbox_available
from nemesis.slice.scenario import run_glass_anvil_scenario

pytestmark = pytest.mark.invariant

AS_OF = "2026-03-10T00:00:00+00:00"

needs_sandbox = pytest.mark.skipif(
    not sandbox_available(), reason="kernel-enforced confinement needs macOS sandbox-exec"
)


def _request() -> PivotRequest:
    return PivotRequest(
        pivot_type=PivotType.PERSONA_ACTIVITY,
        entity_type=EntityType.PERSONA,
        entity_key="GlassAnvil",
        max_results=10,
        reason="a collector-isolation test needs a real pivot to run",
    )


# --- The flag now selects a runtime behaviour ---------------------------------


def test_exactly_one_connector_declares_hostile_content() -> None:
    hostile = [
        c.capabilities.name for c in simulated_connectors() if requires_isolation(c.capabilities)
    ]
    assert hostile == ["simulated-dark-web"], (
        "if another connector starts handling hostile content, it must be routed through "
        "IsolatedCollector as well — this test is the tripwire"
    )


def test_a_hostile_connector_collects_from_inside_a_child_process() -> None:
    """The boundary must not make the plane useless."""

    async def scenario() -> None:
        collector = IsolatedCollector("nemesis.collect.simulated:dark_web_connector")
        result, confinement, failure = await collector.pivot(_request(), as_of=AS_OF)

        assert failure is None, failure
        assert result is not None and result.succeeded
        assert confinement.separate_process
        assert not confinement.reaches_platform

    asyncio.run(scenario())


def test_the_confined_collector_returns_the_same_evidence_as_the_direct_one() -> None:
    """Isolation must not change what was collected, only where it was parsed."""

    async def scenario() -> None:
        direct = await dark_web_connector(AS_OF).pivot(_request())
        confined, _, failure = await IsolatedCollector(
            "nemesis.collect.simulated:dark_web_connector"
        ).pivot(_request(), as_of=AS_OF)

        assert failure is None
        assert confined is not None
        assert [e.content_hash for e in confined.evidence] == [
            e.content_hash for e in direct.evidence
        ]

    asyncio.run(scenario())


# --- What a compromised collector cannot reach --------------------------------


@pytest.mark.parametrize("module", sorted(FORBIDDEN_PREFIXES))
def test_a_collector_cannot_import_the_platform_it_feeds(module: str) -> None:
    """Including `nemesis.authz` entirely.

    The Effects worker legitimately verifies capabilities and needs the public half. A
    collector has no business with authorization at all, which is why the two workers seal
    different lists through one implementation rather than sharing a list.
    """
    import nemesis

    probe = subprocess.run(  # noqa: S603 - fixed command, no shell
        [
            sys.executable,
            "-s",
            "-c",
            "from nemesis.sandbox.seal import seal_imports\n"
            "from nemesis.collect.worker import FORBIDDEN_PREFIXES\n"
            "seal_imports(FORBIDDEN_PREFIXES, plane='collection')\n"
            "try:\n"
            f"    import {module}\n"
            "    print('IMPORTED')\n"
            "except ImportError as exc:\n"
            "    print('SEALED', 'invariant 8' in str(exc))\n",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(Path(nemesis.__file__).resolve().parent.parent),
        },
    )
    assert "SEALED True" in probe.stdout, probe.stdout + probe.stderr


def test_the_seal_leaves_the_collector_able_to_do_its_job() -> None:
    """A seal that broke collection would be found as an outage, not as a control."""
    import nemesis

    probe = subprocess.run(
        [
            sys.executable,
            "-s",
            "-c",
            "from nemesis.sandbox.seal import seal_imports\n"
            "from nemesis.collect.worker import FORBIDDEN_PREFIXES\n"
            "seal_imports(FORBIDDEN_PREFIXES, plane='collection')\n"
            "import nemesis.collect.simulated, nemesis.core.evidence, nemesis.ports.collection\n"
            "print('OK')\n",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": str(Path(nemesis.__file__).resolve().parent.parent),
        },
    )
    assert probe.stdout.strip() == "OK", probe.stdout + probe.stderr


# --- The policy is the mirror image of the Effects one ------------------------


def test_a_collector_may_keep_the_network_while_effects_may_not() -> None:
    """The reason the policy is a parameter rather than a constant in either plane.

    Effects must not reach outward, so its child is denied a socket. A real collector will
    need one the day it fetches something — and everything else being denied is precisely
    what makes that safe, because there the danger runs inward.
    """
    workdir = Path(tempfile.mkdtemp())
    outward = SandboxPolicy(workdir=workdir, allow_network=False).profile()
    inward = SandboxPolicy(workdir=workdir, allow_network=True).profile()

    assert "(deny network*)" in outward
    assert "(deny network*)" not in inward
    # Denied in both directions regardless: a confined process must not be able to have an
    # unconfined one started on its behalf.
    for profile in (outward, inward):
        assert "com.apple.coreservices.launchservicesd" in profile
        assert "(deny file-write*)" in profile


@needs_sandbox
def test_the_confined_collector_cannot_read_the_workspace_it_feeds(tmp_path: Path) -> None:
    """`import-linter` blocks the import; reading the vault off disk needs no import.

    A collector that has been owned is the outside world sitting inside the platform's own
    process, and the vault, the audit trail and the authorization store are all files.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "vault.jsonl").write_text("sealed evidence")

    profile = SandboxPolicy(workdir=tmp_path / "job", read_denied=(workspace,), allow_network=True)
    (tmp_path / "job").mkdir()

    done = subprocess.run(  # noqa: S603 - fixed command, no shell
        [
            "/usr/bin/sandbox-exec",
            "-p",
            profile.profile(),
            sys.executable,
            "-s",
            "-c",
            f"import pathlib\n"
            f"try:\n"
            f"    print('READ', pathlib.Path({str(workspace / 'vault.jsonl')!r}).read_text())\n"
            f"except OSError as exc:\n"
            f"    print('DENIED', type(exc).__name__)\n",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert "DENIED" in done.stdout, done.stdout + done.stderr
    assert "sealed evidence" not in done.stdout


# --- Failure is returned, never raised ----------------------------------------


def test_a_collector_that_cannot_be_built_is_reported_not_raised() -> None:
    """A collection that died is an event the pursuit engine budgets for, not an exception
    that unwinds an investigation."""

    async def scenario() -> None:
        result, confinement, failure = await IsolatedCollector(
            "nemesis.collect.simulated:no_such_factory"
        ).pivot(_request(), as_of=AS_OF)

        assert result is None
        assert failure is not None and "could not be built" in failure
        assert confinement.separate_process

    asyncio.run(scenario())


def test_a_collector_that_hangs_is_killed_and_reported() -> None:
    """The deadline bounds a collection the way it bounds an effect."""

    async def scenario() -> None:
        collector = IsolatedCollector(
            "nemesis.collect.simulated:dark_web_connector", deadline_seconds=0.5
        )
        original = asyncio.create_subprocess_exec

        # `Any` here is the stdlib's own signature, not laziness: these stand in for
        # `asyncio.create_subprocess_exec`, whose keyword arguments are heterogeneous by
        # design. Narrowing them would mean re-declaring a signature we do not own, and a
        # spy that took a *different* signature from the function it replaces would pass
        # the type checker while failing to be a substitute.
        async def sleeper(*_args: Any, **kwargs: Any) -> Any:
            return await original(
                "/bin/sh",
                "-c",
                "/bin/sleep 60 & exec /bin/sleep 60",
                stdin=kwargs["stdin"],
                stdout=kwargs["stdout"],
                stderr=kwargs["stderr"],
                start_new_session=True,
            )

        asyncio.create_subprocess_exec = sleeper
        try:
            result, _, failure = await collector.pivot(_request(), as_of=AS_OF)
        finally:
            asyncio.create_subprocess_exec = original

        assert result is None
        assert failure is not None and "process group was killed" in failure

    asyncio.run(scenario())


# --- Reads denied by default, not merely by name ------------------------------


@needs_sandbox
def test_a_confined_collector_reads_nothing_but_its_interpreter_and_its_job(
    tmp_path: Path,
) -> None:
    """The blocklist told the collector what *not* to read. This inverts the default.

    It matters most in this plane: collection is hostile by definition, so a parser exploit
    in a downloaded artifact lands in a process that — measured here rather than asserted —
    cannot open the operator's credentials or a workspace it was never handed.

    ADR-0007 recorded a read allowlist as impossible ("aborts CPython on this platform"). It
    was an incomplete enumeration, mis-diagnosed; the amendment on that ADR has the detail.
    The collection plane was then never measured under the fix at all — this is that
    measurement, and it passes unchanged.
    """
    import nemesis

    secret = tmp_path / "credentials"
    secret.write_text("AKIA-NOT-A-REAL-KEY")
    job = tmp_path / "job"
    job.mkdir()
    (job / "input.json").write_text("{}")

    policy = SandboxPolicy(
        workdir=job,
        allow_network=True,
        confine_reads=True,
        read_allowed=(Path(nemesis.__file__).resolve().parent.parent,),
    )
    probe = job / "probe.py"
    probe.write_text(
        "import pathlib, sys\n"
        "for label, target in (('job', sys.argv[1]), ('secret', sys.argv[2])):\n"
        "    try:\n"
        "        pathlib.Path(target).read_bytes(); print('READ', label)\n"
        "    except OSError as exc: print('DENY', label)\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed command, no shell
        [
            "/usr/bin/sandbox-exec",
            "-p",
            policy.profile(),
            sys.executable,
            "-s",
            "probe.py",
            str(job / "input.json"),
            str(secret),
        ],
        cwd=job,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "READ job" in done.stdout, done.stdout + done.stderr[:300]
    assert "DENY secret" in done.stdout, "the confined collector read a file nobody gave it"


def test_the_collector_policy_actually_asks_for_read_confinement() -> None:
    """A flag nobody sets is not a control. Pins that IsolatedCollector turns it on."""
    import inspect

    from nemesis.collect import isolation

    source = inspect.getsource(isolation.IsolatedCollector.pivot)
    assert "confine_reads=True" in source


def test_no_hostile_pivot_runs_in_the_main_process(tmp_path: Path) -> None:
    """THE PIN FOR THE DRIFT THAT ACTUALLY HAPPENED, twice, an hour apart.

    `handles_hostile_content` was a declaration nothing acted on: the flag existed,
    `IsolatedCollector` existed and passed its own tests, and both collection paths called
    `connector.pivot()` directly. A connector announcing it retrieves adversary-controlled
    material parsed that material in the process holding the graph, the vault and the audit
    trail.

    Wiring the pursuit engine did not fix it. A full reference run still put **six** hostile
    pivots in the main process, because `slice/scenario.py` has its own collection path — so
    the decision now lives in one function both call, and this test measures the property
    rather than the wiring. A rule implemented once per call site holds until somebody adds a
    call site; a test that counts holds regardless.

    It asserts through instrumentation rather than by reading the code, because reading the
    code is exactly what said the control was in place while six pivots said otherwise.
    """
    isolated_calls = {"n": 0}
    main_process_calls = {"n": 0}

    original_isolated = IsolatedCollector.pivot
    original_direct = SimulatedConnector.pivot

    async def counting_isolated(self: Any, request: Any, *, as_of: str) -> Any:
        isolated_calls["n"] += 1
        return await original_isolated(self, request, as_of=as_of)

    async def counting_direct(self: Any, request: Any) -> Any:
        if self.capabilities.handles_hostile_content:
            main_process_calls["n"] += 1
        return await original_direct(self, request)

    IsolatedCollector.pivot = counting_isolated  # type: ignore[method-assign]
    SimulatedConnector.pivot = counting_direct  # type: ignore[method-assign]
    try:
        result = run_glass_anvil_scenario(workspace=tmp_path)
    finally:
        IsolatedCollector.pivot = original_isolated  # type: ignore[method-assign]
        SimulatedConnector.pivot = original_direct  # type: ignore[method-assign]

    assert main_process_calls["n"] == 0, (
        f"{main_process_calls['n']} pivots by a connector declaring hostile content ran in "
        "the process that holds the graph, the vault and the audit trail"
    )
    assert isolated_calls["n"] > 0, "no hostile pivot ran at all; this test proved nothing"
    # And the isolation did not quietly cost the run its results.
    assert result.attribute.result is not None
    assert result.resurgence is not None
