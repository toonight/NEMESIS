"""Making `handles_hostile_content` mean something at runtime.

The flag has existed since the collection plane was written, and
:class:`~nemesis.collect.base.SimulatedConnector` refuses to construct a hostile-content
connector that does not *declare* a sandbox profile. Declaring one and running in one are
different things, and until now nothing checked the second: the threat model has carried
"opening a malicious document today would happen in the main process" as an open gap, and
the founder's own priority list named "process isolation for Effects **and hostile
collectors**". Effects was done in ADR-0007. This is the other half.

**The direction of danger is reversed here, and the policy follows.** Effects is the plane
that could touch the world, so its child is denied a socket and everything it produces is a
document. Collection is the plane the world touches: it is hostile by definition, it will
need the network the day a connector fetches something real, and the risk runs *inward* — a
parser exploit in a downloaded artifact must not become reach into the graph, the vault or
the signing key. So the confined collector may keep its network and is denied everything
else, which is the mirror image of the Effects profile and the reason the policy is a
parameter of :mod:`nemesis.sandbox.process` rather than a constant inside either plane.

**What this is honest about.** The default registry and every repository test still read
fixtures, but one opt-in Tor connector can now fetch real hostile bytes. That transition makes
the old non-macOS fallback unacceptable: a non-simulated hostile connector requires kernel
confinement and refuses to run where this package cannot supply it. The connector itself parses
no page content; a deployment adding a parser still needs the confined analyser the quarantine
contract calls for.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from nemesis.collect.wire import decode_result
from nemesis.ports.collection import (
    ConnectorCapabilities,
    IntelligenceConnector,
    PivotRequest,
    PivotResult,
)
from nemesis.sandbox.process import SandboxPolicy, run_confined, sandbox_available

WORKER_MODULE: Final = "nemesis.collect.worker"
DEFAULT_DEADLINE_SECONDS: Final = 60.0


@dataclass(frozen=True)
class CollectionConfinement:
    """What confinement one collection actually ran under.

    Reported rather than assumed, for the same reason
    :class:`~nemesis.ports.isolation.IsolationReport` exists: a control that silently
    degraded into a sentence in a document is the failure this whole exercise is against.
    """

    mechanism: str
    separate_process: bool
    reaches_platform: bool
    """Whether the collector could reach the graph, the vault or the signing key.

    False when it ran confined. This is the property that matters for collection: the flag
    on the connector says the *content* is hostile, and this says what happened to be true
    of the process that touched it."""

    network_allowed: bool
    workspace_denied: tuple[str, ...] = ()

    def render(self) -> str:
        return (
            f"mechanism={self.mechanism}; platform="
            f"{'unreachable' if not self.reaches_platform else 'REACHABLE'}; "
            f"network={'allowed' if self.network_allowed else 'denied'}"
        )


def _record_confinement(result: PivotResult, confinement: CollectionConfinement) -> PivotResult:
    """Attach what the parent observed, never what the child claimed about itself."""
    evidence = tuple(
        item.model_copy(
            update={
                "provenance": item.provenance.model_copy(
                    update={
                        "method": item.provenance.method.model_copy(
                            update={"sandbox_profile": confinement.render()}
                        )
                    }
                )
            }
        )
        for item in result.evidence
    )
    return result.model_copy(update={"evidence": evidence})


class IsolatedCollector:
    """Runs one connector's pivot in a child process that cannot reach this one.

    One process per pivot, deliberately. A warm worker would accumulate state across
    collections, and the first thing a compromised parser would do with that is wait for the
    next call — the same reasoning that gives the Effects plane one process per operation.
    """

    def __init__(
        self,
        connector_factory: str,
        *,
        connector_config: Mapping[str, str] | None = None,
        deny_reads: tuple[Path, ...] = (),
        allow_network: bool = False,
        require_kernel_confinement: bool = False,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    ) -> None:
        """``connector_factory`` is an importable ``module:function`` the child calls.

        A name rather than an object, because the object cannot cross a process boundary and
        pickling one would hand the child a deserialization surface — which is precisely the
        class of bug this boundary exists to contain.
        """
        self._factory = connector_factory
        self._connector_config = dict(connector_config or {})
        self._deny_reads = deny_reads
        self._allow_network = allow_network
        self._require_kernel_confinement = require_kernel_confinement
        self._deadline = deadline_seconds

    async def pivot(
        self, request: PivotRequest, *, as_of: str
    ) -> tuple[PivotResult | None, CollectionConfinement, str | None]:
        """Collect, confined. Returns ``(result, confinement, failure)``.

        A failure is returned rather than raised: a collection that died is an event the
        pursuit engine has to record and budget for, not an exception that unwinds an
        investigation.
        """
        import sys

        import nemesis

        workdir = Path(tempfile.mkdtemp(prefix="nemesis-collect-"))
        policy = SandboxPolicy(
            workdir=workdir,
            allow_network=self._allow_network,
            read_denied=self._deny_reads,
            # Reads denied by default, not merely by name. Measured on 2026-08-17: the
            # collection plane runs unchanged under it, so the blocklist was never the
            # constraint here — it was simply the thing nobody had tried to replace. The
            # worker is this package and must import it; everything else on the machine is
            # denied, which matters most in the one plane whose content is hostile by
            # definition.
            confine_reads=True,
            read_allowed=(Path(nemesis.__file__).resolve().parent.parent,),
            environment={
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(Path(nemesis.__file__).resolve().parent.parent),
            },
        )
        envelope = json.dumps(
            {
                "factory": self._factory,
                "request": request.model_dump(mode="json"),
                "as_of": as_of,
                "config": self._connector_config,
            }
        ).encode()

        run = await run_confined(
            [sys.executable, "-s", "-m", WORKER_MODULE],
            stdin=envelope,
            policy=policy,
            deadline_seconds=self._deadline,
            allow_unsandboxed=not self._require_kernel_confinement,
        )
        confinement = CollectionConfinement(
            mechanism=run.mechanism,
            separate_process=run.started,
            # The whole point. Confined, the collector holds no handle to this process's
            # objects and cannot import its way to one; unconfined, it is ordinary code in
            # the main process and this says so rather than implying otherwise.
            reaches_platform=not (run.started and run.mechanism == "sandbox-exec"),
            network_allowed=self._allow_network,
            workspace_denied=tuple(str(p) for p in self._deny_reads),
        )

        if not run.ok:
            return None, confinement, run.failure

        try:
            payload = json.loads(run.stdout or b"{}")
            if "error" in payload:
                return None, confinement, str(payload["error"])
            # Re-validated in this process. Everything crossing that pipe is untrusted data,
            # which is invariant 5 applied to our own worker rather than only to the outside
            # world — a collector that has been owned is exactly the outside world.
            return (
                _record_confinement(decode_result(payload["result"]), confinement),
                confinement,
                None,
            )
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            tail = run.stderr.decode(errors="replace").strip().splitlines()[-1:] or ["no stderr"]
            return (
                None,
                confinement,
                f"the collector returned nothing usable ({type(exc).__name__}: {exc}); "
                f"last stderr line: {tail[0][:200]}",
            )


def requires_isolation(capabilities: ConnectorCapabilities) -> bool:
    """Whether this connector must not run in the main process.

    The single place that reads the flag for this purpose, so "declared hostile" and "run
    confined" cannot drift apart the way they had.
    """
    return capabilities.handles_hostile_content


__all__ = [
    "CollectionConfinement",
    "IsolatedCollector",
    "collect_confined",
    "requires_isolation",
    "sandbox_available",
]


async def collect_confined(
    connector: IntelligenceConnector, request: PivotRequest
) -> tuple[PivotResult | None, str | None]:
    """Run a pivot, in a child process when the connector declares hostile content.

    **The single place that decides.** `handles_hostile_content` was a declaration nothing
    acted on: the flag existed, :class:`IsolatedCollector` existed and was tested, and both
    collection paths called `connector.pivot()` directly — so a connector announcing that it
    retrieves adversary-controlled material parsed that material in the process holding the
    graph, the vault and the audit trail.

    It is one function because there turned out to be **two** collection paths — the pursuit
    engine's and the reference scenario's — and wiring the first left the second running
    hostile pivots in the main process, measured six times in a single `nemesis demo`. A rule
    implemented once per call site is a rule that holds until somebody adds a call site.

    **Fail-closed on a missing factory.** A child cannot be handed an object — pickling one
    would give it a deserialization surface, the bug class this boundary exists to remove — so
    isolation needs an importable ``module:function``. A connector declaring hostile content
    without one cannot be isolated, and the honest outcome is a refused pivot naming why,
    never a quiet fall back to running it here. "We could not look" is a finding; running it
    unconfined would be a finding nobody wrote down.
    """
    capabilities = connector.capabilities
    if not requires_isolation(capabilities):
        return await connector.pivot(request), None

    if capabilities.isolation_factory is None:
        return None, (
            f"{capabilities.name} declares handles_hostile_content and names no "
            "isolation_factory, so it cannot run in a child process. Refused rather than run "
            "here: this connector retrieves adversary-controlled material, and the main "
            "process holds the graph, the vault and the audit trail."
        )

    isolated = IsolatedCollector(
        connector_factory=capabilities.isolation_factory,
        connector_config=capabilities.isolation_config,
        allow_network=not capabilities.is_simulated,
        # A fixture contains bytes we wrote. A real dark-web response contains bytes an
        # adversary wrote, and process separation alone does not stop filesystem reads or
        # imports by path. The first real connector turns the old Linux limitation into a
        # live boundary, so it fails closed where no kernel policy is available.
        require_kernel_confinement=not capabilities.is_simulated,
    )
    # The connector's own `as_of`, never a caller's guess. The first version took it as an
    # argument and the scenario passed a constant, which flattened the phase-2 / phase-8 split
    # the reference run depends on: resurgence stopped finding the key it exists to re-link.
    # A confined connector must be reconstructed as the instance it replaces, and the instant
    # it answers as is part of that instance.
    as_of = getattr(connector, "as_of", None)
    if as_of is None:
        return None, (
            f"{capabilities.name} declares hostile content but exposes no `as_of`, so a child "
            "cannot be reconstructed as the connector it replaces. Refused rather than run "
            "against an instant nobody chose."
        )
    result, _confinement, failure = await isolated.pivot(request, as_of=as_of.isoformat())
    if failure is not None:
        return None, f"confined collection failed: {failure}"
    return result, None
