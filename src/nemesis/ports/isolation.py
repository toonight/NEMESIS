"""Running an effect somewhere it can do less harm.

Invariant 8 says the Effects plane holds no ambient authority. Until now that was enforced
by `import-linter` contracts — a *static* boundary, which stops the code in this repository
from reaching the graph, the vault or the signing key, and stops nothing at runtime. Four
adversarial reviews said the same thing in their residual-risk sections: an attacker with
code execution inside the process defeats every control, and process isolation is
``PROPOSED``.

This port is where that stops being a plan. An :class:`EffectsExecutor` runs one operation
and returns its result; the isolating implementation runs it in a child process that holds
no private key, cannot import the intelligence planes, cannot open a socket, cannot write
outside one directory, and cannot outlive its deadline.

The important type here is :class:`IsolationReport`. It records **what was actually
enforced for this run**, not what the design intends, because those differ by platform and
a control that silently degraded is worse than one that was never claimed.

Read the field docstrings rather than the field names. An adversarial review found that the
first version of this type asserted four controls for a run in which no process was ever
started, and named a property ``external_contact_is_established`` for a denial that applies
to one process rather than to the system. Both are corrected here, and the corrections are
the reason to trust the rest: this type is only useful if it is the thing that refuses to
round up.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from nemesis.core.authorization import AuthorizationCapability, OperationClass
from nemesis.ports.effects import EffectRequest, EffectResult


class IsolationReport(BaseModel):
    """What confinement this particular run actually got.

    Attached to every result an isolating executor returns, and written into the audit
    trail. An operator six months later must be able to tell whether "no external contact"
    was *enforced by the kernel* or *reported by the code that would have made it*.
    """

    model_config = ConfigDict(frozen=True)

    mechanism: str
    """How the effect ran: ``sandbox-exec`` (macOS profile), ``subprocess`` (a child process
    with no sandbox profile available), or ``none`` (no child was started)."""

    separate_process: bool
    """A child process was actually started. Derived from the process existing, not from the
    executor intending to start one — a review reached the report-building line with
    ``create_subprocess_exec`` raising, and got four asserted controls for a run in which
    nothing was ever created."""

    network_denied: bool
    """The kernel refused **this process** a socket.

    Deliberately narrow, and the narrowness is the finding. `(allow default)` permits
    ``mach-lookup``, so a confined child could ask LaunchServices to start a process that
    ``launchd`` owns — inheriting none of the confinement. Named services are now denied, but
    "this process cannot open a socket" is what the kernel establishes and "nothing could
    have left the system" is a stronger claim that no rule here proves."""

    filesystem_confined_to: str | None = None
    """The only directory the child could write to, resolved. ``mkdtemp`` returns a path
    under ``/var`` that the kernel resolves under ``/private/var``, and an unresolved rule
    matched nothing at all — failing closed, and printing a directory the child could not
    use."""

    private_key_withheld: bool = True
    """No signing key crossed the boundary. Structural: the child is handed a public
    verifying key and nothing else, so it cannot mint a capability from what it was given."""

    imports_sealed_by_worker: bool = False
    """The child confirmed it installed its import seal, in its own output.

    **Defence in depth, not a boundary.** The seal is a finder in a mutable list: hostile
    code inside the worker removes it from ``sys.meta_path``, or loads a module by file path
    with ``spec_from_file_location``, or simply ``exec``s the source. A review did all three.
    It stops the accidental import and the careless refactor, which is worth having and is
    not the same as stopping an attacker."""

    contact_claimed_by_worker: bool = False
    """The child's own account of whether it reached outside.

    Kept beside :attr:`network_denied` rather than reconciled with it. An earlier version
    rewrote a worker's ``True`` to ``False`` whenever the sandbox was on, which discarded the
    single most interesting thing a compromised worker could ever say."""

    address_space_bytes: int | None = None
    cpu_seconds: int | None = None
    file_size_bytes: int | None = None
    """Ceilings the child reported applying, accepted only if no weaker than what was asked.

    ``file_size_bytes`` is ``RLIMIT_FSIZE`` and governs *files*. It does not bound what the
    child writes to a pipe — 64 MiB went through a 16 MiB "output ceiling" before this was
    named honestly."""

    deadline_seconds: float | None = None

    @property
    def egress_denied_from_this_process(self) -> bool:
        """The kernel refused a socket to the process that ran the effect.

        Named for exactly what it is. It was called ``external_contact_is_established`` and
        read as "nothing left the system", which is not what a socket denial on one process
        establishes while that process can ask another process to be started.
        """
        return self.separate_process and self.network_denied

    def render(self) -> str:
        controls = [f"mechanism={self.mechanism}"]
        controls.append(f"network={'denied' if self.network_denied else 'NOT DENIED'}")
        if self.filesystem_confined_to:
            controls.append(f"writes={self.filesystem_confined_to}")
        if self.deadline_seconds:
            controls.append(f"deadline={self.deadline_seconds:g}s")
        if self.contact_claimed_by_worker:
            controls.append("WORKER CLAIMS IT MADE CONTACT")
        return "; ".join(controls)


@runtime_checkable
class EffectsExecutor(Protocol):
    """Performs one authorized operation, wherever it is safe to perform it.

    Deliberately narrow: one call, one operation, no session. An executor that could be
    handed a batch, or that kept a worker warm between operations, would rebuild the
    standing authority invariant 8 removes.
    """

    async def perform(
        self,
        request: EffectRequest,
        capability: AuthorizationCapability,
        *,
        operation: OperationClass,
    ) -> tuple[EffectResult, IsolationReport]:
        """Run it, and say what confinement it ran under.

        Must return a result rather than raise, for every failure including a child that
        crashed, hung or returned nonsense. An operation whose outcome nobody recorded is
        the failure mode the audit trail exists to prevent.
        """
        ...
