"""The simulation adapter: the whole authorization path, with the effect removed.

A simulation is not a placeholder for a real adapter. It is the only operation class in
the MVP whose *purpose* is to be exercised end to end, and it earns its place by running
every check a consequential adapter would run — capability, target binding, stop
conditions — and then declining to do the one thing that would matter. If the rehearsal
skipped the checks, it would rehearse nothing.

Two properties are load-bearing:

**It rehearses a class it is not authorized to perform.** The caller may name
``registrar_suspension`` as the operation being rehearsed. That is safe precisely because
the rehearsed class is a string in a document and never reaches a lookup: the capability
is evaluated against :data:`~nemesis.core.authorization.OperationClass.SIMULATION`, which
is the only class this adapter can perform. Letting the parameter select the operation
would turn a rehearsal into an escalation primitive.

**It reports what it did not do.** A simulation whose record is indistinguishable from a
real operation's is a trap for whoever reads the audit trail six months later, so every
result this adapter produces says ``SIMULATED`` and names the steps that were skipped.
"""

from __future__ import annotations

from typing import Final

from nemesis.core.authorization import (
    AuthorizationCapability,
    AuthorizationDecision,
    OperationClass,
)
from nemesis.core.temporal import utcnow
from nemesis.effects.registry import preflight, sanitize
from nemesis.ports.authorization import TrustAnchor
from nemesis.ports.effects import EffectOutcome, EffectRequest, EffectResult

ADAPTER_NAME: Final = "simulation-effects-adapter"

SIMULATED_LABEL: Final = "SIMULATED"
"""The boundary label from CLAUDE.md. Present in every result this adapter returns."""

REHEARSED_OPERATION_PARAMETER: Final = "rehearsed_operation"
"""Which operation class the caller is rehearsing. Documentation only — see the module
docstring for why this string is never used to select behaviour."""

RECIPIENT_PARAMETER: Final = "recipient"

_UNSPECIFIED: Final = "<unspecified>"


class SimulationEffectsAdapter:
    """Executes nothing, verifies everything.

    Holds no state: the class carries three constants and the coroutine keeps nothing
    between calls. An adapter that remembered an earlier authorization would have rebuilt
    the standing authority invariant 8 removes — the second call would ride on the first
    call's approval.
    """

    name: str = ADAPTER_NAME
    operation: OperationClass = OperationClass.SIMULATION
    makes_external_contact: bool = False

    def __init__(self, anchor: TrustAnchor) -> None:
        """The authorizer this adapter believes, fixed at construction.

        Required and positional: an adapter with no anchor could verify nothing, and one
        that took the anchor per call would believe whoever called it.
        """
        self._anchor = anchor

    @property
    def anchor(self) -> TrustAnchor:
        """Exposed so the registry can refuse an adapter wired to a different authorizer."""
        return self._anchor

    async def execute(
        self, request: EffectRequest, capability: AuthorizationCapability
    ) -> EffectResult:
        check = preflight(
            request,
            capability,
            operation=OperationClass.SIMULATION,
            anchor=self._anchor,
        )
        if check.refusal is not None:
            return self._record(
                request, outcome=check.refusal, decision=check.decision, detail=check.detail
            )

        # The reconstruction, not the object handed in: a rehearsal record that quoted the
        # caller's copy of the grant would misreport what was authorized, and a record that
        # misreports is worse than no record.
        assert check.granted is not None
        granted = check.granted

        rehearsed = sanitize(
            request.parameters.get(REHEARSED_OPERATION_PARAMETER, _UNSPECIFIED), limit=80
        )
        recipient = sanitize(request.parameters.get(RECIPIENT_PARAMETER, _UNSPECIFIED), limit=120)
        target = sanitize(request.target_natural_key, limit=120)

        skipped = "; ".join(
            (
                f"resolve {target} — not performed, this plane makes no lookup",
                f"contact {recipient} — not performed, this plane has no network reach",
                "confirm the effect took hold — not performed, nothing was attempted",
            )
        )
        return self._record(
            request,
            outcome=EffectOutcome.SIMULATED,
            decision=check.decision,
            detail=(
                f"{SIMULATED_LABEL}: rehearsed {rehearsed} against {target} under "
                f"{granted.capability_id}. Nothing left NEMESIS. Steps not performed: "
                f"{skipped}."
            ),
        )

    def _record(
        self,
        request: EffectRequest,
        *,
        outcome: EffectOutcome,
        decision: AuthorizationDecision,
        detail: str,
    ) -> EffectResult:
        """Build the audit record, refusal or not.

        ``operation`` is the class the *request* named rather than the one this adapter
        performs, so a request misrouted to the wrong adapter is recorded under the class
        its author asked for. Reading the trail must show what was attempted, not what the
        code happened to accept.

        ``external_contact_made`` is a literal here and nowhere else. There is no branch,
        no parameter and no capability field that can raise it.
        """
        return EffectResult(
            operation_id=request.operation_id,
            operation=request.operation,
            outcome=outcome,
            executed_at=utcnow(),
            adapter_name=self.name,
            authorization=decision,
            detail=detail,
            external_contact_made=False,
        )
