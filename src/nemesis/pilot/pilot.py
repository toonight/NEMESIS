"""The seat a frontier model sits in.

An :class:`AutonomousPilot` is handed a :class:`~nemesis.pilot.moves.Briefing` and returns a
move. That is the entire contract, and its narrowness is the point: the pilot receives data
and returns data, and holds no reference to the engine, the graph, the vault, the signing key
or the capability. A production implementation wraps a call to GPT-5/6 (or "Atlas"); a test
implementation is a scripted list of moves; an adversarial test implementation is a pilot
that has been told to cross a limit. The mediator cannot tell them apart, and does not need
to — it validates and rules on the move, never on the pilot's intent.

No such production implementation ships here, and that is deliberate. Wiring a real model is
a `SIMULATED`-to-`IMPLEMENTED` step that needs an API credential, an egress path and a prompt,
none of which belong in a repository whose MVP contacts nothing. What ships is the seat and
the proof that whoever sits in it cannot leave the track — which is the part that had to exist
before a real pilot could be trusted to drive.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from nemesis.pilot.moves import Briefing, PilotMove


@runtime_checkable
class AutonomousPilot(Protocol):
    """Whatever drives NEMESIS: a model, a script, or an attacker's puppet.

    ``propose`` may return a fully-built :class:`PilotMove` or a raw mapping — a real model
    returns JSON, and the mediator validates either through the same adapter, so an
    implementation cannot smuggle an unvalidated object past the seam by constructing it
    itself.
    """

    @property
    def name(self) -> str:
        """Identifies the pilot in the audit trail and names the model on any belief it
        records. A claim a pilot asserts must say which pilot asserted it."""
        ...

    async def propose(self, briefing: Briefing) -> PilotMove | Mapping[str, Any]:
        """Choose the next move from the briefing. Returning anything that is not a valid
        move is itself a (refused) move, not an error the mediator has to guard against."""
        ...


__all__ = ["AutonomousPilot"]
