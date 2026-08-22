"""The one impure boundary in the pilot plane, and the reason it is not crossed here.

Every seat in this package builds a request, hands it to a transport, and parses what comes
back. The transport is injected and the default refuses, so **no module under
``src/nemesis/pilot`` contains network code** — which is not a stylistic preference. The rule in
this repository is that only the collection plane holds network capability, enforced by
``scripts/check_prohibited.py``, and the pilot plane is where an untrusted model's output
arrives. It is the last place that should also own a socket.

The rule survived its first test: the local (Ollama) seat's first draft imported ``urllib``
directly on the reasoning that localhost is harmless. The scan refused it and was right — "but
this destination is safe" is the argument that turns a control into a habit. The concrete
Ollama transport now lives in the test harness, which also keeps every seat honestly comparable
rather than one being special.

**Where the API key lives, and where it does not.** A transport holds the credential, the
endpoint and whatever headers a vendor wants. Nothing in this package does: a
:class:`~nemesis.pilot.providers.config.PilotConfig` carries the *name* of an environment
variable and never a value, a :class:`~nemesis.pilot.providers.contract.PilotResponseMetadata`
has no field a key could occupy, and a :class:`~nemesis.pilot.providers.errors.PilotError`
carries a bounded detail string. A deployment wiring a transport is the point at which a secret
enters the process, and it is outside this package on purpose.

A transport is expected to raise :class:`~nemesis.pilot.providers.errors.PilotError` for
anything that is not a parsed response body. It may raise anything at all — an adapter
translates whatever it gets into the taxonomy — but a transport that classifies from the
vendor's own error code will classify better than one guessing from a status line.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from nemesis.pilot.model_seat import unwired_error


@runtime_checkable
class PilotTransport(Protocol):
    """Whatever actually carries a request to a model and back.

    One method, taking JSON-shaped data and returning JSON-shaped data. Deliberately not an SDK
    handle: an adapter that held a vendor client could reach whatever else that client exposes,
    and this seam is where a provider's surface is narrowed to "send these bytes, return those".
    """

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnwiredPilotTransport:
    """The default for every seat: it refuses.

    A build with nothing wired contacts nothing, and finds out loudly rather than silently
    behaving as though a model had declined. The mediator contains the raised error as a refused
    move and, repeated, a recorded halt — so an unwired deployment produces a session that
    halted with a reason, not a crash and not a plausible-looking empty investigation.
    """

    def __init__(self, vendor: str, *, transmits_offsite: bool = True) -> None:
        self._vendor = vendor
        self._transmits_offsite = transmits_offsite

    @property
    def vendor(self) -> str:
        return self._vendor

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise unwired_error(self._vendor, transmits_offsite=self._transmits_offsite)


__all__ = ["PilotTransport", "UnwiredPilotTransport"]
