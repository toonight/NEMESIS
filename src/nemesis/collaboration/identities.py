"""Which NEMESIS actor a channel message came from, and what that does not mean.

A collaboration backend gives every participant a keypair, and a message signed by that
keypair is attributable. That is genuinely useful: a reader scrolling a channel can tell
the pilot's hypothesis from the analyst's judgement from the scheduler's notice, and an
auditor can tell them apart six months later. This module is the mapping that makes it
readable — NEMESIS actor id on one side, backend public reference on the other.

**A binding is a label, not a grant.** There is no field in :class:`RegisteredActor` that
grants anything, and there is no method that consults one before allowing anything. The
registry cannot be used as an access-control list because nothing asks it a yes/no
question. Authorization runs on :class:`~nemesis.core.identity.Principal` and
:class:`~nemesis.core.authorization.AuthorizationCapability`, both of which live in planes
this module cannot import.

The direction of the lookup matters and is deliberately restricted.
:meth:`ActorRegistry.backend_reference_for` answers "how does this NEMESIS actor sign?" —
safe, because the answer is used to publish.
:meth:`ActorRegistry.actor_for_backend` answers "which NEMESIS actor does this key claim to
be?" and returns ``None`` for anything unregistered, because the interesting case is a
message from a key nobody enrolled, and the honest answer there is "I do not know who that
is" rather than a plausible guess.

**On the agent roster this module does not contain.** The brief this design answers proposes
around ten named agent identities — triage, intel, malware, infrastructure, attribution,
evidence, legal, disruption, supervisor. NEMESIS does not have them and this module does not
invent them. The architecture is deliberately the other shape: there is exactly **one** seat
for a model, the pilot's (ADR-0008), and every other component is deterministic Python, not
an agent. Enrolling nine identities that no code drives would put nine names in a channel
that never speak, and a reader would reasonably conclude a multi-agent system was running.
:data:`STANDING_ACTORS` therefore lists the actors that exist, and adding one is a
consequence of building the component, never a way of announcing it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from types import MappingProxyType
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from nemesis.collaboration.base import ActorBinding
from nemesis.core.identity import ActorKind
from nemesis.core.ids import IdPrefix


class DuplicateBindingError(ValueError):
    """One backend reference was claimed by two NEMESIS actors, or the reverse.

    A hard error rather than a last-writer-wins update. Two actors publishing under one key
    makes the channel's attribution meaningless, and one actor holding two keys makes a
    reader see two participants where there is one — the same failure the audit trail
    refuses when it rejects two names for one person.
    """


class RegisteredActor(BaseModel):
    """A NEMESIS actor that may appear in a channel.

    :attr:`declared_capabilities` and :attr:`data_scopes` are prose for humans and for the
    ``kind:0``-style profile a backend publishes. They are documentation of what a component
    does; they are not consulted by any check, and calling them permissions would be the
    exact confusion this design exists to prevent. What a component may actually do is
    decided by the import graph, by the closed move vocabulary in
    :mod:`nemesis.pilot.moves`, and by the capability the effects plane verifies.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    actor_id: Annotated[str, Field(min_length=1, max_length=200)]
    actor_kind: ActorKind
    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    purpose: Annotated[str, Field(min_length=1, max_length=500)]
    declared_capabilities: tuple[str, ...] = ()
    data_scopes: tuple[str, ...] = ()
    model_identifier: str | None = None
    """Set only for an actor that is a model, and then it names the model. ``None`` for
    every deterministic component — the field exists so a reader can tell which messages in
    a channel a model wrote, which is the first thing anyone wants to know."""


def platform_actor_id(component: str) -> str:
    """A stable actor id for a named platform component.

    Derived rather than minted, for the reason
    :func:`~nemesis.collect.base.connector_actor_id` gives: a component that received a
    fresh identifier on every construction would appear in a channel as a new participant
    on every restart, and an auditor correlating a week of messages would see a crowd.
    """
    digest = hashlib.sha256(f"platform:{component}".encode()).hexdigest()
    return f"{IdPrefix.ACTOR.value}_{digest[:32]}"


STANDING_ACTORS: Mapping[str, RegisteredActor] = MappingProxyType(
    {
        actor.actor_id: actor
        for actor in (
            RegisteredActor(
                actor_id=platform_actor_id("pursuit-scheduler"),
                actor_kind=ActorKind.RULE,
                display_name="nemesis-pursuit",
                purpose=(
                    "Chooses the next pivot by deterministic rule policy and records what it "
                    "collected. Replayable: the same state yields the same decisions."
                ),
                declared_capabilities=("select_pivot", "execute_pivot", "record_claim"),
                data_scopes=("investigation graph", "claim store"),
            ),
            RegisteredActor(
                actor_id=platform_actor_id("pilot-seat"),
                actor_kind=ActorKind.AGENT,
                display_name="nemesis-pilot",
                purpose=(
                    "The single seat an external, untrusted frontier model drives. Proposes "
                    "moves from a closed four-verb vocabulary; every move is validated by the "
                    "mediator and may be refused."
                ),
                declared_capabilities=(
                    "run_pivot",
                    "record_belief",
                    "request_effect",
                    "conclude",
                ),
                data_scopes=("briefing projection only",),
                model_identifier="configured per deployment",
            ),
            RegisteredActor(
                actor_id=platform_actor_id("authorization-gateway"),
                actor_kind=ActorKind.SYSTEM,
                display_name="nemesis-authorization",
                purpose=(
                    "Raises approval requests, records human decisions and mints the signed "
                    "capability. The only component that can turn a decision into authority."
                ),
                declared_capabilities=("request_approval", "record_decision", "issue", "revoke"),
                data_scopes=("authorization store",),
            ),
            RegisteredActor(
                actor_id=platform_actor_id("resurgence-watcher"),
                actor_kind=ActorKind.RULE,
                display_name="nemesis-resurgence",
                purpose=(
                    "Watches for the reappearance of disrupted infrastructure. A takedown "
                    "closes no case (invariant 14)."
                ),
                declared_capabilities=("monitor", "reopen_investigation"),
                data_scopes=("investigation graph",),
            ),
        )
    }
)
"""The actors that exist and can speak. Four, not ten, and the docstring above says why."""


class ActorRegistry:
    """Bindings between NEMESIS actors and their presence on one backend.

    In-memory and per-provider. Not persisted, because a binding is cheap to re-establish
    and a stale one on disk is worse than none: it would attribute a channel message to an
    actor whose key was rotated.
    """

    def __init__(self, provider: str) -> None:
        self._provider = provider
        self._by_actor: dict[str, ActorBinding] = {}
        self._by_backend: dict[str, str] = {}

    @property
    def provider(self) -> str:
        return self._provider

    def enrol(self, actor: RegisteredActor, backend_reference: str) -> ActorBinding:
        """Bind a registered actor to a backend reference. Idempotent when unchanged."""
        if not backend_reference:
            raise ValueError("backend_reference must not be empty")

        existing = self._by_actor.get(actor.actor_id)
        if existing is not None and existing.backend_reference == backend_reference:
            return existing
        if existing is not None:
            raise DuplicateBindingError(
                f"actor {actor.display_name!r} is already bound to "
                f"{existing.backend_reference!r}; rebinding would make a week of channel "
                "history read as two participants who are one"
            )

        claimant = self._by_backend.get(backend_reference)
        if claimant is not None and claimant != actor.actor_id:
            raise DuplicateBindingError(
                f"backend reference {backend_reference!r} is already bound to another actor; "
                "two actors publishing under one key makes attribution meaningless"
            )

        binding = ActorBinding(
            actor_id=actor.actor_id,
            actor_kind=actor.actor_kind,
            display_name=actor.display_name,
            provider=self._provider,
            backend_reference=backend_reference,
            role_description=actor.purpose,
        )
        self._by_actor[actor.actor_id] = binding
        self._by_backend[backend_reference] = actor.actor_id
        return binding

    def backend_reference_for(self, actor_id: str) -> str | None:
        binding = self._by_actor.get(actor_id)
        return binding.backend_reference if binding is not None else None

    def actor_for_backend(self, backend_reference: str) -> str | None:
        """Which NEMESIS actor a backend key was enrolled as, or ``None``.

        ``None`` is the important answer, not a fallback. A message from an unenrolled key
        is a message from someone this deployment has not accounted for, and naming them
        "unknown" in a way that reads like an actor would hide exactly that.
        """
        return self._by_backend.get(backend_reference)

    def bindings(self) -> Iterator[ActorBinding]:
        yield from self._by_actor.values()

    def __len__(self) -> int:
        return len(self._by_actor)


__all__ = [
    "STANDING_ACTORS",
    "ActorRegistry",
    "DuplicateBindingError",
    "RegisteredActor",
    "platform_actor_id",
]
