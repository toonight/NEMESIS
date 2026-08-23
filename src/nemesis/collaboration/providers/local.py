"""The provider that ships enabled: a channel on the local filesystem, and no network.

This is the default, and it is not a stub. A deployment that never configures a
collaboration backend still gets everything the collaboration plane is for — projected
events with their epistemic standing intact, approval notices carrying a proposal digest,
inbound decision intents read from replies, and a durable record of all of it. It simply
happens in a directory instead of in a chat room.

Two reasons that is the right default rather than a placeholder:

**It makes "NEMESIS works without Buzz" testable instead of asserted.** The whole
integration test suite runs against this provider. If the abstraction ever leaks — if some
caller starts depending on a relay-shaped behaviour — the local provider stops satisfying
it and a test goes red, which is a much earlier signal than discovering it during an
outage.

**It is the honest offline mode.** The brief asks for a simulation execution mode and a dry
run. Rather than a flag on the remote provider that somebody can forget to set, the
simulation is a *different object*, and the remote one has no way to be run in a mode where
it does not reach the network — because it has no network implementation at all. A mode you
cannot accidentally leave is stronger than a mode you have to remember to enter.

Storage is one JSONL file per channel plus one for inbound signals. Append-only, and
deliberately not hash-chained: this is a mirror of what was published, not the record of
what happened. The record is the audit trail, which is chained, and duplicating that
property here would invite someone to treat the mirror as evidence.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Final

from nemesis.collaboration.base import (
    ActorBinding,
    ChannelDescriptor,
    ChannelHandle,
    InboundSignal,
    PublicationReceipt,
    PublicationStatus,
)
from nemesis.collaboration.events import CollaborationEvent
from nemesis.core.temporal import require_utc, utcnow

PROVIDER_NAME: Final = "local"

_SAFE_KEY: Final = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class LocalCollaborationProvider:
    """A :class:`~nemesis.collaboration.base.CollaborationProvider` backed by a directory.

    Reaches no network, holds no credential, and has no configuration that could give it
    either. ``import-linter`` and ``scripts/check_prohibited.py`` both enforce that no
    module in this plane imports a network client; this class needs neither exception.
    """

    def __init__(self, root: Path | str, *, clock: object = None) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._channels_root = self._root / "channels"
        self._channels_root.mkdir(exist_ok=True)
        self._inbox_root = self._root / "inbox"
        self._inbox_root.mkdir(exist_ok=True)
        self._bindings: dict[str, ActorBinding] = {}
        self._lock = threading.Lock()
        self._clock = clock

    @property
    def name(self) -> str:
        return PROVIDER_NAME

    @property
    def root(self) -> Path:
        return self._root

    async def open_channel(self, descriptor: ChannelDescriptor) -> ChannelHandle:
        path = self._channel_path(descriptor.key)
        with self._lock:
            created = not path.exists()
            if created:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                metadata = path.with_suffix(".meta.json")
                metadata.write_text(
                    json.dumps(descriptor.model_dump(mode="json"), indent=2, sort_keys=True),
                    encoding="utf-8",
                )
        return ChannelHandle(
            key=descriptor.key,
            provider=PROVIDER_NAME,
            backend_id=str(path),
            created=created,
        )

    async def publish(
        self, channel: ChannelHandle, event: CollaborationEvent
    ) -> PublicationReceipt:
        path = Path(channel.backend_id)
        if not path.exists():
            return PublicationReceipt(
                event_id=event.event_id,
                provider=PROVIDER_NAME,
                status=PublicationStatus.REFUSED_REJECTED,
                detail=(
                    f"channel {channel.key!r} does not exist at {path}; open it before "
                    "publishing rather than creating it as a side effect of a write"
                ),
            )

        line = json.dumps(
            {
                "event_id": event.event_id,
                "integrity_hash": event.integrity_hash(),
                "event": event.model_dump(mode="json"),
            },
            separators=(",", ":"),
            ensure_ascii=False,
            sort_keys=True,
        )

        with self._lock:
            if self._holds(path, event.event_id):
                return PublicationReceipt(
                    event_id=event.event_id,
                    provider=PROVIDER_NAME,
                    status=PublicationStatus.DUPLICATE,
                    detail="already published; the content-addressed id matched an existing entry",
                    backend_reference=event.event_id,
                )
            try:
                offset = _append(path, line)
            except OSError as exc:
                return PublicationReceipt(
                    event_id=event.event_id,
                    provider=PROVIDER_NAME,
                    status=PublicationStatus.FAILED,
                    detail=f"could not write {path}: {exc}",
                )

        return PublicationReceipt(
            event_id=event.event_id,
            provider=PROVIDER_NAME,
            status=PublicationStatus.PUBLISHED,
            backend_reference=f"{path.name}#{offset}",
            published_at=self._now(),
        )

    async def poll(
        self, channel: ChannelHandle, *, since: datetime | None = None, limit: int = 100
    ) -> Sequence[InboundSignal]:
        if since is not None:
            require_utc(since, "since")
        path = self._inbox_path(channel.key)
        if not path.exists():
            return ()

        signals: list[InboundSignal] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                signal = InboundSignal.model_validate_json(stripped)
                if since is not None and signal.received_at <= since:
                    continue
                signals.append(signal)
        signals.sort(key=lambda signal: signal.received_at)
        return tuple(signals[:limit])

    async def bind_actor(self, binding: ActorBinding) -> ActorBinding:
        recorded = binding.model_copy(update={"provider": PROVIDER_NAME})
        with self._lock:
            self._bindings[recorded.actor_id] = recorded
        return recorded

    async def health(self) -> bool:
        return self._root.is_dir()

    # --- test and demonstration affordances ---------------------------------------
    #
    # Deliver a signal *into* the local channel. Present because the local provider is the
    # only one that can be driven end to end in CI, and an approval flow that cannot be
    # exercised without a relay is an approval flow nobody exercises. Named to be
    # unmistakable: nothing in `src/` outside a demonstration calls it, and it is the local
    # analogue of a human typing in a chat window, not a way for the platform to author
    # inbound signals it will then read as human input.

    def deliver_inbound(self, channel_key: str, signal: InboundSignal) -> InboundSignal:
        """Record a signal as though a human had sent it to this channel."""
        path = self._inbox_path(channel_key)
        recorded = signal.model_copy(update={"provider": PROVIDER_NAME, "channel_key": channel_key})
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            _append(
                path,
                json.dumps(
                    recorded.model_dump(mode="json"),
                    separators=(",", ":"),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
        return recorded

    def published(self, channel_key: str) -> tuple[CollaborationEvent, ...]:
        """Everything published to a channel, in order. For assertions and for the CLI."""
        path = self._channel_path(channel_key)
        if not path.exists():
            return ()
        events: list[CollaborationEvent] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    events.append(CollaborationEvent.model_validate(json.loads(stripped)["event"]))
        return tuple(events)

    def _now(self) -> datetime:
        clock = self._clock
        if clock is None:
            return utcnow()
        return require_utc(clock(), "clock")  # type: ignore[operator]

    def _channel_path(self, key: str) -> Path:
        return self._channels_root / f"{_require_safe_key(key)}.jsonl"

    def _inbox_path(self, key: str) -> Path:
        return self._inbox_root / f"{_require_safe_key(key)}.jsonl"

    @staticmethod
    def _holds(path: Path, event_id: str) -> bool:
        needle = f'"event_id":"{event_id}"'
        with path.open("r", encoding="utf-8") as handle:
            return any(needle in line for line in handle)


def _require_safe_key(key: str) -> str:
    """Refuse a channel key that could escape the storage root.

    The key reaches a filesystem path, so ``../`` in it would write outside the directory
    the provider was given. :class:`~nemesis.collaboration.base.ChannelDescriptor` already
    constrains the pattern, but this function is reached by
    :meth:`LocalCollaborationProvider.published` with a bare string, and a validator that
    only runs on one of two doors is not a validator.
    """
    if not _SAFE_KEY.match(key):
        raise ValueError(
            f"channel key {key!r} is not safe as a path component; keys must match "
            f"{_SAFE_KEY.pattern}"
        )
    return key


def _append(path: Path, line: str) -> int:
    """Append one line and return the byte offset it was written at.

    The bytes are on disk before this returns. A receipt reporting a publication that a
    crash then loses is the local analogue of an in-memory audit head running ahead of the
    file, and it fails the same way: the outbox marks the event delivered and never sends it
    again.
    """
    with path.open("a", encoding="utf-8") as handle:
        offset = handle.tell()
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return offset


__all__ = ["PROVIDER_NAME", "LocalCollaborationProvider"]
