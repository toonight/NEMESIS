"""Bitemporal primitives.

Two independent time axes, never conflated:

**Valid time** — when the assertion was true of the world. A domain resolved to an IP
between March and June.

**Transaction time** — when NEMESIS recorded it. We may learn in December about a
resolution that ended in June, and we may later learn we were wrong.

Keeping both is what allows the two questions an investigation actually asks:
*"what was true then?"* and *"what did we believe then?"* The second one is what an
opposing expert will ask when challenging an attribution, and a system that cannot
reconstruct its own past belief state cannot answer it.

A third distinction, usually skipped and consequential here: an observation bounds a
validity interval, it does not define it. Passive DNS reporting `first_seen` and
`last_seen` tells you the relationship held *at least* over that window — not that it
started or stopped there. Collapsing that into a closed interval manufactures precision
that the source never provided. :class:`TemporalExtent` keeps the distinction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow() -> datetime:
    """Current time, timezone-aware, UTC. The only sanctioned clock read."""
    return datetime.now(UTC)


def require_utc(value: datetime, field: str = "timestamp") -> datetime:
    """Normalise to UTC, refusing a naive datetime.

    Exported because ordering by ISO-8601 string — which is what any store that keeps
    timestamps as text does — is only correct on UTC-normalised, timezone-aware values.
    A review found `Revocation.revoked_at` accepting both a naive datetime and a ``+02:00``
    offset, so an earlier withdrawal recorded from another timezone compared as later and
    was discarded by the store's earliest-wins rule. That rule exists so a second revocation
    cannot narrow the window the first applied to.
    """
    return _require_utc(value, field)


def _require_utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware; naive datetimes are a correctness bug")
    return value.astimezone(UTC)


class TemporalExtent(BaseModel):
    """When an assertion held, with honest bounds on what is actually known.

    Four points, ordered ``possible_from <= known_from <= known_until <= possible_until``:

    - ``known_from`` / ``known_until``: the interval directly supported by observation.
      We can defend this range.
    - ``possible_from`` / ``possible_until``: the widest interval consistent with the
      evidence. ``None`` means unbounded in that direction — the relationship may have
      begun before our first sighting, or may still hold.

    A single sighting yields a zero-width known interval with unbounded possible bounds,
    which is the truthful representation of "we saw it once".
    """

    model_config = ConfigDict(frozen=True)

    known_from: datetime
    known_until: datetime
    possible_from: datetime | None = None
    possible_until: datetime | None = None

    @model_validator(mode="after")
    def _check_ordering(self) -> Self:
        known_from = _require_utc(self.known_from, "known_from")
        known_until = _require_utc(self.known_until, "known_until")
        if known_from > known_until:
            raise ValueError("known_from must not be after known_until")
        if self.possible_from is not None:
            possible_from = _require_utc(self.possible_from, "possible_from")
            if possible_from > known_from:
                raise ValueError("possible_from must not be after known_from")
        if self.possible_until is not None:
            possible_until = _require_utc(self.possible_until, "possible_until")
            if possible_until < known_until:
                raise ValueError("possible_until must not be before known_until")
        return self

    @classmethod
    def at(cls, moment: datetime) -> TemporalExtent:
        """A single sighting: known at one instant, unbounded either side."""
        return cls(known_from=moment, known_until=moment)

    @classmethod
    def between(cls, start: datetime, end: datetime) -> TemporalExtent:
        """Observed across a window, with no claim about what happened outside it."""
        return cls(known_from=start, known_until=end)

    @classmethod
    def closed(cls, start: datetime, end: datetime) -> TemporalExtent:
        """A relationship known to have begun and ended at these exact times.

        Only use this when the source genuinely establishes the boundaries — a registrar
        record with a creation and expiry date, not a scanner's first and last sighting.
        """
        return cls(known_from=start, known_until=end, possible_from=start, possible_until=end)

    @property
    def is_open_ended(self) -> bool:
        """True if the relationship may still hold."""
        return self.possible_until is None

    def known_duration_seconds(self) -> float:
        return (self.known_until - self.known_from).total_seconds()

    def certainly_held_at(self, moment: datetime) -> bool:
        """True only inside the directly-observed window."""
        return self.known_from <= moment <= self.known_until

    def possibly_held_at(self, moment: datetime) -> bool:
        """True anywhere the evidence does not exclude."""
        before_window = self.possible_from is not None and moment < self.possible_from
        after_window = self.possible_until is not None and moment > self.possible_until
        return not (before_window or after_window)

    def known_overlaps(self, other: TemporalExtent) -> bool:
        """Whether both extents are *certainly* concurrent.

        Deliberately strict. Co-occurrence is a common pivot signal ("these two domains
        resolved to the same IP at the same time"), and using merely-possible overlap to
        justify a link is how weak correlations get promoted to apparent facts.
        """
        return self.known_from <= other.known_until and other.known_from <= self.known_until

    def possibly_overlaps(self, other: TemporalExtent) -> bool:
        """Whether concurrency cannot be excluded. Useful to *rule out*, never to assert."""

        def strictly_before(end: datetime | None, start: datetime | None) -> bool:
            return end is not None and start is not None and end < start

        return not (
            strictly_before(self.possible_until, other.possible_from)
            or strictly_before(other.possible_until, self.possible_from)
        )


class RecordVersion(BaseModel):
    """Transaction-time metadata: what NEMESIS believed, and when.

    Records are never updated in place. A correction supersedes its predecessor and both
    remain readable, so the belief state at any past moment can be reconstructed. This is
    the mechanism behind invariant 11 (auditable) and invariant 13 (an adversary who
    poisons the graph must leave a visible trace of having done so).
    """

    model_config = ConfigDict(frozen=True)

    recorded_at: datetime = Field(default_factory=utcnow)
    superseded_at: datetime | None = None
    supersedes: str | None = Field(
        default=None, description="Identifier of the record version this one replaces."
    )
    revision: Annotated[int, Field(ge=1)] = 1

    @model_validator(mode="after")
    def _check(self) -> Self:
        recorded_at = _require_utc(self.recorded_at, "recorded_at")
        if self.superseded_at is not None:
            superseded_at = _require_utc(self.superseded_at, "superseded_at")
            if superseded_at < recorded_at:
                raise ValueError("superseded_at must not precede recorded_at")
        if self.revision > 1 and self.supersedes is None:
            raise ValueError("a revision above 1 must name the record version it supersedes")
        return self

    @property
    def is_current(self) -> bool:
        return self.superseded_at is None
