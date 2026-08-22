"""Retrying, bounded and deterministic, and the three things it must never do.

A hosted model fails in ordinary ways — a 429 at the wrong moment, a 503, a connection dropped
mid-flight — and a platform that gave up on the first one would be unusable. A platform that
retried without bounds would be worse: an autonomous pilot at machine speed turns "keep trying"
into an unbounded spend against a vendor, and a stalled call that is never abandoned parks a
session on one turn with no halt ever recorded.

So the policy is small, explicit, and has three prohibitions built into its shape.

**It never retries what a retry cannot fix.** Only the kinds in
:data:`~nemesis.pilot.providers.errors.RETRYABLE_KINDS` are attempted again, and every one of
them is a failure where the *identical* request might succeed. A malformed response is not
retried: re-sending a request that produced garbage is a loop, and the mediator already contains
a failing pilot as a refused move and eventually a recorded halt — which is the correct
outcome, not a fallback to be avoided.

**It never changes the request between attempts.** No dropped parameter, no lowered
``max_tokens``, no shorter briefing, and above all no different model. An attempt that altered
the request would produce a run whose audit record names a configuration that did not run. This
is also why there is no provider fallback here at all: switching vendors mid-session is
explicitly out of scope, recorded as `PROPOSED` in ADR-0009 rather than half-built.

**The backoff has no randomness in it.** Jitter is the right answer for a fleet hammering one
endpoint and the wrong answer here, because ``docs/calibration/PROTOCOL.md`` asks every figure
to be explicable and a benchmark that cannot say why two runs took different wall-clock time is
one dial short. The schedule is a pure function of the attempt number, so a run replays. Where a
vendor supplies ``Retry-After`` it wins, because a server saying when to come back is better
information than a client's exponent — and it is still bounded by :attr:`RetryPolicy.max_delay`,
since a hostile or broken endpoint asking us to wait an hour must not be obeyed.

The sleep is injected. A test that waited out a real backoff would be a slow test that everyone
eventually marks skipped.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final

from nemesis.pilot.providers.errors import PilotError, PilotErrorKind

Sleeper = Callable[[float], Awaitable[None]]

DEFAULT_MAX_ATTEMPTS: Final = 3
DEFAULT_BASE_DELAY_SECONDS: Final = 0.5
DEFAULT_MAX_DELAY_SECONDS: Final = 8.0


@dataclass(frozen=True)
class RetryPolicy:
    """How many times, and how long between. Deterministic by construction."""

    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS
    max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("a pilot must be allowed at least one attempt")
        if self.base_delay_seconds < 0 or self.max_delay_seconds < 0:
            raise ValueError("retry delays cannot be negative")

    def delay_before(self, attempt: int, *, retry_after_seconds: float | None = None) -> float:
        """Seconds to wait before ``attempt`` (1-based; attempt 1 never waits).

        The server's own ``Retry-After`` takes precedence over the exponent, capped at
        :attr:`max_delay_seconds` so an endpoint cannot park a session by asking it to.
        """
        if attempt <= 1:
            return 0.0
        if retry_after_seconds is not None and retry_after_seconds > 0:
            return min(retry_after_seconds, self.max_delay_seconds)
        exponential: float = self.base_delay_seconds * float(2 ** (attempt - 2))
        return min(exponential, self.max_delay_seconds)


NO_RETRIES: Final = RetryPolicy(max_attempts=1)


async def call_with_retries[T](
    operation: Callable[[int], Awaitable[T]],
    *,
    policy: RetryPolicy,
    sleep: Sleeper = asyncio.sleep,
) -> tuple[T, int]:
    """Run ``operation(attempt)`` until it succeeds, is unretryable, or the budget is spent.

    Returns the value and the number of attempts made. Re-raises the last
    :class:`~nemesis.pilot.providers.errors.PilotError` when the budget is spent, so the mediator
    sees a raising pilot and contains it as a refused move — the failure is not swallowed into a
    plausible-looking empty answer, which for an investigation platform is the dangerous shape.

    Anything that is not a ``PilotError`` propagates immediately and untouched. A
    ``KeyboardInterrupt`` or a cancellation is not a provider failure and must not be retried
    into oblivion; the mediator's own handler already distinguishes them.
    """
    last: PilotError | None = None
    for attempt in range(1, policy.max_attempts + 1):
        if attempt > 1:
            delay = policy.delay_before(
                attempt,
                retry_after_seconds=last.retry_after_seconds if last is not None else None,
            )
            if delay > 0:
                await sleep(delay)
        try:
            return await operation(attempt), attempt
        except PilotError as error:
            last = error
            if not error.retryable or attempt == policy.max_attempts:
                raise
    # Unreachable: the loop either returns or raises. Kept as an explicit failure rather than an
    # implicit `None`, because a retry helper that can fall through is a retry helper that
    # silently returns "no move" on a path nobody tested.
    raise PilotError(
        PilotErrorKind.UNKNOWN,
        "the retry loop ended without a result or an error",
        provider=last.provider if last is not None else "",
    )


__all__ = [
    "DEFAULT_BASE_DELAY_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_DELAY_SECONDS",
    "NO_RETRIES",
    "RetryPolicy",
    "Sleeper",
    "call_with_retries",
]
