"""What went wrong on the way to a move, classified once for every provider.

Five vendors fail in five dialects and in one taxonomy. A 429 is a 429 whether it arrives as an
HTTP status, a JSON error code or an exception type, and the decision that follows it — retry,
or refuse and record — must not depend on which vendor produced it, because a retry policy that
is stricter for one vendor is an availability difference an operator will resolve by choosing
the lax one.

Three properties are load-bearing and are the reason this is a module rather than a few
`except` clauses:

**Retryability is a property of the kind, not of the caller.** :data:`RETRYABLE_KINDS` is the
whole list, and it holds only failures where the *same request* might succeed unchanged. A
malformed response is not on it: re-sending a request that produced garbage is how a hung model
becomes an unbounded spend, and the mediator already contains a failing pilot as a refused move
and eventually a recorded halt.

**An unsupported parameter is never retried by removing it.** The obvious repair for "this
model does not accept ``reasoning_effort``" is to drop the field and try again. That silently
changes the decision surface the deployment configured, on a run whose audit record will say it
used the configured one. It is a configuration error, reported as one.

**An error never carries a credential.** :class:`PilotError` holds a kind, a provider, a model,
an optional status and a short detail. There is no field for a header, a request body or a
response body, so there is nothing for a key to be attached to — and :meth:`PilotError.audit`
truncates what is left. This is the same reasoning as the effects plane holding no standing
credentials: the safest place to keep a secret out of a log is a structure with nowhere to put
one.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class PilotErrorKind(StrEnum):
    """Why a provider did not return a usable move."""

    TIMEOUT = "timeout"
    """The transport gave up waiting. Includes a connect timeout: from here they are the same
    event, and the distinction belongs to whoever wired the transport."""

    RATE_LIMITED = "rate_limited"
    """HTTP 429, or a vendor's equivalent. Retryable, and the one kind where waiting is the
    correct response rather than a hope."""

    SERVER_ERROR = "server_error"
    """HTTP 5xx. Retryable within the attempt budget."""

    TRANSPORT = "transport"
    """The request never completed: a dropped connection, a DNS failure, a proxy refusing.
    Retryable, because nothing about the request is known to be wrong."""

    AUTHENTICATION = "authentication"
    """HTTP 401/403, or a missing credential. NOT retryable: a key that is wrong now is wrong
    in eight seconds, and retrying an auth failure is how a deployment locks itself out."""

    UNSUPPORTED_MODEL = "unsupported_model"
    """The provider does not serve the configured model id. A configuration error."""

    UNSUPPORTED_PARAMETER = "unsupported_parameter"
    """The provider rejected a parameter the configuration asked for. A configuration error,
    and deliberately not repaired by dropping the parameter — see the module docstring."""

    CONTEXT_OVERFLOW = "context_overflow"
    """The request did not fit. Not retryable unchanged; a briefing that overflows is a
    mediator-side problem (``MAX_BRIEFING_ENTITIES``), not a provider-side one."""

    TRUNCATED = "truncated"
    """The response stopped before the model finished — a length cap, usually. Whatever tool
    call it had begun is incomplete, and an incomplete call is not a move."""

    MALFORMED_RESPONSE = "malformed_response"
    """The body did not parse, or did not have the shape the vendor documents."""

    NO_TOOL_CALL = "no_tool_call"
    """The model answered in prose instead of choosing a verb. A refused move, not an error in
    the platform: it is the most ordinary thing a weak model does."""

    MULTIPLE_TOOL_CALLS = "multiple_tool_calls"
    """The model asked for more than one action in a turn where exactly one is allowed.

    Refused rather than resolved by taking the first. Taking the first executes one action while
    silently discarding another the model asked for, and records a transcript that says the
    model proposed one thing when it proposed two — an audit record that is wrong about what was
    requested is worse than a refusal."""

    REFUSED_BY_PROVIDER = "refused_by_provider"
    """The vendor's own safety layer declined. Recorded as what it is rather than as a
    platform failure, because it is information about the run."""

    UNKNOWN = "unknown"


RETRYABLE_KINDS: Final[frozenset[PilotErrorKind]] = frozenset(
    {
        PilotErrorKind.TIMEOUT,
        PilotErrorKind.RATE_LIMITED,
        PilotErrorKind.SERVER_ERROR,
        PilotErrorKind.TRANSPORT,
    }
)
"""The kinds where re-sending the identical request might work.

Everything else is either a configuration error or a statement about what the model said, and
neither is fixed by asking again.
"""


class PilotError(RuntimeError):
    """A provider call that did not produce a move, in the one taxonomy.

    Raised by a transport or by an adapter's parsing, caught by
    :func:`nemesis.pilot.providers.reliability.call_with_retries`, and — if the attempts run out
    — allowed to reach the mediator, which contains it as a refused move and eventually a
    recorded halt. That containment already exists and is not weakened here: this only makes the
    reason legible.
    """

    def __init__(
        self,
        kind: PilotErrorKind,
        detail: str,
        *,
        provider: str = "",
        model: str = "",
        status: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(f"{provider or 'provider'}: {kind.value}: {detail}")
        self.kind = kind
        self.detail = detail
        self.provider = provider
        self.model = model
        self.status = status
        self.retry_after_seconds = retry_after_seconds

    @property
    def retryable(self) -> bool:
        return self.kind in RETRYABLE_KINDS

    def audit(self) -> dict[str, str]:
        """The bounded, credential-free view an audit record may carry."""
        fields = {"error_kind": self.kind.value, "error_detail": self.detail[:200]}
        if self.status is not None:
            fields["error_status"] = str(self.status)
        return fields


def kind_for_status(status: int, *, message: str = "") -> PilotErrorKind:
    """Classify a provider failure the way every provider in this tree classifies it.

    A transport that knows nothing about a vendor's error bodies can still hand back the right
    kind, which is what keeps a deployment-supplied transport from re-deriving the retry policy
    and getting it subtly different.

    ``message`` refines the ambiguous statuses, and the refinement is deliberately allowed to be
    fragile because of what it can and cannot cost. Every branch below 500 is non-retryable
    whichever way it resolves, so a wrong guess changes the *label* in an audit record and never
    a control decision. Vendors phrase these differently and will rephrase them again; a
    transport that can read a vendor's own error code should classify from that and pass the
    kind directly rather than relying on this.
    """
    if status in {401, 403}:
        return PilotErrorKind.AUTHENTICATION
    if status == 408:
        return PilotErrorKind.TIMEOUT
    if status == 413:
        return PilotErrorKind.CONTEXT_OVERFLOW
    if status == 429:
        return PilotErrorKind.RATE_LIMITED
    if 500 <= status < 600:
        return PilotErrorKind.SERVER_ERROR
    if status == 404:
        return (
            PilotErrorKind.UNSUPPORTED_MODEL if _mentions_model(message) else PilotErrorKind.UNKNOWN
        )
    if 400 <= status < 500:
        return _classify_bad_request(message)
    return PilotErrorKind.UNKNOWN


_MODEL_PHRASES: Final[tuple[str, ...]] = ("model", "deployment", "engine")
_PARAMETER_PHRASES: Final[tuple[str, ...]] = (
    "unsupported",
    "not supported",
    "unrecognized",
    "unknown parameter",
    "unknown field",
    "unexpected keyword",
    "invalid parameter",
    "does not support",
)
_OVERFLOW_PHRASES: Final[tuple[str, ...]] = (
    "context length",
    "context window",
    "maximum context",
    "too many tokens",
    "too long",
    "exceeds the",
)


def _mentions_model(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in _MODEL_PHRASES)


def _classify_bad_request(message: str) -> PilotErrorKind:
    lowered = message.lower()
    if any(phrase in lowered for phrase in _OVERFLOW_PHRASES):
        return PilotErrorKind.CONTEXT_OVERFLOW
    if any(phrase in lowered for phrase in _PARAMETER_PHRASES):
        return PilotErrorKind.UNSUPPORTED_PARAMETER
    if _mentions_model(message) and "not" in lowered:
        return PilotErrorKind.UNSUPPORTED_MODEL
    return PilotErrorKind.UNKNOWN


__all__ = ["RETRYABLE_KINDS", "PilotError", "PilotErrorKind", "kind_for_status"]
