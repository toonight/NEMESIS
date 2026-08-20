"""One encoding, used both to sign and to reconstruct.

An adversarial review broke the previous scheme, and the break is worth stating exactly
because the lesson generalises past this codebase.

Signing payloads used to be hand-written projections of a model's fields — ``op.value`` for
an operation, ``role.value`` for a role, ``dt.isoformat()`` for a timestamp. Every decision
downstream, meanwhile, was made against the *objects*: ``operation in permitted_operations``,
``moment >= expires_at``. So the signature covered a **rendering** of the grant while the
platform acted on the **grant**, and anything that rendered as the approved value but
compared as something else slipped between the two::

    class Masked(str):
        @property
        def value(self): return "simulation"

    widened = capability.model_copy(
        update={"permitted_operations": frozenset({Masked("provider_notification")})}
    )
    widened.signing_payload() == capability.signing_payload()   # True
    verify_capability(widened, key).is_usable_now               # True
    # ... and the Effects plane drafted a provider notification from a rehearsal grant.

Two rules follow, and this module exists to make both cheap:

1. **Sign the whole object, not a summary of it.** The payload is the model's own JSON
   serialization, so a field cannot be signed as one thing and read as another, and a field
   added later is covered by default instead of by remembering.
2. **Verify by reconstructing.** A signature proves an issuer produced *these bytes*. What
   those bytes say is then obtained by parsing them into a fresh, validated object — never
   by trusting the object somebody handed you alongside them. A reconstructed object cannot
   carry a masked enum or a lying ``datetime`` subclass, because it was built by the model's
   own validators from text.

The encoding is canonical so that the same content always produces the same bytes: object
keys sorted, arrays sorted by their own encoding, no insignificant whitespace. Array sorting
is safe **only** because every sequence signed here is order-insensitive — a set of
operations, a list of approvals, a tuple of targets. Nothing signed with this encoding may
carry meaning in its ordering; if that ever changes, this is the wrong tool and a
deterministic non-sorting encoding is the right one.

Sorting is also what makes the encoding stable across processes at all: Pydantic serializes
a ``frozenset`` as a list in set-iteration order, and Python randomises string hashing per
process, so an unsorted payload would verify in the process that signed it and nowhere else.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonical_bytes", "canonical_form"]


# `Any` on purpose: this walks arbitrary JSON, whose shape is genuinely heterogeneous and
# whose element types are exactly what the function must not assume.
def canonical_form(value: Any) -> Any:
    """Recursively put a JSON-compatible value into its canonical shape.

    Mappings get sorted keys; sequences get sorted by the encoding of their elements, so
    that reordering an approval list or a target tuple cannot produce different bytes for
    the same grant.
    """
    if isinstance(value, dict):
        # Non-string keys would sort by an ordering that differs between key types (and
        # raises outright on a mixed dict), and `json.dumps` silently coerces them to
        # strings anyway — so `{1: "x"}` and `{"1": "x"}` would encode identically. Refuse
        # instead: nothing this signs has non-string keys, and a signing function that
        # quietly merges two different objects is the beginning of a collision.
        if any(not isinstance(key, str) for key in value):
            raise TypeError(
                "canonical encoding requires string keys; a non-string key would be "
                f"coerced and could collide with its own string form: {sorted(map(repr, value))}"
            )
        return {key: canonical_form(item) for key, item in sorted(value.items())}
    if isinstance(value, list | tuple):
        return sorted(
            (canonical_form(item) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False),
        )
    return value


def canonical_bytes(value: Any) -> bytes:
    """The exact bytes a signature covers."""
    return json.dumps(
        canonical_form(value),
        sort_keys=True,
        separators=(",", ":"),
        # `NaN`, `Infinity` and `-Infinity` are not JSON. Python emits them and reads them
        # back, so a payload carrying one would verify here and be rejected by any other
        # implementation — or, worse, be read differently by one. No float is signed today;
        # this refuses the day one is.
        allow_nan=False,
        ensure_ascii=False,
    ).encode("utf-8", errors="strict")
