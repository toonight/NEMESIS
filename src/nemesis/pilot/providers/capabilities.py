"""What a model *can* do, kept strictly apart from what NEMESIS *permits*.

These two get confused, and the confusion has a direction: a capable model arrives, its vendor
documents computer use and code execution and web search, and the shortest path to using it is
to pass the capabilities through. That is how a platform whose whole argument is "the pilot
holds nothing" acquires a pilot that holds a shell.

So the distinction is made structural here rather than left to a reviewer's memory:

    model capability  !=  NEMESIS authorization

A :class:`ModelCapabilities` set is **descriptive metadata about a vendor's API**. It decides
whether a request may carry ``reasoning_effort``, whether a ``seed`` means anything, whether
usage counts come back — request-shaping questions, all of them, and none of them a question
about what the pilot may do. What the pilot may do is the four verbs in
:mod:`nemesis.pilot.moves` and the pre-signed envelope, neither of which any value in this
module can reach.

:data:`NEVER_EXPOSED_TOOL_TYPES` is the other half, and it is the half with teeth: the vendor
tool types that must never appear in a request this platform builds, whatever a model supports
and whatever a future adapter's author finds convenient. A test scans every provider's rendered
request for every one of them, so adding a provider that quietly enables one fails the build
rather than shipping.

Capability metadata is also honest about its own standing. It is **declared configuration**,
not something discovered by asking the vendor, and it can be wrong the day a vendor changes an
API. What follows from it is therefore only ever *narrowing*: an absent capability means a
parameter is not sent, or a configuration is refused at construction. Nothing here can turn a
capability on that the platform would not otherwise have used.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict


class ModelCapability(StrEnum):
    """Something a provider's API supports. Not a permission — see the module docstring."""

    STRUCTURED_TOOL_CALLING = "structured_tool_calling"
    """The API accepts tool/function schemas and returns a structured call.

    Load-bearing rather than informational: a seat whose provider lacks it would have to parse
    a verb out of free text, and a free-text verb is a vocabulary that is no longer closed. The
    registry refuses to build a pilot without it."""

    FORCED_TOOL_CHOICE = "forced_tool_choice"
    """The API can be told the model *must* call one of the offered tools.

    Where present it is used, so the vendor's own machinery refuses a fifth verb before the
    seam has to. Where absent the seam still refuses it; this only moves the refusal earlier."""

    SINGLE_TOOL_CALL = "single_tool_call"
    """Parallel tool calls can be disabled, so exactly one move comes back per turn."""

    REASONING_EFFORT = "reasoning_effort"
    """A reasoning level can be requested **without the trace being returned**.

    The qualification is the whole point. NEMESIS does not request or persist private reasoning
    traces, so a vendor whose reasoning mode returns thinking blocks does not carry this
    capability here even though it reasons perfectly well — see
    :mod:`nemesis.pilot.providers.anthropic`."""

    SEEDING = "seeding"
    """A seed makes sampling reproducible. Best-effort at every vendor that offers it, and
    absent means a configured seed is a configuration error rather than a silent no-op."""

    USAGE_REPORTING = "usage_reporting"
    """Token counts come back with the response, so a run can report what it cost."""

    NATIVE_JSON = "native_json"
    LARGE_CONTEXT = "large_context"
    VISION = "vision"
    STREAMING = "streaming"
    """Declared for completeness and used by nothing here. A briefing is small, a move is one
    tool call, and streaming a decision that is validated as a whole buys latency in exchange
    for a partially-parsed action — which is not a trade this seam makes."""


class ModelCapabilities(BaseModel):
    """The declared capability set of one provider/model pairing."""

    model_config = ConfigDict(frozen=True)

    declared: frozenset[ModelCapability]

    def supports(self, capability: ModelCapability) -> bool:
        return capability in self.declared

    def missing(self, *required: ModelCapability) -> tuple[ModelCapability, ...]:
        return tuple(item for item in required if item not in self.declared)


REQUIRED_OF_EVERY_PILOT: Final[tuple[ModelCapability, ...]] = (
    ModelCapability.STRUCTURED_TOOL_CALLING,
)
"""What a seat cannot do without.

Exactly one entry, and the shortness is deliberate. Forced tool choice and single-tool-call are
*preferred* and their absence is handled at the seam, so requiring them would refuse a usable
provider for a property the platform already enforces itself. Structured tool calling is
different: without it there is no closed vocabulary to enforce.
"""

NEVER_EXPOSED_TOOL_TYPES: Final[frozenset[str]] = frozenset(
    {
        "code_interpreter",
        "code_execution",
        "computer",
        "computer_use",
        "computer_use_preview",
        "bash",
        "shell",
        "text_editor",
        "str_replace_editor",
        "file_search",
        "retrieval",
        "web_search",
        "web_search_preview",
        "google_search",
        "google_search_retrieval",
        "url_context",
        "browser",
        "mcp",
        "function_calling_with_execution",
    }
)
"""Vendor tool types that must never appear in a request NEMESIS builds.

Every one of them is a real capability some frontier model offers and several offer by name in
a request body. None of them is a NEMESIS verb, and a pilot that could reach one would hold
exactly the thing this platform's design says it does not: arbitrary execution, arbitrary
retrieval, or a path to the network that the collection plane does not own.

Enumerated rather than inferred, and enumeration is usually the weaker control in this
repository. It is the right one here because the check runs over a *rendered request* — the
list does not have to be complete to catch the case it exists for, which is an adapter's author
adding a vendor's convenience tool beside the four verbs. The complete control is
:func:`nemesis.pilot.providers.schema.render_tools`, which refuses anything not in the suite;
this is the scan that also reads the rest of the payload.
"""


UNTRUSTED_CONTENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "messages",
        "contents",
        "system",
        "system_instruction",
        "systemInstruction",
        "prompt",
        "input",
    }
)
"""Where a rendered request carries text NEMESIS did not write.

The scan below skips these, and the direction of that decision is the point. An adversary
chooses some of what lands here — a domain's natural key reaches the briefing because a pivot
surfaced it, which is exactly how the injection demonstration works — so scanning message
bodies for a list of vendor tool names would let anyone who can register
``web_search.example`` halt an investigation by making every request look like a violation. A
control an adversary can trigger is a denial of service they were handed.

Enumerating where untrusted text goes, rather than where tool declarations go, also fails in
the safe direction: an adapter that put the briefing somewhere new would produce a *false
positive*, which is loud and caught by the first test run, rather than a silent miss.
"""


def forbidden_tool_types(payload: object) -> tuple[str, ...]:
    """Every never-exposed tool type appearing anywhere in a rendered request.

    Walks the whole structure rather than the ``tools`` key, minus the keys in
    :data:`UNTRUSTED_CONTENT_KEYS`: a vendor may enable a built-in through a sibling field
    (``tool_config``, ``tools`` nested in ``config``, a top-level flag), and a scan that only
    knew about one shape would report clean on the request that mattered.
    """
    found: set[str] = set()
    _walk(payload, found)
    return tuple(sorted(found))


def _walk(node: object, found: set[str]) -> None:
    if isinstance(node, str):
        if node in NEVER_EXPOSED_TOOL_TYPES:
            found.add(node)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                _walk(value, found)
                continue
            if key in NEVER_EXPOSED_TOOL_TYPES:
                found.add(key)
            if key in UNTRUSTED_CONTENT_KEYS:
                continue
            _walk(value, found)
        return
    if isinstance(node, list | tuple):
        for item in node:
            _walk(item, found)


__all__ = [
    "NEVER_EXPOSED_TOOL_TYPES",
    "REQUIRED_OF_EVERY_PILOT",
    "UNTRUSTED_CONTENT_KEYS",
    "ModelCapabilities",
    "ModelCapability",
    "forbidden_tool_types",
]
