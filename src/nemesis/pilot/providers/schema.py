"""One definition of what a pilot may say, and five dialects for saying it.

The four verbs live in :mod:`nemesis.pilot.moves` and their argument schemas are derived from
those models in :mod:`nemesis.pilot.model_seat`. This module is the single place that turns
them into the shape a vendor's tool-calling API wants, and it exists because the alternative
was already visible: three adapters each rebuilding the same list, drifting one field at a
time, until a containment argument that says "the vocabulary is closed" is true of three
vendors and not of the fourth.

The rule this module enforces is narrow and mechanical: **a provider adapter never chooses
which tools exist.** It is handed a :class:`PilotToolSuite` — a frozen, module-level constant
— and supplies only a *dialect*, a pure function from one :class:`PilotToolSpec` to the JSON
that vendor accepts. There is no argument through which an adapter can add a fifth tool,
rename one, or widen an argument schema, and :func:`render_tools` re-checks the names it
emitted against the suite it was given anyway. Belt, and braces, for the same reason the
mediator re-validates a move it just built.

Two suites exist in this tree and there is deliberately nowhere to add a third by accident:

- :data:`MOVE_TOOL_SUITE` — the four verbs. What a pilot may propose.
- :data:`CHALLENGER_TOOL_SUITE` — one verb, ``challenger_verdict``, which returns an opinion
  and can cause a refusal but never an action. See :mod:`nemesis.pilot.challenger`.

**The Gemini dialect is where the interesting work is.** Pydantic emits enum arguments as
``$ref`` into ``$defs``; Gemini's ``FunctionDeclaration.parameters`` takes an OpenAPI 3.0
subset that has neither, and no ``additionalProperties``. Translating means inlining the
reference and dropping the unsupported keywords — and the temptation is to drop the ``enum``
with them, because it arrives attached to the ``$ref``. That would silently widen what the
model may say for exactly one vendor, which is the n-way version of the drift this module
exists to prevent. :func:`to_openapi_subset` inlines and preserves, and a test asserts every
``PivotType`` and ``OperationClass`` value survives the translation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any, Final

from pydantic import BaseModel, ConfigDict

from nemesis.pilot.model_seat import MOVE_MODELS, argument_schema, move_description


class PilotToolSpec(BaseModel):
    """One verb, provider-neutral: the name the model calls and the arguments it may pass."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    parameters: dict[str, Any]
    """JSON Schema for the arguments, with ``kind`` already removed — the tool *name* carries
    the verb, so a model chooses by picking a tool rather than by writing a discriminator into
    a free-form blob, and cannot disagree with itself about which verb it called."""


PilotToolSuite = tuple[PilotToolSpec, ...]
"""A closed set of verbs. Only the module-level constants below are ever built."""

ToolDialect = Callable[[PilotToolSpec], dict[str, Any]]
"""A provider's way of writing one tool. Pure: it receives a spec and returns JSON.

Deliberately not a class with access to the suite. A dialect cannot enumerate the tools, so it
cannot add one; it is called once per spec by :func:`render_tools`, which owns the list.
"""


def _suite_from(models: tuple[tuple[type[BaseModel], str], ...]) -> PilotToolSuite:
    return tuple(
        PilotToolSpec(
            name=name, description=move_description(model), parameters=argument_schema(model)
        )
        for model, name in models
    )


MOVE_TOOL_SUITE: Final[PilotToolSuite] = _suite_from(MOVE_MODELS)
"""The four verbs a pilot may propose. Exactly four; a fifth would be new authority handed to
an untrusted driver, and there is nowhere here to add one by accident."""

MOVE_TOOL_NAMES: Final[frozenset[str]] = frozenset(spec.name for spec in MOVE_TOOL_SUITE)


def suite_version(suite: PilotToolSuite) -> str:
    """A digest of a suite, so a recorded run names the schema it was measured under.

    Sixteen hex characters of SHA-256 over the canonical JSON. Reproducibility asks which tool
    schema produced a result (`docs/calibration/PROTOCOL.md` §6 applies the same rule to every
    other figure this platform reports); a version string somebody remembers to bump does not
    answer it, and a digest computed from the schemas cannot disagree with them.
    """
    payload = json.dumps(
        [[spec.name, spec.description, spec.parameters] for spec in suite],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


MOVE_TOOL_SCHEMA_VERSION: Final = suite_version(MOVE_TOOL_SUITE)


class ToolSuiteViolationError(RuntimeError):
    """A dialect emitted something other than the suite it was handed.

    Not a ``ValueError``: this is the closed vocabulary failing to be closed, which is the one
    property every containment argument in this plane rests on. It should be loud enough that
    nobody handles it by widening an except clause.
    """


def render_tools(suite: PilotToolSuite, dialect: ToolDialect) -> list[dict[str, Any]]:
    """Write a suite in one vendor's dialect, and check that nothing was added or lost.

    The check is not defensive programming against a hostile dialect — every dialect in this
    tree is first-party code three lines long. It is a tripwire against the failure that
    actually happens: a vendor requiring one more transformation, the transformation being
    written inside the dialect, and a tool quietly acquiring a different name for one provider.
    """
    rendered = [dialect(spec) for spec in suite]
    expected = [spec.name for spec in suite]
    emitted = [_declared_name(item) for item in rendered]
    if emitted != expected:
        raise ToolSuiteViolationError(
            f"the dialect emitted {emitted!r} for a suite of {expected!r}; a provider adapter "
            "does not get to decide which verbs exist"
        )
    return rendered


def _declared_name(rendered: Mapping[str, Any]) -> str | None:
    """The tool name a rendered payload declares, in whichever dialect wrote it."""
    name = rendered.get("name")
    if isinstance(name, str):
        return name
    function = rendered.get("function")
    if isinstance(function, Mapping):
        inner = function.get("name")
        if isinstance(inner, str):
            return inner
    return None


# --- dialects -----------------------------------------------------------------


def openai_dialect(spec: PilotToolSpec) -> dict[str, Any]:
    """OpenAI chat-completions: a function under ``function``, arguments under ``parameters``.

    Shared with xAI and with every other OpenAI-compatible endpoint, which is a transport
    similarity and not an identity — see :mod:`nemesis.pilot.providers.openai_dialect`.
    """
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        },
    }


def anthropic_dialect(spec: PilotToolSpec) -> dict[str, Any]:
    """Anthropic Messages: a flat tool with its schema under ``input_schema``."""
    return {
        "name": spec.name,
        "description": spec.description,
        "input_schema": spec.parameters,
    }


def gemini_dialect(spec: PilotToolSpec) -> dict[str, Any]:
    """Gemini: a ``FunctionDeclaration`` whose parameters are an OpenAPI 3.0 subset."""
    return {
        "name": spec.name,
        "description": spec.description,
        "parameters": to_openapi_subset(spec.parameters),
    }


_OPENAPI_UNSUPPORTED: Final[frozenset[str]] = frozenset(
    {"$defs", "$schema", "additionalProperties", "title", "default", "const", "examples"}
)
"""Keywords Gemini's schema subset does not accept, dropped rather than sent.

``default`` is dropped for a reason worth stating: Gemini rejects it, and a defaulted argument
the model omits is filled in by the *move model* at the seam anyway, which is where it should
be filled in. Nothing about what the model may say changes — only what the request says about
what happens when it stays silent.
"""


def to_openapi_subset(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Translate a Pydantic JSON Schema into the OpenAPI 3.0 subset Gemini accepts.

    Inlines every ``$ref`` against the schema's own ``$defs`` and drops the keywords the subset
    has no room for. The one thing it must never drop is a constraint: an ``enum`` arrives
    attached to the reference being inlined, and losing it would widen what one vendor's model
    may say while the other four stay narrow. A test walks both enum-bearing move schemas and
    asserts every value survives.

    A ``$ref`` that cannot be resolved is left as an unconstrained object rather than raised on:
    the mediator re-validates the move regardless, so the failure mode is a model that guesses
    at an argument and is refused, not a request that never leaves.
    """
    definitions = schema.get("$defs")
    resolved: Mapping[str, Any] = definitions if isinstance(definitions, Mapping) else {}
    translated = _subset(schema, resolved)
    if not isinstance(translated, dict):  # pragma: no cover - a Mapping in always yields a dict
        return {"type": "object"}
    return translated


def _subset(node: Any, definitions: Mapping[str, Any]) -> Any:
    if isinstance(node, Mapping):
        reference = node.get("$ref")
        if isinstance(reference, str):
            target = _resolve(reference, definitions)
            if target is None:
                return {"type": "string"}
            merged = {**_subset(target, definitions)}
            for key, value in node.items():
                if key != "$ref" and key not in _OPENAPI_UNSUPPORTED:
                    merged[key] = _subset(value, definitions)
            return merged
        return {
            key: _subset(value, definitions)
            for key, value in node.items()
            if key not in _OPENAPI_UNSUPPORTED
        }
    if isinstance(node, list):
        return [_subset(item, definitions) for item in node]
    return node


def _resolve(reference: str, definitions: Mapping[str, Any]) -> Mapping[str, Any] | None:
    prefix = "#/$defs/"
    if not reference.startswith(prefix):
        return None
    target = definitions.get(reference[len(prefix) :])
    return target if isinstance(target, Mapping) else None


__all__ = [
    "MOVE_TOOL_NAMES",
    "MOVE_TOOL_SCHEMA_VERSION",
    "MOVE_TOOL_SUITE",
    "PilotToolSpec",
    "PilotToolSuite",
    "ToolDialect",
    "ToolSuiteViolationError",
    "anthropic_dialect",
    "gemini_dialect",
    "openai_dialect",
    "render_tools",
    "suite_version",
    "to_openapi_subset",
]
