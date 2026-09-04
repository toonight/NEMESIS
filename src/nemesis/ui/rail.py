"""What the rail may say, and what it knows about the pipeline. No I/O, no scenario.

Two things live here and nothing else may join them:

- **Static metadata of the design** (:data:`STAGE_META`): which loop phase a stage belongs to,
  which plane it runs in, whether its input is hostile by default, whether the platform can
  refuse there, whether a human decides. This is true of every investigation, so it is drawn
  the same way for every investigation and is not data from any run.
- **The closed registry of ledger facts** (:data:`FACT_FORMS`) and the two typed shapes that
  carry them, :class:`StageFact` and :class:`StageMark`. A fact is an integer or a boolean
  under a label registered here. There is no free-text field, so the registry is the whole of
  what the rail can be made to say about a run.

The renderer imports this module. It does not import :mod:`nemesis.ui.ledger`, which is the
one place the scenario is read — so "the renderer never sees the scenario" holds at the module
graph, not only in a docstring.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Phase = Literal["detect", "pursue", "attribute", "disrupt", "watch"]
"""The loop's phases, in the order the platform's own summary gives them:
``DETECT → PURSUE → ATTRIBUTE → DISRUPT → WATCH → REAPPEARANCE → PURSUE``."""


class StageMeta(BaseModel):
    """What is true of a stage in *every* investigation. Design, not data."""

    model_config = ConfigDict(frozen=True)

    phase: Phase | None
    plane: str
    hostile: bool = False
    """Input crosses the collection boundary here and is hostile by default (invariant 5)."""
    gate: bool = False
    """The platform can refuse here, in code the model cannot reach (invariants 6, 7, 9)."""
    human: bool = False
    """A named human decides here; nothing proceeds because an agent asked (invariant 7)."""


STAGE_META: Final[dict[str, StageMeta]] = {
    "detect": StageMeta(phase="detect", plane="collection", hostile=True),
    "pursue": StageMeta(phase="pursue", plane="agent execution", hostile=True),
    "graph": StageMeta(phase="pursue", plane="data"),
    "darkweb": StageMeta(phase="pursue", plane="dark web", hostile=True),
    "blockchain": StageMeta(phase="pursue", plane="collection", hostile=True),
    "resolve": StageMeta(phase="pursue", plane="resolution", gate=True),
    "attribute": StageMeta(phase="attribute", plane="attribution", gate=True),
    "evidence": StageMeta(phase="attribute", plane="evidence"),
    "disrupt": StageMeta(phase="disrupt", plane="control"),
    "authorize": StageMeta(phase="disrupt", plane="control", gate=True, human=True),
    "effect": StageMeta(phase="disrupt", plane="effects", gate=True),
    "resurgence": StageMeta(phase="watch", plane="collection", hostile=True),
    # The pursuit trace (`nemesis trace`) names two stages the reference scenario does not.
    "cluster": StageMeta(phase="pursue", plane="data"),
    "standing": StageMeta(phase="pursue", plane="resolution"),
}

UNKNOWN_STAGE: Final = StageMeta(phase=None, plane="unregistered")
"""A stage this module has no metadata for is drawn, unphased, rather than dropped: a rail
that silently omits a stage reads as though it never ran."""


def meta_for(stage: str) -> StageMeta:
    return STAGE_META.get(stage, UNKNOWN_STAGE)


FACT_FORMS: Final[dict[str, tuple[str, str]]] = {
    # Counts: (singular, plural). The value is an integer.
    "sensors": ("sensor", "sensors"),
    "autonomous pivots": ("autonomous pivot", "autonomous pivots"),
    "directed collections": ("directed collection", "directed collections"),
    "pivots failed": ("pivot failed", "pivots failed"),
    "entities": ("entity", "entities"),
    "relationships": ("relationship", "relationships"),
    "shared infrastructure excluded": ("shared host excluded", "shared hosts excluded"),
    "hostile claims": ("hostile claim", "hostile claims"),
    "injection attempts": ("injection attempt", "injection attempts"),
    "inbound payments": ("inbound payment", "inbound payments"),
    "dimensions withheld from": ("dimension withheld from", "dimensions withheld from"),
    "signals used": ("signal used", "signals used"),
    "signals unavailable": ("signal unavailable", "signals unavailable"),
    "dimensions assessed": ("dimension assessed", "dimensions assessed"),
    "dimensions refused": ("dimension refused at the gate", "dimensions refused at the gate"),
    "weak markers not scored": ("weak marker not scored", "weak markers not scored"),
    "entries exported": ("entry exported", "entries exported"),
    "restricted entries withheld": ("restricted entry withheld", "restricted entries withheld"),
    "levers executable now": ("lever executable now", "levers executable now"),
    "levers needing legal authority": (
        "lever needs legal authority",
        "levers need legal authority",
    ),
    "levers needing ownership confirmation": (
        "lever needs ownership confirmed",
        "levers need ownership confirmed",
    ),
    "approvals": ("approval", "approvals"),
    "human rejections": ("human rejection", "human rejections"),
    "platform refusals": ("platform refusal", "platform refusals"),
    "capability lifetime hours": ("hour of capability lifetime", "hours of capability lifetime"),
    "effects rehearsed": ("effect rehearsed", "effects rehearsed"),
    "reconnecting artifacts": ("reconnecting artifact", "reconnecting artifacts"),
    "candidates examined": ("candidate examined", "candidates examined"),
    # Flags: (when true, when false). The value is a boolean.
    "injection acted on": ("injection acted on", "injection not acted on"),
    "identity lead withheld": ("identity lead withheld", "identity lead promoted"),
    "vault intact": ("vault intact", "vault not intact"),
    "anchor externally held": ("anchor externally held", "anchor held internally"),
    "external contact made": ("external contact made", "no external contact"),
    "separate process": ("ran in a separate process", "ran in-process"),
    "network denied": ("network denied by the kernel", "network not denied"),
    "case reopened": ("case reopened", "case not reopened"),
}
"""The closed registry of what a ledger fact may say, and how it reads at each value.

Adding a label is a deliberate act with a review: the label is the only prose the ledger can
put on the page, so the registry is the whole of what the rail can be made to say."""

FACT_LABELS: Final[frozenset[str]] = frozenset(FACT_FORMS)

# Flags where one value means a boundary held and the other means it did not. The rail draws
# a held boundary in the belief colour and a breached one in the alarm colour — the same
# vocabulary as the bars, so a reader never has to learn a second one.
HELD_WHEN_TRUE: Final[frozenset[str]] = frozenset(
    {
        "identity lead withheld",
        "vault intact",
        "anchor externally held",
        "separate process",
        "network denied",
    }
)
HELD_WHEN_FALSE: Final[frozenset[str]] = frozenset({"injection acted on", "external contact made"})
# Counts that are refusals: non-zero is drawn in the alarm colour, because a refusal is the
# product and must not read as a footnote.
REFUSAL_COUNTS: Final[frozenset[str]] = frozenset(
    {"dimensions refused", "human rejections", "platform refusals"}
)


class StageFact(BaseModel):
    """One thing the rail may say about a stage: a registered label and a number or a flag."""

    model_config = ConfigDict(frozen=True)

    label: str
    value: int | bool

    @field_validator("label")
    @classmethod
    def _label_is_registered(cls, label: str) -> str:
        if label not in FACT_FORMS:
            raise ValueError(f"ledger label {label!r} is not in the registry")
        return label

    @field_validator("value")
    @classmethod
    def _value_is_not_negative(cls, value: int | bool) -> int | bool:
        if isinstance(value, bool):
            return value
        if value < 0:
            raise ValueError("a ledger count cannot be negative")
        return value

    def phrase(self) -> str:
        singular, plural = FACT_FORMS[self.label]
        if isinstance(self.value, bool):
            return singular if self.value else plural
        return f"{self.value} {singular if self.value == 1 else plural}"

    def tone(self) -> str:
        """``held`` / ``breach`` for boundary flags, ``refused`` for non-zero refusal counts,
        ``plain`` otherwise. A class name for the renderer, never a judgement in prose."""
        if isinstance(self.value, bool):
            if self.label in HELD_WHEN_TRUE:
                return "held" if self.value else "breach"
            if self.label in HELD_WHEN_FALSE:
                return "breach" if self.value else "held"
            return "plain"
        if self.label in REFUSAL_COUNTS and self.value > 0:
            return "refused"
        return "plain"


class StageMark(BaseModel):
    """One station on the rail: a stage name and what the run recorded there, typed."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=40, pattern=r"^[a-z][a-z0-9_-]*$")
    facts: tuple[StageFact, ...] = ()
    refusals: int = Field(default=0, ge=0)
    """How many times something was refused at this stage — by a gate, by a human, by the
    platform itself. Drawn as a count on the station; the reasons stay where they are."""


__all__ = [
    "FACT_FORMS",
    "FACT_LABELS",
    "HELD_WHEN_FALSE",
    "HELD_WHEN_TRUE",
    "REFUSAL_COUNTS",
    "STAGE_META",
    "UNKNOWN_STAGE",
    "Phase",
    "StageFact",
    "StageMark",
    "StageMeta",
    "meta_for",
]
