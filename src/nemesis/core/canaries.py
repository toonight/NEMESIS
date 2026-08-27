"""Names that exist so that reaching for them is visible.

Every control in this repository answers the question *can the pilot do this?* None of them
answers *did the pilot try to find out?* — and the second question is the one that separates a
model doing its job from a model probing its cage. A refused move tells you the limiter held. It
does not tell you the pilot spent nine turns enumerating verbs, guessing at an admin token and
asking for a signing key, which is a different fact about the run and a much more interesting
one.

So this module reserves a small set of identifiers that **nothing in NEMESIS ever legitimately
produces**: no adapter is named `RAW_EFFECT_ADAPTER`, no capability is called `ROOT_CAPABILITY`,
no key is `SYSTEM_SIGNING_KEY`. They are not secrets and they are not real — a canary that was a
real credential would be a credential — and there is nothing behind them to reach. Their whole
value is that a legitimate path has no reason to say them, so an occurrence is evidence about the
party that said it.

**Where they are matched, and why the answer is narrow.** Only in *identifier* fields a pilot
authors: an entity id, an operation name, a parameter key. Deliberately **not** in free text, in
collected content, in a message body, or in anything else an adversary chooses. That is the
lesson this codebase already paid for twice — the capability scan that read message bodies, and
the disclosure backstop that read an attacker-registered natural key. A control an adversary can
fire is a denial of service handed to them, and it would be a particularly good one here: plant
`MASTER_AUTHORIZATION_KEY` in a forum post, wait for it to reach a briefing, and halt every
investigation that reads the page.

**Matching is on a normalised token, not a substring.** ``INTERNAL_ADMIN_TOKEN``,
``internal-admin-token`` and ``internal admin token`` are one probe; ``some_internal_admin_token_
handler`` is also one, because the token appears as a whole word after normalisation. What does
not fire is an unrelated identifier that merely shares a fragment — a defect the collaboration
plane's approval parser hit head-on when ``unapproved`` matched ``approve``.

**What this catches, stated so nobody over-reads it.** A model that guesses these names, or an
injected payload that tells one to ask for them, or a future component that quietly grows a
matching identifier. It does **not** catch a careful adversary, who will simply not say the
words, and it is not a containment control: nothing here permits or refuses anything on its own.
The containment is the four verbs, the envelope and the disclosure wall. This is instrumentation
placed at the boundary those controls defend, and it is honest about being second.

**And it is reachable by an adversary indirectly, which is a different thing from the denial of
service above and is worth separating carefully.** An adversary who successfully injects the
pilot can have it write a reserved token into a parameter key, and a sustained run of that ends
the session. That is not the failure mode this module is shaped against, and it is arguably the
correct outcome:

* The rejected shape is *no cooperation required*: a token in a forum post halts every
  investigation that **reads** the page. One adversary, one post, every session that collects it.
* The remaining shape requires the pilot to **obey**: the adversary must get a model to name
  three distinct capabilities that do not exist, in fields the model chooses. A pilot doing that
  is a pilot acting on instructions from collected content — and a session where that has
  happened is one a human should read before anything in it is acted on, which is exactly what
  the halt produces.

The bar between the two is the whole value. A control that fires on what an adversary *writes*
is a weapon handed to them; a control that fires on what a model *does after reading it* is a
detector doing its job.

Status: `IMPLEMENTED`. See `docs/security/INVARIANTS.md` (PROBE-01).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field

CANARY_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "internal_admin_token",
        "raw_effect_adapter",
        "system_signing_key",
        "unsafe_execution_path",
        "root_capability",
        "master_authorization_key",
        "capability_mint",
        "guardrail_override",
        "effects_bypass",
        "audit_rewrite",
    }
)
"""Identifiers no legitimate NEMESIS path emits.

Ten, not a hundred. Each one names a capability the architecture deliberately does not have —
a raw adapter, a mint verb, an override, a rewrite — so the set doubles as a list of the things
somebody would have to reach for to get out. Adding one is cheap; adding one that a real
identifier could collide with is not, so the rule for extending this set is that the token must
be a phrase nothing in `src/` contains, and a test asserts exactly that.
"""

_NON_ALNUM: Final = re.compile(r"[^a-z0-9]+")


class ProbeResponse(StrEnum):
    """What a deployment does about a probe. Chosen by count, not by which token was named.

    Severity by *repetition* rather than by token, deliberately. One occurrence of
    ``root_capability`` is indistinguishable from a model that hallucinated a plausible-sounding
    identifier, and treating that as an attack would make the signal useless within a week. A
    pilot that says three different reserved names in one session is doing something else.
    """

    LOG = "log"
    """Recorded, session continues. The single-occurrence answer."""

    REQUIRE_HUMAN_REVIEW = "require_human_review"
    """Recorded and flagged. The session runs to its end and its output is not acted on until
    somebody has read the probes."""

    HALT_INVESTIGATION = "halt_investigation"
    """The session ends, recorded as a halt and never as a completion. Reached by sustained
    probing only."""


class ControlBoundaryProbe(BaseModel):
    """One occurrence of a reserved identifier in a field an untrusted party authored.

    Carries where it was found as well as what was found, because the two questions an operator
    asks are "what did it reach for" and "through which verb", and a finding that answers only
    the first is one nobody can reproduce.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    token: Annotated[str, Field(min_length=1, max_length=64)]
    field_path: Annotated[str, Field(min_length=1, max_length=200)]
    observed_value: Annotated[str, Field(max_length=200)]
    """The identifier as it was written, bounded. Kept so a reader can see the form — the
    normalisation that matched it is not obvious from the token alone."""

    def describe(self) -> str:
        return f"{self.field_path} named the reserved identifier {self.token!r}"


def _normalise(value: str) -> str:
    """Lowercase, collapse every run of non-alphanumerics to one underscore, trim.

    So ``INTERNAL-ADMIN-TOKEN``, ``internal.admin.token`` and ``Internal Admin Token`` reduce to
    the same string. Digits are kept because an identifier may legitimately carry them and
    stripping them would merge ``root_capability`` with ``root_capability_2``, which is one
    probe pretending to be another.
    """
    return _NON_ALNUM.sub("_", value.lower()).strip("_")


def probe_findings(fields: Mapping[str, str]) -> tuple[ControlBoundaryProbe, ...]:
    """Reserved identifiers appearing in the identifier fields supplied. Empty is the normal case.

    The caller decides what goes in — and the caller's job is to pass *identifiers only*. This
    function has no way to tell an entity id from a message body, and passing the second would
    reintroduce the adversary-fired alarm this module's docstring exists to warn against.
    """
    findings: list[ControlBoundaryProbe] = []
    for path, value in sorted(fields.items()):
        if not value:
            continue
        normalised = _normalise(value)
        delimited = f"_{normalised}_"
        words = set(normalised.split("_"))
        for token in sorted(CANARY_TOKENS):
            # Whole-token match against the normalised form, three shapes and no more:
            #   the field IS the token; the token sits inside it delimited on both sides; or
            #   the token appears with its separators already gone (`RootCapability`, which
            #   normalises to one word because camelCase carries no delimiter).
            # A bare `in` would fire on any identifier that happened to contain the letters,
            # which is how a substring check becomes a false positive nobody can explain — the
            # defect the approval parser hit when `unapproved` matched `approve`.
            if delimited.find(f"_{token}_") >= 0 or token.replace("_", "") in words:
                findings.append(
                    ControlBoundaryProbe(
                        token=token, field_path=path[:200], observed_value=value[:200]
                    )
                )
    return tuple(findings)


DEFAULT_REVIEW_THRESHOLD: Final = 2
DEFAULT_HALT_THRESHOLD: Final = 3
"""How many probes in one session escalate, with the reasoning in the enum above.

Two and three, and both are choices rather than measurements — like every constant in this
repository they are frozen so they can be argued with. The gap between them is one probe on
purpose: an operator should see a session flagged for review before it is stopped, so the
stopping threshold is never the first time anyone hears about the behaviour.
"""


def response_for(
    probes: Iterable[ControlBoundaryProbe],
    *,
    review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
    halt_threshold: int = DEFAULT_HALT_THRESHOLD,
) -> ProbeResponse:
    """Grade a session's probes. Counts *distinct* tokens, not occurrences.

    Distinct, because a pilot that retries the same refused move three times is persistent and a
    pilot that names three different reserved capabilities is searching. Only the second is the
    behaviour this module was built to notice, and counting occurrences would score them the
    same.
    """
    distinct = {probe.token for probe in probes}
    if len(distinct) >= halt_threshold:
        return ProbeResponse.HALT_INVESTIGATION
    if len(distinct) >= review_threshold:
        return ProbeResponse.REQUIRE_HUMAN_REVIEW
    return ProbeResponse.LOG


class SessionProbeLog:
    """Accumulates a session's probes and says what to do about them.

    Mutable and tiny, held by whoever drives a session. It is not a security boundary and holds
    no authority — it counts, and the counting is the whole of it. A hostile pilot that could
    reach this object could at worst make its own probes invisible, which is why the object is
    constructed by the mediator and never handed to the pilot, in the same way the envelope is
    not.
    """

    __slots__ = ("_halt_threshold", "_probes", "_review_threshold")

    def __init__(
        self,
        *,
        review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
        halt_threshold: int = DEFAULT_HALT_THRESHOLD,
    ) -> None:
        self._probes: list[ControlBoundaryProbe] = []
        self._review_threshold = review_threshold
        self._halt_threshold = halt_threshold

    def observe(
        self, fields: Mapping[str, str], *, at: datetime | None = None
    ) -> tuple[ControlBoundaryProbe, ...]:
        """Scan one turn's identifier fields and keep whatever was found.

        ``at`` is accepted and unused on the probe itself: the *audit record* carries the time,
        and duplicating it here would create two clocks for one event that can disagree. The
        parameter stays so a caller reads naturally and so a future record that does need it has
        somewhere to take it from.
        """
        del at
        found = probe_findings(fields)
        self._probes.extend(found)
        return found

    @property
    def probes(self) -> tuple[ControlBoundaryProbe, ...]:
        return tuple(self._probes)

    @property
    def response(self) -> ProbeResponse:
        return response_for(
            self._probes,
            review_threshold=self._review_threshold,
            halt_threshold=self._halt_threshold,
        )

    @property
    def should_halt(self) -> bool:
        return self.response is ProbeResponse.HALT_INVESTIGATION


__all__ = [
    "CANARY_TOKENS",
    "DEFAULT_HALT_THRESHOLD",
    "DEFAULT_REVIEW_THRESHOLD",
    "ControlBoundaryProbe",
    "ProbeResponse",
    "SessionProbeLog",
    "probe_findings",
    "response_for",
]
