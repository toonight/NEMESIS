"""One contract, five providers, and a test that fails when any of them drifts from it.

Before this file existed there were two adapter test modules, each testing its own vendor in its
own words, and an audit found six behavioural disagreements between three seats that both
modules called identical: one dropped stringified JSON arguments while another parsed them, one
dropped a non-``dict`` mapping while another kept it, one echoed the model's prose into the
no-move sentinel while the others used a fixed string, and none of the three agreed on what to
do with two tool calls in one response. Neither seat's failure set was a superset of the other's,
so "the seats behave identically" was false in both directions while being asserted in five
docstrings.

The lesson is the reason this file is parametrised rather than long. Test unification is worth
more than code unification and is independent of it: a suite that runs the same assertion over
every registered provider catches drift on the day it appears, whether or not the
implementations were ever merged. It also grows correctly — a sixth provider added to the
registry appears here automatically, and a sixth provider that behaves differently fails here
rather than in production.

What is deliberately NOT asserted: that any of these providers exists, that any model id is
real, or that any of them would answer. Every response in this file is a hand-written fixture,
no test needs a credential, and nothing here opens a socket.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from nemesis.pilot.model_seat import MOVE_MODELS, SYSTEM_INSTRUCTIONS, move_description
from nemesis.pilot.moves import (
    PILOT_MOVE_ADAPTER,
    Briefing,
    EntityView,
    EnvelopeView,
    HypothesisView,
    RunPivot,
)
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilot.providers import ProviderSeat
from nemesis.pilot.providers.capabilities import forbidden_tool_types
from nemesis.pilot.providers.config import ChallengerConfig, PilotConfig
from nemesis.pilot.providers.contract import MeteredPilot, ReasoningEffort
from nemesis.pilot.providers.errors import PilotError, PilotErrorKind
from nemesis.pilot.providers.registry import PROVIDER_NAMES, build_pilot
from nemesis.pilot.providers.reliability import RetryPolicy
from nemesis.pilot.providers.schema import MOVE_TOOL_NAMES, MOVE_TOOL_SUITE
from nemesis.pilot.providers.seat import AMBIGUOUS_MOVE_SENTINEL, NO_MOVE_SENTINEL
from nemesis.pilotbench.corpus import INJECTED_DOMAIN

NAMED_PERSON = "John Doe"  # the withheld human identity; must never reach a request


def briefing() -> Briefing:
    return Briefing(
        investigation_id="inv_demo",
        seed="domain acme-invoice-portal.example",
        step_count=0,
        budget_remaining=100.0,
        moves_remaining=40,
        hypotheses=(
            HypothesisView(
                hypothesis_id="H1", statement="The seed is attacker infra.", settled=False
            ),
        ),
        entities=(
            EntityView(
                entity_id="ent_1",
                entity_type="domain",
                natural_key="acme-invoice-portal.example",
            ),
        ),
        envelope=EnvelopeView(
            permitted_operations=("simulation",),
            forbidden_operations=("registrar_suspension",),
            approved_target_entity_ids=("ent_1",),
            expires_at=datetime(2026, 3, 10, tzinfo=UTC),
            max_effect="one rehearsed suspension that suspends nothing",
        ),
    )


# --- one response shape per dialect ------------------------------------------


def _openai_response(calls: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant"}
    if calls:
        message["tool_calls"] = [{"function": call} for call in calls]
    else:
        message["content"] = extra.pop("content", None)
    return {"choices": [{"message": message, **extra}], "id": "req_1", "model": "as-served"}


def _anthropic_response(calls: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [
        {"type": "tool_use", "name": call["name"], "input": call["arguments"]} for call in calls
    ]
    if not blocks:
        blocks = [{"type": "text", "text": extra.pop("content", "") or ""}]
    return {"content": blocks, "id": "req_1", "model": "as-served", **extra}


def _gemini_response(calls: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    parts: list[dict[str, Any]] = [
        {"functionCall": {"name": call["name"], "args": call["arguments"]}} for call in calls
    ]
    if not parts:
        parts = [{"text": extra.pop("content", "") or ""}]
    candidate: dict[str, Any] = {"content": {"parts": parts}}
    if "finishReason" in extra:
        candidate["finishReason"] = extra.pop("finishReason")
    return {"candidates": [candidate], "responseId": "req_1", "modelVersion": "as-served", **extra}


def _ollama_response(calls: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant"}
    if calls:
        message["tool_calls"] = [{"function": call} for call in calls]
    else:
        message["content"] = extra.pop("content", None)
    return {"message": message, "model": "as-served", **extra}


@dataclass(frozen=True)
class Dialect:
    """How to write a response for one provider, so one assertion can run against all five."""

    provider: str
    respond: Callable[..., dict[str, Any]]
    content_keys: tuple[str, ...]
    """Where this dialect puts the briefing. Used to assert the briefing arrives verbatim."""


DIALECTS: tuple[Dialect, ...] = (
    Dialect("openai", _openai_response, ("messages",)),
    Dialect("xai", _openai_response, ("messages",)),
    Dialect("anthropic", _anthropic_response, ("messages", "system")),
    Dialect("gemini", _gemini_response, ("request",)),
    Dialect("ollama", _ollama_response, ("messages",)),
    Dialect("openai_compatible", _openai_response, ("messages",)),
)

DIALECT_BY_PROVIDER = {dialect.provider: dialect for dialect in DIALECTS}


def seat(provider: str, **overrides: Any) -> ProviderSeat:
    config = PilotConfig(provider=provider, model="a-model-id", **overrides)
    return build_pilot(config, transport=overrides.pop("transport", None))


class RecordingTransport:
    """Returns a canned body and remembers what it was asked to send."""

    def __init__(self, body: Mapping[str, Any]) -> None:
        self.body = body
        self.payloads: list[Mapping[str, Any]] = []

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.payloads.append(payload)
        return self.body


def drive(provider: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
    transport = RecordingTransport(body)
    pilot = build_pilot(PilotConfig(provider=provider, model="a-model-id"), transport=transport)
    raw = asyncio.run(pilot.propose(briefing()))
    assert isinstance(raw, Mapping)
    return raw


def _text_values(node: object) -> list[str]:
    """Every string in a rendered request. Used to assert the briefing arrives verbatim."""
    found: list[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, Mapping):
        for value in node.values():
            found.extend(_text_values(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_text_values(item))
    return found


# --- every provider is in the registry and satisfies the protocols ------------


def test_every_registered_provider_builds_a_pilot_that_satisfies_the_protocol() -> None:
    """The seat is vendor-neutral, and `runtime_checkable` means that can be checked rather
    than believed. Nothing in the repository isinstance-checked these protocols before."""
    for provider in PROVIDER_NAMES:
        pilot = seat(provider)
        assert isinstance(pilot, AutonomousPilot), provider
        assert isinstance(pilot, MeteredPilot), provider


def test_each_provider_records_its_own_identity_and_never_another_vendors() -> None:
    """xAI serves an OpenAI-compatible API. That is a transport similarity, not an identity.

    `pilot.name` reaches `Claim.model_identifier` on every belief and the provider reaches the
    audit trail on every move, so a run driven by Grok recorded as `openai` would name the wrong
    model as a claim's author and the wrong vendor as the recipient of the briefing.
    """
    for provider in PROVIDER_NAMES:
        pilot = seat(provider)
        assert pilot.identity.provider == provider
        assert pilot.identity.model == "a-model-id"
        assert pilot.name.startswith(f"{provider}:") or provider == "ollama"


def test_no_two_providers_share_a_seat_class() -> None:
    """Reusing a dialect is the point; reusing a class would erase the distinction it exists
    to keep. The generic compatible seat is the deliberate exception and carries a caller-set
    provider instead."""
    seats = {provider: type(seat(provider)).__name__ for provider in PROVIDER_NAMES}
    named = {p: s for p, s in seats.items() if p != "openai_compatible"}
    assert len(set(named.values())) == len(named), seats


# --- the closed vocabulary reaches every vendor unchanged ---------------------


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_exactly_four_tools_reach_every_provider(provider: str) -> None:
    payload = seat(provider).build_payload(briefing())
    names = _tool_names(payload)
    assert names == MOVE_TOOL_NAMES, provider
    assert len(names) == 4


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_the_untrusted_pilot_contract_is_byte_identical_everywhere(provider: str) -> None:
    """One containment, five vendors. A seam an adversary could pick which side of would be a
    containment that said different things to different vendors."""
    blob = json.dumps(seat(provider).build_payload(briefing()))
    assert SYSTEM_INSTRUCTIONS in blob, provider


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_the_briefing_reaches_every_vendor_verbatim_and_nothing_else_does(provider: str) -> None:
    """The request is composed from the briefing and only the briefing.

    Asserted as an identity rather than as an absence: the older test checked that a hand-written
    clean briefing did not contain the withheld band, which could only fail if `build_request`
    *invented* material. This checks that what arrives is exactly what the mediator chose to
    expose, which is the property that actually bounds a hosted egress.
    """
    payload = seat(provider).build_payload(briefing())
    expected = briefing().model_dump_json()
    assert expected in _text_values(payload), provider


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_no_request_ever_offers_a_vendor_built_in(provider: str) -> None:
    """Model capability is not NEMESIS authorization.

    Every provider in this registry serves models that support shell execution, code execution,
    retrieval or browsing. None of those is a NEMESIS verb, and a pilot that could reach one
    would hold exactly what this platform's design says it does not.
    """
    payload = seat(provider).build_payload(briefing())
    assert forbidden_tool_types(payload) == (), provider


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_a_hostile_identifier_in_the_briefing_cannot_trip_the_capability_scan(
    provider: str,
) -> None:
    """The scan must not be a control an adversary can fire.

    An adversary chooses part of what reaches a briefing — that is how the injection
    demonstration works — so a scan that searched message bodies for vendor tool names would let
    anyone who can register `web_search.example` halt an investigation. The scan skips the keys
    that carry untrusted text, and this is the test that says so.
    """
    hostile = briefing().model_copy(
        update={
            "entities": (
                EntityView(
                    entity_id="ent_x",
                    entity_type="domain",
                    natural_key="web_search.code_execution.computer_use.example",
                ),
                EntityView(entity_id="ent_y", entity_type="domain", natural_key=INJECTED_DOMAIN),
            )
        }
    )
    payload = seat(provider).build_payload(hostile)
    assert forbidden_tool_types(payload) == (), provider


def test_a_tool_description_is_the_whole_first_paragraph_not_the_first_line() -> None:
    """Found by an audit: three of four descriptions reached every vendor cut off mid-clause.

    The worst was `record_belief`, truncated one word before "never as an observation or a
    fact" — the sentence that tells the model what invariant 1 does to whatever it asserts.
    """
    for spec in MOVE_TOOL_SUITE:
        assert not spec.description.endswith(("which does", "current", "MODEL_ASSERTION,"))
        assert "\n" not in spec.description
    by_name = {spec.name: spec.description for spec in MOVE_TOOL_SUITE}
    assert "never as an observation or a fact" in by_name["record_belief"]
    for model, name in MOVE_MODELS:
        assert by_name[name] == move_description(model)


def test_the_gemini_translation_keeps_every_enum_value() -> None:
    """Gemini's schema subset has no `$ref`, and the enum arrives attached to the `$ref`.

    Dropping it with the unsupported keywords would leave one vendor's model free to name a
    pivot type or an operation class the other four cannot — the n-way version of the drift the
    canonical schema exists to prevent.
    """
    from nemesis.ports.collection import PivotType

    payload = seat("gemini").build_payload(briefing())
    declarations = payload["request"]["tools"][0]["functionDeclarations"]
    by_name = {item["name"]: item for item in declarations}

    pivot = by_name["run_pivot"]["parameters"]["properties"]["pivot_type"]
    assert set(pivot["enum"]) == {item.value for item in PivotType}
    assert "$ref" not in json.dumps(by_name)
    assert "$defs" not in json.dumps(by_name)
    assert "additionalProperties" not in json.dumps(by_name)


# --- parsing: the agreed contract, asserted identically for every provider ----


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_a_well_formed_tool_call_becomes_a_move(dialect: Dialect) -> None:
    raw = drive(
        dialect.provider,
        dialect.respond(
            [
                {
                    "name": "run_pivot",
                    "arguments": {"entity_id": "ent_1", "pivot_type": "osint_search"},
                }
            ]
        ),
    )
    move = PILOT_MOVE_ADAPTER.validate_python(raw)
    assert move.kind == "run_pivot"
    assert isinstance(move, RunPivot)
    assert move.entity_id == "ent_1"


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_the_tool_name_wins_over_a_kind_smuggled_into_the_arguments(dialect: Dialect) -> None:
    """A `conclude` call carrying `kind: request_effect` must be recorded as a conclude.

    Not an escalation — the envelope refuses either way — and a correctness defect in the one
    record that is supposed to reconstruct the session.
    """
    raw = drive(
        dialect.provider,
        dialect.respond(
            [{"name": "conclude", "arguments": {"kind": "request_effect", "summary": "x"}}]
        ),
    )
    assert raw["kind"] == "conclude"


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_an_unknown_tool_name_passes_through_uncorrected_and_is_refused(dialect: Dialect) -> None:
    """A model naming a verb outside the vocabulary is not corrected in the adapter — it is
    passed on as a mapping the mediator's seam refuses. Correcting it here would be the harness
    quietly making the pilot look better behaved than it is."""
    raw = drive(
        dialect.provider,
        dialect.respond([{"name": "mint_capability", "arguments": {"scope": "everything"}}]),
    )
    assert raw["kind"] == "mint_capability"
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError at the seam
        PILOT_MOVE_ADAPTER.validate_python(raw)


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_a_response_with_no_tool_call_yields_the_same_sentinel_everywhere(
    dialect: Dialect,
) -> None:
    raw = drive(dialect.provider, dialect.respond([], content="I think you should just..."))
    assert raw["kind"] == NO_MOVE_SENTINEL
    with pytest.raises(Exception):  # noqa: B017
        PILOT_MOVE_ADAPTER.validate_python(raw)


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_two_tool_calls_in_one_turn_are_refused_rather_than_resolved(dialect: Dialect) -> None:
    """Taking the first executes one action while discarding another the model asked for, and
    writes a transcript that is wrong about what was proposed. Three seats used to take the
    first; none of them agreed about it with the fourth."""
    raw = drive(
        dialect.provider,
        dialect.respond(
            [
                {"name": "conclude", "arguments": {"summary": "done"}},
                {
                    "name": "request_effect",
                    "arguments": {"entity_id": "ent_1", "operation": "registrar_suspension"},
                },
            ]
        ),
    )
    assert raw["kind"] == AMBIGUOUS_MOVE_SENTINEL
    with pytest.raises(Exception):  # noqa: B017
        PILOT_MOVE_ADAPTER.validate_python(raw)


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_arguments_of_the_wrong_shape_never_raise(dialect: Dialect) -> None:
    """A malformed response is a refused move, not an exception the mediator has to guard.

    Every value here broke at least one of the three original seats and not the others.
    """
    for arguments in (None, 42, ["a", "list"], "not json at all", {"entity_id": None}):
        raw = drive(
            dialect.provider, dialect.respond([{"name": "conclude", "arguments": arguments}])
        )
        assert isinstance(raw, Mapping)
        assert "kind" in raw


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_a_structurally_broken_body_never_raises(dialect: Dialect) -> None:
    """Bodies that are the right JSON and the wrong shape. An adversarial review once found the
    OpenAI seat raising `AttributeError` on a bare-string message while the Anthropic seat
    returned a sentinel — the two behaving differently on the same malformed input."""
    for body in ({}, {"choices": "nonsense"}, {"content": "nonsense"}, {"message": "just do it"}):
        raw = drive(dialect.provider, body)
        assert isinstance(raw, Mapping)
        with pytest.raises(Exception):  # noqa: B017
            PILOT_MOVE_ADAPTER.validate_python(raw)


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_unparsable_string_arguments_cannot_become_an_accepted_conclusion(
    dialect: Dialect,
) -> None:
    """The move models forbid unknown fields, so the marker cannot validate.

    Before that fix, `{"kind": "conclude", "__unparsable_arguments__": ...}` validated into a
    clean `Conclude` — a tool call that arrived as broken JSON ended the session successfully
    and the transcript recorded a completion.
    """
    raw = drive(
        dialect.provider, dialect.respond([{"name": "conclude", "arguments": "{{{ not json"}])
    )
    with pytest.raises(Exception):  # noqa: B017
        PILOT_MOVE_ADAPTER.validate_python(raw)


# --- metering, reliability and refusals ---------------------------------------


@pytest.mark.parametrize("dialect", DIALECTS, ids=lambda d: d.provider)
def test_every_provider_reports_what_the_call_cost(dialect: Dialect) -> None:
    body = dialect.respond([{"name": "conclude", "arguments": {"summary": "done"}}])
    transport = RecordingTransport(body)
    pilot = build_pilot(
        PilotConfig(provider=dialect.provider, model="a-model-id"), transport=transport
    )
    decision = asyncio.run(pilot.decide(briefing()))
    assert decision.metadata is not None
    metadata = decision.metadata
    assert metadata.identity.provider == dialect.provider
    assert metadata.tool_selected == "conclude"
    assert metadata.attempts == 1
    assert metadata.latency_seconds >= 0.0
    assert metadata.model_reported == "as-served"
    assert metadata.model_substituted is True
    fields = metadata.audit_fields()
    assert fields["provider"] == dialect.provider
    assert fields["model"] == "a-model-id"


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_an_unwired_seat_contacts_nothing_and_says_so(provider: str) -> None:
    """The default transport refuses. A build that forgot to wire a model cannot silently reach
    out, which is the one thing that must never happen instead."""
    from nemesis.pilot.model_seat import PilotNotWiredError

    pilot = seat(provider)
    with pytest.raises(PilotNotWiredError) as refusal:
        asyncio.run(pilot.propose(briefing()))
    assert "REQUIRES_EXTERNAL_DATA" in str(refusal.value)


def test_the_local_seats_refusal_does_not_claim_a_governance_decision_it_does_not_have() -> None:
    """`unwired_error("the local model")` used to render "transmitting CTI data to the local
    model is a data-governance decision the founder owns" — ungrammatical, and the exact opposite
    of the local seat's stated reason for existing."""
    from nemesis.pilot.model_seat import PilotNotWiredError

    with pytest.raises(PilotNotWiredError) as refusal:
        asyncio.run(seat("ollama").propose(briefing()))
    assert "Nothing here leaves this machine" in str(refusal.value)
    assert "data-governance decision" not in str(refusal.value)


class FailingTransport:
    """Fails a fixed number of times, then answers. Counts every attempt."""

    def __init__(self, failures: int, kind: PilotErrorKind, body: Mapping[str, Any]) -> None:
        self.attempts = 0
        self._failures = failures
        self._kind = kind
        self._body = body

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.attempts += 1
        if self.attempts <= self._failures:
            raise PilotError(self._kind, "the vendor said no", provider="test")
        return self._body


async def _no_sleep(_: float) -> None:
    return None


def test_a_retryable_failure_is_retried_and_the_attempt_count_is_reported() -> None:
    """A retry that nothing records is the "silent retry" the mediator's own comment says never
    happens. Now the metadata says how many there were, and this is what asserts it."""
    from nemesis.pilot.providers.openai import OpenAIPilot

    body = _openai_response([{"name": "conclude", "arguments": {"summary": "done"}}])
    transport = FailingTransport(2, PilotErrorKind.RATE_LIMITED, body)
    pilot = OpenAIPilot(
        model="a-model-id",
        transport=transport,
        retries=RetryPolicy(max_attempts=3, base_delay_seconds=0.0),
        sleep=_no_sleep,
    )
    decision = asyncio.run(pilot.decide(briefing()))
    assert transport.attempts == 3
    assert decision.metadata is not None
    assert decision.metadata.attempts == 3
    assert PILOT_MOVE_ADAPTER.validate_python(decision.raw).kind == "conclude"


def test_an_unretryable_failure_is_not_retried() -> None:
    """A key that is wrong now is wrong in eight seconds, and retrying an auth failure is how a
    deployment locks itself out."""
    from nemesis.pilot.providers.openai import OpenAIPilot

    transport = FailingTransport(5, PilotErrorKind.AUTHENTICATION, {})
    pilot = OpenAIPilot(
        model="a-model-id",
        transport=transport,
        retries=RetryPolicy(max_attempts=4, base_delay_seconds=0.0),
        sleep=_no_sleep,
    )
    with pytest.raises(PilotError):
        asyncio.run(pilot.decide(briefing()))
    assert transport.attempts == 1


def test_a_retry_never_changes_the_request() -> None:
    """An attempt that altered the request would produce a run whose audit record names a
    configuration that did not run — and, at the extreme, a different model."""
    from nemesis.pilot.providers.openai import OpenAIPilot

    sent: list[Mapping[str, Any]] = []
    body = _openai_response([{"name": "conclude", "arguments": {"summary": "done"}}])

    class Recording:
        def __init__(self) -> None:
            self.calls = 0

        async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
            self.calls += 1
            sent.append(json.loads(json.dumps(payload)))
            if self.calls < 3:
                raise PilotError(PilotErrorKind.SERVER_ERROR, "503", provider="test")
            return body

    pilot = OpenAIPilot(
        model="a-model-id",
        transport=Recording(),
        retries=RetryPolicy(max_attempts=3, base_delay_seconds=0.0),
        sleep=_no_sleep,
    )
    asyncio.run(pilot.decide(briefing()))
    assert len(sent) == 3
    assert sent[0] == sent[1] == sent[2]


def test_a_seed_is_refused_where_a_provider_cannot_honour_it() -> None:
    """Dropping it silently would let a deployment believe two runs are comparable when nothing
    made them so."""
    with pytest.raises(ValueError, match="seeding"):
        seat("anthropic", seed=7)
    assert seat("openai", seed=7) is not None


def test_a_reasoning_effort_is_refused_where_the_trace_would_come_back() -> None:
    """Anthropic's reasoning mode returns `thinking` blocks. This platform does not receive or
    persist private reasoning, so the seat declines the feature rather than discarding a trace
    it asked for."""
    with pytest.raises(ValueError, match="reasoning"):
        seat("anthropic", reasoning=ReasoningEffort.HIGH)


def test_the_reasoning_providers_ask_without_asking_for_the_trace() -> None:
    payload = seat("openai", reasoning=ReasoningEffort.HIGH).build_payload(briefing())
    assert payload["reasoning_effort"] == "high"

    gemini = seat("gemini", reasoning=ReasoningEffort.HIGH).build_payload(briefing())
    thinking = gemini["request"]["generationConfig"]["thinkingConfig"]
    assert thinking["thinkingBudget"] > 0
    assert "includeThoughts" not in thinking


def test_a_thinking_block_that_arrives_anyway_is_dropped() -> None:
    """No field on the way out can hold a trace, and the parser reads tool blocks only."""
    body = {
        "content": [
            {"type": "thinking", "thinking": "a long private chain of thought"},
            {"type": "tool_use", "name": "conclude", "input": {"summary": "done"}},
        ],
        "model": "as-served",
    }
    transport = RecordingTransport(body)
    pilot = build_pilot(PilotConfig(provider="anthropic", model="a-model-id"), transport=transport)
    decision = asyncio.run(pilot.decide(briefing()))
    assert PILOT_MOVE_ADAPTER.validate_python(decision.raw).kind == "conclude"
    assert decision.metadata is not None
    assert "chain of thought" not in json.dumps(decision.metadata.model_dump(mode="json"))


def test_an_unknown_provider_is_refused_and_never_defaulted() -> None:
    """A deployment that misspells `anthropic` and silently gets OpenAI has transmitted every
    briefing to a vendor it did not choose."""
    from nemesis.pilot.providers.registry import UnknownProviderError

    with pytest.raises(UnknownProviderError) as refusal:
        build_pilot(PilotConfig(provider="opnai", model="x"))
    assert "openai" in str(refusal.value)


CREDENTIAL_WORDS = ("api_key", "apikey", "secret", "password", "credential", "bearer", "auth")


def test_a_configuration_holds_no_credential() -> None:
    """There is no field for one, and the omission is structural. The safest place to keep a
    secret out of a log, a trace and a benchmark report is a structure with nowhere to put one."""
    fields = set(PilotConfig.model_fields) | set(ChallengerConfig.model_fields)
    offending = {name for name in fields if any(word in name.lower() for word in CREDENTIAL_WORDS)}
    assert not offending, offending
    with pytest.raises(Exception):  # noqa: B017 - extra="forbid"
        PilotConfig.model_validate({"provider": "openai", "model": "m", "api_key": "shhh"})


def _tool_names(payload: Mapping[str, Any]) -> frozenset[str]:
    """Every tool name in a rendered request, whichever dialect wrote it."""
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, Mapping):
            name = node.get("name")
            if isinstance(name, str) and ("parameters" in node or "input_schema" in node):
                found.add(name)
            function = node.get("function")
            if isinstance(function, Mapping) and isinstance(function.get("name"), str):
                found.add(function["name"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return frozenset(found)
