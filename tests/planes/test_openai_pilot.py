"""The concrete OpenAI-backed pilot: the seat shaped for the specific model NEMESIS is built
for, tested without ever contacting anything.

The adapter is pure but for one injected boundary — the transport — so everything here is a
unit test over the request it builds and the tool call it parses, plus the one property that
matters most for a *hosted* model: what leaves for OpenAI is bounded by the briefing, and an
unwired build contacts nothing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from nemesis.pilot.moves import (
    PILOT_MOVE_ADAPTER,
    Briefing,
    Conclude,
    EntityView,
    EnvelopeView,
    HypothesisView,
    RequestEffect,
    RunPivot,
)
from nemesis.pilot.openai_pilot import (
    SYSTEM_INSTRUCTIONS,
    OpenAIPilot,
    PilotNotWiredError,
    build_request,
    move_tool_schemas,
    parse_tool_call,
)

NAMED_PERSON = "John Doe"  # the withheld human identity; must never reach a request


def _briefing() -> Briefing:
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


def _response(name: str, arguments: Any) -> dict[str, Any]:
    return {
        "choices": [
            {"message": {"tool_calls": [{"function": {"name": name, "arguments": arguments}}]}}
        ]
    }


# --- The closed vocabulary, expressed as OpenAI tools -------------------------


def test_the_four_moves_are_exactly_four_tools() -> None:
    tools = move_tool_schemas()
    names = {t["function"]["name"] for t in tools}
    assert names == {"run_pivot", "record_belief", "request_effect", "conclude"}
    assert len(tools) == 4


def test_the_tool_schemas_drop_kind_from_the_arguments() -> None:
    """The function name carries the verb; the model must not also have to write a
    discriminator, and must not be able to disagree with itself about which verb it called."""
    for tool in move_tool_schemas():
        params = tool["function"]["parameters"]
        assert "kind" not in params["properties"]
        assert "kind" not in params.get("required", [])


# --- A tool call becomes a move, validated at the seam -----------------------


def test_a_tool_call_parses_into_a_valid_move() -> None:
    move = PILOT_MOVE_ADAPTER.validate_python(
        parse_tool_call(
            _response("run_pivot", {"entity_id": "ent_1", "pivot_type": "resolution_history"})
        )
    )
    assert isinstance(move, RunPivot)
    assert move.entity_id == "ent_1"


def test_string_json_arguments_are_parsed() -> None:
    """OpenAI returns tool arguments as a JSON string; the adapter parses it."""
    move = PILOT_MOVE_ADAPTER.validate_python(
        parse_tool_call(
            _response("request_effect", '{"entity_id": "ent_1", "operation": "simulation"}')
        )
    )
    assert isinstance(move, RequestEffect)
    assert move.operation.value == "simulation"


def test_a_conclude_tool_call_parses() -> None:
    move = PILOT_MOVE_ADAPTER.validate_python(
        parse_tool_call(_response("conclude", {"summary": "done"}))
    )
    assert isinstance(move, Conclude)


def test_an_unknown_tool_name_is_refused_at_the_seam() -> None:
    """A model that names a verb outside the vocabulary is not corrected here — it is passed on
    as a mapping the mediator's seam refuses. The containment is the same as for any pilot."""
    raw = parse_tool_call(_response("mint_capability", {"operation": "domain_seizure"}))
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError at the seam
        PILOT_MOVE_ADAPTER.validate_python(raw)


def test_the_tool_name_wins_over_a_kind_smuggled_into_arguments() -> None:
    """A model that calls the `conclude` tool but puts `kind: request_effect` in its arguments
    must not have the arguments override the tool name — the audit trail would otherwise record
    the wrong verb. Not an escalation (the envelope refuses either way), but a correctness bug."""
    raw = parse_tool_call(
        _response("conclude", {"kind": "request_effect", "entity_id": "ent_1", "summary": "x"})
    )
    assert raw["kind"] == "conclude"


def test_a_response_with_no_tool_call_yields_a_non_move() -> None:
    """A model that answers in prose instead of calling a tool produces a mapping that cannot
    validate — a refused move, never a crash."""
    raw = parse_tool_call({"choices": [{"message": {"content": "I think you should just..."}}]})
    with pytest.raises(Exception):  # noqa: B017
        PILOT_MOVE_ADAPTER.validate_python(raw)


def test_a_non_dict_message_returns_the_sentinel_and_does_not_raise() -> None:
    """A malformed response whose `message` is a bare string must not raise (an adversarial
    review found it raised AttributeError, diverging from the Anthropic seat). It returns the
    no-move sentinel, identically to the Anthropic parser."""
    raw = parse_tool_call({"choices": [{"message": "just do it"}]})
    assert raw["kind"] == "__no_move__"
    with pytest.raises(Exception):  # noqa: B017
        PILOT_MOVE_ADAPTER.validate_python(raw)


# --- What leaves for OpenAI is bounded by the briefing -----------------------


def test_the_request_is_built_only_from_the_briefing() -> None:
    request = build_request(_briefing(), model="gpt-5.6-cyber")

    assert request["model"] == "gpt-5.6-cyber"
    assert request["tool_choice"] == "required"
    assert {t["function"]["name"] for t in request["tools"]} == {
        "run_pivot",
        "record_belief",
        "request_effect",
        "conclude",
    }
    # The untrusted-pilot contract is stated to the model, and the briefing is what it sees.
    assert request["messages"][0]["content"] == SYSTEM_INSTRUCTIONS
    assert "acme-invoice-portal.example" in request["messages"][1]["content"]


def test_the_request_never_carries_the_withheld_band() -> None:
    """The consequence of a *hosted* model: the request is transmitted to OpenAI. A clean
    briefing carries no persona linkage and no human identity, so neither reaches the wire —
    the same minimization as the HTTP surface, now guarding a third-party egress too."""
    import json

    blob = json.dumps(build_request(_briefing(), model="gpt-5.6-cyber"))
    assert NAMED_PERSON not in blob
    assert "same_operator_as" not in blob
    assert "persona_linkage" not in blob


# --- An unwired build contacts nothing ---------------------------------------


def test_an_unwired_pilot_contacts_nothing_and_raises() -> None:
    """No transport wired means no OpenAI call, loudly. The default is a refusal, so a build
    that forgot to wire the model cannot silently reach out — the one thing that must never
    happen instead."""
    pilot = OpenAIPilot(model="gpt-5.6-cyber")
    assert pilot.name == "openai:gpt-5.6-cyber"
    with pytest.raises(PilotNotWiredError):
        asyncio.run(pilot.propose(_briefing()))


def test_a_wired_transport_drives_a_move() -> None:
    """With a transport that returns a canned tool call, the pilot yields a move. The transport
    is the only impure part, and a test supplies it directly."""

    class FakeTransport:
        async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
            assert payload["model"] == "gpt-5.6-cyber"
            return _response("conclude", {"summary": "nothing to add"})

    pilot = OpenAIPilot(model="gpt-5.6-cyber", transport=FakeTransport())
    raw = asyncio.run(pilot.propose(_briefing()))
    assert PILOT_MOVE_ADAPTER.validate_python(raw).kind == "conclude"
