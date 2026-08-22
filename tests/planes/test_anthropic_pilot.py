"""The concrete Anthropic-backed pilot: the mirror of the OpenAI seat, in Anthropic's dialect,
tested without ever contacting anything.

The two seats must say the same thing to two vendors — same closed vocabulary, same
untrusted-pilot contract, same briefing minimization — so these tests deliberately parallel
``test_openai_pilot.py`` and add the one dialect difference: a ``tool_use`` block whose ``input``
is already an object.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from nemesis.pilot.anthropic_pilot import (
    AnthropicPilot,
    anthropic_tool_schemas,
    build_request,
    parse_tool_use,
)
from nemesis.pilot.model_seat import SYSTEM_INSTRUCTIONS, PilotNotWiredError
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


def _response(name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "Here is my move."},
            {"type": "tool_use", "name": name, "input": tool_input},
        ],
    }


# --- The closed vocabulary, expressed as Anthropic tools ----------------------


def test_the_four_moves_are_exactly_four_tools() -> None:
    tools = anthropic_tool_schemas()
    assert {t["name"] for t in tools} == {
        "run_pivot",
        "record_belief",
        "request_effect",
        "conclude",
    }
    assert len(tools) == 4
    # Anthropic's dialect: the schema is under input_schema, and kind is dropped.
    for tool in tools:
        assert "input_schema" in tool
        assert "kind" not in tool["input_schema"]["properties"]


# --- A tool use becomes a move, validated at the seam -------------------------


def test_a_tool_use_parses_into_a_valid_move() -> None:
    move = PILOT_MOVE_ADAPTER.validate_python(
        parse_tool_use(
            _response("run_pivot", {"entity_id": "ent_1", "pivot_type": "resolution_history"})
        )
    )
    assert isinstance(move, RunPivot)
    assert move.entity_id == "ent_1"


def test_a_request_effect_tool_use_parses() -> None:
    move = PILOT_MOVE_ADAPTER.validate_python(
        parse_tool_use(
            _response("request_effect", {"entity_id": "ent_1", "operation": "simulation"})
        )
    )
    assert isinstance(move, RequestEffect)
    assert move.operation.value == "simulation"


def test_a_conclude_tool_use_parses() -> None:
    move = PILOT_MOVE_ADAPTER.validate_python(
        parse_tool_use(_response("conclude", {"summary": "done"}))
    )
    assert isinstance(move, Conclude)


def test_an_unknown_tool_name_is_refused_at_the_seam() -> None:
    raw = parse_tool_use(_response("mint_capability", {"operation": "domain_seizure"}))
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError at the seam
        PILOT_MOVE_ADAPTER.validate_python(raw)


def test_the_tool_name_wins_over_a_kind_smuggled_into_the_input() -> None:
    """The tool name is authoritative for the verb; a `kind` in the input must not override it,
    or the audit trail would name the wrong verb."""
    raw = parse_tool_use(
        _response("conclude", {"kind": "request_effect", "entity_id": "ent_1", "summary": "x"})
    )
    assert raw["kind"] == "conclude"


def test_a_response_with_no_tool_use_yields_a_non_move() -> None:
    raw = parse_tool_use({"stop_reason": "end_turn", "content": [{"type": "text", "text": "hmm"}]})
    with pytest.raises(Exception):  # noqa: B017
        PILOT_MOVE_ADAPTER.validate_python(raw)


# --- What leaves for Anthropic is bounded by the briefing ---------------------


def test_the_request_is_built_only_from_the_briefing() -> None:
    request = build_request(_briefing(), model="claude-cyber")

    assert request["model"] == "claude-cyber"
    # `disable_parallel_tool_use` was added when the seam grew to five providers: exactly one
    # action per turn, asked for at the vendor as well as enforced at the parser. Taking the
    # first of several requested actions executes one and discards another the model asked for,
    # and writes a transcript that is wrong about what was proposed.
    assert request["tool_choice"] == {"type": "any", "disable_parallel_tool_use": True}
    assert request["system"] == SYSTEM_INSTRUCTIONS
    assert {t["name"] for t in request["tools"]} == {
        "run_pivot",
        "record_belief",
        "request_effect",
        "conclude",
    }
    assert "acme-invoice-portal.example" in request["messages"][0]["content"]


def test_the_request_never_carries_the_withheld_band() -> None:
    import json

    blob = json.dumps(build_request(_briefing(), model="claude-cyber"))
    assert NAMED_PERSON not in blob
    assert "same_operator_as" not in blob
    assert "persona_linkage" not in blob


# --- An unwired build contacts nothing ----------------------------------------


def test_an_unwired_pilot_contacts_nothing_and_raises() -> None:
    pilot = AnthropicPilot(model="claude-cyber")
    assert pilot.name == "anthropic:claude-cyber"
    with pytest.raises(PilotNotWiredError):
        asyncio.run(pilot.propose(_briefing()))


def test_a_wired_transport_drives_a_move() -> None:
    class FakeTransport:
        async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
            assert payload["model"] == "claude-cyber"
            assert payload["system"] == SYSTEM_INSTRUCTIONS
            return _response("conclude", {"summary": "nothing to add"})

    pilot = AnthropicPilot(model="claude-cyber", transport=FakeTransport())
    raw = asyncio.run(pilot.propose(_briefing()))
    assert PILOT_MOVE_ADAPTER.validate_python(raw).kind == "conclude"
