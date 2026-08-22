"""The three commands this work added, exercised — including the one that must send nothing.

`nemesis pilot-preview` exists so a founder decision about transmitting CTI data to a vendor can
be made by *reading what would leave the building* rather than imagining it. A command with that
job has to be tested for the thing it promises: that it renders a real request and opens no
socket. The rest is ordinary CLI surface, tested because an operator console that crashes on a
misspelled provider name is a console nobody trusts with the ones spelled right.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from nemesis.cli.main import app
from nemesis.collect.fixtures.glass_anvil import NAMED_PERSON
from nemesis.pilot.model_seat import SYSTEM_INSTRUCTIONS
from nemesis.pilot.providers.registry import PROVIDER_NAMES

runner = CliRunner()


def test_providers_lists_every_registered_provider_and_no_credential() -> None:
    result = runner.invoke(app, ["providers"])
    assert result.exit_code == 0, result.output
    for provider in PROVIDER_NAMES:
        assert provider in result.output
    assert "OPENAI_API_KEY" in result.output
    assert "GOOGLE_API_KEY" in result.output
    # The variable NAME, never a value. Nothing here reads the environment.
    assert "sk-" not in result.output
    assert "capability is not NEMESIS authorization" in result.output


@pytest.mark.parametrize("provider", PROVIDER_NAMES)
def test_pilot_preview_renders_a_real_request_and_sends_nothing(provider: str) -> None:
    """Every provider, because the point of the command is comparing what each would transmit."""
    result = runner.invoke(app, ["pilot-preview", "--provider", provider, "--model", "a-model-id"])
    assert result.exit_code == 0, result.output
    assert "a-model-id" in result.output
    assert "REQUIRES_EXTERNAL_DATA" in result.output
    assert "no transport is wired" in result.output
    # The briefing really is in there, and so is the untrusted-pilot contract. Whitespace is
    # normalised because Rich wraps the rendered JSON to the console width — an exact substring
    # check would pass or fail on the terminal size, which is not a property worth asserting.
    flattened = " ".join(result.output.split())
    assert "acme-invoice-portal.example" in result.output
    assert " ".join(SYSTEM_INSTRUCTIONS.split())[:80] in flattened
    # And the withheld band is not.
    assert NAMED_PERSON not in result.output
    assert "persona_linkage" not in result.output
    assert "internal-class material" in result.output


def test_pilot_preview_refuses_an_unknown_provider_without_defaulting() -> None:
    result = runner.invoke(app, ["pilot-preview", "--provider", "opnai", "--model", "x"])
    assert result.exit_code == 2
    assert "opnai" in result.output
    assert "openai" in result.output


def test_pilot_preview_refuses_a_configuration_the_seat_cannot_honour() -> None:
    """Anthropic's reasoning mode returns the trace, so a reasoning effort is refused loudly
    rather than dropped — and the CLI has to report that rather than crash on it."""
    result = runner.invoke(
        app,
        ["pilot-preview", "--provider", "anthropic", "--model", "m", "--reasoning", "high"],
    )
    assert result.exit_code == 2
    assert "reasoning" in result.output.lower()


def test_pilotbench_runs_offline_and_prints_the_caveats_first() -> None:
    result = runner.invoke(app, ["pilotbench", "--scenario", "baseline_infrastructure"])
    assert result.exit_code == 0, result.output
    caveats = result.output.index("WHAT THIS BENCHMARK CANNOT TELL YOU")
    numbers = result.output.index("AGREEMENT WITH THE CORPUS")
    assert caveats < numbers
    assert "CONTROL-PLANE PROPERTIES" in result.output


def test_pilotbench_refuses_an_unknown_scenario() -> None:
    result = runner.invoke(app, ["pilotbench", "--scenario", "not_a_scenario"])
    assert result.exit_code == 2
    assert "baseline_infrastructure" in result.output


def test_pilotbench_refuses_providers_without_a_model() -> None:
    """A provider without a model is not a pilot, and guessing one would be this repository
    asserting which models exist."""
    result = runner.invoke(app, ["pilotbench", "--providers", "openai"])
    assert result.exit_code == 2
    assert "--model" in result.output


def test_pilotbench_with_an_unwired_provider_reports_it_rather_than_scoring_it() -> None:
    """A provider nobody wired produces a session whose every move is a refusal — which is the
    demonstration that provider failure cannot weaken policy enforcement, and must not read as a
    cautious model."""
    result = runner.invoke(
        app,
        [
            "pilotbench",
            "--providers",
            "openai",
            "--model",
            "a-model-id",
            "--scenario",
            "baseline_infrastructure",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "openai" in result.output
    assert "[PASS]" in result.output
