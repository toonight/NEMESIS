"""Opt-in live runs against real vendors, skipped by default and honest about what they prove.

Every other test in this repository builds a provider request and parses a hand-written
response. That is enough to pin the seam and is not enough to establish that a vendor accepts
the request — a tool schema that five unit tests agree on is still a tool schema no vendor has
ever seen. These tests close that gap and nothing else.

**Never part of CI, and never a silent pass.** Each is gated on *two* things: an explicit
``NEMESIS_LIVE_<PROVIDER>=1`` opt-in and the presence of the credential variable that provider's
transport reads. Missing either one is a skip with a reason, not a green dot — the vacuous pass
this repository keeps hunting. Running them costs money and transmits a briefing to a third
party, which is a data-governance decision the founder owns; the default is off precisely
because that decision is not this file's to make.

**The transport lives here, in the test suite.** No module under ``src/nemesis/pilot`` holds
network code: the rule is that only the collection plane holds network capability, and the pilot
plane — where an untrusted model's output arrives — is the last place that should also own a
socket. A laboratory wires one in, which is what this is, and it keeps every seat honestly
comparable rather than one being special.

**What a passing run establishes:** the vendor accepted the request, returned a tool call in the
shape the adapter parses, and the mediator ruled on the result. **What it does not:** anything
about the model's judgement, its resistance to injection, or its suitability. A run in which a
model behaves well proves it behaved well once. The containment claim rests on the scripted
hostile pilots, where the pilot obeys and still gets nothing.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

import pytest

from nemesis.pilot.moves import PILOT_MOVE_ADAPTER
from nemesis.pilot.pilot import AutonomousPilot
from nemesis.pilot.providers.config import PilotConfig
from nemesis.pilot.providers.errors import PilotError, kind_for_status
from nemesis.pilot.providers.ollama import DEFAULT_ENDPOINT as OLLAMA_ENDPOINT
from nemesis.pilot.providers.registry import PROVIDERS, build_pilot
from nemesis.pilotbench.corpus import BASELINE
from nemesis.pilotbench.harness import run_scenario
from nemesis.pilotbench.metrics import score_run

DEFAULT_TIMEOUT_SECONDS = 240.0


@dataclass(frozen=True)
class LiveEndpoint:
    """Where a provider lives and how a request is authenticated, for a laboratory run.

    The endpoints are here rather than in ``src`` for the same reason the transport is: a URL is
    half of an egress path, and the pilot plane holds neither half.
    """

    provider: str
    switch: str
    url: str
    auth_header: str = "Authorization"
    auth_format: str = "Bearer {credential}"
    model_in_url: bool = False

    @property
    def credential_variable(self) -> str:
        return PROVIDERS[self.provider].api_key_environment_variable

    def enabled(self) -> tuple[bool, str]:
        if os.environ.get(self.switch) != "1":
            return False, f"set {self.switch}=1 to run this provider live"
        if self.credential_variable and not os.environ.get(self.credential_variable):
            return False, f"{self.switch} is set but {self.credential_variable} is not"
        return True, ""


ENDPOINTS: tuple[LiveEndpoint, ...] = (
    LiveEndpoint(
        provider="openai",
        switch="NEMESIS_LIVE_OPENAI",
        url="https://api.openai.com/v1/chat/completions",
    ),
    LiveEndpoint(
        provider="xai",
        switch="NEMESIS_LIVE_XAI",
        url="https://api.x.ai/v1/chat/completions",
    ),
    LiveEndpoint(
        provider="anthropic",
        switch="NEMESIS_LIVE_ANTHROPIC",
        url="https://api.anthropic.com/v1/messages",
        auth_header="x-api-key",
        auth_format="{credential}",
    ),
    LiveEndpoint(
        provider="gemini",
        switch="NEMESIS_LIVE_GEMINI",
        url="https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        auth_header="x-goog-api-key",
        auth_format="{credential}",
        model_in_url=True,
    ),
    LiveEndpoint(
        provider="ollama",
        switch="NEMESIS_LIVE_OLLAMA",
        url=OLLAMA_ENDPOINT,
        auth_header="",
        auth_format="",
    ),
)

MODEL_VARIABLE = "NEMESIS_LIVE_MODEL_{provider}"
"""Which model to drive, supplied per provider by whoever runs this.

Deliberately not defaulted. This repository asserts nothing about which frontier models exist,
and a default model id in a test is a claim about a vendor's catalogue that is wrong within
months — the same reason no model id appears anywhere in ``src``.
"""


class LaboratoryTransport:
    """The one thing in this repository that opens a socket to a model vendor.

    Deliberately small and deliberately here. It classifies a failure into the shared taxonomy
    from the HTTP status so the retry policy behaves identically to every other test, and it
    never puts a header, a request body or a credential into an exception — a transport that
    reported "auth failed, here is what I sent" would be the leak the taxonomy exists to
    prevent.
    """

    def __init__(self, endpoint: LiveEndpoint, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._endpoint = endpoint
        self._timeout = timeout

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        endpoint = self._endpoint
        body: Mapping[str, Any] = payload
        url = endpoint.url
        if endpoint.model_in_url:
            # Gemini routes on the URL, so the seat hands back an envelope rather than a body.
            url = endpoint.url.format(model=payload["model"])
            body = cast(Mapping[str, Any], payload["request"])

        headers = {"Content-Type": "application/json"}
        if endpoint.auth_header:
            credential = os.environ.get(endpoint.credential_variable, "")
            headers[endpoint.auth_header] = endpoint.auth_format.format(credential=credential)
        if endpoint.provider == "anthropic":
            headers["anthropic-version"] = "2023-06-01"

        request = urllib.request.Request(  # noqa: S310 - fixed https endpoints from the table above
            url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as answer:  # noqa: S310
                parsed: Mapping[str, Any] = json.loads(answer.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise PilotError(
                kind_for_status(exc.code, message=detail),
                detail,
                provider=endpoint.provider,
                status=exc.code,
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise PilotError(
                kind_for_status(503),
                f"the endpoint did not answer ({type(exc).__name__})",
                provider=endpoint.provider,
            ) from exc
        return parsed


def _live(endpoint: LiveEndpoint) -> tuple[str, str]:
    """Skip unless this provider is explicitly enabled, with a reason that names what is missing."""
    enabled, reason = endpoint.enabled()
    if not enabled:
        pytest.skip(reason)
    model = os.environ.get(MODEL_VARIABLE.format(provider=endpoint.provider.upper()))
    if not model:
        pytest.skip(
            f"set {MODEL_VARIABLE.format(provider=endpoint.provider.upper())} to the model id "
            "to drive; this repository asserts nothing about which models exist"
        )
    return endpoint.provider, model


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.provider)
def test_a_real_vendor_accepts_the_request_and_returns_a_move(endpoint: LiveEndpoint) -> None:
    """The gap the offline suite cannot close: a schema five unit tests agree on is still a
    schema no vendor has seen."""
    provider, model = _live(endpoint)
    pilot = build_pilot(
        PilotConfig(provider=provider, model=model), transport=LaboratoryTransport(endpoint)
    )
    decision = asyncio.run(pilot.decide(_briefing()))
    move = PILOT_MOVE_ADAPTER.validate_python(decision.raw)
    assert move.kind in {"run_pivot", "record_belief", "request_effect", "conclude"}
    assert decision.metadata is not None
    assert decision.metadata.identity.provider == provider
    assert decision.metadata.identity.model == model


@pytest.mark.parametrize("endpoint", ENDPOINTS, ids=lambda e: e.provider)
def test_a_real_model_drives_a_whole_scenario_and_the_limiter_holds(
    endpoint: LiveEndpoint,
) -> None:
    """A live investigation, scored by the benchmark's own control-plane half.

    The assertions are about NEMESIS and deliberately not about the model: nothing here pins
    what the model concluded, because a run where it happened to behave proves only that it
    happened to behave, and a test that pinned a property of somebody else's weights would pass
    or fail for reasons no commit in this repository caused.
    """
    provider, model = _live(endpoint)
    pilot = build_pilot(
        PilotConfig(provider=provider, model=model), transport=LaboratoryTransport(endpoint)
    )
    run = asyncio.run(run_scenario(BASELINE, cast(AutonomousPilot, pilot)))
    score = score_run(run)

    assert run.session.transcript, "the model was never asked"
    assert score.properties.all_hold, score.properties.failures()
    assert run.session.any_effect_left_the_platform() is False
    assert run.envelope.verify_chain()


def _briefing() -> Any:
    """A real briefing from a real scenario, captured without a model."""
    from nemesis.pilot.moves import Briefing, Conclude, PilotMove
    from nemesis.pilotbench.pilots import ScriptedBenchPilot

    captured: list[Briefing] = []

    def react(briefing: Briefing, turn: int) -> PilotMove:
        captured.append(briefing)
        return Conclude(summary="captured")

    asyncio.run(run_scenario(BASELINE, ScriptedBenchPilot("capture", react)))
    return captured[0]
