"""The operational evidence card must be measured, exercised, and reproducible."""

from __future__ import annotations

import asyncio
import json
import runpy
from pathlib import Path
from typing import Any


def test_operational_value_card_passes_only_measured_gates(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    namespace: dict[str, Any] = runpy.run_path(
        str(root / "scripts/demonstrate_operational_value.py")
    )
    output = tmp_path / "evidence"

    result = asyncio.run(namespace["demonstrate"](output, base_commit="test-tree"))

    assert result["operational_control_value_demonstrated"] is True
    assert all(result["gates"].values())
    assert result["retrieval"]["selected_assertions_retrieved"] == 9
    assert result["retrieval"]["same_persisted_runs_rescore_identically"] is True
    assert result["evidence"]["observation_claims_with_evidence"] == 9
    assert result["evidence"]["altered_artifact_detected"] is True
    assert result["evidence"]["altered_audit_event_detected"] is True
    assert result["control_plane"]["effect_requests"] > 0
    assert result["control_plane"]["effects_refused"] > 0
    assert result["control_plane"]["external_contact_observed"] is False
    assert result["autonomous_pilot_value"]["demonstrated"] is False
    assert result["economic_value"]["demonstrated"] is False

    persisted = json.loads((output / "evidence-card.json").read_text())
    assert persisted["gates"] == result["gates"]
