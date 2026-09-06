"""The offline evaluation must reject changed code and edited/incomplete transcripts."""

import json
import runpy
import shutil
from pathlib import Path

import pytest

from nemesis.calibration.freeze import engine_digest
from nemesis.pilotbench.replay import sha256

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/evaluate_public_replay.py"
PUBLISHED = ROOT / "docs/evaluation/public-replay-2026-09-06"


def test_freeze_checks_engine_code_not_only_confidence_values(monkeypatch):
    namespace = runpy.run_path(str(SCRIPT))
    verify = namespace["verify"]
    manifest = {
        "inputs_sha256": sha256(ROOT / "data/benchmarks/public-replay-v1/inputs.json"),
        "engine_digest": engine_digest(),
        "runner_sha256": sha256(SCRIPT),
    }
    verify(manifest)
    monkeypatch.setitem(verify.__globals__, "engine_digest", lambda: "changed-engine")
    with pytest.raises(ValueError, match="Engine changed"):
        verify(manifest)


@pytest.mark.parametrize("defect", ["edited", "missing"])
def test_offline_scorer_refuses_changed_or_incomplete_transcripts(tmp_path, monkeypatch, defect):
    shutil.copytree(PUBLISHED, tmp_path / "run")
    out = tmp_path / "run"
    (out / "scores.json").unlink()
    if defect == "edited":
        target = out / "runs/R17-local.json"
        target.write_text("{}")
    else:
        target = out / "runs-sealed.json"
        sealed = json.loads(target.read_text())
        del sealed["R17-local.json"]
        target.write_text(json.dumps(sealed))
    monkeypatch.setattr("sys.argv", [str(SCRIPT), "score", "--out", str(out)])
    with pytest.raises(ValueError, match=r"Transcript changed|Incomplete run matrix"):
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert not (out / "scores.json").exists()
