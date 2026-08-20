"""Measuring what can honestly be measured about NEMESIS's confidence.

Splits assertions the harness can prove from numbers it can only compute under its own
assumptions, and refuses to present the second kind as calibration. See ADR-0003.
"""

from nemesis.calibration.generator import CaseGenerator, CaseKind, GeneratorAssumptions
from nemesis.calibration.harness import CalibrationReport, run_calibration
from nemesis.calibration.scoring import brier_decomposition, discrimination_auc

__all__ = [
    "CalibrationReport",
    "CaseGenerator",
    "CaseKind",
    "GeneratorAssumptions",
    "brier_decomposition",
    "discrimination_auc",
    "run_calibration",
]
