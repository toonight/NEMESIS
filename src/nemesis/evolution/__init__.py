"""Plane 12 — the Evolution Plane: how an investigation keeps learning after 500 moves.

Trust level: CONTROL, and **strictly weaker than the plane below it**. Everything the pilot
seam refuses, this plane also cannot do — not by policy but because it holds none of the
handles that would let it. It has no engine, no graph writer, no vault, no capability, no
signing key and no effects registry. What it holds is a :class:`~nemesis.pilot.mediator.
PilotMediator`, three read-only ports, and its own memory of what the trajectory already
tried.

The shape, in one line: **Evolution decides what to ask next; the Pilot proposes a move; the
Mediator decides whether that move is allowed.** Adding a research loop above the limiter must
not make the limiter more permissive, and the way that is guaranteed here is that the loop sits
*outside* the seam and speaks to the model only through the briefing.

Inspired by AVO (Agentic Variation Operators for Autonomous Evolutionary Search, Chen et al.,
NVIDIA, arXiv:2603.24517v1, 2026-03-25) and adapted rather than reproduced: NVIDIA's production
agent harness is not published, this is not it, and the objective function here is deliberately
*not* the thing AVO optimises. See ADR-0011,
`docs/adr/0011-avo-inspired-long-horizon-evolution.md`.

Status: `IMPLEMENTED` for the single-lineage loop, the evaluator, the lineage store, the
deterministic plateau detector, the deterministic supervisor and the serial branch portfolio.
`PROPOSED` for model-backed supervision and for concurrent multi-model islands.
"""
