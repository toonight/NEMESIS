"""Alternative investigative directions, and the arithmetic that keeps them from multiplying.

A branch is a *strategy*: pursue the infrastructure hypothesis, pursue the false-flag hypothesis,
pursue the temporal-correlation hypothesis. It is not an independent truth store. Every branch
shares one evidence vault, one graph, one scope, one set of provenance rules and — the one that
matters — **one authorization boundary**.

The property this module exists to guarantee is arithmetic and is asserted by a test: opening a
branch **partitions** an allowance, it never creates one. Three branches from a twelve-step run are
three ways of spending twelve steps. The failure this prevents is not hypothetical and it is the
obvious one: a design where each branch got the run's allowance would turn "delegate autonomy for
twelve steps" into thirty-six steps by writing the word "branch" twice more, and the same shape
applied to an effect budget would turn a pre-signed envelope into a multiplier.

The autonomous-**effect** budget is not partitioned here because it is not held here. It belongs to
:class:`~nemesis.authz.envelope.AutonomyEnvelope`, which this plane cannot import, cannot read and
cannot spend — so branching cannot multiply it for the strongest possible reason, which is that
there is nothing here to multiply.

Serial by construction. :meth:`BranchPortfolio.next_branch` returns one branch at a time and the
controller runs it to completion or to its allowance. Concurrent multi-model islands are
`PROPOSED`: correctness first, and a portfolio whose branches ran concurrently against one shared
ledger would need the atomic reservation the in-memory lineage store does not have.

Status: `IMPLEMENTED` (serial). `PROPOSED` (concurrent islands).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from nemesis.core.ids import EvolutionBranchId, IdPrefix, new_id
from nemesis.evolution.memory import ResearchMemory
from nemesis.evolution.models import BranchStatus, EvolutionBranch


class BudgetError(RuntimeError):
    """A branch was asked for an allowance the run does not have."""


class BranchPortfolio:
    """Holds a run's branches and partitions one step allowance between them.

    Not a scheduler and not a store: the trajectory is the store, and this is the arithmetic plus
    the ordering. It is deliberately small, because the interesting property is a subtraction that
    must never be an addition.
    """

    def __init__(self, *, run_id: str, total_steps: int) -> None:
        if total_steps < 0:
            raise BudgetError("a step allowance cannot be negative")
        self._run_id = run_id
        self._total = total_steps
        self._branches: dict[str, EvolutionBranch] = {}
        self._order: list[str] = []

    @property
    def total_steps(self) -> int:
        """The run's whole allowance. Fixed at construction and never raised by this class."""
        return self._total

    @property
    def allocated(self) -> int:
        return sum(branch.step_allowance for branch in self._branches.values())

    @property
    def unallocated(self) -> int:
        return max(0, self._total - self.allocated)

    def branches(self) -> tuple[EvolutionBranch, ...]:
        return tuple(self._branches[key] for key in self._order)

    def open_branches(self) -> tuple[EvolutionBranch, ...]:
        return tuple(branch for branch in self.branches() if branch.is_open)

    def get(self, branch_id: str) -> EvolutionBranch | None:
        return self._branches.get(branch_id)

    def open(
        self,
        *,
        objective: str,
        created_at: datetime,
        steps: int,
        parent_checkpoint_id: str | None = None,
        hypothesis_refs: Sequence[str] = (),
        memory: ResearchMemory | None = None,
    ) -> EvolutionBranch:
        """Open a branch against the run's unallocated allowance.

        Raises :class:`BudgetError` when the request exceeds what is left, rather than clamping.
        Clamping would be the friendlier failure and the wrong one: a caller that asked for six
        steps and silently got two would run a strategy it did not choose, and the whole point of
        a portfolio is that the split is deliberate.
        """
        if steps < 0:
            raise BudgetError("a branch allowance cannot be negative")
        if steps > self.unallocated:
            raise BudgetError(
                f"a branch asked for {steps} step(s) and the run has {self.unallocated} "
                f"unallocated of {self._total}. Branching divides a run's allowance; it does not "
                "create one, and a portfolio that granted this would turn one delegation into "
                "several"
            )
        branch_id: EvolutionBranchId = new_id(IdPrefix.EVOLUTION_BRANCH)
        branch = EvolutionBranch(
            branch_id=branch_id,
            run_id=self._run_id,
            parent_checkpoint_id=parent_checkpoint_id,
            objective=objective,
            hypothesis_refs=tuple(hypothesis_refs),
            created_at=created_at,
            step_allowance=steps,
            memory=memory or ResearchMemory(),
        )
        self._branches[branch_id] = branch
        self._order.append(branch_id)
        return branch

    def record_step(
        self, branch_id: str, *, memory: ResearchMemory | None = None
    ) -> EvolutionBranch:
        """Charge one step to a branch, and carry its memory forward.

        Charging happens whether the step promoted anything or not, for the reason the spend ledger
        gives: an allowance that decremented only on success is an allowance an adversary — or an
        unlucky run — empties by failing, and the resulting loop never ends.
        """
        branch = self._require(branch_id)
        if branch.steps_remaining <= 0:
            raise BudgetError(
                f"branch {branch_id} has spent all {branch.step_allowance} of its step(s); "
                "charging another would let a branch spend past what the run granted it"
            )
        updated = EvolutionBranch.model_validate(
            branch.model_dump()
            | {
                "steps_taken": branch.steps_taken + 1,
                "memory": (memory if memory is not None else branch.memory).model_dump(),
            }
        )
        self._branches[branch_id] = updated
        return updated

    def close(
        self,
        branch_id: str,
        *,
        status: BranchStatus,
        reason: str,
        closed_at: datetime,
    ) -> EvolutionBranch:
        """Close a branch and **return its unspent allowance to the run**.

        The return is what makes a portfolio worth having: a pruned direction that kept its unspent
        steps would make branching strictly worse than not branching. What is deliberately *not*
        returned is what it already spent — a branch cannot refund a step by being wrong about it.
        """
        branch = self._require(branch_id)
        # Re-validated rather than `model_copy`-ed into place. `model_copy(update=...)` skips every
        # validator, so the rule that a pruned branch must state a reason simply would not run --
        # the model would carry the invariant and the one call site that closes a branch would be
        # the one place it did not hold. Found by a test that asserted the refusal and got none.
        closed = EvolutionBranch.model_validate(
            branch.model_dump()
            | {
                "status": status,
                "closure_reason": reason,
                "closed_at": closed_at,
                # `min`, not `steps_taken`. An adversarial review found that closing a branch which
                # had somehow spent more than it was granted RAISED its allowance to what it spent,
                # so `allocated` could exceed `total_steps` and branching would have multiplied the
                # very number this class exists to divide. `record_step` now refuses to overspend,
                # and this is the second lock on the same door: a closure can only ever give
                # allowance back.
                "step_allowance": min(branch.steps_taken, branch.step_allowance),
            }
        )
        self._branches[branch_id] = closed
        return closed

    def next_branch(self) -> EvolutionBranch | None:
        """The next branch to run: the first open one with steps left, in creation order.

        Deterministic, and the determinism is not decoration — invariant 11 asks for replayable,
        and a portfolio that picked by a heuristic over mutable state would make two replays of one
        trajectory diverge.
        """
        return next(
            (branch for branch in self.branches() if branch.is_open and branch.steps_remaining > 0),
            None,
        )

    def _require(self, branch_id: str) -> EvolutionBranch:
        branch = self._branches.get(branch_id)
        if branch is None:
            raise BudgetError(f"no branch {branch_id!r} in this portfolio")
        return branch


__all__ = ["BranchPortfolio", "BudgetError"]
