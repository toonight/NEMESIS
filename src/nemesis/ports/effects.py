"""The effects port: the only way anything leaves NEMESIS and touches the world.

Invariant 8 says Effects has no ambient authority. Concretely that means an adapter here
receives, per call, exactly one signed capability and nothing else. It holds no standing
credentials, no graph handle, no vault handle, no API keys retrieved from a shared config.
Whatever it needs to act, it is handed for that one operation, and it loses it afterwards.

The interface is shaped to make the wrong thing hard:

- ``execute`` takes the capability as a required argument. There is no path that acts
  without one.
- The adapter re-verifies the capability itself rather than trusting the caller. A caller
  that already checked is not evidence; a compromised caller is precisely the threat.
- The adapter re-checks the target's *current* state against the approved fingerprint.
  Time passes between approval and execution, and the world changes in it.
- Every outcome, including refusals, is returned as a structured record for the audit
  trail. An effect that fails silently is worse than one that fails loudly.

``.importlinter`` enforces that nothing in :mod:`nemesis.effects` can import the graph,
the collection plane, the pursuit engine, the vault or the planner. If an adapter is ever
compromised, it must not be a path out of the investigation.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from nemesis.core.authorization import (
    AuthorizationCapability,
    AuthorizationDecision,
    OperationClass,
)
from nemesis.core.ids import OperationId
from nemesis.ports.authorization import TrustAnchor


class EffectOutcome(StrEnum):
    """What happened. Every value is recorded; none is swallowed."""

    SIMULATED = "simulated"
    """Nothing left the system. The full authorization path was exercised."""

    DRAFTED = "drafted"
    """An artifact was produced for a human to review and send. Nothing was sent."""

    REFUSED_UNVERIFIED_CAPABILITY = "refused_unverified_capability"
    """The capability's Ed25519 signature did not verify, or it carried none.

    Distinct from REFUSED_UNAUTHORIZED on purpose. "You are not permitted to do this" and
    "I cannot establish that anybody authorized this" are different events: the first is an
    operator mistake, the second is an attempted forgery, and an operator reading a log
    needs to tell them apart."""

    REFUSED_REVOKED = "refused_revoked"
    """The issuing authority has withdrawn this capability, or the revocation oracle could
    not be reached. Fails closed: an unreachable oracle is not an absent revocation."""

    REFUSED_UNAUTHORIZED = "refused_unauthorized"
    REFUSED_TARGET_CHANGED = "refused_target_changed"
    REFUSED_NO_ADAPTER = "refused_no_adapter"
    """The operation class is declared but has no implementation — REQUIRES_LEGAL_AUTHORITY."""

    REFUSED_STOP_CONDITION = "refused_stop_condition"
    FAILED = "failed"


class EffectRequest(BaseModel):
    """A request to perform one operation against one target."""

    model_config = ConfigDict(frozen=True)

    operation_id: OperationId
    operation: OperationClass
    target_fingerprint: str
    target_natural_key: str

    current_target_attributes: dict[str, str]
    """The target's state *now*, observed immediately before execution. Checked against
    the fingerprint bound at approval. This is the field that stops a stale approval from
    being applied to a target that has since changed hands."""

    parameters: dict[str, str] = Field(default_factory=dict)
    requested_by: str
    requested_at: datetime


class EffectResult(BaseModel):
    """What an adapter did, or refused to do, and why."""

    model_config = ConfigDict(frozen=True)

    operation_id: OperationId
    operation: OperationClass
    outcome: EffectOutcome
    executed_at: datetime
    adapter_name: str

    authorization: AuthorizationDecision
    """Always present, permitted or not. The record of a refusal is as important as the
    record of an action."""

    detail: str
    produced_artifacts: tuple[str, ...] = ()
    """Locators for anything generated — a draft notice, an evidence bundle. Never the
    content itself: artifacts go to the vault, not into an audit record."""

    reversible: bool = True
    external_contact_made: bool = Field(
        default=False,
        description="Whether anything actually left the system. False for every MVP "
        "adapter. A test asserts this across the whole adapter registry, so the day it "
        "becomes true is a deliberate, visible event.",
    )

    @property
    def succeeded(self) -> bool:
        return self.outcome in {EffectOutcome.SIMULATED, EffectOutcome.DRAFTED}


@runtime_checkable
class EffectsAdapter(Protocol):
    """Performs one class of operation, under one capability, for one target.

    Implementations must be stateless between calls. An adapter that caches a credential,
    a session or a target list across invocations has reconstructed the ambient authority
    this interface exists to remove.
    """

    @property
    def name(self) -> str: ...

    @property
    def operation(self) -> OperationClass: ...

    @property
    def makes_external_contact(self) -> bool:
        """Whether this adapter can cause anything to leave the system.

        Must be False for every adapter in the MVP. Declared rather than inferred so the
        property can be asserted over the registry in a test.
        """
        ...

    @property
    def anchor(self) -> TrustAnchor:
        """The authorizer this adapter believes, fixed when it was constructed.

        Exposed so a registry can refuse an adapter wired to a different authorizer, and so
        that "which key does this adapter trust?" is a question with an answer rather than a
        property of whoever last called it.
        """
        ...

    async def execute(
        self, request: EffectRequest, capability: AuthorizationCapability
    ) -> EffectResult:
        """Verify, then act.

        Implementations must, in this order: verify the capability's signature against
        **their own anchor**; ask its revocation oracle whether the grant still stands,
        failing closed if it cannot answer; reason from the grant *reconstructed from the
        signed bytes* rather than from the object passed in; verify it authorizes this exact
        operation against this exact target; verify the target's current attributes still
        match the approved fingerprint; check stop conditions; only then act. A refusal at
        any step returns an :class:`EffectResult`, never an exception — the refusal is an
        outcome that must be recorded, not an error that might be caught and ignored.

        This docstring used to say the adapter "re-verifies rather than trusting the
        caller" while the key and the oracle arrived as call arguments. An adversarial
        review took an adapter from ``registry.adapters``, passed it a capability signed by
        its own key along with that key, and received a drafted document. Verification
        against a credential the caller chose is not verification.

        The anchor is the means to *refuse*: a public key cannot mint a capability and a
        read-only oracle cannot widen one, so holding it gives this plane no ambient
        authority. Both are protocols from :mod:`nemesis.ports.authorization`, so the plane
        depends on the ability to check rather than on the gateway that provides it.
        """
        ...
