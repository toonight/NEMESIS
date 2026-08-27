"""How long NEMESIS may keep a node, and the conflict that answer runs into.

:class:`~nemesis.core.entities.EntityCategory` says it "drives access control, **retention
policy** and UI treatment". :attr:`~nemesis.core.entities.Entity.is_personal_data` says it
"triggers **retention limits**, access restrictions and minimization obligations". Both were
true statements about an intent and false statements about the code: nothing enforced either.
This module is the policy half of making them true — and it is deliberately only the policy
half, because :mod:`nemesis.core` performs no I/O and deleting things is I/O.

**Why retention is a security property here and not only a legal one.** A platform that
accumulates human-identity leads forever is a platform whose breach is worse every year, and
whose worst day is the day someone exfiltrates a decade of unproven accusations about named
people. Minimization is the control that bounds the blast radius of every other control failing.

**Retention runs from last observation, not from creation.** An adversary observed last week is
live intelligence; a lead nobody has touched in a year is stale, and staleness is what makes it
both useless and dangerous to hold. So the clock starts at ``extent.known_until`` — the last
moment we can actually defend having seen the thing — and a re-observation legitimately restarts
it, because the node is then current intelligence again rather than a record of an old suspicion.

**The conflict this cannot resolve, and must not pretend to.** Invariant 10 says evidence is
append-only, hash-chained and tamper-evident; the operator is in the threat model. Data
protection says personal data must be erasable. **These genuinely conflict**: you cannot remove a
row from a hash chain without breaking it, and a vault that can be silently edited is not a vault.
The honest options are three, and choosing between them is a founder decision, not an
architectural detail:

1. **Crypto-erasure.** Personal data enters the vault encrypted under a per-subject key; erasure
   destroys the key. The chain stays intact and verifies; the content is unrecoverable. Standard,
   and it moves the problem to key custody.
2. **Never vault personal data.** The graph holds the lead; the vault holds only the artifact it
   came from. Cheapest, and it weakens provenance for exactly the claims that most need it.
3. **Record erasure as its own chained event.** The chain shows a hole *and* shows who made it
   and why, so a deletion is visible rather than silent. Preserves tamper-evidence at the cost of
   admitting the object is gone.

Until that is settled, this module scopes erasure to **the graph** — which is mutable by design —
and says so. `RETENTION IN THE VAULT: NOT IMPLEMENTED` is the honest label, and the sweep below
reports it rather than implying the whole platform forgets.

Status: `IMPLEMENTED` as policy and as a report. Enforcement — a component that actually removes
graph nodes on a schedule — is `PROPOSED`, and the vault question is a **founder decision**.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict

from nemesis.core.entities import CATEGORY_OF, Entity, EntityCategory, EntityType

VAULT_RETENTION_NOTICE: Final = (
    "RETENTION IN THE VAULT: NOT IMPLEMENTED. This policy scopes erasure to the graph, which is "
    "mutable by design. Sealed evidence is append-only and hash-chained (invariant 10); removing "
    "an entry would break the chain that makes the vault worth having. Reconciling the two is a "
    "founder decision — crypto-erasure, never vaulting personal data, or recording erasure as its "
    "own chained event."
)


class RetentionVerdict(StrEnum):
    """What the policy says about one node, right now."""

    NO_LIMIT = "no_limit"
    """Not personal data and not otherwise regulated. Kept as long as it is useful.

    Infrastructure, certificates, malware, wallets: holding a domain name for a decade harms
    nobody, and the Global Adversary Graph is worth more the longer it remembers."""

    WITHIN_PERIOD = "within_period"
    """Regulated, and still inside its period."""

    DUE = "due"
    """Past its period. Should be erased from the graph.

    Not "may be" — the period is the answer to "how long can we justify holding this", and past
    it the justification has expired even if the node is still interesting."""

    HELD_UNDER_LEGAL_BASIS = "held_under_legal_basis"
    """Past its period, but retained because a named legal instrument requires it.

    A live court order or a preservation request outranks the ordinary period. Requires a
    reference, so "we are keeping it because it matters" cannot masquerade as a legal basis."""


class RetentionClass(BaseModel):
    """A period, and the reason it is that number.

    The period is a **choice, not a measurement** — like every constant in this repository it is
    stated in code so it can be argued with, and a deployment under a specific regime will
    replace it with what its counsel says.
    """

    model_config = ConfigDict(frozen=True)

    category: EntityCategory
    period: timedelta | None
    """``None`` means no limit: the category holds no personal data."""

    rationale: str

    @property
    def is_regulated(self) -> bool:
        return self.period is not None


DEFAULT_RETENTION: Final[dict[EntityCategory, RetentionClass]] = {
    EntityCategory.HUMAN_IDENTITY: RetentionClass(
        category=EntityCategory.HUMAN_IDENTITY,
        period=timedelta(days=365),
        rationale=(
            "The shortest period in the table, deliberately. A human-identity lead is an "
            "unproven assertion about a named natural person, held by a platform that has "
            "already refused to promote it to an attribution. A year without re-observation "
            "means it never corroborated, and an uncorroborated accusation about a person is "
            "the single most damaging thing here to still be holding."
        ),
    ),
    EntityCategory.VICTIM: RetentionClass(
        category=EntityCategory.VICTIM,
        period=timedelta(days=365),
        rationale=(
            "Victims are third parties whose exposure is not ours to trade. They are in the "
            "graph because an incident touched them, not because they are under suspicion, and "
            "the case for holding their data expires with the investigation."
        ),
    ),
    EntityCategory.DIGITAL_IDENTITY: RetentionClass(
        category=EntityCategory.DIGITAL_IDENTITY,
        period=timedelta(days=1095),
        rationale=(
            "Personas and aliases are pseudonymous, not anonymous: they can identify a natural "
            "person once linked, which is exactly what this platform tries to do. Three years, "
            "because alias reuse across years is a genuine and hard-won signal — the longest "
            "period defensible for something that may resolve to a person."
        ),
    ),
    EntityCategory.ACTOR: RetentionClass(
        category=EntityCategory.ACTOR,
        period=None,
        rationale=(
            "Organizations and threat actors are the deliverable unit of attribution and are "
            "not natural persons. Persistent adversary memory is the strategic asset; forgetting "
            "a criminal organization after three years would defeat the resurgence loop that "
            "invariant 14 requires."
        ),
    ),
    EntityCategory.CREDENTIAL: RetentionClass(
        category=EntityCategory.CREDENTIAL,
        period=timedelta(days=365),
        rationale=(
            "A credential belongs to somebody, and often to a natural person who is a victim "
            "rather than a suspect — a reused password in a criminal dump identifies the person "
            "it was stolen from. Held on the same clock as a human-identity lead for the same "
            "reason: the intelligence value is in the correlation, which the keyed fingerprint "
            "preserves, and the material itself stops earning its risk quickly. See "
            ":mod:`nemesis.core.credentials`."
        ),
    ),
}
"""Retention per category. Anything absent has no limit and holds no personal data.

Only the categories that can identify a natural person carry a period. That is the whole
distinction, and it is why ``HUMAN_IDENTITY`` is a category rather than a flag on a node:
policy has to be decidable without reading free text.
"""


class RetentionAssessment(BaseModel):
    """What the policy says about one node, with why — never a bare verdict."""

    model_config = ConfigDict(frozen=True)

    entity_id: str
    entity_type: EntityType
    category: EntityCategory
    verdict: RetentionVerdict
    last_observed: datetime
    period: timedelta | None
    overdue_by: timedelta | None = None
    legal_hold_reference: str | None = None
    rationale: str

    @property
    def must_erase(self) -> bool:
        return self.verdict is RetentionVerdict.DUE

    def render(self) -> str:
        if self.verdict is RetentionVerdict.NO_LIMIT:
            return f"{self.entity_type.value}: no limit — {self.rationale}"
        if self.verdict is RetentionVerdict.HELD_UNDER_LEGAL_BASIS:
            return (
                f"{self.entity_type.value}: held past its period under {self.legal_hold_reference}"
            )
        if self.verdict is RetentionVerdict.DUE:
            days = 0 if self.overdue_by is None else self.overdue_by.days
            return f"{self.entity_type.value}: DUE for erasure, {days} day(s) past its period"
        return f"{self.entity_type.value}: within its period"


def retention_class(entity_type: EntityType) -> RetentionClass:
    """The policy for a node type. Every type has one, so nothing falls through unassessed.

    **Category alone is not enough, and finding that out was the point of writing the tests
    first.** ``PERSONA`` and ``ALIAS`` sit in the ``ACTOR`` category — deliberately, because an
    organization is a deliverable actor — and ``ACTOR`` carries no period. A table keyed only on
    category therefore held personas forever: pseudonymous data about what may be one natural
    person, kept indefinitely, in the exact category the platform tries hardest to resolve to a
    human. :mod:`nemesis.core.disclosure` already hit this and answered it with
    ``PERSONA_ENTITY_TYPES``; this reuses that constant rather than declaring a second list, so
    the two policies cannot drift about what counts as a persona.
    """
    from nemesis.core.disclosure import PERSONA_ENTITY_TYPES

    category = CATEGORY_OF[entity_type]
    if entity_type in PERSONA_ENTITY_TYPES and category is not EntityCategory.HUMAN_IDENTITY:
        # A persona or alias, whatever category it files under. Regulated on the
        # digital-identity period, because that is what it is.
        return DEFAULT_RETENTION[EntityCategory.DIGITAL_IDENTITY]
    known = DEFAULT_RETENTION.get(category)
    if known is not None:
        return known
    return RetentionClass(
        category=category,
        period=None,
        rationale=(
            "Not personal data: infrastructure, cryptographic material, code, financial or "
            "ecosystem nodes. Holding these indefinitely is what makes the Global Adversary "
            "Graph worth having, and harms no natural person."
        ),
    )


def assess(
    entity: Entity,
    *,
    now: datetime,
    legal_hold_reference: str | None = None,
    policy: dict[EntityCategory, RetentionClass] | None = None,
) -> RetentionAssessment:
    """Decide what should happen to one node, and say why.

    ``legal_hold_reference`` must name a real instrument — a case number, a preservation
    request. It is the only thing that keeps a node past its period, and requiring a reference
    is what stops "this is still interesting" from being recorded as a legal basis.

    The clock runs from ``extent.known_until``: the last moment we can defend having observed
    this. Re-observing a node legitimately restarts it, because the node is then current
    intelligence rather than the record of an old suspicion.
    """
    # `retention_class` is the single decision point, because it is the one that knows a
    # persona is regulated despite filing under ACTOR. Reading the table directly here would
    # reintroduce exactly the hole that check exists to close.
    rule = retention_class(entity.entity_type)
    if policy is not None:
        rule = policy.get(rule.category, rule)
    category = rule.category
    last_observed = entity.extent.known_until

    if rule.period is None:
        return RetentionAssessment(
            entity_id=entity.entity_id,
            entity_type=entity.entity_type,
            category=category,
            verdict=RetentionVerdict.NO_LIMIT,
            last_observed=last_observed,
            period=None,
            rationale=rule.rationale,
        )

    expires_at = last_observed + rule.period
    if now < expires_at:
        return RetentionAssessment(
            entity_id=entity.entity_id,
            entity_type=entity.entity_type,
            category=category,
            verdict=RetentionVerdict.WITHIN_PERIOD,
            last_observed=last_observed,
            period=rule.period,
            rationale=rule.rationale,
        )

    overdue = now - expires_at
    if legal_hold_reference:
        return RetentionAssessment(
            entity_id=entity.entity_id,
            entity_type=entity.entity_type,
            category=category,
            verdict=RetentionVerdict.HELD_UNDER_LEGAL_BASIS,
            last_observed=last_observed,
            period=rule.period,
            overdue_by=overdue,
            legal_hold_reference=legal_hold_reference,
            rationale=(
                f"Past its {rule.period.days}-day period, retained under "
                f"{legal_hold_reference}. The hold outranks the period and is itself auditable."
            ),
        )

    return RetentionAssessment(
        entity_id=entity.entity_id,
        entity_type=entity.entity_type,
        category=category,
        verdict=RetentionVerdict.DUE,
        last_observed=last_observed,
        period=rule.period,
        overdue_by=overdue,
        rationale=(
            f"Last observed {last_observed.date().isoformat()}, {overdue.days} day(s) past its "
            f"{rule.period.days}-day period. {rule.rationale}"
        ),
    )


class RetentionSweep(BaseModel):
    """What a whole graph looks like against the policy. A report, not an action.

    Deliberately not a deleter. Erasing graph nodes is I/O and belongs outside
    :mod:`nemesis.core`; separating the decision from the deletion also means an operator can
    read what *would* be erased before anything is, which for personal data is the order those
    two steps belong in.
    """

    model_config = ConfigDict(frozen=True)

    assessed_at: datetime
    assessments: tuple[RetentionAssessment, ...]
    vault_notice: str = VAULT_RETENTION_NOTICE

    @property
    def due(self) -> tuple[RetentionAssessment, ...]:
        return tuple(item for item in self.assessments if item.must_erase)

    @property
    def held(self) -> tuple[RetentionAssessment, ...]:
        return tuple(
            item
            for item in self.assessments
            if item.verdict is RetentionVerdict.HELD_UNDER_LEGAL_BASIS
        )

    @property
    def regulated(self) -> tuple[RetentionAssessment, ...]:
        """Every node carrying a period, whatever its verdict — the population that matters."""
        return tuple(
            item for item in self.assessments if item.verdict is not RetentionVerdict.NO_LIMIT
        )

    def render(self) -> str:
        lines = [
            f"Retention sweep at {self.assessed_at.isoformat()}",
            f"  {len(self.assessments)} node(s) assessed, {len(self.regulated)} regulated",
            f"  {len(self.due)} due for erasure, {len(self.held)} held under a legal basis",
            f"  {self.vault_notice}",
        ]
        lines.extend(f"    - {item.render()}" for item in self.due)
        return "\n".join(lines)


def sweep(
    entities: tuple[Entity, ...],
    *,
    now: datetime,
    legal_holds: dict[str, str] | None = None,
    policy: dict[EntityCategory, RetentionClass] | None = None,
) -> RetentionSweep:
    """Assess a population. ``legal_holds`` maps entity id to the instrument holding it."""
    holds = legal_holds or {}
    return RetentionSweep(
        assessed_at=now,
        assessments=tuple(
            assess(
                entity,
                now=now,
                legal_hold_reference=holds.get(entity.entity_id),
                policy=policy,
            )
            for entity in entities
        ),
    )


__all__ = [
    "DEFAULT_RETENTION",
    "VAULT_RETENTION_NOTICE",
    "RetentionAssessment",
    "RetentionClass",
    "RetentionSweep",
    "RetentionVerdict",
    "assess",
    "retention_class",
    "sweep",
]
