"""The wall between what NEMESIS concludes and what NEMESIS is willing to hand over.

Founder decision D1: NEMESIS resolves **both** organizations and operators, separated by a
wall. Organizational attribution is the deliverable product. Persona linkage stays, and
stays *internal* — a lead that directs an investigation, never a conclusion that leaves the
platform.

That distinction is not a label, and it will not survive as one. It is a data-flow
constraint, and a constraint enforced by a naming convention erodes on the first deadline.
So it is enforced three ways, each catching what the others miss:

1. **The external product type has no field for it.** :class:`ExternalAttributionProduct`
   cannot represent a persona or human-identity dimension. You cannot serialize what the
   type does not have, and no amount of careless calling code can add it back.
2. **Redaction is recorded, not silent.** The external product states how many dimensions
   were withheld and why. A recipient who is told nothing about persona linkage should know
   that something was withheld, rather than inferring from silence that nothing was found.
3. **A boundary guard on free text.** Effects receives its content through a string
   dictionary, which no type can constrain. Every value crossing that boundary is scanned
   for internal-classified markers and the operation is refused if one appears.

The third is a backstop and is honest about being one: it catches a marker, not an idea. An
analyst determined to paraphrase a persona linkage into a takedown request will succeed, and
no code in this repository will stop them. What the guard prevents is the *accidental*
path — the one where a well-meaning caller passes an internal assessment's own text into a
document because it was the field that happened to be at hand.

Why the wall exists at all, stated plainly: misattributing a criminal organization is a
serious error, and misidentifying a person is a life-altering one. Organizational
attribution also touches far less personal data, which materially changes what obligations
attach to it. The wall is the difference between those two risk profiles.
"""

from __future__ import annotations

from enum import StrEnum

from nemesis.core.entities import EntityCategory, EntityType


class DisclosureClass(StrEnum):
    """Whether a finding may leave the platform.

    Ordered from most to least disclosable. The ordering is used, so do not reorder it
    without reading :func:`most_restrictive`.
    """

    DELIVERABLE = "deliverable"
    """May be exported, referred, drafted into a notice, or shown to a recipient.

    Infrastructure, campaign and organizational findings. These are what NEMESIS sells and
    what a provider, regulator or investigator receives."""

    INTERNAL_LEAD = "internal_lead"
    """Directs the investigation and never leaves it.

    Persona linkage lives here. It is genuinely useful — it is how an investigation knows
    where to look next — and it is not a conclusion about a person that anybody outside
    this platform should act on."""

    RESTRICTED = "restricted"
    """Never leaves, and carries obligations beyond our own policy.

    Human-identity leads and material under mandatory-reporting or data-protection
    constraints. Distinguished from INTERNAL_LEAD because the consequence of leaking it is
    legal rather than merely analytic."""


_ORDER: dict[DisclosureClass, int] = {
    DisclosureClass.DELIVERABLE: 0,
    DisclosureClass.INTERNAL_LEAD: 1,
    DisclosureClass.RESTRICTED: 2,
}


def most_restrictive(*classes: DisclosureClass) -> DisclosureClass:
    """The strictest class among the inputs.

    A product assembled from mixed material takes the classification of its most restricted
    part. Anything else would let a deliverable wrapper launder an internal finding by
    containing it.
    """
    if not classes:
        return DisclosureClass.DELIVERABLE
    return max(classes, key=lambda item: _ORDER[item])


ENTITY_DISCLOSURE: dict[EntityCategory, DisclosureClass] = {
    EntityCategory.ACTIVITY: DisclosureClass.DELIVERABLE,
    EntityCategory.NETWORK_INFRASTRUCTURE: DisclosureClass.DELIVERABLE,
    EntityCategory.CRYPTOGRAPHIC_MATERIAL: DisclosureClass.DELIVERABLE,
    EntityCategory.CODE: DisclosureClass.DELIVERABLE,
    EntityCategory.OPERATIONAL_INFRASTRUCTURE: DisclosureClass.DELIVERABLE,
    EntityCategory.FINANCIAL: DisclosureClass.DELIVERABLE,
    EntityCategory.ECOSYSTEM: DisclosureClass.DELIVERABLE,
    EntityCategory.INDICATOR: DisclosureClass.DELIVERABLE,
    # An organization is the deliverable unit of attribution. This single line is the
    # product decision D1 records.
    EntityCategory.ACTOR: DisclosureClass.DELIVERABLE,
    EntityCategory.DIGITAL_IDENTITY: DisclosureClass.INTERNAL_LEAD,
    EntityCategory.HUMAN_IDENTITY: DisclosureClass.RESTRICTED,
    EntityCategory.VICTIM: DisclosureClass.RESTRICTED,
    EntityCategory.CREDENTIAL: DisclosureClass.RESTRICTED,
}
"""Disclosure class per entity category.

``VICTIM`` is restricted for the opposite reason to ``HUMAN_IDENTITY``: not because naming
them would be an accusation, but because they are third parties whose exposure is not ours
to trade. A takedown request that names the victims is a breach notification nobody asked
us to send.

``CREDENTIAL`` is restricted for a third reason again, and it is the one this map buys most
cheaply. Authentication material found during collection must not reach a briefing, a drafted
document, a channel or an export — and every one of those paths already asks this map. One
line here does what a credential-specific filter in four places would have done worse, because
four filters drift and this cannot. See :mod:`nemesis.core.credentials`.
"""

PERSONA_ENTITY_TYPES: frozenset[EntityType] = frozenset(
    {EntityType.PERSONA, EntityType.ALIAS, EntityType.HUMAN_IDENTITY_LEAD}
)
"""Entity types whose *linkage* is an internal lead regardless of their category.

``PERSONA`` and ``ALIAS`` sit in the ACTOR category, which is deliverable — an organization
is a deliverable actor. The distinction the wall turns on is not the node but the claim: a
campaign attributed to an organization is a product; two personas asserted to be one
operator is a lead.
"""


def disclosure_of_entity(entity_type: EntityType) -> DisclosureClass:
    """Disclosure class for a node type."""
    from nemesis.core.entities import CATEGORY_OF

    if entity_type in PERSONA_ENTITY_TYPES:
        return (
            DisclosureClass.RESTRICTED
            if entity_type is EntityType.HUMAN_IDENTITY_LEAD
            else DisclosureClass.INTERNAL_LEAD
        )
    return ENTITY_DISCLOSURE[CATEGORY_OF[entity_type]]


class DisclosureViolationError(RuntimeError):
    """Internal material reached a boundary it must not cross.

    Deliberately not a ``ValueError``. This is not a malformed input to be reported to a
    caller and retried with better arguments — it is the wall doing the one thing it exists
    to do, and it should be loud enough that nobody handles it by widening an except clause.
    """


INTERNAL_MARKERS: tuple[str, ...] = (
    "persona_linkage",
    "PersonaLinkageAssessment",
    "same_operator_as",
    "human_identity_lead",
    "identity_lead",
    "INTERNAL LEAD",
    "internal_lead",
)
"""Markers that indicate internal material in free text crossing into Effects.

A blunt instrument, and its limits are the point. It catches the *accidental* path: a caller
passing an internal assessment's own rendered text into a document because that was the
field at hand. It does not catch paraphrase, and pretending otherwise would be worse than
having no guard, because someone would then trust it.

Every marker here is a token the platform itself emits. That is what makes the guard useful:
it fires on NEMESIS's own internal vocabulary appearing where it should never appear,
which is exactly the shape of a copy-paste leak.
"""


def scan_for_internal_material(values: dict[str, str]) -> tuple[str, ...]:
    """Return the ``key: marker`` pairs where internal material appears to have leaked.

    Empty tuple means nothing was detected — which is not the same as nothing being there,
    and callers must not describe it that way.
    """
    findings: list[str] = []
    for key, value in sorted(values.items()):
        for marker in INTERNAL_MARKERS:
            if marker.lower() in value.lower():
                findings.append(f"{key}: contains {marker!r}")
    return tuple(findings)
