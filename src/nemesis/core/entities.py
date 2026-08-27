"""Entity taxonomy for the Global Adversary Graph.

Every node in the graph is an :class:`Entity`. What makes this model different from a
generic property graph is the *natural key*: an entity's identity is derived from a
normalized form of what it actually is, not from a surrogate row id. The domain
``EVIL.Example.COM`` observed by a passive-DNS connector and ``evil.example.com`` observed
by a certificate-transparency connector are one node, not two.

That sounds like housekeeping. It is not. Entity duplication is the second way an
attribution engine deceives itself: the same infrastructure appears under three ids, three
weak links become an apparent cluster, and the cluster looks like a finding. Normalization
is therefore part of the domain model rather than a database concern, and every
normalization rule is stated and testable.

Where normalization is genuinely ambiguous — cryptocurrency address casing differs by
chain, some are checksummed, some are not — the rule is to normalize conservatively and
record the observed form. Over-normalizing merges distinct entities, which is worse than
failing to merge identical ones: the first creates a false link, the second only misses one.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nemesis.core.ids import EntityId
from nemesis.core.temporal import TemporalExtent


class EntityCategory(StrEnum):
    """Coarse grouping. Drives access control, retention policy and UI treatment.

    ``HUMAN_IDENTITY`` is separated from ``ACTOR`` deliberately: entities in that category
    are natural persons under data-protection law even when they are criminal suspects,
    and they carry retention, minimization and access obligations that infrastructure
    nodes do not. Making it a category rather than a flag means the policy engine can
    reason about it without inspecting every node's attributes.
    """

    ACTIVITY = "activity"
    ACTOR = "actor"
    HUMAN_IDENTITY = "human_identity"
    DIGITAL_IDENTITY = "digital_identity"
    NETWORK_INFRASTRUCTURE = "network_infrastructure"
    CRYPTOGRAPHIC_MATERIAL = "cryptographic_material"
    CODE = "code"
    OPERATIONAL_INFRASTRUCTURE = "operational_infrastructure"
    FINANCIAL = "financial"
    ECOSYSTEM = "ecosystem"
    VICTIM = "victim"
    INDICATOR = "indicator"
    CREDENTIAL = "credential"
    """Authentication material found during collection.

    Its own category rather than a kind of ``CRYPTOGRAPHIC_MATERIAL``, because the two need
    opposite treatment. A TLS certificate or a PGP key is a deliverable identifier — publishing
    its fingerprint is how attribution is checked. A credential is the opposite: it belongs to
    somebody, it is frequently a natural person's, and NEMESIS finding one must never be a step
    towards NEMESIS using one. See :mod:`nemesis.core.credentials`.
    """


class EntityType(StrEnum):
    """What a node is."""

    # Activity
    ATTACK = "attack"
    INCIDENT = "incident"
    CAMPAIGN = "campaign"

    # Actors and their presentations
    ORGANIZATION = "organization"
    THREAT_ACTOR = "threat_actor"
    PERSONA = "persona"
    ALIAS = "alias"

    # Human identity — regulated, see EntityCategory.HUMAN_IDENTITY
    HUMAN_IDENTITY_LEAD = "human_identity_lead"

    # Digital identity
    EMAIL_ADDRESS = "email_address"
    ACCOUNT = "account"
    SOCIAL_ACCOUNT = "social_account"
    MESSAGING_ACCOUNT = "messaging_account"
    HOSTING_ACCOUNT = "hosting_account"

    # Network infrastructure
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    NETBLOCK = "netblock"
    ASN = "asn"
    HOSTING_PROVIDER = "hosting_provider"
    REGISTRAR = "registrar"

    # Cryptographic material
    TLS_CERTIFICATE = "tls_certificate"
    SSH_KEY = "ssh_key"
    PGP_KEY = "pgp_key"

    # Code
    MALWARE = "malware"
    MALWARE_FAMILY = "malware_family"
    SOURCE_CODE_ARTIFACT = "source_code_artifact"
    PHISHING_KIT = "phishing_kit"

    # Operational infrastructure — a role, not a thing. See below.
    C2_INFRASTRUCTURE = "c2_infrastructure"
    EXPLOIT_INFRASTRUCTURE = "exploit_infrastructure"
    PROXY_INFRASTRUCTURE = "proxy_infrastructure"
    TOR_INFRASTRUCTURE = "tor_infrastructure"

    # Financial
    CRYPTO_ADDRESS = "crypto_address"
    WALLET_CLUSTER = "wallet_cluster"
    TRANSACTION = "transaction"
    EXCHANGE = "exchange"

    # Criminal ecosystem
    MARKETPLACE = "marketplace"
    FORUM = "forum"

    # Impact
    VICTIM = "victim"

    # Authentication material found in collected content. Never usable, see credentials.py.
    CREDENTIAL_INDICATOR = "credential_indicator"

    # Analytic indicators
    GEOGRAPHIC_INDICATOR = "geographic_indicator"
    LANGUAGE_INDICATOR = "language_indicator"
    BEHAVIORAL_PATTERN = "behavioral_pattern"
    TTP = "ttp"


CATEGORY_OF: dict[EntityType, EntityCategory] = {
    EntityType.ATTACK: EntityCategory.ACTIVITY,
    EntityType.INCIDENT: EntityCategory.ACTIVITY,
    EntityType.CAMPAIGN: EntityCategory.ACTIVITY,
    EntityType.ORGANIZATION: EntityCategory.ACTOR,
    EntityType.THREAT_ACTOR: EntityCategory.ACTOR,
    EntityType.PERSONA: EntityCategory.ACTOR,
    EntityType.ALIAS: EntityCategory.ACTOR,
    EntityType.HUMAN_IDENTITY_LEAD: EntityCategory.HUMAN_IDENTITY,
    EntityType.EMAIL_ADDRESS: EntityCategory.DIGITAL_IDENTITY,
    EntityType.ACCOUNT: EntityCategory.DIGITAL_IDENTITY,
    EntityType.SOCIAL_ACCOUNT: EntityCategory.DIGITAL_IDENTITY,
    EntityType.MESSAGING_ACCOUNT: EntityCategory.DIGITAL_IDENTITY,
    EntityType.HOSTING_ACCOUNT: EntityCategory.DIGITAL_IDENTITY,
    EntityType.DOMAIN: EntityCategory.NETWORK_INFRASTRUCTURE,
    EntityType.IP_ADDRESS: EntityCategory.NETWORK_INFRASTRUCTURE,
    EntityType.NETBLOCK: EntityCategory.NETWORK_INFRASTRUCTURE,
    EntityType.ASN: EntityCategory.NETWORK_INFRASTRUCTURE,
    EntityType.HOSTING_PROVIDER: EntityCategory.NETWORK_INFRASTRUCTURE,
    EntityType.REGISTRAR: EntityCategory.NETWORK_INFRASTRUCTURE,
    EntityType.TLS_CERTIFICATE: EntityCategory.CRYPTOGRAPHIC_MATERIAL,
    EntityType.SSH_KEY: EntityCategory.CRYPTOGRAPHIC_MATERIAL,
    EntityType.PGP_KEY: EntityCategory.CRYPTOGRAPHIC_MATERIAL,
    EntityType.MALWARE: EntityCategory.CODE,
    EntityType.MALWARE_FAMILY: EntityCategory.CODE,
    EntityType.SOURCE_CODE_ARTIFACT: EntityCategory.CODE,
    EntityType.PHISHING_KIT: EntityCategory.CODE,
    EntityType.C2_INFRASTRUCTURE: EntityCategory.OPERATIONAL_INFRASTRUCTURE,
    EntityType.EXPLOIT_INFRASTRUCTURE: EntityCategory.OPERATIONAL_INFRASTRUCTURE,
    EntityType.PROXY_INFRASTRUCTURE: EntityCategory.OPERATIONAL_INFRASTRUCTURE,
    EntityType.TOR_INFRASTRUCTURE: EntityCategory.OPERATIONAL_INFRASTRUCTURE,
    EntityType.CRYPTO_ADDRESS: EntityCategory.FINANCIAL,
    EntityType.WALLET_CLUSTER: EntityCategory.FINANCIAL,
    EntityType.TRANSACTION: EntityCategory.FINANCIAL,
    EntityType.EXCHANGE: EntityCategory.FINANCIAL,
    EntityType.MARKETPLACE: EntityCategory.ECOSYSTEM,
    EntityType.FORUM: EntityCategory.ECOSYSTEM,
    EntityType.VICTIM: EntityCategory.VICTIM,
    EntityType.CREDENTIAL_INDICATOR: EntityCategory.CREDENTIAL,
    EntityType.GEOGRAPHIC_INDICATOR: EntityCategory.INDICATOR,
    EntityType.LANGUAGE_INDICATOR: EntityCategory.INDICATOR,
    EntityType.BEHAVIORAL_PATTERN: EntityCategory.INDICATOR,
    EntityType.TTP: EntityCategory.INDICATOR,
}

SHARED_INFRASTRUCTURE_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.PROXY_INFRASTRUCTURE,
        EntityType.TOR_INFRASTRUCTURE,
        EntityType.HOSTING_PROVIDER,
        EntityType.REGISTRAR,
        EntityType.EXCHANGE,
        EntityType.ASN,
        EntityType.NETBLOCK,
    }
)
"""Entity types where co-location implies nothing about common control.

Two domains behind the same Cloudflare IP, two personas exiting the same Tor node, two
wallets at the same exchange: these share infrastructure with millions of unrelated
parties. Treating co-location on these as a pivot generates enormous false clusters, and
it is the single most common way naive infrastructure analysis produces confident nonsense.

Pivots through these types must be explicitly justified, not inferred by default. The
graph layer enforces this rather than trusting analysts to remember it.
"""


class NormalizationError(ValueError):
    """The observed value cannot be normalized into a natural key."""


KEYED_BY_CONSTRUCTION_TYPES: frozenset[EntityType] = frozenset({EntityType.CREDENTIAL_INDICATOR})
"""Types whose natural key must be *built*, never observed — so the normalizer may only refuse.

Most entity types normalize an observed form into a key, and a form that will not normalize is
allowed through on a caller-supplied key, because personas and campaigns have no syntax. That
escape hatch is right for them and wrong here: a credential indicator's normalizer exists solely
to refuse anything that is not ``kind:credfp-…``, so falling through it accepts the raw
credential it just rejected.

Membership therefore means: the key is re-validated even when the observed form could not be
normalized. Add a type here only when its normalizer has no success path from a raw observation —
otherwise this closes a door that was supposed to be open.
"""


_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")
_ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def normalize_identifier(entity_type: EntityType, value: str) -> str:
    """Reduce an observed value to the canonical form that defines node identity.

    Conservative by design. When a rule would be ambiguous, the value is lowercased and
    trimmed and nothing more, because merging two distinct entities creates a false link
    while failing to merge two identical ones merely misses a true one. Only one of those
    errors ends up in an attribution.
    """
    raw = value.strip()
    if not raw:
        raise NormalizationError(f"empty identifier for {entity_type.value}")

    match entity_type:
        case EntityType.DOMAIN:
            host = raw.lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            # IDNA: a Unicode homograph and its punycode form are one domain.
            # Failure means the host is already ASCII or malformed; the regex below
            # is the actual gate, so suppression here loses nothing.
            with contextlib.suppress(UnicodeError, UnicodeDecodeError):
                host = host.encode("idna").decode("ascii")
            if not _DOMAIN_RE.match(host):
                raise NormalizationError(f"{value!r} is not a well-formed domain name")
            return host

        case EntityType.IP_ADDRESS:
            try:
                # Collapses IPv6 forms: 2001:db8::1 == 2001:0db8:0000::0001
                return str(ipaddress.ip_address(raw))
            except ValueError as exc:
                raise NormalizationError(f"{value!r} is not an IP address") from exc

        case EntityType.NETBLOCK:
            try:
                return str(ipaddress.ip_network(raw, strict=False))
            except ValueError as exc:
                raise NormalizationError(f"{value!r} is not a CIDR block") from exc

        case EntityType.ASN:
            match_asn = _ASN_RE.match(raw)
            if not match_asn:
                raise NormalizationError(f"{value!r} is not an AS number")
            return f"AS{int(match_asn.group(1))}"

        case EntityType.EMAIL_ADDRESS:
            local, sep, domain = raw.rpartition("@")
            if not sep or not local:
                raise NormalizationError(f"{value!r} is not an email address")
            # The domain is case-insensitive; the local part is NOT, per RFC 5321 §2.4.
            # Lowercasing it would merge two addresses that may be different mailboxes.
            return f"{local}@{normalize_identifier(EntityType.DOMAIN, domain)}"

        case EntityType.TLS_CERTIFICATE | EntityType.SSH_KEY | EntityType.MALWARE:
            fingerprint = raw.lower().replace(":", "").replace(" ", "")
            if not _HEX_RE.match(fingerprint):
                raise NormalizationError(
                    f"{entity_type.value} identity must be a hex fingerprint, got {value!r}"
                )
            return fingerprint

        case EntityType.PGP_KEY:
            fingerprint = raw.lower().replace(" ", "").removeprefix("0x")
            if not _HEX_RE.match(fingerprint):
                raise NormalizationError(f"{value!r} is not a PGP fingerprint")
            # Short key ids are forgeable and collide; refuse to key identity on them.
            if len(fingerprint) < 40:
                raise NormalizationError(
                    f"PGP identity requires a full 160-bit fingerprint, got {len(fingerprint) * 4} "
                    "bits; short key ids are trivially collidable and must not define identity"
                )
            return fingerprint

        case EntityType.CRYPTO_ADDRESS:
            # Casing is chain-dependent and sometimes a checksum (EIP-55). Preserve it and
            # let the blockchain adapter supply a chain-qualified key in `qualifiers`.
            return raw

        case EntityType.CREDENTIAL_INDICATOR:
            # The one entity type whose observed form must never be its natural key. A
            # credential node keyed on the credential would put the secret into every edge,
            # every audit line and every projection that names the node — and a natural key is
            # the most widely copied string in this system. So the key is `kind:fingerprint`
            # from `CredentialIndicator.natural_key`, and anything else is refused rather than
            # lowercased and stored, which is what the default branch below would have done.
            from nemesis.core.credentials import CredentialKind, is_fingerprint

            kind, _, fingerprint = raw.partition(":")
            if not is_fingerprint(fingerprint) or kind not in set(CredentialKind):
                raise NormalizationError(
                    "a credential indicator is keyed on 'kind:credfp-...', never on the "
                    "credential. Build the key with CredentialIndicator.natural_key so the "
                    "material stays in the vault and out of the graph"
                )
            return raw

        case _:
            return raw.lower()


class Entity(BaseModel):
    """A node in the Global Adversary Graph.

    Identity is the pair (type, natural key). The surrogate ``entity_id`` exists for
    referencing, but two entities with the same natural key are the same entity and must
    be merged on write.
    """

    model_config = ConfigDict(frozen=True)

    entity_id: EntityId
    entity_type: EntityType
    natural_key: Annotated[str, Field(min_length=1, max_length=1024)]
    """Normalized canonical form. Produced by :func:`normalize_identifier`."""

    observed_form: Annotated[str, Field(min_length=1, max_length=1024)]
    """The value exactly as first seen, before normalization. Kept because the raw form
    is sometimes itself a signal — a homograph domain, an unusual capitalization habit."""

    display_name: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)
    labels: tuple[str, ...] = ()

    extent: TemporalExtent
    """When this entity was observed to exist, with honest bounds."""

    is_synthetic: bool = Field(
        default=False,
        description="True for entities originating from simulated connectors. Never "
        "silently cleared: a synthetic node that loses this flag corrupts every "
        "downstream confidence figure that touches it.",
    )

    @model_validator(mode="after")
    def _check_normalization(self) -> Self:
        try:
            expected = normalize_identifier(self.entity_type, self.observed_form)
        except NormalizationError:
            # An unnormalizable observed form is allowed only if the caller supplied the
            # key explicitly — some entity types (personas, campaigns) have no syntax.
            #
            # **Except where the refusal IS the rule.** For a type in
            # `KEYED_BY_CONSTRUCTION_TYPES` the normalizer's only job is to raise on anything
            # that is not the required shape, so falling through here accepts exactly what it
            # refused. An adversarial review walked straight through it: `Entity.create` refused
            # a raw credential and `Entity(...)` and `Entity.model_validate(...)` — the
            # deserialization path every storage adapter uses — both accepted it as a natural
            # key. The claim "a credential cannot be a graph key" was true of the function and
            # false of the graph.
            if self.entity_type in KEYED_BY_CONSTRUCTION_TYPES:
                normalize_identifier(self.entity_type, self.natural_key)
            return self
        if self.natural_key != expected:
            raise ValueError(
                f"natural_key {self.natural_key!r} does not match the normalized form of "
                f"observed_form {self.observed_form!r} ({expected!r})"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        entity_id: str,
        entity_type: EntityType,
        observed_form: str,
        display_name: str | None = None,
        attributes: dict[str, str] | None = None,
        labels: tuple[str, ...] = (),
        extent: TemporalExtent,
        is_synthetic: bool = False,
    ) -> Entity:
        """Build an entity, normalizing the observed form into its natural key."""
        return cls(
            entity_id=entity_id,
            entity_type=entity_type,
            natural_key=normalize_identifier(entity_type, observed_form),
            observed_form=observed_form,
            display_name=display_name or observed_form,
            attributes=attributes or {},
            labels=labels,
            extent=extent,
            is_synthetic=is_synthetic,
        )

    @property
    def category(self) -> EntityCategory:
        return CATEGORY_OF[self.entity_type]

    @property
    def is_shared_infrastructure(self) -> bool:
        """Whether co-location on this entity is analytically meaningless by default."""
        return self.entity_type in SHARED_INFRASTRUCTURE_TYPES

    @property
    def is_personal_data(self) -> bool:
        """Whether this node holds data about a natural person.

        Triggers retention limits, access restrictions and minimization obligations.
        Criminal suspects retain data-protection rights; the platform must be able to
        find every such node without inspecting free-text attributes.
        """
        return self.category in {EntityCategory.HUMAN_IDENTITY, EntityCategory.VICTIM}

    def identity(self) -> tuple[EntityType, str]:
        """The pair on which two entities are the same entity."""
        return (self.entity_type, self.natural_key)
