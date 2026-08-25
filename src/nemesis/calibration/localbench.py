"""Controlled operations on a loopback range, where the linkage is real because we made it.

Milestone 3 is *controlled operations on infrastructure we own* — the protocol's only path to
ground truth for this project — and it was costed at ~283 operations and declined (ADR-0012).
This is the part of it that needs no funding, no registrar and no third party: a range on
127.0.0.1, where the operations are ours and the linkage is known because this module minted it.

**What is genuinely real here, and it is more than a fixture.** The keypairs are real, the X.509
certificates are real, and every fingerprint is computed from serialised DER — the SPKI parsed
back out of those bytes rather than read off the object this module minted. The kits are real
bytes whose hashes come from their real contents. When two operations share a key, they share it
because one key object was used twice, and that is the ground truth — not a label attached
beside the evidence, but the reason the evidence looks the way it does.

**What it cannot buy, and this is the whole reason it is not milestone 3.** Selectivity for
several signal kinds lives in the world's registries: how many domains a registrar carries, how
many hosts a certificate appears on in a CT log, how common a naming habit is in a zone file.
A loopback range has no such populations and this module refuses to invent them, so signals
whose weight comes from a counted population arrive weighing nothing. Concretely it exercises
the artifact-borne kinds — key control, tooling, exfiltration — and leaves provider-and-timing
and naming patterns exactly where they were.

So: real controlled operations, real ground truth, over a **narrow slice** of the signal
vocabulary. Reported that way, per kind, with the untouched kinds named rather than omitted.

**Containment.** This module opens no socket at all. An earlier version served each certificate
over loopback TLS so the fingerprint came off a wire; ``scripts/check_prohibited.py`` refused it,
because only the collection plane may hold network capability and a control with an exemption for
its author is not a control. Nothing here reaches any network, nothing is registered anywhere and
no third party is contacted.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nemesis.core.entities import EntityType
from nemesis.core.ids import IdPrefix, content_id
from nemesis.core.provenance import SourceClass, SourceDescriptor, SourceReliability
from nemesis.core.relationships import PivotSelectivity
from nemesis.core.temporal import TemporalExtent
from nemesis.pursuit.resurgence import (
    ResurgenceAssessment,
    ResurgenceEngine,
    ResurgenceSignal,
    ResurgenceSignalKind,
)

EXERCISED_KINDS: Final[frozenset[ResurgenceSignalKind]] = frozenset(
    {
        ResurgenceSignalKind.SHARED_PRIVATE_KEY,
        ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
        ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT,
    }
)
"""The signal kinds a loopback range can produce genuine material for.

Their evidence lives in artifacts we can actually make: a private key, a build tree, a drop
address inside a kit. Every other kind's weight comes from a population counted against the
world, and this module will not invent one.
"""

UNTOUCHED_KINDS: Final[frozenset[ResurgenceSignalKind]] = (
    frozenset(ResurgenceSignalKind) - EXERCISED_KINDS
)
"""Named rather than omitted. A report that silently covered three of seven kinds would read as
covering the vocabulary."""


@dataclass(frozen=True)
class Operation:
    """One controlled operation: an identity, a key, a certificate and a kit.

    ``key_id``, ``kit_id`` and ``drop`` are the ground truth. Two operations are linked when
    they share one, and they share it because this module handed them the same object.
    """

    name: str
    started_at: datetime
    key_id: str
    kit_id: str
    drop: str
    certificate_der: bytes
    kit_bytes: bytes
    operator: str = ""
    """Who actually ran this. The ground truth a shared artifact is *not* evidence of.

    Two operations can share a key because one operator reused it, or because a second operator
    copied it to be mistaken for the first. Only this field knows which, and it is the whole
    reason the bench has an adversarial category."""

    planted_from: str | None = None
    """Set when this operation deliberately copied another's observables to frame them."""

    @property
    def certificate_fingerprint(self) -> str:
        """SHA-256 of the DER an observer actually received. A real fingerprint."""
        return hashlib.sha256(self.certificate_der).hexdigest()

    @property
    def spki_fingerprint(self) -> str:
        """SHA-256 of the observed certificate's SubjectPublicKeyInfo.

        The observable that actually means *shared private key*, and the correction the bench
        made to itself: two operations reusing one key get two different certificates, so their
        certificate fingerprints differ and comparing those found nothing. The public key is
        what survives reissuance, and it is what a defender pivots on in practice.

        Parsed back out of the DER the client received rather than read off the object this
        module minted, so it is genuinely an observation.
        """
        observed = x509.load_der_x509_certificate(self.certificate_der)
        return hashlib.sha256(
            observed.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()

    @property
    def kit_hash(self) -> str:
        return hashlib.sha256(self.kit_bytes).hexdigest()


@dataclass
class Range:
    """The loopback range: a local CA, and the operations minted under it."""

    workspace: Path
    ca_key: ec.EllipticCurvePrivateKey
    ca_certificate: x509.Certificate
    operations: list[Operation] = field(default_factory=list)
    _keys: dict[str, ec.EllipticCurvePrivateKey] = field(default_factory=dict)

    def key(self, key_id: str) -> ec.EllipticCurvePrivateKey:
        """One key per id, minted once. Sharing an id is what makes two operations linked."""
        if key_id not in self._keys:
            self._keys[key_id] = ec.generate_private_key(ec.SECP256R1())
        return self._keys[key_id]


def _self_signed_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "NEMESIS local bench CA (SIMULATED)")]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def open_range(workspace: Path) -> Range:
    """Stand up a local CA. Nothing is registered anywhere and nothing leaves the machine."""
    workspace.mkdir(parents=True, exist_ok=True)
    key, certificate = _self_signed_ca()
    return Range(workspace=workspace, ca_key=key, ca_certificate=certificate)


def run_operation(
    span: Range,
    *,
    name: str,
    key_id: str,
    kit_id: str,
    drop: str,
    started_at: datetime,
    operator: str = "",
    planted_from: str | None = None,
) -> Operation:
    """Mint a certificate and a kit, and take the certificate as an observer would hold it.

    Serialised to DER and, for the SPKI, parsed back out of those bytes — so no fingerprint here
    is read off in-memory state. See :func:`_as_an_observer_would_see_it` for what this used to
    do and why it no longer does.
    """
    key = span.key(key_id)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(span.ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(started_at - timedelta(minutes=5))
        .not_valid_after(started_at + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        .sign(span.ca_key, hashes.SHA256())
    )

    kit_bytes = (
        f"// SIMULATED phishing kit for {name}\n"
        f"// sourceMappingURL=/home/operator/{kit_id}/login.js.map\n"
        f"const DROP = '{drop}';\n"
    ).encode()

    observed_der = _as_an_observer_would_see_it(certificate)

    operation = Operation(
        name=name,
        started_at=started_at,
        key_id=key_id,
        kit_id=kit_id,
        drop=drop,
        certificate_der=observed_der,
        kit_bytes=kit_bytes,
        operator=operator,
        planted_from=planted_from,
    )
    span.operations.append(operation)
    return operation


def _as_an_observer_would_see_it(certificate: x509.Certificate) -> bytes:
    """Serialise to DER and hand back the bytes, which is what any observer of it would hold.

    **This used to be a real TLS handshake on 127.0.0.1**, and the argument for it was that a
    fingerprint taken off the wire is an observation while one read off the object we minted is
    an assertion. That argument was fine and the design was not: ``scripts/check_prohibited.py``
    refuses a network import outside the collection plane, and it is right to. Its own rationale
    is that the danger is not somebody writing an obvious scanner but a well-intentioned module
    quietly growing a real socket during development — which is precisely what this was. A
    plane-separation control with an exemption for the author's convenience is not a control.

    What is lost is real and is not papered over: the provenance below is no longer *earned* by
    an observation crossing a wire. What survives is the round trip through DER — every
    fingerprint here is computed from serialised bytes and, for the SPKI, parsed back out of
    them, so nothing is read off in-memory state. That is meaningfully stronger than a fixture
    and meaningfully weaker than a handshake, and the docstrings say so in both directions.
    """
    return certificate.public_bytes(serialization.Encoding.DER)


# -- turning observations into signals ---------------------------------------------

BENCH_SENSOR: Final = SourceDescriptor(
    source_class=SourceClass.OWN_SENSOR,
    identifier="nemesis-local-bench (SIMULATED range)",
    reliability=SourceReliability.COMPLETELY_RELIABLE,
)
"""``OWN_SENSOR``, and the label is weaker than it was.

An earlier version earned it: the observation was a TLS handshake this process performed against
a server this process ran. That required a socket outside the collection plane and was removed.
What remains is a certificate this module minted and serialised, so the class is asserted rather
than demonstrated — accurate for a bench whose whole point is that we own both ends, and not the
same thing as an observation crossing a boundary. Read the bench's results with that discount."""


def signals_between(left: Operation, right: Operation) -> tuple[ResurgenceSignal, ...]:
    """Every continuity actually observable between two operations.

    No population is supplied for any of them, because a loopback range has none to count and
    inventing one is the failure this project has spent its calibration effort refusing. The
    consequence is visible in the results: these signals weigh what an uncounted attribute
    weighs, which is nothing, and the report says so rather than quietly scaling them up.
    """
    found: list[ResurgenceSignal] = []

    def add(kind: ResurgenceSignalKind, attribute: str, *, unique: bool) -> None:
        found.append(
            ResurgenceSignal(
                kind=kind,
                shared_attribute=attribute,
                selectivity=PivotSelectivity(attribute=attribute, is_globally_unique=unique),
                observed_by=BENCH_SENSOR,
                new_entity_type=EntityType.DOMAIN,
                new_entity_key=right.name,
                prior_entity_key=left.name,
                extent=TemporalExtent.at(right.started_at),
                supporting_claims=(content_id(IdPrefix.CLAIM, attribute.encode()),),
            )
        )

    if left.spki_fingerprint == right.spki_fingerprint:
        add(
            ResurgenceSignalKind.SHARED_PRIVATE_KEY,
            f"public_key:{right.spki_fingerprint}",
            unique=True,
        )
    if left.kit_id == right.kit_id:
        add(
            ResurgenceSignalKind.SHARED_TOOLING_ARTIFACT,
            f"source_code_artifact:/home/operator/{right.kit_id}/",
            unique=False,
        )
    if left.drop == right.drop:
        add(
            ResurgenceSignalKind.SHARED_EXFILTRATION_ENDPOINT,
            f"email_address:{right.drop}",
            unique=False,
        )
    return tuple(found)


@dataclass(frozen=True)
class PairOutcome:
    """One pair, what the engine said, and what was actually true."""

    left: str
    right: str
    truly_linked: bool
    signals: tuple[ResurgenceSignal, ...]
    assessment: ResurgenceAssessment

    @property
    def called_linked(self) -> bool:
        return self.assessment.is_actionable


@dataclass(frozen=True)
class BenchResult:
    """What the range produced, scored against the linkage it was built with."""

    operations: int
    outcomes: tuple[PairOutcome, ...]

    @property
    def linked_pairs(self) -> tuple[PairOutcome, ...]:
        return tuple(o for o in self.outcomes if o.truly_linked)

    @property
    def unlinked_pairs(self) -> tuple[PairOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.truly_linked)

    @property
    def planted_pairs(self) -> tuple[PairOutcome, ...]:
        """Different operators, linked anyway by artifacts one of them copied.

        Reported apart from the rest of the unlinked pairs because they are the only ones that
        test anything. A pair sharing nothing is refused trivially, and a false-positive rate
        averaged over thousands of those is a number that cannot go up.
        """
        return tuple(o for o in self.unlinked_pairs if o.signals)

    @property
    def clearable_pairs(self) -> tuple[PairOutcome, ...]:
        """Linked pairs with two or more independent facts behind them.

        The denominator a recall figure needs. A pair sharing one attribute is refused by the
        single-origin veto however real that attribute is, and that refusal is the engine
        working — counting it as a miss would report a control as a failure.
        """
        return tuple(o for o in self.linked_pairs if len(o.signals) >= 2)

    @property
    def single_fact_refusals(self) -> int:
        """Linked pairs correctly refused for resting on one fact."""
        return sum(1 for o in self.linked_pairs if len(o.signals) == 1 and not o.called_linked)

    @property
    def true_positives(self) -> int:
        return sum(1 for o in self.clearable_pairs if o.called_linked)

    @property
    def false_positives(self) -> int:
        return sum(1 for o in self.unlinked_pairs if o.called_linked)

    def render(self) -> str:
        linked = self.linked_pairs
        clearable = self.clearable_pairs
        unlinked = self.unlinked_pairs
        recall = self.true_positives / len(clearable) if clearable else 0.0
        single = sum(1 for o in linked if len(o.signals) == 1)
        planted = self.planted_pairs
        planted_called = sum(1 for o in planted if o.called_linked)
        false_rate = self.false_positives / len(unlinked) if unlinked else 0.0
        lines = [
            "Local bench — controlled operations on a loopback range",
            "",
            "  Real keys, real certificates, real kit bytes, and no socket at all. The linkage is",
            "  ground truth because this module minted it, not a label attached beside the",
            "  evidence. Nothing was registered anywhere and no third party was contacted.",
            "",
            f"  {self.operations} operations, {len(self.outcomes)} pairs "
            f"({len(linked)} truly linked, {len(unlinked)} not)",
            f"  recognised {self.true_positives}/{len(clearable)} linked pairs carrying two "
            f"or more independent facts ({recall:.0%})",
            f"  correctly refused {self.single_fact_refusals}/{single} linked pairs resting on "
            "a single fact — the single-origin veto, working",
            f"  called {self.false_positives}/{len(unlinked)} unlinked pairs linked "
            f"({false_rate:.0%}) — but {len(unlinked) - len(planted)} of those share nothing "
            "and are refused trivially",
            f"  ADVERSARIAL: {planted_called}/{len(planted)} pairs where a *different* operator "
            "copied the observables were called a finding",
            "",
            "  Kinds exercised with real material: "
            + ", ".join(sorted(k.value for k in EXERCISED_KINDS)),
            "  Kinds this range cannot touch: "
            + ", ".join(sorted(k.value for k in UNTOUCHED_KINDS)),
            "",
            "  Their weight comes from a population counted against the world — how many",
            "  domains a registrar carries, how common a naming habit is — and a loopback",
            "  range has none. This module supplies no population for any signal rather than",
            "  inventing one, so even the exercised kinds arrive weighing what an uncounted",
            "  attribute weighs. Read the recall figure with that in mind: it measures the",
            "  engine on real artifacts with no selectivity, which is a harder test than it",
            "  will face and a narrower one than milestone 3 would have been.",
        ]
        return "\n".join(lines)


def run_local_bench(
    workspace: Path,
    *,
    operations: int = 12,
    now: datetime | None = None,
) -> BenchResult:
    """Mint a range, run its operations, and score every pair against the truth.

    Operations are laid out so that linkage is genuinely mixed: successive pairs share a key,
    a kit or a drop, and the rest share nothing. The shape is a choice — the same objection the
    swept grid carries — but the *linkage* is not: two operations share a key because one key
    object signed both certificates.
    """
    if operations < 2:
        raise ValueError("a range of fewer than two operations contains no pair to assess")

    started = now or datetime.now(UTC)
    span = open_range(workspace)

    for index in range(operations):
        family = index // 3
        role = index % 3
        # Families of three, standing for one operator running three campaigns. Reuse inside a
        # family is *graded* rather than total: an operator who reuses a key does not
        # necessarily reuse everything, and a layout where every linked pair shared everything
        # would measure an easier world than the real one.
        #
        #   roles 0+1 share a key and a kit -> two facts, two groups: clearable
        #   roles 0+2 share a key only      -> one fact: the single-origin veto holds
        #   roles 1+2 share a key only      -> likewise
        #
        # So the set contains linked pairs the engine should recognise and linked pairs it
        # should refuse, which is the distinction a recall figure is worthless without.
        run_operation(
            span,
            name=f"op{index:03d}.bench.invalid",
            key_id=f"key-{family}",
            kit_id=f"kit-{family}" if role in (0, 1) else f"kit-{index}-solo",
            # Shared per family, because an operator's takings have to go somewhere and the
            # same operator sends them to the same place. Until ADR-0013 every operation was
            # minted with its own drop, so SHARED_EXFILTRATION_ENDPOINT — the one kind whose
            # docstring argues a framer bears a cost — fired zero times, while three docstrings
            # here and in the rendered report claimed it was exercised. That omission is what
            # made the genuine pair and the framed pair the same object: with the drop back,
            # a genuine pair carries exfil + key + tooling and a framed pair carries key +
            # tooling, and the bench can tell a real fix from one that just refuses everything.
            # ...but only for the two that also share a kit. The third keeps its own, so the
            # range still contains linked pairs resting on a single fact and the single-origin
            # veto still has something to refuse. Sharing it across all three took that
            # category to 0/0 and quietly retired a control the bench exists to measure.
            drop=(
                f"drop-family-{family}@bench.invalid"
                if role in (0, 1)
                else f"drop-{index}@bench.invalid"
            ),
            started_at=started + timedelta(days=index * 7),
            operator=f"operator-{family}",
        )

    # One framer, run by somebody else, copying family 0's key and kit wholesale. This is the
    # protocol's *adversarially linked* category and it is the case a bench without one cannot
    # see: every other unlinked pair here shares literally nothing, so refusing them measures
    # nothing at all.
    if operations >= 3:
        run_operation(
            span,
            name="framer000.bench.invalid",
            key_id="key-0",
            kit_id="kit-0",
            drop="drop-framer@bench.invalid",
            started_at=started + timedelta(days=operations * 7),
            operator="operator-framer",
            planted_from="operator-0",
        )

    engine = ResurgenceEngine()
    outcomes: list[PairOutcome] = []
    for i, left in enumerate(span.operations):
        for right in span.operations[i + 1 :]:
            signals = signals_between(left, right)
            # Ground truth is *same operator*, not *shares an artifact*. The framer shares both
            # of family 0's observables and is a different operator, which is precisely the
            # case that separates a resurgence engine from a hash-matching script.
            truly_linked = bool(left.operator) and left.operator == right.operator
            outcomes.append(
                PairOutcome(
                    left=left.name,
                    right=right.name,
                    truly_linked=truly_linked,
                    signals=signals,
                    assessment=engine.assess(
                        campaign=left.name,
                        signals=signals,
                        candidate_population=max(operations, 2),
                        assessed_at=right.started_at,
                    ),
                )
            )
    return BenchResult(operations=operations, outcomes=tuple(outcomes))


__all__ = [
    "BENCH_SENSOR",
    "EXERCISED_KINDS",
    "UNTOUCHED_KINDS",
    "BenchResult",
    "Operation",
    "PairOutcome",
    "Range",
    "open_range",
    "run_local_bench",
    "run_operation",
    "signals_between",
]
