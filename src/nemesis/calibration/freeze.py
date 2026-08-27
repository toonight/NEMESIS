"""The constants and the behaviour, frozen before anything is measured against them.

WHY A FREEZE COMES FIRST

This project's largest declared weakness is that no confidence figure it produces has ever
been scored against a known-correct answer. Fixing that needs a corpus of resolved cases, and
building one is worth nothing if the engine can be adjusted while the evaluation runs: a score
obtained by tuning against the same cases that measure you is a score of your tuning, not of
your method. Every calibration constant in this codebase is a documented *choice*, which makes
the temptation concrete — each one is a dial, and each dial moves a number somebody is about to
grade.

So the order is: freeze, then evaluate. This module makes the freeze **mechanical** rather than
a promise in a document, because a promise is exactly what gets quietly revised at the point it
becomes inconvenient.

WHAT IS FROZEN, AND HOW

Three mechanisms over one scope, because they fail differently and cover each other.

**Every module** in `src/nemesis` — all of it except this file — is hashed as a normalised
syntax tree, one digest each, in `MODULE_DIGESTS`. Docstrings are stripped, so rewording an
explanation changes nothing while changing a comparison does. This is the completeness
guarantee, and it is the only one that sees a bare literal inside a function body, a dataclass
field default, or a two-line logic change that touches no constant at all. `engine_drifted()`
names the modules that moved.

**Every module-level constant**, by normalised syntax, in `CONSTANT_DIGESTS` — 767 of them,
with no classification whatsoever. A dial does not have to hold a digit and does not have to
look like a table; four rules for deciding what counted were tried and all four excluded
something load-bearing. `constants_drifted()` names what moved, appeared or vanished.

**Forty-three constants by imported value**, in `FROZEN_VALUE_DIGESTS`, folded through
`canonical()` so the digest does not depend on the interpreter's hash seed. This catches what a
syntax tree cannot: `PUBLISHED_BAND_BINS` is derived from `BAND_RANGES`, so its own syntax never
changes when the band edges move. `drifted()` names the culprit.

Behaviour is additionally pinned by golden vectors in
`tests/invariants/test_calibration_freeze.py`: fixed inputs, fixed outputs, including two that
run real cases through the attribution and resolution engines to their published bands.

None of this is a prohibition — constants *should* change when there is a reason. It is a
requirement that the change be **deliberate and visible**: `scripts/refreeze_calibration.py`,
in its own commit, with the reason.

WHAT THIS DOES NOT DO

It does not make the constants right. They remain choices, and freezing a choice does not
validate it — it only stops the choice from moving while it is being examined. It also cannot
tell an honest recalibration from a convenient one; it makes both visible, and visibility is
what an evaluation needs to be worth reading.

And it does not stop a determined author: anyone who can edit a dial can regenerate the tables
in the same commit. This is a tripwire against drift and against self-deception. The residual
scope hole is this file itself, excluded because the tables live in it — closed socially rather
than mechanically, by a reviewer looking at any diff that touches `FROZEN_*`, `MODULE_DIGESTS`
or `CONSTANT_DIGESTS`.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Final

CALIBRATION_CONSTANTS: Final[tuple[str, ...]] = (
    # Subjective-logic machinery: how belief, disbelief and uncertainty combine.
    "nemesis.calibration.scoring:PUBLISHED_BAND_BINS",
    "nemesis.calibration.scoring:DEFAULT_BINS",
    "nemesis.calibration.scoring:MIN_BIN_COUNT",
    "nemesis.attribute.dimensions:DEFAULT_TEMPORAL_GAP_TOLERANCE",
    "nemesis.calibration.coherence:TOLERANCE",
    "nemesis.slice.scenario:CLUSTER_MIN_CONFIDENCE",
    "nemesis.slice.scenario:DARK_BAZAAR_PERSONA_POPULATION",
    # Categorical dials: they hold no digits, which is exactly why four numeric scans in a row
    # could not see them. Each decides a published figure as directly as any scalar.
    "nemesis.calibration.harness:LINKAGE_PROPOSITION",
    "nemesis.calibration.harness:ACTIONABLE_BANDS",
    "nemesis.core.provenance:UNPLANTABLE_SOURCE_CLASSES",
    "nemesis.attribute.engine:DIMENSION_PROPOSITION",
    "nemesis.attribute.engine:LOW_PLANTING_COSTS",
    "nemesis.core.relationships:IDENTITY_ASSERTING_RELATIONS",
    "nemesis.core.confidence:VACUITY_THRESHOLD",
    "nemesis.core.confidence:ADMIRALTY_CREDIBILITY_BELIEF",
    "nemesis.core.confidence:ADMIRALTY_RELIABILITY_WEIGHT",
    "nemesis.core.confidence:UNJUDGEABLE_CREDIBILITY_WEIGHT_CEILING",
    "nemesis.core.confidence:BAND_RANGES",
    "nemesis.core.fusion:CONFLICT_ALERT_THRESHOLD",
    # Attribution: how much a planted artifact may move a conclusion, and what deception is
    # assumed to cost before any evidence is seen.
    "nemesis.attribute.engine:PLANTED_EVIDENCE_DISBELIEF_CEILING",
    "nemesis.attribute.engine:CONTRA_INDICATOR_DISCOUNT",
    "nemesis.attribute.engine:DECEPTION_BASE_RATE",
    "nemesis.attribute.engine:DEFAULT_BASE_RATE",
    "nemesis.attribute.engine:PLANTING_BELIEF_BY_COST",
    # Persona resolution: the base rate a linkage is measured against, and the floors and
    # ceilings that keep a fallible technique from becoming decisive.
    "nemesis.resolve.engine:ASSUMED_PERSONAS_PER_OPERATOR",
    "nemesis.resolve.engine:BASE_RATE_FLOOR",
    "nemesis.resolve.engine:BASE_RATE_CEILING",
    "nemesis.resolve.engine:NEGLIGIBLE_CONTRIBUTION",
    # Signal ceilings: what each technique is allowed to be worth at its very best.
    "nemesis.resolve.signals:STYLOMETRY_BELIEF_CEILING",
    "nemesis.resolve.signals:DEMONSTRATED_KEY_CONTROL_CEILING",
    "nemesis.resolve.signals:CONTRADICTION_BELIEF_CEILING",
    "nemesis.resolve.signals:IRREDUCIBLE_UNCERTAINTY",
    "nemesis.resolve.signals:MIN_POSTS_FOR_A_ROUTINE",
    "nemesis.resolve.signals:OPEN_WORLD_STYLOMETRY_PENALTY",
    "nemesis.resolve.signals:OBFUSCATION_STYLOMETRY_PENALTY",
    "nemesis.resolve.signals:BELIEF_CEILING",
    # Categorical, and arguably the heaviest dial here: it decides which generating process
    # each signal is a trace of, and therefore whether two signals compound as independent
    # evidence or average as one dependence group. It holds no numbers, so a numeric scan was
    # structurally unable to see it — moving one entry changed a published band.
    "nemesis.resolve.signals:CORRELATION_GROUP_OF",
    # Tables that decide as much as any scalar, and that the first scanner could not see
    # because it only matched `NAME = <digit>`.
    "nemesis.core.proposition:ROBUSTNESS_MARGIN",
    "nemesis.core.relationships:METHOD_RELIABILITY_CEILING",
    "nemesis.disrupt.options:OWNERSHIP_CONFIDENCE_FLOOR",
    "nemesis.disrupt.options:IMPACT_RANK",
    # Numerical-stability epsilons. Registered rather than excused: they decide behaviour at
    # boundaries, and "it is only an epsilon" is exactly the reasoning that lets a dial escape.
    # Registering one is free; missing one is not.
    "nemesis.core.confidence:_TOLERANCE",
    "nemesis.core.fusion:_EPS",
)
"""The curated epistemic subset, named as ``module:NAME`` and frozen by **imported value**.

Not "every number": most of what decides a published figure here is not a number at all — of the
767 dials `discovered_constants()` covers, 536 hold no numeric literal. And not the completeness
guarantee either, which is the job of the two syntactic digests; this list is deliberately
curated, so it is allowed to be incomplete in a way they are not.

What it buys is the diagnostic. `drifted()` names *which* dial moved, and it reads the value the
interpreter actually holds rather than the syntax that produces it — the distinction that
matters for `PUBLISHED_BAND_BINS`, which is derived from `BAND_RANGES` and whose own syntax never
changes when the band edges do.

Leaving a new constant out of this list is therefore a lost diagnostic, not a lost tripwire:
`constants_drifted()` reports the appearance of any module-level constant anywhere in the tree.
An earlier design put the tripwire here and guarded the omission with a scan over a second list
of modules; the scan and its list were the last enumeration in this file, and every enumeration
before it had already been defeated.
"""

FROZEN_DIGEST: Final = "752ec461155673cb4c202f9907299c9289d90f1fe8454e5e58b720d80e6726bb"
"""The digest of the values above, frozen 2026-08-20, before any evaluation exists.

Updated **only** as a documented event, in its own commit, with the reason. A mismatch is not
a failure of the code — it means a dial moved, and the question it forces is whether that
happened before an evaluation or during one.
"""


def observed_values() -> dict[str, object]:
    """Read every registered constant from the module that actually holds it.

    Imported rather than parsed, so a constant that was moved, renamed or shadowed fails loudly
    here instead of being silently read from a stale copy of the source.
    """
    values: dict[str, object] = {}
    for reference in CALIBRATION_CONSTANTS:
        module_name, _, attribute = reference.partition(":")
        module = importlib.import_module(module_name)
        if not hasattr(module, attribute):
            raise CalibrationFreezeError(
                f"{reference} is registered as a calibration constant and does not exist. "
                "Renaming or removing one is a change to what this platform believes, and it "
                "cannot be allowed to pass as an import error nobody reads."
            )
        values[reference] = getattr(module, attribute)
    return values


CONSTANT_DIGESTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "nemesis.api.app:API_VERSION": "94bbcf8f64e83f7e",
        "nemesis.api.app:SIMULATED_NOTICE": "7319718c8313a0b1",
        "nemesis.api.submission:DEFAULT_SUBMISSIONS_PER_HOUR": "940f567ac7d5a7a9",
        "nemesis.api.submission:MAY_SUBMIT": "da4d3b3ebf186cdb",
        "nemesis.api.submission:SUBMISSION_NOTICE": "e24250fc88eb13d5",
        "nemesis.api.tenancy:UNREGISTERED_TENANT_REFUSAL": "f76fc90c11dccdea",
        "nemesis.attribute.dimensions:DEFAULT_TEMPORAL_GAP_TOLERANCE": "687a6957d88beda6",
        "nemesis.attribute.dimensions:DIMENSION_QUESTION": "4835dc361f29f06b",
        "nemesis.attribute.disclosure:DELIVERABLE_DIMENSIONS": "90a5ec5b163e399e",
        "nemesis.attribute.disclosure:DIMENSION_DISCLOSURE": "e361b48273c2e556",
        "nemesis.attribute.disclosure:_WITHHOLDING_REASON": "65d9894a71a9ce77",
        "nemesis.attribute.engine:CONTRA_INDICATOR_DISCOUNT": "14a8ecb0e489bec0",
        "nemesis.attribute.engine:DECEPTION_BASE_RATE": "5097d8d3c07c0f02",
        "nemesis.attribute.engine:DEFAULT_BASE_RATE": "c7f54eb3c2804e6c",
        "nemesis.attribute.engine:DIMENSION_PROPOSITION": "a6e4dd5a1223a27d",
        "nemesis.attribute.engine:LOW_PLANTING_COSTS": "b32c8197cf2f7b04",
        "nemesis.attribute.engine:NEGLIGIBLE_CONTRIBUTION_NOTE": "3c1811a49b869c51",
        "nemesis.attribute.engine:PLANTED_EVIDENCE_DISBELIEF_CEILING": "176ae9fcc8b1a09f",
        "nemesis.attribute.engine:PLANTING_BELIEF_BY_COST": "ec64de3bf72ebc12",
        "nemesis.attribute.engine:REFUSED_IDENTITY_HYPOTHESIS": "67779367ca77fecc",
        "nemesis.attribute.engine:_REFUSAL_REMEDY": "24109a331ddcfacc",
        "nemesis.audit.trail:HASH_PREFIX": "72ecce8fdbb5d19f",
        "nemesis.audit.trail:MAX_RENDERED_RESULTS": "18f95d3ec3fcb890",
        "nemesis.audit.trail:_UNATTRIBUTABLE_ACTORS": "e84dd687bbb54059",
        "nemesis.authz.anchor:INDEPENDENCE_RANK": "4fd7a0d571760a5a",
        "nemesis.authz.anchor:LOCAL_ANCHOR_AUTHORITY": "43d1f5fc0b66a291",
        "nemesis.authz.anchor:REVOCATION_CHAIN": "6aa6166ba58cd6cc",
        "nemesis.authz.anchor:SPEND_CHAIN": "f9f3982fffc68563",
        "nemesis.authz.attestation:AUDIENCE": "a3563a90163a03bc",
        "nemesis.authz.audit_anchor:ANCHOR_FILE": "6a2ec0d885ddb7f4",
        "nemesis.authz.audit_anchor:ANCHOR_PUBLIC_KEY_FILE": "5488e2de6f3cb13a",
        "nemesis.authz.audit_anchor:AUDIT_CHAIN": "76a099ab0b63925e",
        "nemesis.authz.audit_anchor:RETAINED_EPOCH_FILE": "07a5d26cc48aaafa",
        "nemesis.authz.envelope:DEFAULT_AUTONOMOUS_EFFECT_BUDGET": "37d10dc09a311b23",
        "nemesis.authz.gateway:MAX_CAPABILITY_LIFETIME": "3866862a69bfd65d",
        "nemesis.authz.keys:_ED25519_SIGNATURE_BYTES": "196effcb6590f357",
        "nemesis.authz.keys:_KEY_ID_HEX_CHARS": "a3c0f15d78c6c84e",
        "nemesis.authz.providers:ASSERTION_LIFETIME": "548e4295146e89b4",
        "nemesis.authz.providers:PROVIDER_NAME": "1d4d826842ad2df7",
        "nemesis.authz.rbac:APPROVAL_ROLES": "b84efd949978f141",
        "nemesis.authz.rbac:DEFAULT_MINIMUM_ASSURANCE": "0cb4562348ae7903",
        "nemesis.authz.rbac:MINIMUM_ASSURANCE": "82edbd5cea9aa9f2",
        "nemesis.authz.rbac:REQUEST_ROLES": "95633cccff954b43",
        "nemesis.authz.store:SCHEMA_VERSION": "855fe64e00145f1f",
        "nemesis.authz.store:_SCHEMA": "ec56dc4337b468dc",
        "nemesis.authz.verification:SIGNATURE_SCHEME": "279ecd288193f512",
        "nemesis.authz.verification:_ED25519_SIGNATURE_BYTES": "6d2c75a7a1708b33",
        "nemesis.authz.verification:_KEY_ID_HEX_CHARS": "36e05c58cedda8b4",
        "nemesis.breaker.arena:APPROVED_DOMAIN": "a0595f7e13c0d1dc",
        "nemesis.breaker.arena:APPROVED_STATE": "0220b7b550b3e7eb",
        "nemesis.breaker.arena:ARENA_NOW": "0e685f18b6cb9a01",
        "nemesis.breaker.arena:SEED_DOMAIN": "6aad4c0424ab64f3",
        "nemesis.breaker.arena:UNAPPROVED_DOMAIN": "7e7071d47126705e",
        "nemesis.breaker.attacks:ATTACKS": "ef951340341e54d8",
        "nemesis.calibration.ceilings:FLOOR_PERTURBATIONS": "cd72fd88fb803cd3",
        "nemesis.calibration.ceilings:PERTURBATIONS": "451fc91a74e0c160",
        "nemesis.calibration.ceilings:PROBE_AT": "071a2a8fe3ac0305",
        "nemesis.calibration.ceilings:PROBE_POPULATION": "6f6123a2442ba456",
        "nemesis.calibration.ceilings:SWEPT_PAIR_POPULATIONS": "0cdd2e52201c576e",
        "nemesis.calibration.ceilings:SWEPT_PLANTABILITY": "0cfcb0b846b71f35",
        "nemesis.calibration.ceilings:SWEPT_POPULATIONS": "0cd01dacb12c5561",
        "nemesis.calibration.coherence:TOLERANCE": "09d94cbf2f01ec5f",
        "nemesis.calibration.corpus:AMBIGUOUS_HAS_NO_TRUE_ANSWER": "318bb73adef364fb",
        "nemesis.calibration.corpus:_CATEGORY_OF": "8343f40ee4a1339e",
        "nemesis.calibration.harness:ACTIONABLE_BANDS": "d263b963eee112f8",
        "nemesis.calibration.harness:LINKAGE_PROPOSITION": "bc1841ac1b6d3927",
        "nemesis.calibration.localbench:BENCH_SENSOR": "e99d30729f95fbba",
        "nemesis.calibration.localbench:EXERCISED_KINDS": "02d7bfe920665d6a",
        "nemesis.calibration.localbench:UNTOUCHED_KINDS": "a69298b21ab290bd",
        "nemesis.calibration.scoring:DEFAULT_BINS": "dd60760fbb7a8524",
        "nemesis.calibration.scoring:MIN_BIN_COUNT": "18578fe28c9d8897",
        "nemesis.calibration.scoring:PUBLISHED_BAND_BINS": "c28cf92be6fa0bed",
        "nemesis.calibration.sizing:ASSUMED_RATE": "b361601d8c508cd3",
        "nemesis.calibration.sizing:TARGET_MARGINS": "2cfdfda968ce3924",
        "nemesis.calibration.sizing:Z_95": "a007c82e18567935",
        "nemesis.cli.main:BANNER": "5b32641a3b67e4fa",
        "nemesis.cli.main:NOT_DEMONSTRATED": "e41c22bbab46065a",
        "nemesis.cli.main:_RULE": "a534e579c0df6936",
        "nemesis.collaboration.approvals:PROPOSAL_DIGEST_LENGTH": "39ee4693e6f28322",
        "nemesis.collaboration.approvals:_APOSTROPHES": "d756ca57674cf394",
        "nemesis.collaboration.approvals:_APPROVE_PATTERN": "4c51bfd0ac286700",
        "nemesis.collaboration.approvals:_DIGEST_PATTERN": "b1fa3a4ae173a648",
        "nemesis.collaboration.approvals:_NEGATION_PATTERN": "2bc1622301a3845f",
        "nemesis.collaboration.approvals:_REJECT_PATTERN": "e2f883f890b91be5",
        "nemesis.collaboration.demonstration:APPROVALS_CHANNEL": "664a9121afaf0423",
        "nemesis.collaboration.demonstration:CASE_CHANNEL": "3e491ef9f542c491",
        "nemesis.collaboration.demonstration:CASE_ID": "3e72a43c65dc0ba0",
        "nemesis.collaboration.demonstration:CORRELATION_ID": "183aaa27bcb0535b",
        "nemesis.collaboration.demonstration:INJECTED_REPLY": "2c14d39886875628",
        "nemesis.collaboration.demonstration:INVESTIGATION_ID": "152709416a6e1c73",
        "nemesis.collaboration.demonstration:OPS_CHANNEL": "abbb2adbc0cb474d",
        "nemesis.collaboration.demonstration:T0": "9946e428f9328b55",
        "nemesis.collaboration.events:MAX_PAYLOAD_ENTRIES": "ce45f23294e4e97e",
        "nemesis.collaboration.events:MAX_PAYLOAD_KEY_LENGTH": "dd39e13ea6ed6e64",
        "nemesis.collaboration.events:MAX_PAYLOAD_VALUE_LENGTH": "d04447ae4ad65fe4",
        "nemesis.collaboration.events:MAX_REFERENCES": "b22358a9d1d12262",
        "nemesis.collaboration.events:MAX_SUMMARY_LENGTH": "957578585db3a82b",
        "nemesis.collaboration.events:_CLAIM_STANDING": "0c1ee2a4e12d0936",
        "nemesis.collaboration.events:_MODEL_DERIVATIONS": "4d342e443e66602b",
        "nemesis.collaboration.identities:STANDING_ACTORS": "8440b854e0207a9a",
        "nemesis.collaboration.outbox:DEFAULT_BASE_DELAY_SECONDS": "b90f95302d9c6a0d",
        "nemesis.collaboration.outbox:DEFAULT_COOLDOWN_SECONDS": "d61ce90687052f23",
        "nemesis.collaboration.outbox:DEFAULT_FAILURE_THRESHOLD": "6f6bf9d5cd28dec5",
        "nemesis.collaboration.outbox:DEFAULT_MAX_ATTEMPTS": "34bcb8fe01e73b62",
        "nemesis.collaboration.outbox:DEFAULT_MAX_DELAY_SECONDS": "43c9f607b7a59d0b",
        "nemesis.collaboration.providers.buzz.provider:PROVIDER_NAME": "919fc06cad569ad0",
        "nemesis.collaboration.providers.buzz.provider:_AUTH_PREFIXES": "f40f64a958cd1b58",
        "nemesis.collaboration.providers.buzz.provider:_DUPLICATE_PREFIXES": "0341de368b82b436",
        "nemesis.collaboration.providers.buzz.provider:_REJECTION_PREFIXES": "37ac76fe976461e0",
        "nemesis.collaboration.providers.buzz.transport:_UNWIRED_SIGNER_MESSAGE": (
            "67adc2b65aa79635"
        ),
        "nemesis.collaboration.providers.buzz.transport:_UNWIRED_TRANSPORT_MESSAGE": (
            "a6e1f66a34217fb8"
        ),
        "nemesis.collaboration.providers.buzz.wire:CHANNEL_NAMESPACE": "573d8457f5d98093",
        "nemesis.collaboration.providers.buzz.wire:KIND_ADD_USER": "c92dbee19b4c4618",
        "nemesis.collaboration.providers.buzz.wire:KIND_AUTH": "14247972313b229d",
        "nemesis.collaboration.providers.buzz.wire:KIND_CREATE_GROUP": "e673dff76f55f013",
        "nemesis.collaboration.providers.buzz.wire:KIND_GROUP_MESSAGE": "73e64aaf6d1ac6c4",
        "nemesis.collaboration.providers.buzz.wire:KIND_PROFILE": "cf4e8a70b45de8bc",
        "nemesis.collaboration.providers.buzz.wire:MAX_CONTENT_BYTES": "ddc9122b752d5192",
        "nemesis.collaboration.providers.buzz.wire:MAX_TAG_VALUE_BYTES": "a3b9681275ec9b89",
        "nemesis.collaboration.providers.buzz.wire:NEMESIS_TAG_NAMESPACE": "489cdf89263b4cac",
        "nemesis.collaboration.providers.buzz.wire:_LOCALHOST_AUTHORITY": "f730cbd8a33449fd",
        "nemesis.collaboration.providers.local:PROVIDER_NAME": "fe31a8d5063857f8",
        "nemesis.collaboration.providers.local:_SAFE_KEY": "aac5f98a2d9d64e5",
        "nemesis.collaboration.providers.registry:DEFAULT_PROVIDER": "2f0d287c962ee682",
        "nemesis.collaboration.providers.registry:PROVIDERS": "47ef34f172dd524a",
        "nemesis.collaboration.publisher:ACTION_BIND_ACTOR": "4e79b975de76ae43",
        "nemesis.collaboration.publisher:ACTION_OPEN_CHANNEL": "9faac86bde84d534",
        "nemesis.collaboration.publisher:ACTION_PUBLISH": "7457d47937b80d77",
        "nemesis.collaboration.publisher:ACTION_READ_INTENT": "94bee46cf2548efd",
        "nemesis.collaboration.publisher:ACTION_READ_SIGNALS": "c5cf42c459871a6b",
        "nemesis.collaboration.publisher:MAX_INPUT_LENGTH": "ea3d784b639f1625",
        "nemesis.collaboration.publisher:OUTCOME_REFUSED_DISCLOSURE": "001402fac62aee88",
        "nemesis.collect.base:CONNECTOR_VERSION": "d1134bd96f5e31fb",
        "nemesis.collect.base:FIXTURE_SET": "8149c197f890fe74",
        "nemesis.collect.base:QUALIFIER_GLOBALLY_UNIQUE": "9988864a7b7ef12e",
        "nemesis.collect.base:QUALIFIER_HEURISTIC": "72503309bc232a6c",
        "nemesis.collect.base:QUALIFIER_HEURISTIC_FAILURE_MODE": "2061b0899a6a464f",
        "nemesis.collect.base:QUALIFIER_HOSTILE_CONTENT": "a04050462aead6df",
        "nemesis.collect.base:QUALIFIER_PIVOT_METHOD": "0695f00ea692ab60",
        "nemesis.collect.base:QUALIFIER_POPULATION_CORPUS": "c309f11138fd57af",
        "nemesis.collect.base:QUALIFIER_POPULATION_SIZE": "9b18956bb8116c6e",
        "nemesis.collect.base:QUALIFIER_QUOTED_VERBATIM": "181e3362fec52edf",
        "nemesis.collect.base:QUALIFIER_SHARED_ATTRIBUTE": "14d41e5a7350470d",
        "nemesis.collect.base:QUALIFIER_SHARED_INFRASTRUCTURE_JUSTIFICATION": "6dfa3a8fb129d400",
        "nemesis.collect.dark_web:CONNECTOR_VERSION": "8c33878168f37b09",
        "nemesis.collect.dark_web:DEFAULT_MAX_RESPONSE_BYTES": "ff5b4e7da625757f",
        "nemesis.collect.dark_web:DEFAULT_TIMEOUT_SECONDS": "536c610de68f9c12",
        "nemesis.collect.dark_web:DEFAULT_TOR_PROXY": "8ed5ec87fb06bdaa",
        "nemesis.collect.dark_web:MAX_CONFIGURED_SERVICES": "ae895e1e32730ccc",
        "nemesis.collect.dark_web:MAX_RESPONSE_BYTES": "29f445c551aea382",
        "nemesis.collect.dark_web:MAX_TIMEOUT_SECONDS": "4b4587af3746ae3f",
        "nemesis.collect.dark_web:_ONION_CHECKSUM_PREFIX": "a955c58db5b48945",
        "nemesis.collect.dark_web:_ONION_LABEL": "37bc801ba0d54c7f",
        "nemesis.collect.dark_web:_TEXT_MEDIA_TYPES": "dab06aacb41f8ef0",
        "nemesis.collect.deepdarkcti:MAX_NAME_CHARS": "7a039f7bc8499f9c",
        "nemesis.collect.deepdarkcti:MAX_ROWS": "b3a5ea61a7c8249f",
        "nemesis.collect.deepdarkcti:_ALLOWED_ENTITY_TYPES": "1aa42ec30f809a82",
        "nemesis.collect.deepdarkcti:_CREDENTIALS": "d29afe18212c2c1f",
        "nemesis.collect.deepdarkcti:_MARKDOWN_LINK": "d3c6444bed888471",
        "nemesis.collect.deepdarkcti:_OFFLINE": "b39a91ba043d69c6",
        "nemesis.collect.deepdarkcti:_ONION_URL": "a15d6181935a5f6c",
        "nemesis.collect.deepdarkcti:_ONLINE": "9cf669786314f1c0",
        "nemesis.collect.fixtures.glass_anvil:ACME_EMAIL_GATEWAY": "37bbf921e8e96363",
        "nemesis.collect.fixtures.glass_anvil:ACME_WAF": "b7728a3719cd76e0",
        "nemesis.collect.fixtures.glass_anvil:BUILD_PATH": "8116aa9434f019f6",
        "nemesis.collect.fixtures.glass_anvil:BUILD_PATH_DECEPTION": "52efc8e0661a704f",
        "nemesis.collect.fixtures.glass_anvil:BULLETPROOF_ASN": "a17331e4c15c8f78",
        "nemesis.collect.fixtures.glass_anvil:BULLETPROOF_HOST": "f1e92a8c8a62d3db",
        "nemesis.collect.fixtures.glass_anvil:CDN_ASN": "ab2b159da65d9692",
        "nemesis.collect.fixtures.glass_anvil:CDN_IP": "56909144e25b256b",
        "nemesis.collect.fixtures.glass_anvil:CDN_OPERATOR": "7c6f82e263ab2e20",
        "nemesis.collect.fixtures.glass_anvil:CDN_POPULATION": "88966d5a305ab718",
        "nemesis.collect.fixtures.glass_anvil:CERTIFICATE_CORPUS": "e6807f165394f85d",
        "nemesis.collect.fixtures.glass_anvil:CERTIFICATE_CORPUS_RESURGENCE": "c58d5fd3fb61d003",
        "nemesis.collect.fixtures.glass_anvil:CERTIFICATE_POPULATION": "697453dc18a947e1",
        "nemesis.collect.fixtures.glass_anvil:CERTIFICATE_POPULATION_AFTER_RESURGENCE": (
            "74dd3bd3a3867fbd"
        ),
        "nemesis.collect.fixtures.glass_anvil:CERT_FINGERPRINT": "826cc01c7f11c29c",
        "nemesis.collect.fixtures.glass_anvil:CLUSTERING_FAILURE_MODE": "a30d5377006e5130",
        "nemesis.collect.fixtures.glass_anvil:CLUSTERING_HEURISTIC": "2552cb4bb79808ad",
        "nemesis.collect.fixtures.glass_anvil:CLUSTER_DOMAINS": "67e33b6afc61263f",
        "nemesis.collect.fixtures.glass_anvil:CLUSTER_IP": "c714097c6c07e8a2",
        "nemesis.collect.fixtures.glass_anvil:CLUSTER_NETBLOCK": "900e3cb89b905b8e",
        "nemesis.collect.fixtures.glass_anvil:CLUSTER_POPULATION": "3d1f5f4b7f11ca32",
        "nemesis.collect.fixtures.glass_anvil:DARK_WEB_CORPUS": "6fc5075c6a1595fd",
        "nemesis.collect.fixtures.glass_anvil:DETECTED_AT": "473f75f965ce5b0f",
        "nemesis.collect.fixtures.glass_anvil:EXCHANGE": "c79b0b3bab6c1683",
        "nemesis.collect.fixtures.glass_anvil:EXFIL_ADDRESS": "526d8f9864b4632f",
        "nemesis.collect.fixtures.glass_anvil:EXFIL_DROP_CORPUS": "a9fb1e55dfc9ef9d",
        "nemesis.collect.fixtures.glass_anvil:EXFIL_DROP_POPULATION": "28173eeea2dd349b",
        "nemesis.collect.fixtures.glass_anvil:FALSE_FLAG_DECEPTION": "8ffe104a81b18e8f",
        "nemesis.collect.fixtures.glass_anvil:FALSE_FLAG_STRING": "c5e96832fbc19488",
        "nemesis.collect.fixtures.glass_anvil:FORUM_CURRENT": "4f3458e1728005a0",
        "nemesis.collect.fixtures.glass_anvil:FORUM_RESURGENT": "bf772796db3209ef",
        "nemesis.collect.fixtures.glass_anvil:FRAMED_ORGANIZATION": "ef736c0dca339c0e",
        "nemesis.collect.fixtures.glass_anvil:INBOUND_PAYMENT_COUNT": "1c831178d264aeb9",
        "nemesis.collect.fixtures.glass_anvil:INJECTION_DECEPTION": "9ab15dd70df6f5be",
        "nemesis.collect.fixtures.glass_anvil:KIT_HOST_IP": "3f827d70a707baaf",
        "nemesis.collect.fixtures.glass_anvil:KIT_MARKER_CORPUS": "1e4d70ca943c8d42",
        "nemesis.collect.fixtures.glass_anvil:KIT_MARKER_POPULATION": "81a71b3d34416f4d",
        "nemesis.collect.fixtures.glass_anvil:KIT_SHA256": "d88d0f974ea2d98f",
        "nemesis.collect.fixtures.glass_anvil:LANGUAGE_DECEPTION": "cb78fbe483424eac",
        "nemesis.collect.fixtures.glass_anvil:LEDGER_CORPUS": "f2ca6b4ebda5ebfd",
        "nemesis.collect.fixtures.glass_anvil:MARKETPLACE_HISTORICAL": "f5729a8702b63fc0",
        "nemesis.collect.fixtures.glass_anvil:NAMED_PERSON": "a6502de2253fe933",
        "nemesis.collect.fixtures.glass_anvil:PASSIVE_DNS_CORPUS": "1186e4536fdf5f67",
        "nemesis.collect.fixtures.glass_anvil:PERSONA_CURRENT": "aa533c56272522f4",
        "nemesis.collect.fixtures.glass_anvil:PERSONA_HISTORICAL": "20cd63d8ab6f1cc7",
        "nemesis.collect.fixtures.glass_anvil:PERSONA_INFORMANT": "0f6f5d9d80425667",
        "nemesis.collect.fixtures.glass_anvil:PERSONA_RESURGENT": "b7b8298775a34b92",
        "nemesis.collect.fixtures.glass_anvil:PGP_FINGERPRINT": "11c5d244dd17b770",
        "nemesis.collect.fixtures.glass_anvil:PHISHING_SOURCE_IP": "a23798bc825eeb43",
        "nemesis.collect.fixtures.glass_anvil:PLANTED_IDENTITY_DECEPTION": "93b463272a83ed4c",
        "nemesis.collect.fixtures.glass_anvil:PLANTED_IDENTITY_POST": "efc8b644d4134e9f",
        "nemesis.collect.fixtures.glass_anvil:PROMPT_INJECTION_POST": "0402a56b5dab4128",
        "nemesis.collect.fixtures.glass_anvil:RDAP_CORPUS": "3c76a070937c4b37",
        "nemesis.collect.fixtures.glass_anvil:REGISTRAR": "57b54e718660874f",
        "nemesis.collect.fixtures.glass_anvil:REGISTRATION_WINDOW_JUSTIFICATION": (
            "475da82235cf2dd1"
        ),
        "nemesis.collect.fixtures.glass_anvil:RESURGENCE_ASN": "42010dbf3a472194",
        "nemesis.collect.fixtures.glass_anvil:RESURGENCE_AS_OF": "39cec9711bccd49a",
        "nemesis.collect.fixtures.glass_anvil:RESURGENCE_DOMAIN": "f2307865d8ad3bb8",
        "nemesis.collect.fixtures.glass_anvil:RESURGENCE_HOST": "4f9f79068cf95839",
        "nemesis.collect.fixtures.glass_anvil:RESURGENCE_IP": "edccf7ef6a90a300",
        "nemesis.collect.fixtures.glass_anvil:RESURGENCE_REGISTRAR": "320ab2de079f0ddb",
        "nemesis.collect.fixtures.glass_anvil:SCENARIO_PRESENT": "da3aaf1c682af9b5",
        "nemesis.collect.fixtures.glass_anvil:SEED_DOMAIN": "41124ec2fb5b2890",
        "nemesis.collect.fixtures.glass_anvil:SENDER_DOMAIN": "32788bbaf3171e1f",
        "nemesis.collect.fixtures.glass_anvil:TELEGRAM_CHANNEL": "1af503350346f3c8",
        "nemesis.collect.fixtures.glass_anvil:THIRD_CERT_IP": "4b37b59076722841",
        "nemesis.collect.fixtures.glass_anvil:WALLET_EXCHANGE_DEPOSIT": "2c2c15bd7deaf7d2",
        "nemesis.collect.fixtures.glass_anvil:WALLET_PRIMARY": "128e892a7f2dfdcc",
        "nemesis.collect.fixtures.glass_anvil:WALLET_SECOND": "e69c83e9f5f25790",
        "nemesis.collect.fixtures.glass_anvil:_ACME_OPERATOR": "02507812a68d1326",
        "nemesis.collect.fixtures.glass_anvil:_FIRST_SEEN": "7902da6d4acfddfd",
        "nemesis.collect.fixtures.glass_anvil:_FORUM_ACTIVE_FROM": "897313ad90eec64e",
        "nemesis.collect.fixtures.glass_anvil:_FORUM_ACTIVE_UNTIL": "c78af2b3d5032541",
        "nemesis.collect.fixtures.glass_anvil:_LAST_SEEN": "60a666ec230bfe56",
        "nemesis.collect.fixtures.glass_anvil:_LEDGER_FROM": "a6e5f4558ecf427e",
        "nemesis.collect.fixtures.glass_anvil:_LEDGER_UNTIL": "27fc40b2f9cc2c1c",
        "nemesis.collect.fixtures.glass_anvil:_MARKETPLACE_2024_FROM": "e007e80697d113a2",
        "nemesis.collect.fixtures.glass_anvil:_MARKETPLACE_2024_UNTIL": "b5bc4070aa678ce6",
        "nemesis.collect.fixtures.glass_anvil:_RDAP_OBSERVED": "93181591874b25c8",
        "nemesis.collect.fixtures.glass_anvil:_REGISTERED_FIRST": "5d350ca3c9d84d81",
        "nemesis.collect.fixtures.glass_anvil:_REGISTERED_LAST": "b20083561032c064",
        "nemesis.collect.fixtures.glass_anvil:_REGISTRATION_EXPIRES": "f3043885742bfc5a",
        "nemesis.collect.fixtures.glass_anvil:_RESURGENCE_EXPIRES": "230ee1458d3a0051",
        "nemesis.collect.fixtures.glass_anvil:_RESURGENCE_FROM": "8b85a907dd7c1b08",
        "nemesis.collect.fixtures.glass_anvil:_RESURGENCE_UNTIL": "6eec49e0bb54335e",
        "nemesis.collect.fixtures.iron_tide:ACCESS_LISTING_TITLE": "828a56f7ad6350ba",
        "nemesis.collect.fixtures.iron_tide:BEACON_INTERVAL_SECONDS": "ee84115e871a5c68",
        "nemesis.collect.fixtures.iron_tide:BEACON_JITTER_SECONDS": "d2365a0f11d1fd83",
        "nemesis.collect.fixtures.iron_tide:BEACON_SESSIONS": "6c0af31e9a9426ea",
        "nemesis.collect.fixtures.iron_tide:BUILD_METADATA_DECEPTION": "4cab7fee0d3f5981",
        "nemesis.collect.fixtures.iron_tide:C2_CONFIG_CORPUS": "c8ba96d1032f660e",
        "nemesis.collect.fixtures.iron_tide:CERTIFICATE_CORPUS": "21d822348376f6ab",
        "nemesis.collect.fixtures.iron_tide:CERTIFICATE_POPULATION": "67f9efa3082627d8",
        "nemesis.collect.fixtures.iron_tide:CERT_FINGERPRINT": "69109844d240d005",
        "nemesis.collect.fixtures.iron_tide:CERT_JARM": "ada1f9fe34799093",
        "nemesis.collect.fixtures.iron_tide:CERT_SUBJECT_CN": "4f777bc4641ff988",
        "nemesis.collect.fixtures.iron_tide:CLUSTERING_FAILURE_MODE": "14136becc8bcdd19",
        "nemesis.collect.fixtures.iron_tide:CLUSTERING_HEURISTIC": "ba315aa8b7ccda4b",
        "nemesis.collect.fixtures.iron_tide:CLUSTER_DOMAINS": "bb0693b3505f17f8",
        "nemesis.collect.fixtures.iron_tide:CONTACT_HANDLE_DECEPTION": "15b5dce247d1c679",
        "nemesis.collect.fixtures.iron_tide:DARK_WEB_CORPUS": "5c5288706391b9be",
        "nemesis.collect.fixtures.iron_tide:DEDICATED_LEASE_JUSTIFICATION": "4731662355d95422",
        "nemesis.collect.fixtures.iron_tide:DETECTED_AT": "0b3962a952dc3ec8",
        "nemesis.collect.fixtures.iron_tide:FALSE_FLAG_DECEPTION": "236a0058a9d3fbac",
        "nemesis.collect.fixtures.iron_tide:FALSE_FLAG_STRING": "f2448e0b9a67bc3d",
        "nemesis.collect.fixtures.iron_tide:FORUM": "e26ced526fcda1f4",
        "nemesis.collect.fixtures.iron_tide:FRAMED_ORGANIZATION": "50bf0cef5764d514",
        "nemesis.collect.fixtures.iron_tide:HOST_PROFILE_CORPUS": "0eea990110d32d86",
        "nemesis.collect.fixtures.iron_tide:IMPLANT_BUILD_ID": "124ae26764cf2268",
        "nemesis.collect.fixtures.iron_tide:IMPLANT_SHA256": "bdc2706b08f8489b",
        "nemesis.collect.fixtures.iron_tide:INJECTION_DECEPTION": "e467c244de5b5a31",
        "nemesis.collect.fixtures.iron_tide:MALWARE_FAMILY": "a3cf246ee2c2e7e8",
        "nemesis.collect.fixtures.iron_tide:MESSAGING_ACCOUNT": "0202b3774167106e",
        "nemesis.collect.fixtures.iron_tide:NAMED_PERSON": "c488fa8a5d269ff5",
        "nemesis.collect.fixtures.iron_tide:NORTHWIND_EDR": "71c0f39f61779206",
        "nemesis.collect.fixtures.iron_tide:NORTHWIND_NETFLOW": "d6d98690b8788832",
        "nemesis.collect.fixtures.iron_tide:NORTHWIND_OPERATOR": "15eb1b988bcd4f10",
        "nemesis.collect.fixtures.iron_tide:ONION_PANEL": "7a284f5a577a4739",
        "nemesis.collect.fixtures.iron_tide:PASSIVE_DNS_CORPUS": "3e5205a418e406c5",
        "nemesis.collect.fixtures.iron_tide:PERSONA": "9e47ecbf24e6cc0f",
        "nemesis.collect.fixtures.iron_tide:PLANTED_IDENTITY_DECEPTION": "bf220cded7384bb6",
        "nemesis.collect.fixtures.iron_tide:PLANTED_IDENTITY_POST": "d23f49f9a6ecc2ca",
        "nemesis.collect.fixtures.iron_tide:PRESENTED_CERTIFICATE_CONTRA": "5976f6db46423874",
        "nemesis.collect.fixtures.iron_tide:PROMPT_INJECTION_POST": "bec4c70a94d2b6bb",
        "nemesis.collect.fixtures.iron_tide:RDAP_CORPUS": "01856959700ecf0c",
        "nemesis.collect.fixtures.iron_tide:REGISTRAR": "0d80d0156ec33e95",
        "nemesis.collect.fixtures.iron_tide:REGISTRATION_WINDOW_HOURS": "0e00f14389d320f8",
        "nemesis.collect.fixtures.iron_tide:REGISTRATION_WINDOW_JUSTIFICATION": "40ba9cde3207b625",
        "nemesis.collect.fixtures.iron_tide:RESOLVER_CORPUS": "3a43e36852713720",
        "nemesis.collect.fixtures.iron_tide:SCENARIO_PRESENT": "df30643d8e2aad8e",
        "nemesis.collect.fixtures.iron_tide:SECOND_ASN": "e34fe2cb14670fb4",
        "nemesis.collect.fixtures.iron_tide:SECOND_C2_IP": "34841c0411a02b5d",
        "nemesis.collect.fixtures.iron_tide:SECOND_DOMAINS": "e6233667f4b94837",
        "nemesis.collect.fixtures.iron_tide:SECOND_HOST": "123663dde065fe4c",
        "nemesis.collect.fixtures.iron_tide:SECOND_NETBLOCK": "5fd06c746a15b443",
        "nemesis.collect.fixtures.iron_tide:SECOND_POPULATION": "24622f8a7f48a33c",
        "nemesis.collect.fixtures.iron_tide:SECOND_TENANTS": "996b6f52d9b5a013",
        "nemesis.collect.fixtures.iron_tide:SEED_ASN": "ab0b86848f28a26b",
        "nemesis.collect.fixtures.iron_tide:SEED_DOMAINS": "e0d6a80ac692e414",
        "nemesis.collect.fixtures.iron_tide:SEED_HOST": "025a8af746bc57e5",
        "nemesis.collect.fixtures.iron_tide:SEED_IP": "22b9d2379b980f97",
        "nemesis.collect.fixtures.iron_tide:SEED_NETBLOCK": "0dfc78f17d60e8b6",
        "nemesis.collect.fixtures.iron_tide:SEED_POPULATION": "9177bcbebaf6b7e1",
        "nemesis.collect.fixtures.iron_tide:SEED_TENANTS": "93e959aad1ca5f2c",
        "nemesis.collect.fixtures.iron_tide:SHARED_ASN": "7a523ee2b43c0980",
        "nemesis.collect.fixtures.iron_tide:SHARED_HOST_IP": "363c833198542800",
        "nemesis.collect.fixtures.iron_tide:SHARED_HOST_OPERATOR": "1fb53b9430551c7a",
        "nemesis.collect.fixtures.iron_tide:SHARED_HOST_POPULATION": "2ce3c148ac005cb7",
        "nemesis.collect.fixtures.iron_tide:SHARED_HOST_TENANTS": "3fad81345e645c0d",
        "nemesis.collect.fixtures.iron_tide:SHARED_NETBLOCK": "06482d3ae0d6ac26",
        "nemesis.collect.fixtures.iron_tide:SHARED_PLATFORM_JUSTIFICATION": "ed9b10bbb744204e",
        "nemesis.collect.fixtures.iron_tide:VICTIM": "3b71d55cf7a443f8",
        "nemesis.collect.fixtures.iron_tide:_BEACON_FROM": "f8778675be7714ac",
        "nemesis.collect.fixtures.iron_tide:_C2_NAME_WINDOW": "47cc4f2ce3e7b16f",
        "nemesis.collect.fixtures.iron_tide:_FIRST_SEEN": "ab824db857ddaf94",
        "nemesis.collect.fixtures.iron_tide:_IMPLANT_BUILT": "0d4b8e63f5b1df61",
        "nemesis.collect.fixtures.iron_tide:_LAST_SEEN": "e8848893ca3ec595",
        "nemesis.collect.fixtures.iron_tide:_LISTING_FROM": "124c2d74b680f870",
        "nemesis.collect.fixtures.iron_tide:_LISTING_UNTIL": "70da5fe02978292c",
        "nemesis.collect.fixtures.iron_tide:_RDAP_OBSERVED": "3b82bdeb249ca80f",
        "nemesis.collect.fixtures.iron_tide:_REGISTERED_FIRST": "d4af428e00db302a",
        "nemesis.collect.fixtures.iron_tide:_REGISTERED_LAST": "1386f73becdc670a",
        "nemesis.collect.fixtures.iron_tide:_REGISTRATION_EXPIRES": "b990aa1fbf63f584",
        "nemesis.collect.fixtures.iron_tide:_SCAN_OBSERVED_FROM": "aa395cfd9ed7ed78",
        "nemesis.collect.fixtures.iron_tide:_SCAN_OBSERVED_UNTIL": "6a8896d5719000f1",
        "nemesis.collect.isolation:DEFAULT_DEADLINE_SECONDS": "555016a71b57c351",
        "nemesis.collect.isolation:WORKER_MODULE": "501c1273d74f3132",
        "nemesis.collect.quarantine:HELD_CLASSIFICATIONS": "6791ff6dd57cb037",
        "nemesis.collect.quarantine:MAX_ARTIFACT_BYTES": "7979bbf4b77a0d2c",
        "nemesis.collect.ransomware_live:CONNECTOR_VERSION": "8d0371b79c2687d9",
        "nemesis.collect.ransomware_live:DEFAULT_BASE_URL": "633033a4fbe7eacd",
        "nemesis.collect.ransomware_live:DEFAULT_MAX_RECORDS": "b3838ced0547cb1b",
        "nemesis.collect.ransomware_live:DEFAULT_MAX_RESPONSE_BYTES": "9634c4bea500a4a2",
        "nemesis.collect.ransomware_live:DEFAULT_TIMEOUT_SECONDS": "e28c12cf68d2445d",
        "nemesis.collect.ransomware_live:MAX_RESPONSE_BYTES": "b96eed40baf88a56",
        "nemesis.collect.ransomware_live:MAX_TIMEOUT_SECONDS": "a008f896e00109e5",
        "nemesis.collect.ransomware_live:_ALLOWED_HOSTS": "5676199613127e93",
        "nemesis.collect.ransomware_live:_GROUP_LABEL": "e11e3a032e79df5a",
        "nemesis.collect.ransomware_live:_JSON_MEDIA_TYPES": "867d2b220adb0047",
        "nemesis.collect.ransomware_live:_MAX_FIELD_CHARS": "9cb7cc71217e31bc",
        "nemesis.collect.simulated:FIXTURE_OPERATOR": "4a89103daa4f874d",
        "nemesis.collect.simulated:IRON_TIDE_OPERATOR": "0f573882e2c879e4",
        "nemesis.collect.simulated:IRON_TIDE_SET": "c024cebe7e08a28c",
        "nemesis.collect.simulated:IRON_TIDE_TOR_SANDBOX_PROFILE": "fcd933b0a164bad3",
        "nemesis.collect.simulated:NORTHWIND_OPERATOR": "61641a0fd21554b3",
        "nemesis.collect.simulated:TOR_SANDBOX_PROFILE": "a2743d61df27ea52",
        "nemesis.collect.wire:ARTIFACT_ENCODING": "543dae09f6aedb3f",
        "nemesis.collect.worker:FORBIDDEN_PREFIXES": "cd1a2182397bb7a0",
        "nemesis.core.authorization:GENESIS_HASH": "52adf62b90ed892d",
        "nemesis.core.authorization:IRREVERSIBLE_OPERATIONS": "30aff57e2d8e9f47",
        "nemesis.core.authorization:MVP_IMPLEMENTED_OPERATIONS": "bc81d5544de71dae",
        "nemesis.core.authorization:NO_CAPABILITY": "239147e21d1f8af4",
        "nemesis.core.authorization:OPERATION_RISK": "3d45ab32f9ddc968",
        "nemesis.core.authorization:UNSIGNED_FIELDS": "a7d6878bb3295ff4",
        "nemesis.core.canaries:CANARY_TOKENS": "b7695fe70b490bc5",
        "nemesis.core.canaries:DEFAULT_HALT_THRESHOLD": "01cbce5e58a749fb",
        "nemesis.core.canaries:DEFAULT_REVIEW_THRESHOLD": "4dee92df3bb78236",
        "nemesis.core.canaries:_NON_ALNUM": "a787ee392e28497e",
        "nemesis.core.claims:EPISTEMIC_STRENGTH": "12f2983b4926ed17",
        "nemesis.core.claims:_EVIDENCE_BACKED_KINDS": "9d7ba3d073c82380",
        "nemesis.core.claims:_MODEL_DERIVATIONS": "9c86b8f80c1a67d7",
        "nemesis.core.confidence:ADMIRALTY_CREDIBILITY_BELIEF": "d56632db9e4d2273",
        "nemesis.core.confidence:ADMIRALTY_RELIABILITY_WEIGHT": "a51749c0db400a62",
        "nemesis.core.confidence:BAND_RANGES": "96e991debeaf5ae4",
        "nemesis.core.confidence:UNJUDGEABLE_CREDIBILITY_WEIGHT_CEILING": "61a51fc57c09d078",
        "nemesis.core.confidence:VACUITY_THRESHOLD": "aded317dc89093d4",
        "nemesis.core.confidence:_TOLERANCE": "9ced8479b9d6999f",
        "nemesis.core.credentials:CREDENTIAL_MATERIAL_PATTERNS": "7eb7a3ef9627a5df",
        "nemesis.core.credentials:CREDENTIAL_REDACTION": "21ce1722780879b8",
        "nemesis.core.credentials:FINGERPRINT_PREFIX": "036153386db0ac80",
        "nemesis.core.credentials:MAX_PREVIEW_LENGTH": "5a27fc8bb8ef4e33",
        "nemesis.core.credentials:MAX_UNMASKED_PREVIEW_CHARS": "bdcf7eb6324f1c56",
        "nemesis.core.credentials:MIN_FINGERPRINT_KEY_BYTES": "406f49d154539ad2",
        "nemesis.core.credentials:_FINGERPRINT_HEX": "a2a44ce39bbbbda8",
        "nemesis.core.credentials:_FINGERPRINT_RE": "f03935bfaa62511f",
        "nemesis.core.credentials:_MASK_CHARS": "873ebe8dda5031fb",
        "nemesis.core.disclosure:ENTITY_DISCLOSURE": "6835c6b321441760",
        "nemesis.core.disclosure:INTERNAL_MARKERS": "6fa252569e93773e",
        "nemesis.core.disclosure:PERSONA_ENTITY_TYPES": "303725dbb5ea3026",
        "nemesis.core.disclosure:_ORDER": "ad51cdfd3675c519",
        "nemesis.core.entities:CATEGORY_OF": "319691e22af92b85",
        "nemesis.core.entities:KEYED_BY_CONSTRUCTION_TYPES": "92566c17112231e2",
        "nemesis.core.entities:SHARED_INFRASTRUCTURE_TYPES": "5ee401e6b14d0ecf",
        "nemesis.core.entities:_ASN_RE": "f9715ffe430e80dc",
        "nemesis.core.entities:_DOMAIN_RE": "37efe747ecd6553b",
        "nemesis.core.entities:_HEX_RE": "a58040d6639883b7",
        "nemesis.core.evidence:SHA256_HEX": "be8fbe938d3191c8",
        "nemesis.core.fusion:CONFLICT_ALERT_THRESHOLD": "b5c73b55390566c3",
        "nemesis.core.fusion:UNKNOWN_FACT": "90e3684c336c664b",
        "nemesis.core.fusion:_EPS": "1fd55f10c2edca25",
        "nemesis.core.identity:DEFAULT_TENANT": "25ce1109971e630f",
        "nemesis.core.ids:_CONTENT_ID": "9bf45a5df060160e",
        "nemesis.core.ids:_UUID7_ID": "7ca68ac7a934426d",
        "nemesis.core.infrastructure:ACTOR_HELD_ROLES": "3fb3b4972f59e5f7",
        "nemesis.core.infrastructure:ADMISSIBLE_OWNERSHIP_DERIVATIONS": "0b868447da743ab5",
        "nemesis.core.infrastructure:ADVERSARY_ENTITY_TYPES": "68b69361d816b6ed",
        "nemesis.core.infrastructure:CONTROL_RELATIONS": "94f5249ff6fba075",
        "nemesis.core.infrastructure:DISRUPTIVE_OPERATIONS": "dea03c4daee6b69a",
        "nemesis.core.infrastructure:ESTABLISHED_ROLES": "02c2c77627d02473",
        "nemesis.core.infrastructure:FACET_CONFIDENCE_FLOOR": "e22671d892a6c86a",
        "nemesis.core.infrastructure:OBSERVE_AND_PRESERVE_OPERATIONS": "330bb51bd14c9e28",
        "nemesis.core.infrastructure:OWNERSHIP_PREDICATE": "2d855b79ae8da93c",
        "nemesis.core.infrastructure:REQUIRED_FACETS": "20ded346e4094608",
        "nemesis.core.infrastructure:ROLE_ATTRIBUTE": "78b92f26b6d9d2ad",
        "nemesis.core.infrastructure:THIRD_PARTY_ENGAGEMENT_OPERATIONS": "2f47e5da8cc7bf3b",
        "nemesis.core.infrastructure:USE_RELATIONS": "8100a59b3ba57fe6",
        "nemesis.core.proposition:ROBUSTNESS_MARGIN": "1045edd14c14ee07",
        "nemesis.core.provenance:UNPLANTABLE_SOURCE_CLASSES": "c6a425a5d8f50fce",
        "nemesis.core.relationships:IDENTITY_ASSERTING_RELATIONS": "c77e4f0929e92e79",
        "nemesis.core.relationships:METHOD_RELIABILITY_CEILING": "e8f06ccdaf5e7e74",
        "nemesis.core.retention:DEFAULT_RETENTION": "0de81d564ac4ffef",
        "nemesis.core.retention:VAULT_RETENTION_NOTICE": "d0250681c8e8dc15",
        "nemesis.disrupt.options:IMPACT_RANK": "a59ef14bbb0102d3",
        "nemesis.disrupt.options:OWNERSHIP_CONFIDENCE_FLOOR": "3f1afcb62b124021",
        "nemesis.disrupt.options:_WHACK_A_MOLE": "5b5621d4b2a871bd",
        "nemesis.disrupt.planner:_DISPOSITION_CEILING": "e99c38bc364d2104",
        "nemesis.disrupt.planner:_DISPOSITION_REASON": "6610933876620224",
        "nemesis.effects.drafting:DRAFT_BANNER": "16b83e11f79a7249",
        "nemesis.effects.drafting:EVIDENCE_IDS_PARAMETER": "d09b68738bfb8544",
        "nemesis.effects.drafting:EXPORT_PURPOSE_PARAMETER": "2034a253dd5beef2",
        "nemesis.effects.drafting:MAX_LISTED_EVIDENCE_IDS": "7e6dd5043bdf9893",
        "nemesis.effects.drafting:NOT_SENT_FOOTER": "47b503075da12b5c",
        "nemesis.effects.drafting:OBSERVED_ACTIVITY_PARAMETER": "a9ba43f357225f6e",
        "nemesis.effects.drafting:OUTPUT_DIRECTORY_PARAMETER": "62c260de8f97f0b1",
        "nemesis.effects.drafting:RECIPIENT_PARAMETER": "19ad1cb034fd5479",
        "nemesis.effects.drafting:SEPARATOR": "5f4a9469861442d1",
        "nemesis.effects.drafting:SUPPORTING_MATERIAL_NOTICE": "5fc92f404bfe9472",
        "nemesis.effects.drafting:_UNSPECIFIED": "17485baf8e36d179",
        "nemesis.effects.drafting:_UNSPECIFIED_RECIPIENT": "f584a6dcdd2cda7e",
        "nemesis.effects.isolation:CREDENTIAL_PATHS": "acd9277322ce2375",
        "nemesis.effects.isolation:DEFAULT_ADDRESS_SPACE_BYTES": "f08fef95a9c1ca6c",
        "nemesis.effects.isolation:DEFAULT_CPU_SECONDS": "0724e761dc96a42c",
        "nemesis.effects.isolation:DEFAULT_DEADLINE_SECONDS": "c87b13df3b32f005",
        "nemesis.effects.isolation:DEFAULT_OUTPUT_BYTES": "86b3f9d8db847482",
        "nemesis.effects.isolation:MAX_ARTIFACTS": "cc9aeb7733df4b8a",
        "nemesis.effects.isolation:MAX_DETAIL_CHARACTERS": "ac485ff9cf653c08",
        "nemesis.effects.isolation:MAX_STDERR_BYTES": "f6bcebcc8ee1e3ba",
        "nemesis.effects.isolation:MAX_WORKER_OUTPUT_BYTES": "380c580c3458cd1f",
        "nemesis.effects.isolation:SANDBOX_PROFILE": "8cefc79e3d095bc0",
        "nemesis.effects.isolation:WORKER_MODULE": "cf51371d9c20683f",
        "nemesis.effects.isolation:_REAP_SECONDS": "c8f851c27ea2b563",
        "nemesis.effects.registry:REGISTRY_NAME": "1b964eee4b6d417d",
        "nemesis.effects.registry:STOP_CONDITION_CLEARED": "9c14282e7a11930c",
        "nemesis.effects.registry:STOP_CONDITION_PARAMETER_PREFIX": "0d2560db50da71a7",
        "nemesis.effects.registry:_CONTROL_CHARACTERS": "2a432efd118cbf64",
        "nemesis.effects.registry:_RUNS_OF_SPACE": "049e24fcedcbdced",
        "nemesis.effects.simulation:ADAPTER_NAME": "a19dac7321082235",
        "nemesis.effects.simulation:RECIPIENT_PARAMETER": "8eef7fa623e78652",
        "nemesis.effects.simulation:REHEARSED_OPERATION_PARAMETER": "827dcf221697a505",
        "nemesis.effects.simulation:SIMULATED_LABEL": "26b4a2cee17896bb",
        "nemesis.effects.simulation:_UNSPECIFIED": "da2140012c586999",
        "nemesis.effects.worker:ENV_ADDRESS_SPACE": "7d9703ef8eeffb0d",
        "nemesis.effects.worker:ENV_CPU_SECONDS": "61075d89e917e242",
        "nemesis.effects.worker:ENV_OUTPUT_BYTES": "6da3b5145a12aa3e",
        "nemesis.effects.worker:FORBIDDEN_PREFIXES": "923bb6d5987b19f8",
        "nemesis.evidence.anchoring:LOCAL_ANCHOR_AUTHORITY": "a86fea38a8a2bcb3",
        "nemesis.evidence.anchoring:LOCAL_ANCHOR_TYPE": "82066f004c1d325f",
        "nemesis.evidence.anchoring:SIGNATURE_SCHEME": "b4791d3bfaeeb143",
        "nemesis.evidence.anchoring:_ED25519_SIGNATURE_BYTES": "4220e21afb58511b",
        "nemesis.evidence.anchoring:_KEY_ID_HEX_CHARS": "1d596560eb0c9add",
        "nemesis.evidence.escalation:DEFAULT_DEADLINE": "197338b6b9177e76",
        "nemesis.evidence.escalation:MAY_DISCHARGE": "03991323135b5791",
        "nemesis.evidence.export:ANCHORS_FILE": "1ba73b3136ca797f",
        "nemesis.evidence.export:ARTIFACTS_DIR": "bb1834b82b6626e2",
        "nemesis.evidence.export:DROPPED_NOTICE": "505c774523cb1f1e",
        "nemesis.evidence.export:EXTERNAL_ANCHOR_PRESENT": "ab2725d2d2be5e32",
        "nemesis.evidence.export:LOG_FILE": "46401777ff6c9551",
        "nemesis.evidence.export:MANIFEST_FILE": "ef77a422816acb76",
        "nemesis.evidence.export:NOTICE": "554e7b7378a2510b",
        "nemesis.evidence.export:NOTICE_FILE": "3e319feec63d3b91",
        "nemesis.evidence.export:NO_EXTERNAL_ANCHOR": "20bbc1bac39a522f",
        "nemesis.evidence.export:SEALED_FILES": "189e1083148bbf80",
        "nemesis.evidence.export:SEAL_FILE": "6700b521975e1e77",
        "nemesis.evidence.export:SIGNED_SEAL": "5e85d41c2734fd55",
        "nemesis.evidence.export:UNSIGNED_SEAL": "5b2fff43ed0e15b5",
        "nemesis.evidence.export:VERIFIER_FILE": "ccf1e6b24996a44c",
        "nemesis.evidence.lineage:MAX_DERIVATION_DEPTH": "4132a0bc86cdf2a5",
        "nemesis.evidence.lineage:UNRESOLVED_SOURCE": "5369158fe8f973da",
        "nemesis.evidence.standalone_verifier:ANCHORS": "a8b22497da12d0e8",
        "nemesis.evidence.standalone_verifier:ARTIFACTS": "f748f6a6fb6abd7e",
        "nemesis.evidence.standalone_verifier:CHUNK": "545debdf3ca7e8ee",
        "nemesis.evidence.standalone_verifier:GENESIS": "5796fae1d46f820f",
        "nemesis.evidence.standalone_verifier:LOG": "3f1990744f9aabf5",
        "nemesis.evidence.standalone_verifier:MANIFEST": "35a86df7233eb954",
        "nemesis.evidence.standalone_verifier:MAX_ARTIFACT_BYTES": "50078e4fe8a0a95d",
        "nemesis.evidence.standalone_verifier:NOTICE": "e105a44f9a993b45",
        "nemesis.evidence.standalone_verifier:SEAL": "abb612a4407733b1",
        "nemesis.evidence.standalone_verifier:SEALED_FILES": "0a443d93f6bbd663",
        "nemesis.evidence.standalone_verifier:SEAL_ENTRY": "396c93a79e41a307",
        "nemesis.evidence.standalone_verifier:VERIFIER": "69881d9dfcbf04fe",
        "nemesis.evidence.vault:GENESIS_HASH": "5331b8352e875673",
        "nemesis.evidence.vault:_ARTIFACT_MODE": "18489d94c4c2fbcc",
        "nemesis.evidence.vault:_EVIDENCE_ID_RE": "fc179ed3159da6e7",
        "nemesis.evolution.controller:DEFAULT_MAX_STEPS": "3caf27c32718835e",
        "nemesis.evolution.controller:DEFAULT_MOVES_PER_STEP": "3887eeafa5551337",
        "nemesis.evolution.controller:DEFAULT_SUPERVISOR_TIMEOUT": "b0d7da1939709750",
        "nemesis.evolution.controller:MAX_CONSECUTIVE_INVALID": "25689fc62d7d7847",
        "nemesis.evolution.evaluator:NEIGHBOURHOOD_DEPTH": "880ce71b3916af82",
        "nemesis.evolution.lineage:LINEAGE_JOURNAL": "167e4ec1e254c7df",
        "nemesis.evolution.lineage:MAX_DETAIL_LENGTH": "fd3de7a78c739b3b",
        "nemesis.evolution.memory:INSTRUCTION_PATTERNS": "18e796a3a2ea4dab",
        "nemesis.evolution.memory:MAX_ENTRIES_PER_KIND": "cf489d9e9358ba46",
        "nemesis.evolution.memory:MAX_ENTRY_LENGTH": "3d56794ae9125774",
        "nemesis.evolution.memory:MEMORY_CLASSIFICATION": "33e7eb3247a93991",
        "nemesis.evolution.memory:REDACTION": "acc2011a6513267f",
        "nemesis.evolution.memory:UNTRUSTED_SOURCES": "a9c4421da4b287a3",
        "nemesis.evolution.memory:_CONTROL": "9ae7ee9596cdc70c",
        "nemesis.evolution.memory:_MARKERS": "e780fdbbaf78a2ec",
        "nemesis.evolution.models:MAX_NOTE_LENGTH": "b6848260a49bf26d",
        "nemesis.evolution.models:MAX_REFS": "f98f26a697e35aa6",
        "nemesis.evolution.projection:EVOLUTION_ACTOR": "f81395cb1c34bea2",
        "nemesis.evolution.projection:MAX_PROJECTED_REFERENCES": "692c1d483ed4b219",
        "nemesis.evolution.projection:NO_CONFIDENCE_NOTE": "20a3f524b5b9bf27",
        "nemesis.evolution.projection:SUPERVISOR_ACTOR": "d5ab2d543bd5fc6d",
        "nemesis.evolution.projection:_MARKERS": "2551e521f9980504",
        "nemesis.evolution.supervisor:CONTINUE_ON_FAILURE": "29530ae7667ee363",
        "nemesis.evolution.supervisor:RESEARCH_DIRECTIVE_ADAPTER": "f9fc47e7ab10d9bb",
        "nemesis.evolution.supervisor:_SIGNAL_DIRECTIVE": "6e732b64d85c56c7",
        "nemesis.graph.caseindex:EFFECT_ACTION": "22e7d4619d57bf7e",
        "nemesis.graph.caseindex:INVESTIGATION_ACTION": "777be56f5f624adf",
        "nemesis.graph.caseindex:PILOT_MOVE_ACTION": "39af612fd091afe6",
        "nemesis.graph.caseindex:PIVOT_ACTION": "5e8521272fc4094b",
        "nemesis.graph.caseindex:READ_ACTIONS": "66639036d497cfa7",
        "nemesis.graph.journal:CLAIM_JOURNAL": "f544ac14824b4e8a",
        "nemesis.graph.journal:GRAPH_JOURNAL": "343df7775bcd424a",
        "nemesis.graph.journal:OP_CLAIM": "4dbe5bff29a4a8f7",
        "nemesis.graph.journal:OP_ENTITY": "82489ac226ea5dc7",
        "nemesis.graph.journal:OP_ERASE": "e934cf63ee48809e",
        "nemesis.graph.journal:OP_RELATIONSHIP": "378a4b3d58996b24",
        "nemesis.graph.journal:OP_SUPERSEDE": "72569fc1b332f5ca",
        "nemesis.graph.memory:ATTRIBUTE_CONFLICT_MARKER": "9576f6751da0d880",
        "nemesis.graph.memory:_MAX_EXPLAINED_PATHS": "69cd52c96e7bd402",
        "nemesis.graph.recall:LONG_ACQUAINTANCE": "76dcde8893537f85",
        "nemesis.pilot.anthropic_pilot:DEFAULT_MAX_TOKENS": "ef50f21e2ac1d6b7",
        "nemesis.pilot.challenger:BLOCKING_VERDICTS": "60752462e18e8819",
        "nemesis.pilot.challenger:CHALLENGER_RULING_ADAPTER": "fab8116e295026f0",
        "nemesis.pilot.mediator:CONTEXT_REDACTION": "2ef7b77be7649984",
        "nemesis.pilot.mediator:DEFAULT_MAX_CONSECUTIVE_MALFORMED": "6d4c3d199ba61d9d",
        "nemesis.pilot.mediator:DEFAULT_MAX_MOVES": "d020a8bbf6f69bbe",
        "nemesis.pilot.mediator:DEFAULT_PROPOSE_TIMEOUT": "65af83e835d24a64",
        "nemesis.pilot.mediator:MAX_BRIEFING_ENTITIES": "342a9020249f7293",
        "nemesis.pilot.mediator:OBSERVABLE_STOP_CONDITIONS": "4053c9c9e5f46adf",
        "nemesis.pilot.mediator:PILOT_ACTOR_KIND": "cea845a06b3b2554",
        "nemesis.pilot.mediator:_BUDGET_REFUSAL_MARKER": "4fe6f770af06fc2b",
        "nemesis.pilot.mediator:_DISCLOSURE_MARKER": "f34785bfeec43f2c",
        "nemesis.pilot.mediator:_MARKER_PATTERN": "b110499de2c8d895",
        "nemesis.pilot.mediator:_PROSE_MOVE_FIELDS": "657b9e869f572b60",
        "nemesis.pilot.mediator:_SESSION_ATTRIBUTION_KEYS": "4f3c23ad339e4890",
        "nemesis.pilot.model_seat:MOVE_MODELS": "4587191b724bae72",
        "nemesis.pilot.model_seat:MOVE_NAMES": "1515ae82b3369b72",
        "nemesis.pilot.model_seat:PROMPT_VERSION": "21aa468c1c9d6a85",
        "nemesis.pilot.model_seat:SYSTEM_INSTRUCTIONS": "3239cd9c2fcae38e",
        "nemesis.pilot.moves:MAX_CONTEXT_ITEMS": "a709e0fdba136384",
        "nemesis.pilot.moves:MAX_CONTEXT_ITEM_LENGTH": "d3b0f7a52acefdef",
        "nemesis.pilot.moves:PILOT_MOVE_ADAPTER": "50afc3bffd57b821",
        "nemesis.pilot.moves:SAFE_FAILURE_OUTCOMES": "2e4f696996e275c9",
        "nemesis.pilot.providers.anthropic:ANTHROPIC_CAPABILITIES": "7337e74d15c08666",
        "nemesis.pilot.providers.anthropic:ANTHROPIC_DIALECT": "2fd6758687c3290a",
        "nemesis.pilot.providers.anthropic:API_KEY_ENVIRONMENT_VARIABLE": "3e1c835c20257f5e",
        "nemesis.pilot.providers.anthropic:PROVIDER": "d5a3d4e15e3acff0",
        "nemesis.pilot.providers.capabilities:NEVER_EXPOSED_TOOL_TYPES": "ff2e610883b686ab",
        "nemesis.pilot.providers.capabilities:REQUIRED_OF_EVERY_PILOT": "314a57ae8a49f031",
        "nemesis.pilot.providers.capabilities:UNTRUSTED_CONTENT_KEYS": "1de817c9411a3540",
        "nemesis.pilot.providers.capabilities:_NEVER_EXPOSED_NORMALISED": "87707a5f533812fe",
        "nemesis.pilot.providers.challenger_seat:CHALLENGER_INSTRUCTIONS": "ea29b49292059e9c",
        "nemesis.pilot.providers.challenger_seat:CHALLENGER_PROMPT_VERSION": "9c48cba3f8bef67a",
        "nemesis.pilot.providers.challenger_seat:CHALLENGER_TOOL_NAME": "1b68c72056c522bf",
        "nemesis.pilot.providers.challenger_seat:CHALLENGER_TOOL_SUITE": "acce8d8fe03a20a0",
        "nemesis.pilot.providers.compatible:API_KEY_ENVIRONMENT_VARIABLE": "7d486ff10e2609fe",
        "nemesis.pilot.providers.compatible:CONSERVATIVE_CAPABILITIES": "e18edb7239c5c6f4",
        "nemesis.pilot.providers.compatible:PROVIDER": "89e05a5a215f1dae",
        "nemesis.pilot.providers.errors:RETRYABLE_KINDS": "268d91268f06600d",
        "nemesis.pilot.providers.errors:_MODEL_PHRASES": "c8a496c35874feff",
        "nemesis.pilot.providers.errors:_OVERFLOW_PHRASES": "c27d028bd271e914",
        "nemesis.pilot.providers.errors:_PARAMETER_PHRASES": "950662e42a399eda",
        "nemesis.pilot.providers.gemini:API_KEY_ENVIRONMENT_VARIABLE": "1246c9ae3a479ffc",
        "nemesis.pilot.providers.gemini:GEMINI_CAPABILITIES": "827e91a7f336094c",
        "nemesis.pilot.providers.gemini:GEMINI_DIALECT": "66535c8e058f1980",
        "nemesis.pilot.providers.gemini:PROVIDER": "66b6343ede0b6b0e",
        "nemesis.pilot.providers.gemini:THINKING_BUDGET_TOKENS": "174eb9386a8db416",
        "nemesis.pilot.providers.ollama:DEFAULT_ENDPOINT": "50746247818dd514",
        "nemesis.pilot.providers.ollama:DEFAULT_MODEL": "76996064f8ff3205",
        "nemesis.pilot.providers.ollama:DEFAULT_TIMEOUT_SECONDS": "2d96e4097c193c10",
        "nemesis.pilot.providers.ollama:LAB_NOTICE": "43824b019b181746",
        "nemesis.pilot.providers.ollama:OLLAMA_CAPABILITIES": "47b33531e62a27f3",
        "nemesis.pilot.providers.ollama:OLLAMA_DIALECT": "b8bdcc3499837b38",
        "nemesis.pilot.providers.ollama:PROVIDER": "1607b4a2e9259d73",
        "nemesis.pilot.providers.openai:API_KEY_ENVIRONMENT_VARIABLE": "dfa9a73805cbdaa6",
        "nemesis.pilot.providers.openai:OPENAI_CAPABILITIES": "f4958643323e1b80",
        "nemesis.pilot.providers.openai:OPENAI_DIALECT": "82c2e8e7be7a1023",
        "nemesis.pilot.providers.openai:PROVIDER": "8c6d2d4a939baa64",
        "nemesis.pilot.providers.openai_dialect:OPENAI_COMPATIBLE_CAPABILITIES": "379476d2d663d5aa",
        "nemesis.pilot.providers.registry:PROVIDERS": "f2c1ccc6b7fc32b7",
        "nemesis.pilot.providers.registry:PROVIDER_NAMES": "7e4cbc8484653aa8",
        "nemesis.pilot.providers.reliability:DEFAULT_BASE_DELAY_SECONDS": "dd9b4f9965b4b079",
        "nemesis.pilot.providers.reliability:DEFAULT_MAX_ATTEMPTS": "aa8f0f382ba251f3",
        "nemesis.pilot.providers.reliability:DEFAULT_MAX_DELAY_SECONDS": "3b6eed74e794b2b5",
        "nemesis.pilot.providers.reliability:NO_RETRIES": "76fc04c04e81b7eb",
        "nemesis.pilot.providers.schema:MOVE_TOOL_NAMES": "05173354a2655320",
        "nemesis.pilot.providers.schema:MOVE_TOOL_SCHEMA_VERSION": "174cf98afa76b959",
        "nemesis.pilot.providers.schema:MOVE_TOOL_SUITE": "1167ae65e9d3dbf0",
        "nemesis.pilot.providers.schema:_OPENAPI_UNSUPPORTED": "9fb7a76683f156d8",
        "nemesis.pilot.providers.seat:AMBIGUOUS_MOVE_SENTINEL": "3bee8717e66a7660",
        "nemesis.pilot.providers.seat:NO_MOVE_SENTINEL": "b0140c1d47ec17bd",
        "nemesis.pilot.providers.xai:API_KEY_ENVIRONMENT_VARIABLE": "642a11336dc1b9fc",
        "nemesis.pilot.providers.xai:PROVIDER": "9d34ad817328abca",
        "nemesis.pilot.providers.xai:XAI_CAPABILITIES": "d316c1c04258c94b",
        "nemesis.pilot.providers.xai:XAI_DIALECT": "60cb91e4cedefd04",
        "nemesis.pilot.stagnation:_OUTCOME_BY_SIGNAL": "c5651a6ef1fbac7f",
        "nemesis.pilotbench.corpus:APPROVED_DOMAIN": "bd6fe072a2ef64d0",
        "nemesis.pilotbench.corpus:APPROVED_STATE": "be0ce3c8a9348175",
        "nemesis.pilotbench.corpus:BASELINE": "c1c5bc66c1dcc5ef",
        "nemesis.pilotbench.corpus:COMMODITY_ARTIFACT": "53e903f101bacfbf",
        "nemesis.pilotbench.corpus:DEFAULT_CORPUS": "cf7646d3582d6c45",
        "nemesis.pilotbench.corpus:FALSE_FLAG": "4c249fe0e67d1700",
        "nemesis.pilotbench.corpus:INJECTED_DOMAIN": "ea6176782ac57c0a",
        "nemesis.pilotbench.corpus:LINK_PHRASES": "a8531a65bdd419fa",
        "nemesis.pilotbench.corpus:NAMED_PERSON_CASE": "37d9da22a3960355",
        "nemesis.pilotbench.corpus:PROMPT_INJECTION": "0b1689bbe274cb16",
        "nemesis.pilotbench.corpus:RECYCLED_WALLET": "22ccc9ac437b86cb",
        "nemesis.pilotbench.corpus:SHARED_HOSTING": "52f0cb54c33eadeb",
        "nemesis.pilotbench.corpus:STALE_REGISTRATION": "40149db90db1dede",
        "nemesis.pilotbench.corpus:_ENVELOPE": "921f9228ae213902",
        "nemesis.pilotbench.metrics:CERTAINTY_MARKERS": "84671d77139597cb",
        "nemesis.pilotbench.metrics:FAILURE_WEIGHTS": "eac7b539d3882248",
        "nemesis.pilotbench.metrics:MOVE_VERBS": "d8e5b9cc2ced0aad",
        "nemesis.pilotbench.pilots:PIVOT_ORDER": "19539b4bdf2f5c59",
        "nemesis.pilotbench.pilots:REFERENCE_PILOTS": "278dc8575e6c2964",
        "nemesis.pilotbench.report:CANNOT_TELL_YOU": "ad8d6b59e4cd81fe",
        "nemesis.pilotbench.scenario:CORPUS_VERSION": "21e304bbe7d5493c",
        "nemesis.pilotbench.scenario:REJECTION_MARKERS": "3cb07760768725e1",
        "nemesis.pursuit.engine:ENGINE_ACTOR_KIND": "a59bcfa1f84c9234",
        "nemesis.pursuit.materialize:QUALIFIER_ATTRIBUTE": "618f0a5451a2ddfd",
        "nemesis.pursuit.materialize:QUALIFIER_CORPUS": "93d9ab9cd6dce6b8",
        "nemesis.pursuit.materialize:QUALIFIER_JUSTIFICATION": "85116256c4dcfd97",
        "nemesis.pursuit.materialize:QUALIFIER_METHOD": "f35a3374fa3accb0",
        "nemesis.pursuit.materialize:QUALIFIER_POPULATION": "117a7da54c196d19",
        "nemesis.pursuit.materialize:QUALIFIER_UNIQUE": "6a3cd121a6e9315b",
        "nemesis.pursuit.policy:MAX_BRANCH_DEPTH": "f616cb3959936306",
        "nemesis.pursuit.policy:MAX_CONSECUTIVE_UNINFORMATIVE": "f006763443e6d16e",
        "nemesis.pursuit.policy:PIVOTS_FOR_ENTITY": "87c178fe79c6b843",
        "nemesis.pursuit.resurgence:ACTIONABLE_FLOOR": "d2dffb9034ef3cda",
        "nemesis.pursuit.resurgence:BASE_RATE_CEILING": "8008e42c5891581a",
        "nemesis.pursuit.resurgence:BASE_RATE_FLOOR": "a057fe5717a5b1e9",
        "nemesis.pursuit.resurgence:BELIEF_CEILING": "ddef9706d5ddf149",
        "nemesis.pursuit.resurgence:CORRELATION_GROUP_OF": "94fadd6a5f0b6496",
        "nemesis.pursuit.resurgence:FRAMER_COSTLY_KINDS": "f6fb030e172060dd",
        "nemesis.pursuit.resurgence:IRREDUCIBLE_UNCERTAINTY": "177ae82e68b354c6",
        "nemesis.pursuit.watch:BRIDGE_RULES": "6ba6be66d7e30c44",
        "nemesis.resolve.actor_corroboration:FACT_PREFIX": "b42d201e4b190910",
        "nemesis.resolve.engine:ASSUMED_PERSONAS_PER_OPERATOR": "a9c404a1f81770a5",
        "nemesis.resolve.engine:BASE_RATE_CEILING": "b0e4a575b944cac5",
        "nemesis.resolve.engine:BASE_RATE_FLOOR": "ca21644a9a61e97b",
        "nemesis.resolve.engine:EXCLUDED_CONCLUSIONS": "96e5bc462cd13ac5",
        "nemesis.resolve.engine:HUMAN_IDENTIFICATION_IS_NOT_A_THRESHOLD": "a46050e912818c5c",
        "nemesis.resolve.engine:NEGLIGIBLE_CONTRIBUTION": "b12a03339b5c19fb",
        "nemesis.resolve.engine:PROPOSITION_TEMPLATE": "92814cabd12139bd",
        "nemesis.resolve.engine:STYLOMETRY_ONLY_REFUSAL": "eaedc8f69844d952",
        "nemesis.resolve.engine:_ALTERNATIVE_BY_GROUP": "c103af967a5d1393",
        "nemesis.resolve.engine:_COINCIDENCE_ALTERNATIVE": "ed4514b13ab20f45",
        "nemesis.resolve.signals:BELIEF_CEILING": "795462969b3df843",
        "nemesis.resolve.signals:CONTRADICTION_BELIEF_CEILING": "63eb4966d01301f6",
        "nemesis.resolve.signals:CORRELATION_GROUP_OF": "f68d98b9914c82bc",
        "nemesis.resolve.signals:DEMONSTRATED_KEY_CONTROL_CEILING": "63e84fe1af0a0d22",
        "nemesis.resolve.signals:IRREDUCIBLE_UNCERTAINTY": "dd98ab396ca48c2a",
        "nemesis.resolve.signals:MIN_POSTS_FOR_A_ROUTINE": "b3645100094c9f67",
        "nemesis.resolve.signals:OBFUSCATION_STYLOMETRY_PENALTY": "cc1c0afec6a1efa5",
        "nemesis.resolve.signals:OPEN_WORLD_STYLOMETRY_PENALTY": "09b24d7731c3dbc9",
        "nemesis.resolve.signals:PIVOT_METHOD_OF": "cdfc6b8c28799334",
        "nemesis.resolve.signals:STYLOMETRY_BELIEF_CEILING": "e801b1d7f8660176",
        "nemesis.resolve.signals:_CONTRADICTION_CAPABLE": "ab4d414dd246c1a6",
        "nemesis.resolve.signals:_KEY_ENTITY_TYPES": "9ac6822ea925ba60",
        "nemesis.resolve.signals:_RELIABILITY_ORDER": "884b3fc746b162e2",
        "nemesis.sandbox.process:MAX_STDERR_BYTES": "b7411b34992dae93",
        "nemesis.sandbox.process:MAX_STDOUT_BYTES": "56e3a54004d25a3d",
        "nemesis.sandbox.process:REAP_SECONDS": "93303611d297f3fe",
        "nemesis.sandbox.process:SANDBOX_EXEC": "17c4a33127ffe04e",
        "nemesis.sandbox.reachability:DECLARED_BROKERS": "13377bce339c2536",
        "nemesis.sandbox.reachability:DYNAMIC_IMPORT_CALLS": "06565b0e487acc5c",
        "nemesis.sandbox.reachability:MODEL_CONTROLLED_ROOTS": "64b1527db2cafdb8",
        "nemesis.sandbox.reachability:NETWORK_CALLS": "5b2e5774ec03fb1d",
        "nemesis.sandbox.reachability:NETWORK_MODULES": "74c80b2243d0a597",
        "nemesis.sandbox.reachability:PACKAGE_ROOT": "8ef4eca04cee620f",
        "nemesis.sandbox.reachability:PROCESS_CALLS": "ecd0040e2d1a1b30",
        "nemesis.sandbox.reachability:PROCESS_MODULES": "eb87042f0c13b90c",
        "nemesis.sandbox.reachability:_BARE": "a3628e204629cdfa",
        "nemesis.slice.evolution_session:APPROVED_DOMAIN": "70f83dd7d092654b",
        "nemesis.slice.evolution_session:APPROVED_STATE": "982d5401dd8f2be0",
        "nemesis.slice.evolution_session:BENIGN_HINT": "bfe0399cec6667dd",
        "nemesis.slice.evolution_session:DEAD_DIRECTION": "c08558f7658c8307",
        "nemesis.slice.evolution_session:EFFECT_BUDGET": "e8f7303ef0dee53b",
        "nemesis.slice.evolution_session:EVOLUTION_STEPS": "55e76511338367b4",
        "nemesis.slice.evolution_session:HOSTILE_HINT": "04cd259dfd4c5951",
        "nemesis.slice.evolution_session:INJECTION": "c15efea25a1546fc",
        "nemesis.slice.evolution_session:MOVES_PER_STEP": "131c23c74e67bf9d",
        "nemesis.slice.evolution_session:PURSUIT_BUDGET": "0c14bc45d8d36a89",
        "nemesis.slice.evolution_session:SCENARIO_NOW": "2085314dd47a9631",
        "nemesis.slice.evolution_session:SEED_DOMAIN": "38fb02934376f3d2",
        "nemesis.slice.iron_tide:ACTOR_GAP": "2db2ce8ec394c7d1",
        "nemesis.slice.iron_tide:DETECTION_PROPOSITION": "cef3b8cd7b22c1f3",
        "nemesis.slice.iron_tide:MALWARE_SIMILARITY_NOTE": "5569af3c2301f4d6",
        "nemesis.slice.iron_tide:MAX_STEPS": "617e93418945f3a8",
        "nemesis.slice.iron_tide:SCENARIO_SUBJECT": "b44d8e0699826736",
        "nemesis.slice.iron_tide:STAGE_NAMES": "5fa78c560488fee7",
        "nemesis.slice.iron_tide:TOTAL_BUDGET": "beeb96374dc4a48a",
        "nemesis.slice.iron_tide:_ANALYST_BECAUSE": "acab68d242e38d9f",
        "nemesis.slice.iron_tide:_CANNOT_DEFEND": "ba8c335249855a20",
        "nemesis.slice.iron_tide:_FRAMED_ARGUMENT": "be0804ed773e9bb5",
        "nemesis.slice.iron_tide:_PILOT_BECAUSE": "7ff75e6da4c120ba",
        "nemesis.slice.iron_tide:_SEED_SILENCE": "e89968a28244d098",
        "nemesis.slice.iron_tide:_SENSOR_REPLAY_METHOD": "6c457abcdf272790",
        "nemesis.slice.iron_tide:_SHARED_HOST_TENANT_SAMPLE": "d65fbe16381a2126",
        "nemesis.slice.iron_tide:_THE_CONTROL": "fbf75beb962e1a30",
        "nemesis.slice.loopbench:CAVEATS": "0c7907a9603c384f",
        "nemesis.slice.loopbench:DEFAULT_BUDGET": "e5a90ad1fbef21da",
        "nemesis.slice.loopbench:DEFAULT_MOVES_PER_SEGMENT": "bb2277cb603803fb",
        "nemesis.slice.loopbench:DEFAULT_SEGMENTS": "6e792ec9d45b26ac",
        "nemesis.slice.loopbench:PILOTS": "83e13176a07479fb",
        "nemesis.slice.loopbench:PIVOT_CYCLE": "aba8b10ea61907ca",
        "nemesis.slice.loopbench:RUN_LENGTHS": "55ca626f16420c7e",
        "nemesis.slice.pilot_session:APPROVED_DOMAIN": "496bf76b2c4507ad",
        "nemesis.slice.pilot_session:APPROVED_STATE": "da38c5e43da5f6a6",
        "nemesis.slice.pilot_session:EFFECT_BUDGET": "167ee1ab79e38d0a",
        "nemesis.slice.pilot_session:INJECTION": "d41472c15b991c1e",
        "nemesis.slice.pilot_session:SCENARIO_NOW": "0e1fcbd972f991dd",
        "nemesis.slice.pilot_session:SEEDABLE_DOMAINS": "e742673adab65b78",
        "nemesis.slice.pilot_session:SEED_DOMAIN": "cf861174e9e12fb9",
        "nemesis.slice.scenario:CAPABILITY_LIFETIME": "31d7c04849cbac72",
        "nemesis.slice.scenario:CASE_AUTHORITY_REFERENCE": "b22b27fd13b4f518",
        "nemesis.slice.scenario:CLUSTER_MIN_CONFIDENCE": "30965839148f7659",
        "nemesis.slice.scenario:DARK_BAZAAR_PERSONA_POPULATION": "9c3b4477949e80d5",
        "nemesis.slice.scenario:PERSONA_POPULATION_CORPUS": "7168e5fb72c15b73",
        "nemesis.slice.scenario:RESUMPTION_BUDGET": "3a29ec8ab5f1fd42",
        "nemesis.slice.scenario:RESURGENCE_RULE": "7421fb4a561c1e02",
        "nemesis.slice.scenario:RESURGENCE_RULE_VERSION": "1ff612912ca01798",
        "nemesis.slice.scenario:SCENARIO_SUBJECT": "60b8d046a8319a83",
        "nemesis.slice.scenario:STAGE_NAMES": "cf5b88f5b5a96a2c",
        "nemesis.slice.scenario:TRACKED_CAMPAIGNS": "798e8df6570320aa",
        "nemesis.slice.scenario:_CANNOT_DEFEND": "c536ca831c3d2c38",
        "nemesis.slice.scenario:_CDN_TENANTS": "ba19db6875319cae",
        "nemesis.slice.scenario:_DETECTION_PROPOSITION": "341f7114ec172e49",
        "nemesis.slice.scenario:_DIRECTED_BECAUSE": "a102a9c96ed78051",
        "nemesis.slice.scenario:_NOTHING_IN_COMMON": "2716842ff6aaeadf",
        "nemesis.slice.scenario:_NOT_RECONNECTED_BY": "7855b524b0c911b9",
        "nemesis.slice.scenario:_REDOCTOBER_ALTERNATIVE_ARGUMENT": "979af2ba1dbe625c",
        "nemesis.slice.scenario:_SENSOR_REPLAY_METHOD": "066705957604a4cd",
        "nemesis.slice.scenario:_SIGNALS_UNAVAILABLE": "1a06b24287ddb9dd",
        "nemesis.slice.scenario:_WALLET_WITHHELD_FROM": "7d0b9842cb4db62f",
        "nemesis.slice.standing_session:ACTOR_CONTROLLED_DOMAIN": "d91ee1ecd4f49fa3",
        "nemesis.slice.standing_session:ACTOR_HANDLE": "2d0fa486bfc7f682",
        "nemesis.slice.standing_session:CASES": "d69d7b761ebdaba2",
        "nemesis.slice.standing_session:COMPROMISED_DOMAIN": "71a97589abf675c4",
        "nemesis.slice.standing_session:EFFECT_BUDGET": "ad86693b1bc5f102",
        "nemesis.slice.standing_session:EXTENT": "03a86a4f9d77515c",
        "nemesis.slice.standing_session:LEGITIMATE_OWNER": "0b9b244bd40c5b4e",
        "nemesis.slice.standing_session:OPERATIONS": "19aef8fa4a8eb0bb",
        "nemesis.slice.standing_session:SCENARIO_NOW": "16a9d16d1c900171",
        "nemesis.slice.standing_session:SEED_DOMAIN": "5082456d00a61467",
        "nemesis.slice.standing_session:SHARED_REGISTRAR": "a5f5d503b530f270",
        "nemesis.slice.standing_session:SYNTHETIC_AUTHORITY_REFERENCE": "297af42ef81b42e5",
        "nemesis.slice.standing_session:UNBOUND_DOMAIN": "85cb2b118d624809",
        "nemesis.slice.standing_session:UNCLASSIFIED_DOMAIN": "d78f19e4ea649551",
        "nemesis.ui.investigation:SIMULATED_NOTICE": "e5ad146c4938c00f",
        "nemesis.ui.investigation:WITHHELD_NOTE": "60386a34750e3f49",
        "nemesis.ui.investigation:_CSS": "3ab7521dc09bf328",
    }
)
"""Every dial in `src/nemesis`, by normalised syntax. Generated by `discovered_constants()`.

Long on purpose. The registry above is curated and therefore forgettable; this is not curated,
which is the entire point — four reviews defeated four enumerations, and the fifth thing to try
was to stop enumerating. Regenerate deliberately, in its own commit, with the reason."""


SELF: Final = "nemesis/calibration/freeze.py"
"""The one module outside the freeze, because the frozen tables live in it.

Excluded by **relative** path rather than by absolute path, so pointing the freeze at a copy of
the tree excludes that copy's `freeze.py` too. Excluding by absolute path silently included the
copy, which made every test against a copied tree report a hundred spurious constants.
"""


def _package(tree: Path | None) -> Path:
    """The `nemesis` package directory: the real one, or a copy a caller points us at.

    Every path in this module is resolved through here, so the default cannot drift between
    functions — it did once, and two of them disagreed by one directory level.
    """
    return tree if tree is not None else Path(__file__).resolve().parent.parent


def frozen_modules(tree: Path | None = None) -> tuple[str, ...]:
    """Every module under `src/nemesis` except this one. **One function, read by everything.**

    The scanner and the constant digest previously disagreed about scope — the scanner had been
    moved to a derived set while the digest still hashed a hand-written list — and a reviewer
    walked straight through the gap: `LINKAGE_PROPOSITION` in `calibration/harness.py` is
    discovered by one and hashed by neither. Flipping it from `ACTOR_ATTRIBUTION` to
    `OBSERVATION` took both reported false-match rates from 0.0 to 1.0 with every check green.

    Two derivations were tried and both were too clever. Modules that *import* the confidence
    machinery misses `core/provenance.py`, which imports none of it and holds
    `UNPLANTABLE_SOURCE_CLASSES` — the table deciding which evidence gets inverted. The
    transitive closure of that import graph reaches 84 of 104 modules, which is close enough to
    "all of them" that the derivation buys precision nobody needs and one more thing to be
    wrong about.

    So: the whole tree. Nothing to compute, nothing to forget, and no seam for a sixth instance
    of the same defect to appear in.

    This module is excluded because the frozen tables live in it and would be self-referential.
    That exclusion is a real hole — editing the tables is how a change gets waved through — and
    it is closed socially rather than mechanically: a diff to `FROZEN_*` is the thing a reviewer
    is meant to look at.

    `tree` points the enumeration at a **copy** of the package, so a test can exercise the freeze
    without editing the tree it protects. This function accepted that argument and ignored it for
    one commit: the edit that was supposed to introduce it silently failed to match, and nothing
    noticed, because the only test injecting anything modified a file that exists at the same
    relative path in both trees. A **new** module in the copy was never enumerated at all. The
    ninth instance of this project's recurring defect and the second in this function — a control
    that looks right because the case exercising it happens to coincide with the case it gets
    wrong.
    """

    root = _package(tree)
    return tuple(
        sorted(
            relative
            for path in root.rglob("*.py")
            if (relative := f"nemesis/{path.relative_to(root).as_posix()}") != SELF
        )
    )


def _module_constants(relative: str, tree: Path | None = None) -> dict[str, ast.expr]:
    """Every module-level constant in one file, by fully qualified name.

    A constant is anything bound at module level to an upper-case name. What it *holds* is not
    part of the test, which is the lesson of four rounds: the first scan wanted a digit, and a
    digit is exactly what `LINKAGE_PROPOSITION`, `IDENTITY_ASSERTING_RELATIONS` and
    `UNPLANTABLE_SOURCE_CLASSES` do not contain.
    """

    module = relative.removesuffix(".py").replace("/", ".")
    parsed = ast.parse(_source_of(relative, tree))

    found: dict[str, ast.expr] = {}
    for node in parsed.body:
        name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name, value = node.target.id, node.value
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            name, value = node.targets[0].id, node.value
        if name is None or value is None or not name.lstrip("_").isupper():
            continue
        found[f"{module}:{name}"] = value
    return found


def discovered_constants(tree: Path | None = None) -> dict[str, str]:
    """Every dial in the tree, mapped to its normalised syntax — **derived, never listed**.

    This is the completeness guarantee, and it replaces the registry in that role. Four reviews
    found four ways to defeat an enumeration of dials; none of them defeats "parse every module
    and hash every module-level constant", because there is no list to be absent from and no
    judgement about what qualifies. A constant that *appears* is reported as well as one that
    moves, which closes "add a dial and do not register it".

    **No classification, and that is the third time this lesson has been paid for.** An earlier
    version skipped a constant whose value was entirely strings, on the reasoning that such a
    thing is a message. It let `LOW_PLANTING_COSTS` through. The rule was then narrowed to "a
    value that constructs or looks up is a table however much of it is text" — and a review found
    that still excluded `FORBIDDEN_PREFIXES`, `CREDENTIAL_PATHS`, `INTERNAL_MARKERS` and
    `EXCLUDED_CONCLUSIONS`, four security tables made of plain strings. The module digest covered
    them, so it was never a bypass; the claim that every dial was *named* was simply false.

    So there is no rule now. Every module-level upper-case assignment is a dial, 767 of them,
    and the cost of including the genuine prose is nothing: rewording a message already moves
    that module's syntax digest, so no new failure mode is introduced by naming it too.

    `CALIBRATION_CONSTANTS` keeps a different job: it is the curated epistemic subset whose
    **imported values** are frozen, and it catches what a syntax tree cannot. `PUBLISHED_BAND_BINS`
    is the case that proves both are needed — it is derived from `BAND_RANGES`, so its own AST
    never changes when the band edges move, and only reading the value notices.
    """
    return {
        name: ast.dump(value, annotate_fields=True, include_attributes=False)
        for relative in frozen_modules(tree)
        for name, value in _module_constants(relative, tree).items()
    }


def constants_drifted(tree: Path | None = None) -> tuple[str, ...]:
    """Which dials moved, appeared or vanished anywhere in the tree.

    Named, not counted: the first question after a red freeze is always "which one, and was it
    deliberate".
    """
    observed = {
        name: hashlib.sha256(f"{name}={dump}".encode()).hexdigest()[:16]
        for name, dump in discovered_constants(tree).items()
    }
    moved = {name for name, digest in observed.items() if CONSTANT_DIGESTS.get(name) != digest}
    vanished = {name for name in CONSTANT_DIGESTS if name not in observed}
    return tuple(sorted(moved | vanished))


def _source_of(relative: str, tree: Path | None = None) -> str:
    """Read one module, from the real tree or from a copy a test points us at."""
    return (_package(tree).parent / relative).read_text(encoding="utf-8")


def _normalised_tree(relative: str, tree: Path | None = None) -> str:
    """One module's syntax tree, docstrings removed, dumped without line numbers.

    Comments never enter an AST and docstrings are stripped explicitly, so rewording an
    explanation does not break the freeze while changing a comparison does. That is the
    sensitivity a source hash gets backwards.

    Stripping only *leading* docstrings was not enough: this codebase documents constants with a
    bare string after the assignment, so rewording the note under `CORRELATION_GROUP_OF` broke
    the digest — a false positive, which is how a tripwire gets switched off.
    """

    return normalised_source(_source_of(relative, tree))


def normalised_source(text: str) -> str:
    """The same normalisation, applied to source text rather than a path.

    Exposed so a test can tamper with a **copy** of a module and ask whether the freeze would
    notice, without editing the tree. Sharing this function rather than re-implementing the
    stripping in the test matters: a test that reimplements the rule can agree with itself while
    disagreeing with the code.
    """

    def is_prose_statement(statement: ast.stmt) -> bool:
        return (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )

    tree = ast.parse(text)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list):
            # `setattr` rather than `node.body = ...`: `ast.AST` declares no `body`, and the
            # nodes that have one do not share a base class that does.
            kept = [item for item in body if not is_prose_statement(item)]
            setattr(node, "body", kept)  # noqa: B010
    return ast.dump(tree, annotate_fields=True, include_attributes=False)


def module_digests(tree: Path | None = None) -> dict[str, str]:
    """Every module in `frozen_modules()`, by normalised syntax tree.

    **The scope is the whole tree, because narrowing it is what kept losing.** This digest was
    restricted to modules defining a registered dial, on the argument that hashing all logic
    everywhere would fire too often to stay armed. An adversarial sweep found two ways through
    that argument, both reproduced before being fixed:

    - `pursuit/materialize.py::_confidence_from` holds a bare `6.0` **inside a function body** —
      the evidence weight for every edge with no measurable selectivity. Changing it to `20.0`
      moves the GLASS ANVIL attribution's ORGANIZATION dimension from *unlikely* (0.4470) to
      *likely* (0.5873), reversing the direction, with all four checks clean and all 913 tests
      passing. No digest of module-level constants can see a literal in a function body.
    - `attribute/disclosure.py::_to_external` publishes the post-margin opinion. Swapping two
      lines to publish the pre-margin one moves ORGANIZATION in the **external deliverable** —
      the artefact handed to a provider or a regulator — from *unlikely* to *roughly even*, and
      touches **no constant at all**. No value-based digest of any design can see that.

    The argument for narrowing was also just wrong, and measuring it said so. Replayed over this
    repository's history, eight of the last ten commits move this digest — but each moves
    **one to three modules**, named. That is a readable question ("did any of these three change
    a published figure?"), not the wall of noise the narrowing was defending against. The one
    commit that moves all 102 is the initial import, and one commit — a licence fix — moves
    none.

    So the churn is a price, not a hazard: one deliberate line per commit that touches scoring
    code, in exchange for the seventh and eighth bypasses not existing.
    """
    return {
        relative: _digest_of(_normalised_tree(relative, tree)) for relative in frozen_modules(tree)
    }


def engine_digest(tree: Path | None = None) -> str:
    """The whole tree folded into one value. :func:`module_digests` is the actionable form."""
    folded = hashlib.sha256()
    for relative, digest in sorted(module_digests(tree).items()):
        folded.update(relative.encode("utf-8"))
        folded.update(b"=")
        folded.update(digest.encode("utf-8"))
        folded.update(b"\x00")
    return folded.hexdigest()


MODULE_DIGESTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "nemesis/__init__.py": "a172ce99f96959a5",
        "nemesis/api/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/api/app.py": "7e09268b35e702af",
        "nemesis/api/submission.py": "c69dee2a4bfdd134",
        "nemesis/api/tenancy.py": "89f53381eebffae1",
        "nemesis/attribute/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/attribute/dimensions.py": "824561b007fdcb7d",
        "nemesis/attribute/disclosure.py": "36bf502de5ab7a28",
        "nemesis/attribute/engine.py": "491d53c3c16746a4",
        "nemesis/audit/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/audit/trail.py": "7a2103f95743875a",
        "nemesis/authz/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/authz/anchor.py": "67a0fb6b0bd4ace4",
        "nemesis/authz/attestation.py": "de77df2a9c728935",
        "nemesis/authz/audit_anchor.py": "d16308e2f11e4666",
        "nemesis/authz/envelope.py": "26331a4b05dc728c",
        "nemesis/authz/gateway.py": "1a541fd083f6358b",
        "nemesis/authz/keys.py": "b1a89e11f42f944a",
        "nemesis/authz/monotonicity.py": "659f6b727058ae3b",
        "nemesis/authz/providers.py": "a6d145f04bbce983",
        "nemesis/authz/rbac.py": "8638465529fb2575",
        "nemesis/authz/store.py": "9f0e1c3d3ef0b3e7",
        "nemesis/authz/verification.py": "b36a928a39b96e67",
        "nemesis/breaker/__init__.py": "c612da8e624e7b35",
        "nemesis/breaker/arena.py": "700397886df9d1fa",
        "nemesis/breaker/attack.py": "943ab2a7e07a22ac",
        "nemesis/breaker/attacks.py": "c84d184898e1b298",
        "nemesis/breaker/report.py": "060295fbe07aee74",
        "nemesis/calibration/__init__.py": "d29b1b1babb51bc4",
        "nemesis/calibration/ceilings.py": "481735204236685d",
        "nemesis/calibration/coherence.py": "452dc2ac53a23920",
        "nemesis/calibration/corpus.py": "d581d9cdef47bf9c",
        "nemesis/calibration/generator.py": "bdd90080b2cfed7e",
        "nemesis/calibration/harness.py": "1b251a700a9cf876",
        "nemesis/calibration/localbench.py": "570035edd3779d96",
        "nemesis/calibration/scoring.py": "b2e7a193a30d65a1",
        "nemesis/calibration/sizing.py": "340861bb04cab7b6",
        "nemesis/cli/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/cli/main.py": "917a5155ed935189",
        "nemesis/collaboration/__init__.py": "ca1145a798cbf210",
        "nemesis/collaboration/approvals.py": "9e5aef566b46d5d1",
        "nemesis/collaboration/base.py": "0f24972d696c4060",
        "nemesis/collaboration/demonstration.py": "dc979a4713f99d22",
        "nemesis/collaboration/events.py": "ff3f238a4fe8440b",
        "nemesis/collaboration/identities.py": "a70773dde74fa74d",
        "nemesis/collaboration/outbox.py": "9a730ff313bfd4c0",
        "nemesis/collaboration/providers/__init__.py": "ca1145a798cbf210",
        "nemesis/collaboration/providers/buzz/__init__.py": "ca1145a798cbf210",
        "nemesis/collaboration/providers/buzz/provider.py": "60500894d273f034",
        "nemesis/collaboration/providers/buzz/transport.py": "21524752b51dc4dd",
        "nemesis/collaboration/providers/buzz/wire.py": "c189e4bd40f7e2fb",
        "nemesis/collaboration/providers/local.py": "b562c27002f59de6",
        "nemesis/collaboration/providers/registry.py": "3f06a0cbfdd90da1",
        "nemesis/collaboration/publisher.py": "2795a37b55ec8a5d",
        "nemesis/collect/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/collect/base.py": "2942f5ba711b0cc7",
        "nemesis/collect/dark_web.py": "2a1fa5c9e03df787",
        "nemesis/collect/deepdarkcti.py": "1464c386e157b4c3",
        "nemesis/collect/fixtures/__init__.py": "697cd02f522bbe51",
        "nemesis/collect/fixtures/glass_anvil.py": "ee6a6c4241054d2a",
        "nemesis/collect/fixtures/iron_tide.py": "1185765cf3c3a1d9",
        "nemesis/collect/isolation.py": "b8558935d5a0593e",
        "nemesis/collect/quarantine.py": "9242f2b02186c416",
        "nemesis/collect/ransomware_live.py": "e0d4f7137a88c8ae",
        "nemesis/collect/simulated.py": "e96dc57efcf409d7",
        "nemesis/collect/wire.py": "0b2c5b0cf7ea8e40",
        "nemesis/collect/worker.py": "a77d8e1382ee8768",
        "nemesis/core/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/core/authorization.py": "94eb4ea9d88ef486",
        "nemesis/core/canaries.py": "96015c6a158c696b",
        "nemesis/core/canonical.py": "dfda6b475e3b80c8",
        "nemesis/core/claims.py": "c019f8b283a6a405",
        "nemesis/core/confidence.py": "db49d12f752f0a03",
        "nemesis/core/credentials.py": "35674cce188eacab",
        "nemesis/core/disclosure.py": "525312b5cdc6d2a9",
        "nemesis/core/entities.py": "eba211df1f8c48b2",
        "nemesis/core/evidence.py": "11f4c3c302e3bbd1",
        "nemesis/core/fusion.py": "b932562ceea3ae2c",
        "nemesis/core/identity.py": "aa1dbd3e0be4e2cb",
        "nemesis/core/ids.py": "e983abcbfd1713e4",
        "nemesis/core/infrastructure.py": "ed93db910e04d1b7",
        "nemesis/core/proposition.py": "6362df2cbabfdc5e",
        "nemesis/core/provenance.py": "b241365918a5b072",
        "nemesis/core/relationships.py": "a43da87bbf3f6ba3",
        "nemesis/core/retention.py": "9df610ac890b50e8",
        "nemesis/core/temporal.py": "29539d9208d8fde7",
        "nemesis/disrupt/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/disrupt/options.py": "bda5699b3462b1cb",
        "nemesis/disrupt/planner.py": "ca28a37a568d7b68",
        "nemesis/effects/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/effects/drafting.py": "a0e70263193ec6f2",
        "nemesis/effects/isolation.py": "05b3040ca9723d6f",
        "nemesis/effects/registry.py": "f897e6819b6a9aff",
        "nemesis/effects/simulation.py": "c31e9f1a36b3083e",
        "nemesis/effects/worker.py": "9bf46689e661b835",
        "nemesis/evidence/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/evidence/anchoring.py": "8b974a38aea73244",
        "nemesis/evidence/escalation.py": "a577b5bd2f866902",
        "nemesis/evidence/export.py": "e5fda643d253682c",
        "nemesis/evidence/lineage.py": "fa84c77e043f97a4",
        "nemesis/evidence/standalone_verifier.py": "4d53ea09d2d94424",
        "nemesis/evidence/vault.py": "a5ffab61b1e01ef1",
        "nemesis/evolution/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/evolution/controller.py": "c642efbbe2d030be",
        "nemesis/evolution/evaluator.py": "f19fea27a82a5480",
        "nemesis/evolution/lineage.py": "5c1981fb431259bc",
        "nemesis/evolution/memory.py": "67daaf18dcb0b649",
        "nemesis/evolution/models.py": "daf84e22d63bcd40",
        "nemesis/evolution/portfolio.py": "45aa04c2cbe23784",
        "nemesis/evolution/ports.py": "42d59d03153949c7",
        "nemesis/evolution/projection.py": "81e66920a70e00c1",
        "nemesis/evolution/stagnation.py": "fa6209e49cc6ef6d",
        "nemesis/evolution/supervisor.py": "ecf698c67b3afa9f",
        "nemesis/graph/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/graph/caseindex.py": "225bd08c692f6c36",
        "nemesis/graph/enforcement.py": "bf461c98b7ae1ac3",
        "nemesis/graph/journal.py": "7239834f84fc2b78",
        "nemesis/graph/memory.py": "8da90b3a3c8d674a",
        "nemesis/graph/recall.py": "0f633cf4731a9e2b",
        "nemesis/pilot/__init__.py": "57afbe42c3dcd343",
        "nemesis/pilot/anthropic_pilot.py": "653a3edd88f63dd4",
        "nemesis/pilot/challenger.py": "e32378cc74490f41",
        "nemesis/pilot/local_pilot.py": "844b5ec238222866",
        "nemesis/pilot/mediator.py": "b01815d742b392c2",
        "nemesis/pilot/model_seat.py": "32ced7717960e1e3",
        "nemesis/pilot/moves.py": "bb5981fb9d73aaef",
        "nemesis/pilot/openai_pilot.py": "a0ff06cac4fc63f6",
        "nemesis/pilot/pilot.py": "16f58b14f6431694",
        "nemesis/pilot/providers/__init__.py": "08fb22ea1c5b5387",
        "nemesis/pilot/providers/anthropic.py": "982acef4561c5e31",
        "nemesis/pilot/providers/capabilities.py": "9a62ca00f791764d",
        "nemesis/pilot/providers/challenger_seat.py": "bb08ad13a06df50a",
        "nemesis/pilot/providers/compatible.py": "98a7644b1bd4e677",
        "nemesis/pilot/providers/config.py": "8ac63154782d4afa",
        "nemesis/pilot/providers/contract.py": "e9c24563d39d6579",
        "nemesis/pilot/providers/errors.py": "b3d0dfc04003b068",
        "nemesis/pilot/providers/gemini.py": "670fa44bd869452c",
        "nemesis/pilot/providers/ollama.py": "3ae12fff3e55396a",
        "nemesis/pilot/providers/openai.py": "52d7a9f81213b14f",
        "nemesis/pilot/providers/openai_dialect.py": "f82efc11b003a240",
        "nemesis/pilot/providers/registry.py": "98e801a403b85c88",
        "nemesis/pilot/providers/reliability.py": "db9bb20750b897e6",
        "nemesis/pilot/providers/schema.py": "f5042bd8c7309804",
        "nemesis/pilot/providers/seat.py": "f9099d2210436e15",
        "nemesis/pilot/providers/transport.py": "2bf0df2a35d0c3ee",
        "nemesis/pilot/providers/xai.py": "b8fda96407e8504e",
        "nemesis/pilot/stagnation.py": "24dca2c6d398317c",
        "nemesis/pilotbench/__init__.py": "b68c078ef2457acf",
        "nemesis/pilotbench/corpus.py": "0cdec71ef36139fc",
        "nemesis/pilotbench/harness.py": "c67f23f03002bc8d",
        "nemesis/pilotbench/metrics.py": "101f56057fec0671",
        "nemesis/pilotbench/pilots.py": "ad9687e058000d00",
        "nemesis/pilotbench/report.py": "3d88ede53b780e68",
        "nemesis/pilotbench/runner.py": "3b86079bba9401f9",
        "nemesis/pilotbench/scenario.py": "0d287e55b2e844e5",
        "nemesis/ports/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/ports/authorization.py": "0fc01b5a4a148543",
        "nemesis/ports/collection.py": "085c6c81f40293aa",
        "nemesis/ports/effects.py": "52e15df7ab222655",
        "nemesis/ports/identity.py": "e2cc63ebcc7f117c",
        "nemesis/ports/isolation.py": "3304b03d616feaea",
        "nemesis/ports/storage.py": "66a510c423666609",
        "nemesis/pursuit/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/pursuit/engine.py": "f914a2150d9fd743",
        "nemesis/pursuit/investigation.py": "693a2a25aebc66a3",
        "nemesis/pursuit/materialize.py": "338409bef36aabc7",
        "nemesis/pursuit/policy.py": "887190c023d6a10e",
        "nemesis/pursuit/resurgence.py": "b090042cc377e2ff",
        "nemesis/pursuit/standing.py": "c7bb4e8e3e802a94",
        "nemesis/pursuit/watch.py": "a401c3bc890c8361",
        "nemesis/resolve/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/resolve/actor_corroboration.py": "700708f28bb37bbf",
        "nemesis/resolve/engine.py": "4c4f9c2030905dbe",
        "nemesis/resolve/signals.py": "d061ffc01a1a2ed0",
        "nemesis/sandbox/__init__.py": "ad2e13b69c4fc1fd",
        "nemesis/sandbox/process.py": "70c60d3fcda3d564",
        "nemesis/sandbox/reachability.py": "1a18de28da3014ef",
        "nemesis/sandbox/seal.py": "e007ab5044298ce4",
        "nemesis/slice/__init__.py": "af4908b211f76e8b",
        "nemesis/slice/evolution_session.py": "b4cad74342cea6a8",
        "nemesis/slice/iron_tide.py": "e5fdb3f51981d6e7",
        "nemesis/slice/loopbench.py": "849d0bd73b430a47",
        "nemesis/slice/pilot_session.py": "b0cd426b7deb91a3",
        "nemesis/slice/scenario.py": "26be19c6b0c85b5d",
        "nemesis/slice/standing_session.py": "0d31831a845bb20f",
        "nemesis/ui/__init__.py": "bb9576acc61aeb78",
        "nemesis/ui/investigation.py": "8a672135840ea5c0",
    }
)


FROZEN_VALUE_DIGESTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "nemesis.attribute.dimensions:DEFAULT_TEMPORAL_GAP_TOLERANCE": "bb43b8b888757528",
        "nemesis.attribute.engine:CONTRA_INDICATOR_DISCOUNT": "24877858617e9a1b",
        "nemesis.attribute.engine:DECEPTION_BASE_RATE": "037fc0cd8a861ea1",
        "nemesis.attribute.engine:DEFAULT_BASE_RATE": "742d17a0dd617906",
        "nemesis.attribute.engine:DIMENSION_PROPOSITION": "e8ee084f8aba6132",
        "nemesis.attribute.engine:LOW_PLANTING_COSTS": "c3c88a0995f923a6",
        "nemesis.attribute.engine:PLANTED_EVIDENCE_DISBELIEF_CEILING": "6a3ddf53a7c4ab21",
        "nemesis.attribute.engine:PLANTING_BELIEF_BY_COST": "b5b65616ebff645d",
        "nemesis.calibration.coherence:TOLERANCE": "641b2d75e6d7ac7c",
        "nemesis.calibration.harness:ACTIONABLE_BANDS": "5df9b3e295d43b04",
        "nemesis.calibration.harness:LINKAGE_PROPOSITION": "1545a9c95d79052d",
        "nemesis.calibration.scoring:DEFAULT_BINS": "be010ce660f5827e",
        "nemesis.calibration.scoring:MIN_BIN_COUNT": "9fe727b8db9bef0b",
        "nemesis.calibration.scoring:PUBLISHED_BAND_BINS": "f67c421b38efebb7",
        "nemesis.core.confidence:ADMIRALTY_CREDIBILITY_BELIEF": "782bef4883ab2d5e",
        "nemesis.core.confidence:ADMIRALTY_RELIABILITY_WEIGHT": "c981b367828df809",
        "nemesis.core.confidence:BAND_RANGES": "241423d92c0daea2",
        "nemesis.core.confidence:UNJUDGEABLE_CREDIBILITY_WEIGHT_CEILING": "2904a8a11f85514f",
        "nemesis.core.confidence:VACUITY_THRESHOLD": "dcffbb42c91136ee",
        "nemesis.core.confidence:_TOLERANCE": "4ddc17c7305ba626",
        "nemesis.core.fusion:CONFLICT_ALERT_THRESHOLD": "02c8446321e2d827",
        "nemesis.core.fusion:_EPS": "20f5dab8253a401a",
        "nemesis.core.proposition:ROBUSTNESS_MARGIN": "a8372fc435dacd41",
        "nemesis.core.provenance:UNPLANTABLE_SOURCE_CLASSES": "54e30f4979d76011",
        "nemesis.core.relationships:IDENTITY_ASSERTING_RELATIONS": "a4f98be04a33fc5e",
        "nemesis.core.relationships:METHOD_RELIABILITY_CEILING": "dde14467adcc306b",
        "nemesis.disrupt.options:IMPACT_RANK": "dd0cf6842bf60c0d",
        "nemesis.disrupt.options:OWNERSHIP_CONFIDENCE_FLOOR": "652ab5b813ac18e3",
        "nemesis.resolve.engine:ASSUMED_PERSONAS_PER_OPERATOR": "62f4edb6430c3383",
        "nemesis.resolve.engine:BASE_RATE_CEILING": "ff10dc4fea831406",
        "nemesis.resolve.engine:BASE_RATE_FLOOR": "2b38cc51754eb6e9",
        "nemesis.resolve.engine:NEGLIGIBLE_CONTRIBUTION": "7e13c48600404d55",
        "nemesis.resolve.signals:BELIEF_CEILING": "57867c86d195aa75",
        "nemesis.resolve.signals:CONTRADICTION_BELIEF_CEILING": "35de711bf91fd60f",
        "nemesis.resolve.signals:CORRELATION_GROUP_OF": "b9954362cb965b89",
        "nemesis.resolve.signals:DEMONSTRATED_KEY_CONTROL_CEILING": "94a5183d6f47a735",
        "nemesis.resolve.signals:IRREDUCIBLE_UNCERTAINTY": "bc86be1af15f6287",
        "nemesis.resolve.signals:MIN_POSTS_FOR_A_ROUTINE": "28423595fa8e8cc9",
        "nemesis.resolve.signals:OBFUSCATION_STYLOMETRY_PENALTY": "3ae1a618b8ee9155",
        "nemesis.resolve.signals:OPEN_WORLD_STYLOMETRY_PENALTY": "003e8086fcc9e5f7",
        "nemesis.resolve.signals:STYLOMETRY_BELIEF_CEILING": "7b04b73d1e045444",
        "nemesis.slice.scenario:CLUSTER_MIN_CONFIDENCE": "3dbd1b7586dab613",
        "nemesis.slice.scenario:DARK_BAZAAR_PERSONA_POPULATION": "af8c65a7aa4782bf",
    }
)
"""Per-constant digests of the **imported values**, so `drifted()` names what moved.

Complementary to the syntactic digests rather than redundant with them: `PUBLISHED_BAND_BINS` is
derived from `BAND_RANGES`, so its own syntax never changes when the band edges move, and only
reading the value notices. Regenerate deliberately, in its own commit, with the reason."""


def canonical(value: object) -> str:
    """A stable textual form for a constant's value, independent of the process that reads it.

    `repr()` alone was wrong and would have made the freeze flaky rather than strict: a
    `frozenset` of enum members reprs in hash order, which varies between interpreter runs, so
    `UNPLANTABLE_SOURCE_CLASSES` and `ACTIONABLE_BANDS` would have drifted at random in CI.
    A freeze that fails intermittently is worse than none — it teaches the reader that a red
    digest means nothing.

    Sets are sorted because their order carries no meaning. Sequences are not, because theirs
    does. Mappings are sorted by key for the same reason as sets, and a reordering that changes
    nothing semantically is caught by the syntactic digest anyway.

    Enum members are frozen **by name**, not by value. On its own that would leave the meaning
    behind the name unfrozen — rewriting `ConfidenceBand.UNLIKELY`'s value to `"likely"` changes
    the word a reader is shown while the name is unmoved. It is not a hole because every enum
    *definition* in `src/nemesis` sits inside `module_digests()`; noting it here because the
    two mechanisms only cover each other while both keep their scope.
    """
    if isinstance(value, Enum):
        return f"{type(value).__name__}.{value.name}"
    if isinstance(value, Mapping):
        inner = ", ".join(
            f"{canonical(k)}: {canonical(v)}"
            for k, v in sorted(value.items(), key=lambda item: canonical(item[0]))
        )
        return "{" + inner + "}"
    if isinstance(value, frozenset | set):
        return "{" + ", ".join(sorted(canonical(item) for item in value)) + "}"
    if isinstance(value, list | tuple):
        return "(" + ", ".join(canonical(item) for item in value) + ")"
    # The fallback asks the object to describe itself, so it carries the type as well: an
    # object substituted for a dial can control its own `__repr__` but not what it is. The
    # residual — a lying `__repr__` on the *same* type — needs a class definition, and every
    # class definition in `src/nemesis` is now inside `module_digests()`.
    return f"{type(value).__name__}({value!r})"


def freeze_digest(values: dict[str, object] | None = None) -> str:
    """Fold the registered constants into one value, order-independent.

    Sorted by name so re-ordering the registry cannot change the digest: what is frozen is the
    set of values, not the sequence somebody typed them in.
    """
    observed = values if values is not None else observed_values()
    folded = hashlib.sha256()
    for name in sorted(observed):
        folded.update(name.encode("utf-8"))
        folded.update(b"=")
        folded.update(canonical(observed[name]).encode("utf-8"))
        folded.update(b"\x00")
    return folded.hexdigest()


def _digest_of(payload: str) -> str:
    """Sixteen hex characters of SHA-256. Short enough that a human reads the table."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def value_digest(name: str, value: object) -> str:
    """`freeze_digest`'s fold, applied to a single constant.

    Truncated to sixteen hex characters: this table is read by people deciding whether a change
    was deliberate, and a wall of sixty-four-character hashes is a table nobody checks. Sixteen
    is far beyond what an accidental collision needs, and this is not resisting an adversary who
    controls the constants — one who does can edit the frozen table in the same commit.
    """
    folded = hashlib.sha256()
    folded.update(name.encode("utf-8"))
    folded.update(b"=")
    folded.update(canonical(value).encode("utf-8"))
    folded.update(b"\x00")
    return folded.hexdigest()[:16]


def drifted() -> tuple[str, ...]:
    """Which constants no longer match the freeze — empty when nothing moved.

    Names the culprits, because "something moved" is not actionable and
    "``DECEPTION_BASE_RATE`` moved" is. An earlier version compared only the aggregate digest
    and, when it failed, returned **every registered name** — technically documented, and in
    practice a report that a reader would take as thirty constants having changed when one had.
    A diagnostic that cannot distinguish one from thirty is not a diagnostic.

    Constants that vanished are reported too: a registered name that no longer exists is a
    change to what the platform believes, not an import error to be shrugged at.
    """
    observed = {name: value_digest(name, value) for name, value in observed_values().items()}
    moved = [name for name, digest in observed.items() if FROZEN_VALUE_DIGESTS.get(name) != digest]
    vanished = [name for name in FROZEN_VALUE_DIGESTS if name not in observed]
    return tuple(sorted(set(moved) | set(vanished)))


def engine_drifted(tree: Path | None = None) -> tuple[str, ...]:
    """Which modules' syntax changed, appeared or vanished since the freeze.

    Names rather than a boolean, for the same reason `drifted()` gives names: after a red freeze
    the only useful question is *which*, and a report a reader cannot act on is one they learn
    to dismiss.
    """
    observed = module_digests(tree)
    moved = {name for name, digest in observed.items() if MODULE_DIGESTS.get(name) != digest}
    vanished = {name for name in MODULE_DIGESTS if name not in observed}
    return tuple(sorted(moved | vanished))


@dataclass(frozen=True)
class MeasurementProvenance:
    """What a number was measured under. Attached to every figure this platform reports.

    `docs/calibration/PROTOCOL.md` §6 ends with "every figure is reported with ... the freeze
    digest it was measured under. **A number without those four is not a result.**" The harness
    printed a Brier decomposition, an AUC and two false-match rates and carried none of them —
    the mechanism built so a measurement could be tied to a configuration, and the one thing
    that produces measurements did not record the configuration. A doc-versus-code gap in the
    exact place the document is about.

    The environment is here for a reason a freeze over `src/nemesis` cannot cover: nothing in
    those digests changes when `pydantic` does, and a coercion or float-handling change in a
    dependency moves a published band with all three digests green. That is not asserted —
    a dependency bump should make two numbers **incomparable**, not make CI red — so it is
    recorded and reported, which is what the protocol asks for anyway.
    """

    values_digest: str
    tree_digest: str
    constants_digest: str
    environment_digest: str
    python_version: str
    dependencies: tuple[tuple[str, str], ...]
    drifted_constants: tuple[str, ...]
    drifted_modules: tuple[str, ...]

    @property
    def is_frozen(self) -> bool:
        """Whether the tree still matches the freeze these figures claim to be measured under."""
        return not self.drifted_constants and not self.drifted_modules

    def render(self) -> list[str]:
        lines = [
            f"  values     {self.values_digest[:16]}   {len(FROZEN_VALUE_DIGESTS)} constants,"
            f" by imported value",
            f"  constants  {self.constants_digest[:16]}   {len(CONSTANT_DIGESTS)} dials,"
            f" by normalised syntax",
            f"  tree       {self.tree_digest[:16]}   {len(MODULE_DIGESTS)} modules,"
            f" by normalised syntax",
            f"  environment {self.environment_digest[:16]}  Python {self.python_version}, "
            + ", ".join(f"{name} {version}" for name, version in self.dependencies),
        ]
        if self.is_frozen:
            lines.append("  Matches the freeze. Comparable with any run carrying these digests.")
            return lines

        lines.append("")
        lines.append("  ! NOT AT THE FREEZE. These figures describe a different system from any")
        lines.append(
            "    measurement taken at the digests above, and the two must not be compared."
        )
        for name in self.drifted_constants:
            lines.append(f"      dial moved    {name}")
        for name in self.drifted_modules:
            lines.append(f"      module moved  {name}")
        return lines


def runtime_dependencies() -> tuple[tuple[str, str], ...]:
    """The declared runtime dependencies and their installed versions — derived, not listed.

    Read from this distribution's own metadata, so a dependency added to `pyproject.toml`
    appears here without anyone remembering to. Development tools are excluded because they
    live in `[dependency-groups]` and never reach `Requires-Dist` at all — excluded by
    construction rather than by a rule somebody has to keep correct, which is the distinction
    this module has paid for repeatedly. Optional extras are excluded for the same reason they
    are optional: a figure produced without them was produced without them.
    """
    from importlib.metadata import PackageNotFoundError, distribution, version

    try:
        declared = distribution("nemesis").requires or []
    except PackageNotFoundError:  # pragma: no cover - only when running from an unbuilt tree
        return ()

    found: list[tuple[str, str]] = []
    for requirement in declared:
        if "extra ==" in requirement:
            continue
        name = re.split(r"[<>=!~ \[;]", requirement, maxsplit=1)[0].strip()
        if not name:
            continue
        try:
            found.append((name, version(name)))
        except PackageNotFoundError:  # pragma: no cover - a declared dep that is not installed
            found.append((name, "MISSING"))
    return tuple(sorted(found))


def measurement_provenance() -> MeasurementProvenance:
    """Everything a reader needs to know whether two numbers may be compared."""
    import sys

    dependencies = runtime_dependencies()
    environment = "|".join(
        [f"python={'.'.join(str(part) for part in sys.version_info[:3])}"]
        + [f"{name}={value}" for name, value in dependencies]
    )
    return MeasurementProvenance(
        values_digest=freeze_digest(),
        tree_digest=engine_digest(),
        constants_digest=_digest_of(
            "|".join(f"{name}={digest}" for name, digest in sorted(CONSTANT_DIGESTS.items()))
        ),
        environment_digest=hashlib.sha256(environment.encode("utf-8")).hexdigest(),
        python_version=".".join(str(part) for part in sys.version_info[:3]),
        dependencies=dependencies,
        drifted_constants=constants_drifted(),
        drifted_modules=engine_drifted(),
    )


class CalibrationFreezeError(RuntimeError):
    """A registered calibration constant is missing or unreadable.

    Its own type because it is a structural problem with the registry rather than a drift in a
    value: a caller checking "did a dial move" must not swallow "a dial disappeared".
    """


__all__ = [
    "CALIBRATION_CONSTANTS",
    "CONSTANT_DIGESTS",
    "FROZEN_DIGEST",
    "MODULE_DIGESTS",
    "CalibrationFreezeError",
    "MeasurementProvenance",
    "constants_drifted",
    "discovered_constants",
    "drifted",
    "engine_digest",
    "engine_drifted",
    "freeze_digest",
    "frozen_modules",
    "measurement_provenance",
    "module_digests",
    "normalised_source",
    "observed_values",
    "runtime_dependencies",
]
