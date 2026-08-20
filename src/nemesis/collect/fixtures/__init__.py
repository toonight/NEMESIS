"""Fixture sets standing in for intelligence sources.

**Status: `SIMULATED`.** Every identifier in here is synthetic and drawn from ranges
reserved for documentation — `.example` domains (RFC 2606), `192.0.2.0/24`,
`198.51.100.0/24` and `203.0.113.0/24` (RFC 5737), private-use AS numbers (RFC 6996).
None of it resolves. That is not a convention: it is what makes invariant 15 structurally
true rather than promised, since there is no reachable system for a bug to reach.

Some fixtures contain adversary-authored text, including an attempt at instructing an
automated reader. It is quoted verbatim because the platform has to be testable against
it. It is data.

Trust level: HOSTILE.
"""

from nemesis.collect.fixtures.glass_anvil import (
    ACME_EMAIL_GATEWAY,
    ACME_WAF,
    RESURGENCE_AS_OF,
    SCENARIO_PRESENT,
    blockchain_fixtures,
    certificate_fixtures,
    dark_web_fixtures,
    malware_fixtures,
    network_fixtures,
    passive_dns_fixtures,
    phase_one_detection,
    rdap_fixtures,
)

__all__ = [
    "ACME_EMAIL_GATEWAY",
    "ACME_WAF",
    "RESURGENCE_AS_OF",
    "SCENARIO_PRESENT",
    "blockchain_fixtures",
    "certificate_fixtures",
    "dark_web_fixtures",
    "malware_fixtures",
    "network_fixtures",
    "passive_dns_fixtures",
    "phase_one_detection",
    "rdap_fixtures",
]
