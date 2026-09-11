# Real Play ransomware actor hunt with Daybreak Blue

**IMPLEMENTED.** On 2026-09-09 local time (2026-09-10 UTC), Daybreak Blue drove a
passive NEMESIS investigation from the public SHA-256 IOC
`75404543de25513b376f097ceb383e8efb9c9b95da8945fd4aa37c7b2f226212`.
Daybreak selected every move from the live frontier. NEMESIS authorized each move,
executed the connector, sealed the evidence, and recorded the decision and result. No
local or embedded LLM was called.

## Operational result

- Daybreak Blue made 10/10 decisions successfully, at `high` reasoning effort, with
  one Codex attempt per decision and no model errors.
- NEMESIS executed nine connector pivots: eight succeeded and one failed visibly.
- The run admitted 110 claims, and all 110 resolve to sealed evidence metadata.
- The vault contains 105 unique real evidence objects: four public captures — one of them
  the official advisory, classified for malicious-code handling — 100 sensitive
  ransomware.live records, and one restricted Tor object.
- All 105 evidence objects have `is_simulated=false`.
- The two explicitly allowlisted Play onion endpoints responded through confined Tor.
  Their identical response bytes deduplicated to one restricted object.
- The evidence-vault chain and the 22-entry audit chain passed independent verification.
- No external effect was requested. The run performed no probing, scanning,
  authentication, payload execution, interaction, or infrastructure modification.
- **No negative control was attempted.** `effects.negative_control.status` is `missing` in
  the run record. Unlike the [public IOC evaluation](../public-ioc-2026-09-09/REPORT.md),
  which had a deliberately forbidden request refused as `refused_out_of_envelope`, this run
  contains no move the limiter had to stop. It therefore shows that no effect was needed,
  not that the effect boundary holds. Read the two reports together, not this one alone.

The move sequence was: C2 extraction from the malware sample, reverse resolution of the
reported C2, official malware lookup, public actor search, ransomware.live actor lookup,
network-ownership context, an additional public IP-intelligence lookup, two Tor snapshots,
then `scope_exhausted`. This sequence came from Daybreak Blue rather than a fixed pivot
script.

## What the hunt established

The [joint CISA/FBI/ASD's ACSC advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
publishes the seed as a SystemBC executable in its Play ransomware reporting. The public
[Triage analysis](https://tria.ge/230226-g3rtcsga84) reports `45.77.195.73:443` as C2 for
that same sample. [BGP Toolkit](https://bgp.he.net/net/45.77.192.0/21) supplied the PTR,
prefix, ASN, and hosting-provider context; shared hosting was retained as context and was
not treated as actor control.

The public [deepdarkCTI index](https://github.com/fastfire/deepdarkCTI/blob/main/ransomware_gang.md)
linked Play to two leak-site locations already present in the operator allowlist. Both
locations returned bytes through confined Tor. NEMESIS did not parse or redistribute
those bytes and did not interact with either service.

The hunt exposed an obsolete NEMESIS connector route. The old
`www.ransomware.live/api` route returned HTTP 404. The connector was corrected to the
documented `api.ransomware.live/v2` base and the entire hunt was rerun. The corrected
connector admitted 100 real Play listings and marked the result truncated at the
requested 100-record bound. Each record remains a third-party report of an adversary's
own claim, carries a deception assessment and `no redistribution`, and does not establish
that any named organization was compromised.

The additional Joe Sandbox lookup returned HTTP 403 and produced no claim or evidence.
The failure is retained in the audit trail rather than silently omitted.

## Assessment

This is a real actor-infrastructure tracking result. Starting from an official malware
IOC, NEMESIS followed evidence to a reported C2, network context, the Play actor label,
records from a live aggregator snapshot, and two reachable leak-site endpoints. It
demonstrates that the framework can combine clearnet and Tor collection while keeping
hostile and sensitive material confined, bounded, attributable to its source, and auditable.

The evidence supports the public-source association between this SystemBC sample and Play
reporting, and it shows that the two indexed Play endpoints answered during the collection
window. It does not identify a human operator, prove that Play controlled the historical
C2 at collection time, confirm any victim claim, or prove that the two onion names are
independent services. The two Tor responses produced the same content hash; because the
vault deduplicated them, the retained export cannot independently rehash two response
measurements and records no response-identity correlation claim.

The run has no independent external integrity anchor. Its hash chains detect partial
editing and prove internal consistency, but an operator able to rewrite the complete
store could rebuild them. The published checksums bind the withheld run files to the
later Git history; they do not create a collection-time external anchor.

## Publication boundary

Raw captures, ransomware victim identities, onion addresses, Tor state, model transcripts,
and the live runner remain in the ignored local artifact directory. The repository contains
only aggregate results, non-sensitive evidence identifiers, verification data, and hashes.
See [verification.json](verification.json),
[evidence-manifest.json](evidence-manifest.json), and
[private-run-checksums.txt](private-run-checksums.txt).
