# Public IOC operational POC

**IMPLEMENTED.** This report records a Codex-directed, passive NEMESIS investigation of the
public SHA-256 IOC
`75404543de25513b376f097ceb383e8efb9c9b95da8945fd4aa37c7b2f226212` on
2026-09-09. Codex selected the move sequence; NEMESIS performed collection, authorization,
evidence sealing, audit recording, and claim provenance checks. No local or embedded LLM was
called.

## Operational result

- 10/10 pilot moves were recorded in the audit chain.
- Five of six public-source pivots succeeded across four of five attempted sources.
- Eight public-source observation claims were admitted from four unique captures.
- Two of two explicitly allowlisted onion endpoints responded through confined Tor.
- Zero collected records were simulated.
- Ten of ten recorded claims resolve to sealed evidence metadata.
- The evidence vault and 21-entry audit chain passed integrity verification.
- One deliberately forbidden registrar-suspension request was refused as
  `refused_out_of_envelope`; it was not accepted and made no external contact.
- The outcome remained `attribution_uncertain`.

This demonstrates the framework's operational value as a control and evidence system. It can
turn a public IOC into a bounded investigation, preserve the sources behind material claims,
keep hostile content quarantined, record every pilot decision, and reject an unauthorized
effect even when the effect budget is non-zero. It also stops short of actor attribution when
the evidence supports malware classification, historical C2 reporting, hosting context, and
endpoint reachability only.

## Evidence findings

The official joint advisory identifies the seed as a SystemBC executable within its Play
ransomware reporting. The public Triage analysis reports `45.77.195.73:443` as C2 for the same
sample. The public deepdarkCTI index supplies the two operator-approved onion candidates. BGP
Toolkit supplies PTR, prefix, ASN, and registrant context for the reported IP.

Joe Sandbox did not enter the evidence graph. Its direct connector returned HTTP 403, and the
issuer of that response was not recorded. The referenced Joe report also concerns another
sample, so it would have been historical corroboration of the IP rather than evidence about the
seed.

The two Tor pivots returned the same content-addressed evidence identifier. NEMESIS preserved one
restricted object through deduplication. The run therefore records no response-identity
correlation claim: a third party cannot independently rehash two distinct response measurements
from the retained vault.

## Time and integrity limits

The run started at `2026-09-09T11:01:02.796280Z` and finished at
`2026-09-09T11:01:30.189724Z`. Collection timestamps came from the real run clock. The maximum
measured collection-to-seal interval was 7.539381 seconds. This removes the earlier run's
hard-coded 50-hour discrepancy.

Claim valid-time extents are single sightings with open possible bounds. They record when a
source was observed or what historical date it reported; they do not establish the exact start
or end of the underlying condition.

The run had no independent external integrity anchor. Its hash chains establish internal
consistency and detect partial editing, but an operator able to rewrite the complete store could
rebuild them. The checksums published with this report bind the withheld local run files to this
later Git history; they do not retroactively create an independent anchor at collection time.

## Publication boundary

The local vault contains four public-source captures and one dark-web object classified
`legally_restricted` with a `no redistribution` restriction. The restricted bytes, all other raw
captures, Tor client state, guard information, prior defective runs, and the live runner are
excluded from Git. The evidence identifiers, aggregate verification results, and checksums below
are sufficient to identify the run without redistributing collected content.

The POC was passive. It performed exact-URL retrieval only, with no scanning, probing,
authentication, interaction, payload execution, or infrastructure modification.
