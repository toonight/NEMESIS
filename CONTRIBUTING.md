# Contributing

NEMESIS is source-available, not open-source, and it is maintained by one person. Read
[`LICENSE`](LICENSE) first: publication grants you the right to read, evaluate and fork within
GitHub, and nothing else.

## What is welcome

**Findings.** This project's most valuable contributions so far have been adversarial reviews
that found controls weaker than their own documentation — four in one day. If you can show that
something here claims more than it does, that is the contribution worth making.

- A **security finding** goes through
  [private vulnerability reporting](https://github.com/toonight/NEMESIS/security/advisories/new),
  not a public issue. See [`SECURITY.md`](SECURITY.md).
- Anything else — a wrong claim, a broken assumption, a defect in reasoning — goes in an issue.

**Reproduction beats assertion.** The bar this repository holds itself to is that a claim about
behaviour is accompanied by something that runs. A test that constructs the attack is worth more
than a description of it, and a finding verified against the code is worth more than one
inferred from the documentation — several external reviews of this project have been wrong
precisely because they read a stale document instead of the source.

## Code contributions

**Ask before writing.** Open an issue describing the change first. A patch that arrives unasked
may be one I cannot accept for licensing reasons, and neither of us gets that time back.

**If a patch is accepted, these are the terms.** By submitting one you:

1. certify that you wrote it, that you have the right to submit it, and that it is not
   encumbered by anyone else's licence or by an employment agreement;
2. **assign copyright in the contribution to the copyright holder of this project**, or, where
   assignment is not effective in your jurisdiction, grant a perpetual, worldwide, irrevocable,
   royalty-free licence to use, modify, sublicense and relicense it — including under a
   commercial licence, and including terms different from the ones this repository carries
   today.

Stated plainly rather than left implicit: without this, contributed code could not be
relicensed without tracking down every author, which would make a commercial licence
impossible in practice. If you are not willing to grant it, open an issue describing the
problem instead of sending code — that is genuinely useful and costs you nothing.

## What a change has to pass

Everything CI runs, and CI is the whole gate:

```bash
uv sync --all-extras
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run lint-imports
uv run pytest
uv run python scripts/check_prohibited.py
uv run python scripts/check_documented_counts.py
```

Beyond green, three rules this project applies to itself:

- **Every bug fix starts with a test that fails without it.** Not "a test was added" — the test
  was *seen to fail*, then seen to pass. A test nobody watched fail proves nothing.
- **Documentation that contradicts the code is a defect**, not tidying. If your change makes a
  claim in `docs/` untrue, the change is not finished.
- **Never weaken a test to make a build pass.** If an assertion is wrong, say why in the commit
  message and fix the assertion deliberately.

The fifteen non-negotiable invariants in [`CLAUDE.md`](CLAUDE.md) are not up for negotiation in
a pull request. A change that violates one is rejected rather than debated; if you think an
invariant is wrong, that is an issue, not a patch.

## What will not be accepted, ever

Anything that scans, probes, connects to, authenticates against or modifies infrastructure this
project does not own. Exploitation, persistence, credential attacks, malware handling, or
destructive remote capability — including "just for testing". Real secrets in the tree.

Capabilities that would require lawful authority belong here as declared interfaces with no
implementation, marked `REQUIRES_LEGAL_AUTHORITY`. That is a deliberate design position, not an
oversight to be helpfully corrected.
