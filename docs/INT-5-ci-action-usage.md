# INT-5 — ARES Security Scan GitHub Action

Wraps `INT-1`'s consolidated CLI (`ares scan` → the real, shipping TS audit
pipeline) as a GitHub Action other repositories can add to their own CI, with
a configurable severity gate.

**Internal-only for now** — not published to the public Marketplace.
Referenced within the org as
`daemon-blockint-tech/4R3S/.github/actions/ares-scan@main`.

## Honest setup cost — read this before adding it to a workflow

This is not a zero-config, drop-in tool, and pretending otherwise would
just move the friction to whoever tries to use it without reading this
first:

1. **A real LLM API key is required.** This is an LLM-based auditor; there
   is no offline mode for the audit itself. You need an
   `OPENROUTER_API_KEY`.
2. **A token with read access to this repo is required.** The calling
   workflow's own default `GITHUB_TOKEN` is scoped to the repo it runs in
   — it cannot check out a separate, private repo (this one). Create a PAT
   or GitHub App token with read access to `daemon-blockint-tech/4R3S`,
   store it as a secret in the calling repo (or org-wide, if many repos
   will use this).

Neither of these is something this Action can remove — they're inherent to
what it actually does (run a real, private, LLM-backed tool against your
code). What it *doesn't* require: a database. `--ephemeral` mode (an
in-memory checkpointer) is used specifically so a CI check doesn't need a
Postgres instance provisioned just to run.

## Why the findings are read from a JSON file, not the human-readable report

The production audit pipeline's report is a formatted, human-readable
string — there was no structured, machine-readable output to gate on
before this. Parsing that report's prose with a regex would have been
fragile for something a CI pass/fail depends on, so a small, additive,
opt-in flag (`--report-json <path>`) was added to `src/index.ts` — nothing
about the existing report changes when this flag isn't passed.

## Default severity threshold: `critical` (fail), `high` (warn)

Every other detector in this scanner earned a more permissive default with
real, measured evidence (see `ENG-4`'s own rollout discipline for
`ast_scanner`). This Action has none yet. Starting at the most conservative
setting and loosening it later, once real usage across a few repos shows
the noise level is acceptable, follows the same principle rather than
guessing at a friendlier default up front.

The task's own example (*"fail on High+, warn on Medium"*) implied a
two-tier system this didn't originally have — caught on a direct
crosscheck against the task wording, not assumed complete. `high`/`medium`
findings below the fail threshold now surface as real GitHub Actions
`::warning::` annotations rather than passing silently. Set
`warn-severity-threshold: none` to disable this tier entirely.

## Example workflow

```yaml
name: ARES Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  ares-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout this repo
        uses: actions/checkout@v4

      - name: Run ARES scan
        uses: daemon-blockint-tech/4R3S/.github/actions/ares-scan@main
        with:
          source-path: ${{ github.workspace }}/programs
          severity-threshold: critical
          ares-repo-token: ${{ secrets.ARES_REPO_TOKEN }}
          openrouter-api-key: ${{ secrets.OPENROUTER_API_KEY }}
```

## Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `source-path` | No | whole checkout | Path to the Solana program source |
| `severity-threshold` | No | `critical` | `critical`\|`high`\|`medium`\|`low`\|`info` — fails at or above this level |
| `warn-severity-threshold` | No | `high` | Annotates (doesn't fail) findings at or above this level and below `severity-threshold`. `none` disables this tier |
| `ares-repo-ref` | No | `main` | Pin this once the Action stabilizes — floating on a branch means a change here can silently change what a downstream repo's CI gates on |
| `ares-repo-token` | **Yes** | — | Read access to this repo |
| `openrouter-api-key` | **Yes** | — | LLM access for the audit itself |
| `solana-rpc-url` | No | mainnet-beta | Only needed scanning by on-chain program address |

## Outputs

| Output | Meaning |
|---|---|
| `findings-json` | Path to the full, structured findings JSON |
| `finding-count` | Total findings, before severity filtering |
| `gate-passed` | `"true"`/`"false"` |

## What the gate actually does, precisely

1. Reads the structured findings JSON `--report-json` wrote
2. **Excludes findings the pipeline's own VERIFY step already marked
   `false-positive`** — gating a CI check on findings the tool has already
   ruled out would make every false-positive an unblockable build failure
3. Compares the remainder's severities against the configured threshold
   (mirrors this repo's own `SEVERITY_RANK` ordering from
   `src/knowledge/finding.ts` — see the note in `gate.mjs` about why this
   is a deliberate, disclosed mirror rather than a real import)
4. Fails (non-zero exit) if anything remains at or above the threshold

**A missing or unreadable findings file is treated as a failure, not a
silent pass** — the same failure shape `ORC2-F6` already found once for a
different tool in this repo (a target the tool never actually looked at
reading as "clean"). If the audit process crashes before writing the
file, the gate fails loudly rather than reporting a clean scan that never
happened.

## Two real gaps found by crosschecking against the task's literal wording, not assumed complete

- **The Action originally called `npm run audit` directly, bypassing `INT-1`'s own CLI entirely** — the task explicitly says "wrapping the consolidated CLI." `cli.ts`'s `cmdScan` is a thin pass-through today, so this was behaviorally identical either way, but going through the real front door means any future validation added to `cli.ts` is automatically inherited here, not silently bypassed. Fixed: now calls `npm run ares -- scan ...`.
- **No warn tier existed at all** — the task's own example (*"fail on High+, warn on Medium"*) implied one. Added `warn-severity-threshold`, defaulting to `high`, surfacing real GitHub Actions `::warning::` annotations for findings below the fail threshold rather than passing them silently.

## Verified

- The gate script (`gate.mjs`) run directly against **9** real scenarios,
  not just reasoned about: the original 6 (a genuine Critical finding, a
  below-threshold Medium finding, a Critical finding marked
  `false-positive`, a missing findings file, an invalid fail threshold, a
  genuinely empty valid array) plus 3 new ones for the warn tier (a High
  finding warns without failing, a Medium finding below the warn threshold
  neither warns nor fails, `none` genuinely disables the tier, and an
  invalid warn-threshold string fails clearly) — every case produced the
  exact expected exit code and output
- `src/index.ts`'s new `--report-json` flag: `npm run typecheck` clean,
  full suite (44 files / 445 tests) passing, zero regressions

**Not yet verified: an actual, real GitHub Actions run.** The composite
action definition (`action.yml`) itself has not been run inside a real
GitHub Actions runner — that requires a real workflow trigger, a real
`OPENROUTER_API_KEY`, and a real token with access to this repo, none of
which are available to verify from here. The gate logic it depends on is
thoroughly verified directly; the YAML wiring around it is not.
