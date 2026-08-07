# services/cve — offline CVE/advisory enrichment

Matches a Solana program's `Cargo.lock` against a vendored snapshot of the
[RustSec advisory database](https://github.com/rustsec/advisory-db), and
reports which of its dependencies carry a known advisory. Exposed via
`POST /cve/scan` and `GET /cve/snapshot` in `apps/auditor-api`.

Deterministic and offline by construction: no LLM, no network call on the
scan path — only crate-name + semver-range matching against a snapshot that
was refreshed by a human, in advance. See "Hermetic by default" in
[`SECURITY.md`](../../SECURITY.md).

## Why dependency-keyed, not category-keyed

Two readings of "CVE enrichment" were possible. This implements
**dependency-keyed**: real CVEs/advisories exist against Rust crates, not
against Solana logic-bug classes. `src/knowledge/solana-vulns.ts`'s 34
entries already carry a `cwe` field for the category-keyed reading — adding
a `cve` column there would be mostly empty, because missing-signer-check,
missing-owner-check, and similar classes are bug *patterns*, not versioned
software defects with CVE assignments. This service instead answers a
different, previously-unaddressed question: does the target's *dependency
tree* carry a known vulnerability. `core-ci.yml`'s `cargo audit` step already
answers that question for ARES's **own** dependencies; nothing in the repo
answered it for a **target's**, until this.

## Scope and its one hard limitation

**Only source audits (`npm run audit -- --source ...`) have a `Cargo.lock`.**
An on-chain audit (`npm run audit -- --program <ADDRESS>`) has no manifest —
there is nothing for this service to match against. This is a designed
`skipped` outcome (see below), not a gap discovered after the fact.

This PR does **not** wire the result into the TS audit graph or the
`Finding` model — see docs/`<ID>`-ASSUMPTIONS.md's "Out of scope" section.
`/cve/scan` is a standalone, independently-callable endpoint today.

## Outcome vocabulary

Reuses the `ok` / `skipped` / `degraded` / `failed` vocabulary the TS
analyzers use (root [`README.md`](../../README.md)'s "Analyzer status"
table), so a broken run can never look identical to a clean one:

| Outcome | Meaning |
|---|---|
| `ok` | Lockfile parsed, at least one dependency matched against the DB. |
| `skipped` | No lockfile was submitted — not applicable, not an error. |
| `degraded` | Lockfile parsed but resolved to zero dependencies. |
| `failed` | Input was not a parseable `Cargo.lock`. |

## Modules

| File | Responsibility |
|---|---|
| `lockfile.py` | `Cargo.lock` text → `[Dependency(name, version, is_local)]`, via stdlib `tomllib`. |
| `version_req.py` | Cargo-grammar version-requirement matching (`^`, `~`, `>=`, comma-conjunctions). Deliberately **not** a general-purpose semver library — RustSec ranges use Cargo's own grammar, which differs from PEP 440 and node-semver. |
| `advisories.py` | Loads and indexes `snapshot/advisories.json`, verifying it against the digest recorded in `snapshot/manifest.json`. |
| `match.py` | Dependencies × advisory DB → matches. Excludes workspace-local crates and withdrawn advisories (counted, not silently dropped). |
| `severity.py` | CVSS v3.1 base-score computation → ARES severity enum. **CVSS v4.0 vectors are recognized and explicitly rejected as unrated**, never mis-scored with the v3.1 formula — see "Two CVSS versions" below. |
| `refresh_snapshot.py` | Manual, networked. Rebuilds `snapshot/`. Never imported by the service. |

## The snapshot

`snapshot/advisories.json` + `snapshot/manifest.json` are **committed**, not
fetched at request time or at CI time. This is a deliberate departure from
`eval/`'s convention (which gitignores fetched data and regenerates it in
CI — see `.gitignore` and `eval/README.md`): the CVE service needs the
snapshot to answer requests, and `SECURITY.md` promises a default run makes
no outbound calls beyond the configured LLM endpoint. A fetch-on-request
design would break that promise; committing the snapshot keeps it.

Provenance is recorded by `refresh_snapshot.py` at generation time, in the
same spirit as `eval/mappings/*.json` (pinned upstream revision + a `notes`
array of prose caveats), adapted for a single normalized file rather than
many per-source rows:

- `revision` / `revision_date` — the upstream `advisory-db` commit this
  snapshot was built from.
- `advisories_sha256` — digest of `advisories.json`'s exact bytes at
  generation time. `AdvisoryDB.load()` recomputes and compares this on
  every load and refuses to load on a mismatch — a hand-edit or corruption
  is a hard failure, not a warning. `test_snapshot_integrity.py` runs the
  same check in CI on every push.
- `license` — recorded **by hand**, not machine-checked. `advisory-db`'s
  own `LICENSE.txt` puts almost everything under CC0-1.0 (public domain),
  except advisories carrying an explicit `license` field in their front
  matter — content imported from GitHub's Security Advisory database — which
  is CC-BY-4.0 and requires attribution. **Neither `scripts/check-licenses.mjs`
  nor `core/deny.toml` inspects committed data files** — both read only
  npm/cargo dependency metadata — so this is the one place in the repo where
  a data file's license was verified by reading the upstream terms directly,
  not by a gate.
- `notes` — includes the withdrawn/informational/CVE-alias counts for the
  revision this snapshot was built from, and states plainly that refreshing
  the snapshot changes future match results with no mechanism to reproduce
  a *past* result except by knowing which revision it came from.

### Refreshing the snapshot

```bash
git clone https://github.com/rustsec/advisory-db.git /tmp/advisory-db
python services/cve/refresh_snapshot.py --source-dir /tmp/advisory-db
```

Or clone fresh in one step: `python refresh_snapshot.py --clone-to <dir>
[--revision <sha>]`. The script fails the whole run rather than writing a
partial snapshot if any advisory file fails to parse — see its module
docstring for why (the ORC2-F7 parallel: a dropped record is invisible at
scan time, indistinguishable from "this crate has no advisory").

## Two CVSS versions, one implemented

The vendored corpus carries **both** `CVSS:3.1/...` and `CVSS:4.0/...`
vectors — confirmed directly, not assumed: `RUSTSEC-2026-0144` (anchor-lang)
is 3.1, `RUSTSEC-2026-0146` (anchor-lang, filed eight days later) is 4.0.
`severity.py` implements only the v3.1 base-score formula. A v4.0 vector
uses an entirely different metric set; running it through the v3.1 formula
would produce a confident-looking wrong number. `severity_for_advisory()`
returns `(None, "unsupported-cvss-version")` for it instead — visibly
unrated, not silently wrong. Extending to v4.0 is future work.

## Verified against real data

- `test_lockfile.py` and `test_snapshot_integrity.py` run against the
  repo's own `core/Cargo.lock` and the full committed advisory snapshot,
  not only hand-written fixtures. The strictness in `version_req.py` (raise
  on anything unparseable, rather than a silent non-match) caught a real gap
  during development: an early version only padded partial versions
  (`>= 0`, `< 0.3`, `>= 111.9`) when no operator was present, which raised
  on all 40 real ranges using an explicit operator with a partial version.
  Fixed and covered by `TestEveryVersionRangeInTheSnapshotIsParseable`.
- Scanning `core/Cargo.lock` through the live endpoint finds
  `RUSTSEC-2026-0187`, `-0194`, `-0195`, and `-0204` — exactly the four
  advisories `core-ci.yml`'s `cargo audit --ignore ...` step already lists
  as accepted risk. This service reproduces that existing gate's finding set
  independently, which is the strongest evidence available that the matcher
  is correct against a real dependency tree, not just synthetic cases.

## What this does not do

- No wiring into the TS audit graph — `src/graph/nodes/`,
  `build-graph.ts`, or the `Finding["source"]` union are untouched. A
  caller (human or a later ORC task) invokes `/cve/scan` directly today.
- No effect on measured detection accuracy (`docs/EVAL-2-REPRODUCTION-REPORT.md`).
  This is dependency-supply-chain data, not a program-logic finding, and it
  is not part of the `eval/` ground truth.
- No on-chain dependency resolution. `--program` targets get `skipped`.
