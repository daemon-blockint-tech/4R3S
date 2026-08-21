# SVC-4 — Evidence bundling (Merkle) + on-chain anchoring via `evidence_registry`: what was done, what was verified, what wasn't

> **Placeholder ID.** `SVC-4` is the id from the task card. `docs/BACKLOG.xlsx` is
> not committed to this repo — and neither are `docs/PRD.md` or
> `docs/DEVELOPMENT_PLAN.md`, though `CLAUDE.md:47`/`:59` cite all three as
> authoritative and `services/README.md:3` points at `DEVELOPMENT_PLAN.md §S3`
> for this very service. If the Notion id differs, replace it in this filename,
> the branch name and the commit prefixes before opening the PR.

## The task, and the reading it settled on

The card reads "Evidence bundling (merkle) + on-chain anchoring via
evidence_registry program", home `services/evidence`, referencing an
`ARES-AGENT ares-evidence` implementation plus an `evidence_registry` Anchor
program.

**That reference material is not available.** `ARES-AGENT` is not on this
machine, is not a submodule, and nothing in this repository's git history
contains an `ares-evidence` crate, a Merkle implementation, or an
`evidence_registry` program — `grep -c 'name = "solana' core/Cargo.lock` returns
0, and there is no `programs/` directory or `Anchor.toml` anywhere. So this is a
design from scratch against the artifact the engine actually produces, not a
port. Where the plan says "the reference does X", it is inference from the names
in the card, and is flagged as such.

Three decisions settled the shape, and the user chose each explicitly:

1. **Python in `services/evidence`**, matching the three sibling services (pure
   Python 3.12, stdlib-only runtime, `pytest==9.1.1` the only pin). Zero edits to
   `core/Cargo.toml`, so no exposure to the Rust build, `cargo deny`, or
   `core-release.yml`'s hardcoded publish list.
2. **Program source + host-target tests only.** There is no `solana` CLI, no
   `anchor` CLI and no `cargo build-sbf` on this machine or in CI. A BPF build and
   a localnet pass are documented as a manual follow-up, never a required check.
3. **Per-finding Merkle leaves with volatile fields excluded**, rather than a
   whole-report hash. Per-finding leaves also give per-finding inclusion proofs,
   which a single document hash cannot.

## What was actually built

**Off-chain (`services/evidence/`, Python, 434 tests).** `canonical.py` (leaf
projection, lexical path normalisation, length-prefix framing),
`merkle.py` (RFC 6962 + commitment), `report.py` (strict loader),
`bundle.py` (assembly + sibling write), `verify.py` (two stages, 15 outcome
codes), `anchor_payload.py` (unsigned anchoring request).

**On-chain (`services/evidence/onchain/`, 40 Rust tests).** Two independent cargo
workspaces: `spec/` with **zero `[dependencies]`** holding every constant, offset
and preimage, and `anchor/` holding the Anchor program as a thin wrapper. The
split is load-bearing — if `spec` were a member of the anchor workspace,
`cargo test` there would still have to *resolve* the `anchor-lang` →
`solana-program` graph, which needs the registry index and is exposed to
toolchain drift under a floating `stable`.

**Cross-language contract.** `vectors/merkle_vectors.json` and
`vectors/pda_vectors.json` are asserted by the Python suite, by
`onchain/spec/tests/golden_vectors.rs`, and by
`scripts/evidence-pda-vectors.test.ts`. Nothing may be added to the `core/` cargo
workspace, so a shared vector file is the only available mechanism for proving
three implementations agree.

**One new CI workflow**, `.github/workflows/evidence-ci.yml`, carrying both
halves. This deviates from the sibling convention of one job inside `ci.yml`, for
two reasons: `ci.yml` is the most-edited file in the repository (nineteen commits
in three weeks) with several backlog tasks live in the same tree, and SVC-4 has
both a Python and a Rust half that belong together.

## What was verified, concretely

- **All three suites green, run locally.** `python -m pytest -q` in
  `services/evidence` → **434 passed**. `cargo fmt --all -- --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` in
  `onchain/spec` → **40 passed**, clean fmt, clean clippy.
  `npx vitest run scripts/evidence-pda-vectors.test.ts` → **14 passed**.
- **Cross-language agreement is mechanical, not asserted.** Rust and Python
  independently reproduce every root for n = 0..8, every leaf hash, every n=5
  inclusion proof, and the CVE-2012-2459 non-collision. Before any value was
  written into the vector file, two independent implementations of the RFC 6962
  recurrence — a recursive transcription of §2.1 and an iterative stack-based
  builder — were required to agree for n = 0..33.
- **PDA derivation checked against an implementation nobody here wrote.**
  `anchor_payload.py` derives PDAs with pure-stdlib sha256 plus a hand-rolled
  ed25519 on-curve test written from RFC 8032. All five vectors match
  `PublicKey.findProgramAddressSync` from `@solana/web3.js` 1.98.4. One case
  resolves to bump 253, so the on-curve rejection demonstrably fires — without
  such a case the whole set would pass even if `is_on_curve` always returned
  `False`. The basepoint and identity element are also checked against their
  published constants.
- **The empty root is the published SHA-256 of the empty string**
  (`e3b0c442…7852b855`), which is an oracle independent of this implementation.
- **Mutation checks, measured rather than asserted** (2026-08-19): node prefix
  `0x01`→`0x00` fails 17 tests; duplicate-last odd-node rule fails 134;
  `parse_float=str`→`float` fails 95; dropping `kind` from `LEAF_FIELDS` fails
  108; dropping the `title` suffix rewrite fails 29. All restore to green.
- **The lockfile-subset invariant holds and is enforced.** All 22 resolved
  dependencies of `spec` already appear in `core/Cargo.lock`, so core's
  already-passing `cargo deny` and `cargo audit` cover them.
  `tests/lockfile_subset.rs` fails if that stops being true.
- **The report is provably untouched.** `test_bundle.py` reads the report bytes
  before and after bundling and asserts equality; `bundle.py` re-reads and raises
  if they differ.
- **Both GOLDEN RULE 1 gates still pass.** `node scripts/check-import-boundary.mjs`
  → 548 files scanned, clean.
- **A 159-report local sweep** (`eval/data/reports-astscan/`) bundles and verifies
  every report. This does **not** run in CI; see the honest-disclosure section.

## Bugs and gaps this work found in existing code

Neither was the task. Both were fixed on a separate branch,
`fix/confirm-timestamp-and-suppressor-comment`, then merged into this one —
this branch was never supposed to touch `core/`, so mixing the fixes directly
into the SVC-4 commits would have muddied that story for review. The merge
commit is `ce1a8ab`.

1. **`ares-core/src/lib.rs:234` documented `suppressed_by` as `"local_judge" or
   "llm_judge"`. There are four write sites.** `triager` (`scan.rs:439`) and
   `semantic_validator` (`validator.rs:72`, `:92`) were missing from that
   comment. Found because the closed schema rejected four real reports in the
   local corpus. A permissive loader would have hashed an unvalidated string
   into leaves instead. Both design agents that read the code before
   implementation reported the two-value set, because they trusted the comment.
   **Fixed in `4c6c80c`** (comment only, no behavioral change).
   `report.py`'s `_SUPPRESSORS` still enumerates all four explicitly rather than
   trusting the comment or this history.
2. **`confirm` never recorded when it ran.** The only `Utc::now()` in
   `confirm.rs` was at `:446`, inside `#[cfg(test)] mod tests`. Production
   `confirm` deserialised, mutated per-finding fields plus five summary
   counters, and re-serialised — `metadata` was untouched. So a
   `.confirmed.json` carried the *scan's* `generated_at`, and nothing anywhere
   recorded the confirmation pass's own time.
   **Fixed in `a34c1e8`**: `ReportMetadata.confirmed_at: Option<DateTime<Utc>>`,
   `#[serde(default)]` so an older report still deserialises. `confirm.rs` sets
   it to `Some(Utc::now())` right after recomputing severity counts.
   `report.py`'s schema and `bundle.py`'s `volatile` block were updated to match
   (see "What changed after the merge" below) — otherwise every future
   `.confirmed.json` would fail this service's closed-schema validation with an
   unknown-key error the moment someone ran the fixed `ares confirm`.
3. **`confirm` leaves the summary partially stale by construction.**
   `confirm.rs:319-339` recomputes five of `ReportSummary`'s twelve fields. The
   bundle publishes both the report's copy and a recount from the leaves, plus
   `summary_agrees`, so a reader can see the divergence rather than trusting it.
4. **`Finding.title` embeds a machine path.** `scan.rs:237` formats AST titles as
   `format!("{}: {}", category, file.display())`, affecting 352 of 1296 findings
   in the local corpus. Normalising only the `PathBuf`-typed fields is not enough.
5. **`target.program_id` and `repository_url` are hardcoded `None`**
   (`scan.rs:102`, `:104`). See the limitation below.

## What changed after the merge

Two more things surfaced while wiring `confirmed_at` through, one expected and
one not.

**Expected**: `report.py`'s `_METADATA_KEYS` gained `confirmed_at`, split into a
`_METADATA_REQUIRED` subset the same way `_FINDING_REQUIRED` already excludes
`validation` — the closed schema would otherwise reject every future
`.confirmed.json` outright. `bundle.py`'s `volatile` block now surfaces it,
`null` when absent or not yet confirmed. It is **not** hashed into any leaf or
the commitment, by the same logic as `generated_at`: confirming a report is not
supposed to require re-anchoring, so a fresh `confirmed_at` value must not move
the root. `test_confirmed_at_leaves_the_root_unchanged_but_moves_the_commitment`
pins both halves — the root is unaffected, but `report_sha256` (and therefore
the commitment, which is built from it) genuinely differs, exactly as it does
for any other byte-level edit to the report.

Two of my own draft tests got this backwards and had to be corrected: one wrote
a bare JSON integer to probe `_check_opt_str`'s type rejection, not noticing
`parse_int=str` turns any integer literal into a string token first — a boolean
was needed to actually reach a non-string Python value. The other asserted the
**commitment** stays equal across a `confirmed_at` change; it does not, and
can't — the commitment is deterministically derived from `report_sha256`, so if
the bytes differ, the commitment differs too, unconditionally. Both were wrong
premises in the test, not the implementation, caught by simply running them.

**Not expected: this branch's own vector fixtures were corrupted on disk.**
While merging and testing, `test_vectors.py`'s manifest-integrity suite started
failing on all seven committed vector files — first with 9 failures, not
because anything was wrong with the *code*, but because this repository has
`core.autocrlf=true` and **no `.gitattributes` anywhere**, so an ordinary
Windows `git checkout` silently rewrites every `\n` in a tracked text file to
`\r\n` in the working tree. `git status`/`git diff` reported nothing, because
git's own comparison machinery normalises line endings before comparing —
the corruption was real on disk but invisible to git itself.

Fixed in three parts:
1. Restored the correct bytes via `git cat-file -p HEAD:<path>` (which bypasses
   the checkout smudge filter) for all seven files under `vectors/`.
2. Found a second, independent bug this uncovered: `merkle_vectors.json` and
   `pda_vectors.json` were originally generated via shell stdout redirection
   rather than `Path.write_bytes()`, which introduced CRLF into them **before**
   they were ever committed. Git's own commit-time clean filter silently
   normalised that back to LF on the way in, so the committed blobs were always
   correct — but the byte counts and SHA-256 digests I recorded in
   `manifest.json` had been measured on the pre-commit, CRLF-tainted files, and
   were wrong by exactly the CRLF count (134 and 47 bytes). Corrected against
   the actual committed blobs.
3. Added `services/evidence/.gitattributes` marking `vectors/*.json -text`, so
   git never touches these bytes in either direction, on any platform, again.
   Verified end-to-end: deliberately re-corrupted a vector file with CRLF,
   confirmed `git diff` now reports a real 134-line change (before the
   `.gitattributes` fix it reported nothing), then confirmed `git checkout --`
   restores the exact original bytes.

**This is not unique to this task.** `services/cve/snapshot/advisories.json` —
the file `services/cve/advisories.py:98-110` recomputes a SHA-256 digest
against — was found to have the identical corruption on this same machine at
the same time, and running `services/cve/test_snapshot_integrity.py` directly
confirmed 9 real failures from it. That is a pre-existing, repo-wide exposure
this task did not fix, since `services/cve/` is outside `services/evidence/`
and outside this task's scope. Flagged to the user rather than fixed silently.

## The most significant limitation, stated plainly

**The artifact contains no on-chain identity for the audited program.** All 636
local reports have `program_id: null` and `repository_url: null`. The only source
binding is `target.commit_hash`, a git SHA of a local checkout that nothing
on-chain can check, with no verified-build link to any deployed bytecode.

For a task whose point is on-chain anchoring, that is the largest gap. Any Solana
program id in a bundle is therefore an **operator assertion**, which is why it
lives under `operator_assertions` and never under `target`, and why the payload
labels it as not engine-derived. Closing it properly needs `scan` to record a
program id and a reproducible-build link, which is a different task.

## A claim I had to walk back

The plan asserted that re-deriving proof positions from `(index, leaf_count)`
means "a proof valid for an n-leaf tree must not verify against the same root at
a different n". **That is false**, and a test caught it before it reached a
README.

Re-deriving positions rejects a wrong count only where the audit path *shape*
differs. For index 4 the path is `["left"]` at n=5 and `["right","left"]` at n=6,
so a substituted count is caught. For index 0 it is `["right"]×3` at both, so it
is not — the root recomputes from whatever siblings were supplied. What actually
closes it is the commitment binding `leaf_count` *together with* the root.

Both halves are now pinned, including the negative one
(`test_a_wrong_leaf_count_is_NOT_caught_where_the_path_shape_coincides`), and the
docstrings say what is true rather than what would have been tidier.

## What could not be verified, and why

- **The Anchor program has never been compiled.** No `solana` CLI, no `anchor`
  CLI, no `cargo build-sbf`. `anchor/` has no committed `Cargo.lock` because
  generating one needs network access to resolve a tree nothing here can build.
- **Every reject path is asserted at the declaration level only.** The `syn`
  conformance test proves `init` is present, the authority is a `Signer`, `bump`
  takes no argument, `init_if_needed` appears nowhere, no `update`/`close` exists,
  and each `require!` is there. It cannot prove the runtime *enforces* any of
  them — a `syn` parse sees tokens, not macro expansion or behaviour. "The
  constraint is declared" is honest; "the program rejects overwrites" is not
  provable until `anchor test` runs.
- **The account discriminator preimage is an assumption.**
  `sha256("account:RecordV1")[..8]` is Anchor-version dependent, so `anchor-lang`
  is pinned to `=0.31.1` and the assumption is recorded in
  `spec/src/discriminator.rs`. No parse can verify a macro expansion.
- **`anchor/`'s dependency tree is outside every gate**, and should be expected to
  fail `core/deny.toml` as written: the Solana tree historically pulls `ring` (not
  SPDX-clean at `confidence-threshold = 0.9`) and can pull git dependencies, which
  `unknown-git = "deny"` rejects. That belongs to the BPF task with its own
  `deny.toml`. **`core/deny.toml` was deliberately not widened.**
- **No end-to-end path was exercised.** Nothing here has put a byte on any
  cluster. There is also no `solana` CLI subcommand that submits an arbitrary
  instruction, so submission needs a multisig UI or an operator-run web3.js
  snippet.
- **CI cannot exercise the real corpus.** `eval/data/` is entirely gitignored —
  `git ls-files eval/data/` returns 0 — so the 159-report sweep runs only locally.
  Its `skipif` reason says so explicitly, because a silently-skipped sweep is how
  a green CI gets mistaken for coverage it does not have. CI coverage is the two
  vendored artifacts.
- **Local Python is 3.14.6; CI pins 3.12.** Per
  `docs/SVC-RISK-1-ASSUMPTIONS.md:98-108` a local green and a CI green are not
  interchangeable here. `test_determinism.py` pins the leaf preimage as a hex
  literal — interpreter-independent by construction, and the only thing making the
  two comparable. The CI run itself has not been observed.
- **`cargo-deny` was not run locally** (not installed). The config is committed
  and the workflow invokes it; the lockfile-subset invariant is the guarantee that
  does not depend on it.

## Out of scope (deliberately, not by oversight)

- **No `apps/auditor-api` endpoint.** The bundler works on filesystem artifacts,
  not request bodies, and it is not clear what a caller would POST. Follows the
  `services/family` precedent of landing a service without wiring it, and keeps a
  9-commit file untouched. The `sys.path.insert` recipe for whoever wires it later
  is at `apps/auditor-api/main.py:131-149`.
- **No wiring into the TS audit graph** (`src/graph/nodes/`) and no registration in
  `build-graph.ts`.
- **No `poc_root`.** `validation` is in the leaf, so the *claim* "confirmed" is
  attested, but nothing binds it to a real fork execution — a hand-edited
  `.confirmed.json` with `validation: "confirmed"` produces a valid bundle. A
  second root over `(id, wiring_marker, sha256(poc_bytes_minus_the_Generated_line))`
  would close it, but PoC contents carry a `Utc::now()` header and may not be on
  disk at bundling time, which is a separate durability problem. Follow-up card.
- **No signing, no submission, no key handling.** The payload builder refuses
  anything that could be a private key — a filesystem path, a 64-byte base58
  value, a JSON byte array, a seed phrase — and has no code path that opens a
  file.
- **`services/evidence/requirements.txt` was not added to the `pip-audit` list**
  at `ci.yml:105-111`, to keep this task's edits out of that file. Defensible —
  stdlib-only runtime, sole dependency `pytest==9.1.1` already audited via three
  other requirement files, and `services/family/requirements.txt` is already
  absent — but a real gap, recorded rather than left implicit.
- **The `core/LICENSE` vs root `LICENSE` discrepancy** in GOLDEN RULE 1 was not
  touched. It is an ownership decision.
- **Any change to measured detection accuracy.** Nothing here is part of the
  `eval/` ground truth, and no figure in
  `docs/EVAL-2-REPRODUCTION-REPORT.md` moves.

## Verified before handing off

- `python -m pytest -q` in `services/evidence` → **442 passed** (434 from the
  original two commits, +8 for `confirmed_at` after the merge).
- `cargo fmt --all -- --check` in `onchain/spec` → clean.
- `cargo clippy --all-targets --locked -- -D warnings` in `onchain/spec` → clean.
- `cargo test --locked` in `onchain/spec` → **40 passed**.
- `npx vitest run scripts/evidence-pda-vectors.test.ts` → **14 passed**.
- `node scripts/check-import-boundary.mjs` → passed, 561 files scanned (up from
  548 after the `.gitattributes` addition).
- **`core/` is no longer untouched** — corrected from an earlier draft of this
  doc. `fix/confirm-timestamp-and-suppressor-comment` (commits `4c6c80c`,
  `a34c1e8`) was merged in at `ce1a8ab` specifically so this service could
  accept and surface `confirmed_at`. `cd core && cargo test --workspace` was run
  in full, non-truncated form on that fix branch before the merge: **221 tests**
  across all eight crates (ares-core 19, ares-v3 62 lib + 6 integration,
  ares-report 4, ares-mapper 116, ares-policy 3, ares-orchestrator 2,
  ares-trident 9), plus `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-features -- -D warnings` both clean. The merge
  itself introduced no conflicts (previewed with `git merge-tree` before
  merging) because the two branches touch entirely disjoint files.
- Mutation harness: all five mutations caught (17 / 134 / 95 / 108 / 29 failures),
  all restoring to green.
- Published corpus figures re-derived directly, not taken from a summary: 636
  reports, 1296 findings including suppressed, 352 path-bearing titles (all 352
  ending with the raw `location.file`), 36 reports containing content-duplicate
  findings, 178 reports producing no leaves at all (194 have `findings == []`, but
  suppressed findings are leaves too — the distinction is easy to conflate and the
  first draft of the README did).
- A CRLF corruption of every vector fixture, found after the merge and fixed;
  see "What changed after the merge" above. Verified end-to-end: deliberately
  re-corrupted a file, confirmed `git diff` now detects it (it silently did not
  before `.gitattributes`), then confirmed `git checkout --` restores it exactly.
