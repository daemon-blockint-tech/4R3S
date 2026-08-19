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

None of these were the task, and none were fixed here.

1. **`ares-core/src/lib.rs:234` documents `suppressed_by` as `"local_judge" or
   "llm_judge"`. There are four write sites.** `triager` (`scan.rs:439`) and
   `semantic_validator` (`validator.rs:72`, `:92`) are missing from that comment.
   Found because the closed schema rejected four real reports in the local
   corpus. A permissive loader would have hashed an unvalidated string into
   leaves instead. Both design agents that read the code before implementation
   reported the two-value set, because they trusted the comment.
2. **`confirm` never records when it ran.** The only `Utc::now()` in `confirm.rs`
   is at `:446`, inside `#[cfg(test)] mod tests`. Production `confirm`
   deserialises, mutates per-finding fields plus five summary counters, and
   re-serialises — `metadata` is untouched. So a `.confirmed.json` carries the
   *scan's* `generated_at`, and nothing anywhere records the confirmation pass's
   time.
3. **`confirm` leaves the summary partially stale by construction.**
   `confirm.rs:319-339` recomputes five of `ReportSummary`'s twelve fields. The
   bundle publishes both the report's copy and a recount from the leaves, plus
   `summary_agrees`, so a reader can see the divergence rather than trusting it.
4. **`Finding.title` embeds a machine path.** `scan.rs:237` formats AST titles as
   `format!("{}: {}", category, file.display())`, affecting 352 of 1296 findings
   in the local corpus. Normalising only the `PathBuf`-typed fields is not enough.
5. **`target.program_id` and `repository_url` are hardcoded `None`**
   (`scan.rs:102`, `:104`). See the limitation below.

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

- `python -m pytest -q` in `services/evidence` → **434 passed**.
- `cargo fmt --all -- --check` in `onchain/spec` → clean.
- `cargo clippy --all-targets --locked -- -D warnings` in `onchain/spec` → clean.
- `cargo test --locked` in `onchain/spec` → **40 passed**.
- `npx vitest run scripts/evidence-pda-vectors.test.ts` → **14 passed**.
- `node scripts/check-import-boundary.mjs` → passed, 548 files scanned.
- `cd core && cargo test --workspace` → unchanged by this task; `core/` has no
  edits at all.
- Mutation harness: all five mutations caught (17 / 134 / 95 / 108 / 29 failures),
  all restoring to green.
- Published corpus figures re-derived directly, not taken from a summary: 636
  reports, 1296 findings including suppressed, 352 path-bearing titles (all 352
  ending with the raw `location.file`), 36 reports containing content-duplicate
  findings, 178 reports producing no leaves at all (194 have `findings == []`, but
  suppressed findings are leaves too — the distinction is easy to conflate and the
  first draft of the README did).
