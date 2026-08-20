# services/evidence — Merkle evidence bundling + on-chain anchoring

Builds a tamper-evident commitment over the findings in an `ares scan` report,
written as a sibling file, so any single finding can be proved to have been part
of that audit and the whole set can be re-derived from the report by a third
party. Optionally emits an unsigned request to anchor that commitment on Solana
via the `evidence_registry` program in [`onchain/`](onchain/README.md).

No endpoint in `apps/auditor-api` — see "Not wired up" below.

Deterministic and offline by construction: no LLM, no network, no randomness, no
keys and no transaction. The bundler operates on filesystem artifacts and
produces the 32 bytes an operator may choose to anchor; submitting is a
deliberate human step with its own runbook. See "Hermetic by default" in
[`SECURITY.md`](../../SECURITY.md).

## Two commitments, because one digest cannot do both jobs

| Commitment | Covers | Property |
|---|---|---|
| `merkle_root` | the per-finding claims, path-normalized, volatile header excluded | **rerun-stable** — same engine + same input → same root, on any OS, from any directory |
| `report_sha256` | the raw artifact bytes, byte for byte | **exact-artifact binding** — catches any edit at all, including ones no leaf covers |

Having both is what lets the verifier distinguish "someone edited the timestamp"
from "someone edited a severity". A root alone cannot see the first; a byte digest
alone cannot survive a legitimate re-run.

## Why the report cannot simply be hashed

Four independent sources of run-to-run variation, all verified against source:

- `metadata.generated_at` is `Utc::now()` (`scan.rs:501`), and
  `scan_duration_secs` is wall clock (`:462`, `:503`).
- `target.source_path`, `location.file` and `proof_of_concept` are absolute,
  machine-specific paths — with **mixed separators inside a single value**, e.g.
  `eval/data/staging/x/src\lib.rs`.
- **`Finding.title` also embeds a machine path.** `scan.rs:237` formats AST titles
  as `format!("{}: {}", category, file.display())`, which affects 352 of the 1296
  findings in the local corpus. Normalizing only the path-typed fields still
  yields a CWD-dependent root for 27% of findings.
- Generated PoC files embed `Utc::now().to_rfc3339()` in their header
  (`poc.rs:90-98`), so their contents differ run to run too.

So a leaf commits to a normalized projection of a finding, never to raw JSON.
Full reasoning: `docs/SVC-4-ASSUMPTIONS.md`.

## The leaf

Twenty-two fields in a fixed order, framed with `u32` length prefixes. Three
non-obvious inclusions:

- **`kind`** (`finding` | `suppressed`) is the highest-value field in the design.
  Without it, moving a real finding into `suppressed_findings` leaves the leaf
  unchanged and the root cannot see the demotion.
- **`suppression_reason` + `suppressed_by`** — otherwise "Confidence below
  threshold" could become anything else and still verify, and *which* filter
  dropped a finding is materially different evidence.
- **`id`**, despite being positional (`format!("ARES-<PHASE>-{}", findings.len() + 1)`).
  Excluding a fragile identifier is tempting, but 36 of 636 local reports contain
  findings identical in every field except `id`, and those would collapse to
  duplicate leaves — a multiset ambiguity and the precondition for the shape
  tricks RFC 6962 exists to prevent.

Excluded and why: the PoC *path* (a function of `--output`, not of the finding —
only `poc_present` survives); PoC file *contents* (a volatile header, and a leaf
that depends on whether a file is still on disk is non-determinism from the
environment); `generated_at` and `scan_duration_secs`; `ares_version` and
`commit_hash` (stable and provenance-bearing, but per-report constants — they bind
via the header and the commitment instead of being copied into N leaves);
`source_path` (the header keeps the normalized form plus a digest of the raw one);
`summary.*` (derived, and partially stale after `confirm`, which recomputes only 5
of its 12 fields).

### Numbers are never turned into floats

`json.loads(..., parse_float=str)` — the leaf carries the literal characters from
the file.

This is not over-engineering, and testing against today's data would not catch
the alternative. The only seven confidence tokens in 636 real reports are
`0.55, 0.7, 0.72, 0.75, 0.78, 0.8, 0.85`, and `repr(float(t)) == t` for **all
seven**. A `repr()`-based encoder is green today and wrong on the first value
that does not round-trip: `serde_json` formats f64 via `ryu`, CPython's `repr`
spells `1e-7` as `1e-07`, and `apply_refuted` computes `(c*0.3).min(0.2)` so small
values are reachable. `test_canonical.py::test_confidence_is_the_raw_json_token_not_a_python_float`
pins this.

## The tree: RFC 6962, not Bitcoin

SHA-256, with `DOMAIN = b"ares.evidence.v1"` (16 bytes) and distinct prefixes:
`0x00` leaf, `0x01` node, `0x02` commitment, `0x03` target binding.

**Why not duplicate-last.** Bitcoin hashes a lone right child as `H(x‖x)`, which
makes `[a,b,c]` and `[a,b,c,c]` produce the *identical* root (CVE-2012-2459) —
two different leaf multisets, one root. For an evidence anchor that means the root
attests to a finding set that was never produced. Our leaves happen to be unique,
so a duplicate check would paper over it, but patching a malleable tree with a
uniqueness invariant is the fragile design: it breaks the moment someone relaxes
the invariant. RFC 6962 splits at the largest power of two below *n* and never
duplicates, so the malleability is structurally impossible rather than
checked-against.

**Why the prefixes.** Without them, `H(L‖R)` for an internal node is drawn from
the same distribution as `H(x)` for a leaf `x = L‖R`, so an attacker could present
an internal node *as* a leaf and produce a valid-looking inclusion proof for a
**fabricated finding that was never in the report**, backed by a real anchored
root.

**Leaf ordering** is by preimage bytes, not report order — nothing in `scan.rs`
sorts `findings`, so that order is incidental, and a root sensitive to a
meaningless permutation changes for no reason. Duplicate ids and duplicate leaf
preimages are both hard `EvidenceError`s, not warnings.

### One thing the leaf_count binding does not buy

Re-deriving proof positions from `(index, leaf_count)` rejects a wrong count only
where the audit path *shape* differs. For index 4 the path is `["left"]` at n=5
and `["right","left"]` at n=6, so a substituted count is caught. For index 0 it is
`["right"]×3` at both, so it is not. That is inherent to any bare inclusion check.
What actually closes it is the commitment binding `leaf_count` *together with* the
root, so a verifier compares the pair against the anchored value.
`test_merkle.py` pins both halves, including the negative one.

## The empty tree is the modal case

**178 of 636 local reports produce no leaves at all** (194 have no
*unsuppressed* findings, but suppressed findings are leaves too), and per
`docs/ORC-2-CORE-CALL-CONTRACT.md:150-181` `ares scan /nonexistent/path` exits 0
and writes a well-formed empty report, indistinguishable in shape from a genuine
clean scan.

The root is then `sha256("")` — RFC 6962 conformant, recognisable on sight, and
carrying neither prefix. But **the bare empty root is the same 32 bytes for every
target on earth**, so anchoring it would publish "nothing found" in a form anyone
could replay against any program. That is the strongest argument for anchoring a
*commitment*: folding in `report_sha256` and the target binding keeps even the
empty case unique per (target, commit, artifact bytes). The verifier emits a
distinct `OK_EMPTY` whose advisory says, in words, that this attests zero findings
and does **not** attest that a scan meaningfully executed.

## Modules

| File | Responsibility |
|---|---|
| `canonical.py` | `EvidenceError`; lexical path normalization + scope; the `title` suffix rewrite; length-prefix framing; the leaf projection; the machine-path refusal |
| `merkle.py` | Pure bytes: domain, prefixes, RFC 6962 root, inclusion proofs, position derivation, commitment, target binding |
| `report.py` | Load + strictly validate one artifact: raw bytes, digest, the guarded `json.loads`, closed schema, four enum whitelists, `scan` vs `confirmed` detection |
| `bundle.py` | Leaves → sort → duplicate policy → tree → proofs → commitment → header; write the sibling. CLI. |
| `verify.py` | Two stages, 15 distinct outcome codes, the decision table. CLI. |
| `anchor_payload.py` | The unsigned anchoring request: base58, PDA derivation, Borsh instruction bytes. Never signs, never submits. CLI. |
| `onchain/` | The `evidence_registry` Anchor program + its zero-dependency spec crate. See [`onchain/README.md`](onchain/README.md). |
| `vectors/` | Two real report artifacts, their golden bundles, and the cross-language Merkle and PDA vectors, with a digest manifest |

## The verifier says *what* is wrong

| digest | leaves | target | Outcome | Meaning |
|---|---|---|---|---|
| ok | ok | ok | `OK` / `OK_EMPTY` | verified |
| ok | bad | — | `BUNDLER_SKEW` | bytes identical, so a leaf difference is encoder drift, not tampering |
| bad | ok | ok | `REPORT_EDITED_OUTSIDE_LEAVES` | changed where no leaf covers: `generated_at`, the summary, key order, whitespace. **The most likely real tamper.** |
| bad | bad | ok | `REPORT_TAMPERED` | same target and commit, finding content changed. Names the diverging ids. |
| bad | bad | bad | `DIFFERENT_REPORT` | built from a different artifact entirely |

Fifteen distinct exit codes, pinned by `test_verify.py`. Codes 4
(`LEAF_HASH_MISMATCH`) and 5 (`ROOT_MISMATCH`) are both needed: an attacker who
edits a leaf's published `fields` *and* its `leaf_hash` to match still fails at
the root, and one who edits `leaf_hash` alone fails at the leaf. **There is no
single-field edit that verifies.**

The bundle stores each leaf's `fields`, never its preimage. A stored preimage
could hash correctly while the readable fields said something else, and a lazy
verifier that checked only the preimage would be fooled by what a human reads.
Forcing re-encoding means **what a human reads is exactly what the digest
covers.**

## Verified against real data

- The two artifacts in `vectors/` are byte-for-byte copies of real
  `ares scan --ast-scan` output, checked for absolute paths and home directories
  before vendoring (both contain relative paths only). They are committed because
  `eval/data/` is entirely gitignored — `git ls-files eval/data/` returns 0 — so
  without them every test that exercises a genuine report would skip in CI.
  `test_vectors.py` regenerates the bundles and compares byte-for-byte, with the
  roots and commitments pinned as hex literals so a change that alters a root
  cannot pass by refreshing the fixture.
- **A fourth suppressor was found by writing this, and fixed upstream.**
  `ares-core/src/lib.rs:234` documented `suppressed_by` as `"local_judge" or
  "llm_judge"`. There are four write sites — `triager` (`scan.rs:439`) and
  `semantic_validator` (`validator.rs:72,:92`) were missing from that comment.
  The closed schema surfaced `semantic_validator` by rejecting four real reports
  in the local corpus, and a permissive loader would have hashed an unvalidated
  string into leaves instead. The comment is now corrected
  (`4c6c80c`); `report.py`'s `_SUPPRESSORS` still enumerates all four itself
  rather than trusting either the comment or this history.
- **`confirm` used to never record when it ran, and now does.** Before
  `a34c1e8`, the only `Utc::now()` in `confirm.rs` was inside `#[cfg(test)]`, so
  a `.confirmed.json` carried the *scan's* timestamp and nothing anywhere
  recorded the confirmation pass's own time. `ReportMetadata.confirmed_at` now
  carries it, `#[serde(default)]` so a report from an older `ares` build still
  parses. `volatile.confirmed_at` in the bundle surfaces it: a timestamp when
  known, `null` when this report has never been confirmed by a build that sets
  it (which includes both "never confirmed" and "confirmed by an older build" —
  the bundle does not try to tell those two apart).
- Cross-language agreement is mechanical, not asserted: `vectors/merkle_vectors.json`
  is checked by the Python suite, by the Rust spec crate
  (`onchain/spec/tests/golden_vectors.rs`), and by
  `scripts/evidence-pda-vectors.test.ts`, which also re-implements RFC 6962 a
  third time in TypeScript. The PDA vectors are checked against
  `@solana/web3.js`'s `findProgramAddressSync` — an implementation nobody here
  wrote — which is what makes the hand-rolled ed25519 on-curve arithmetic in
  `anchor_payload.py` acceptable.

## Tests

```bash
python -m pytest -q        # from services/evidence
```

434 tests. Mutation checks, measured 2026-08-19 by applying one deliberate defect
at a time against the committed suite:

| Mutation | Tests failed |
|---|---|
| `NODE_PREFIX` `0x01` → `0x00` (destroys leaf/node domain separation) | 17 |
| odd-node rule → duplicate-last (Bitcoin, CVE-2012-2459) | 134 |
| `parse_float=str` → `parse_float=float` (respells exponents) | 95 |
| drop `kind` from `LEAF_FIELDS` (a demotion becomes invisible) | 108 |
| drop the `title` suffix rewrite (machine path stays in the digest) | 29 |

All five restore to green. These counts are reproducible: apply the single edit
named in the left column and run `python -m pytest -q`. Worth recording *why*
they are here — an earlier attempt at this table reported zero failures for the
first row, which looked like a suite hole but was actually a broken mutation
harness that never applied the edit. A mutation check is only evidence if you
confirm the mutation landed.

`test_determinism.py` spawns real subprocesses. An in-process test cannot catch
the failure mode it targets: `str` comparison is not seeded, but **set and dict
iteration order is**, so leaf ordering that came from a `set` instead of
`sorted()` would be invisible in-process and shift the root between runs. That is
the same bug commit `dc5c97f` had to fix in `services/family`, where the same
program pair scored 0.32–0.53 across five runs.

CI pins Python **3.12**; local development here ran **3.14.6**. Per
`docs/SVC-RISK-1-ASSUMPTIONS.md:98-108` a local green and a CI green are not
interchangeable on this repo, so `test_determinism.py` pins the leaf preimage as
a hex literal — interpreter-independent by construction, and the only thing making
the two environments comparable.

## What this does not do

- **It does not prove a scan happened.** `ares scan /nonexistent/path` exits 0
  with a well-formed empty report. **An anchored empty root is not evidence of an
  audit.**
- **It does not prove the findings are true.** The root attests to the *text* of
  claims. Only `eval/` speaks to correctness, and accuracy is currently UNSCORED.
- **It does not prove the audited code is the deployed code.**
  `scan.rs:102,104` hardcode `program_id: None` and `repository_url: None`, so the
  only source binding is a local git SHA with no verified-build link to any
  deployed bytecode. Any Solana program id here is an **operator assertion**,
  which is why it lives under `operator_assertions` and never under `target`.
  This is the largest gap in SVC-4.
- **It does not prove *when*.** `generated_at` is self-reported and forgeable
  before bundling. An anchoring slot gives "not later than", never "not earlier
  than".
- **It does not prove the PoC ran.** `validation` is in the leaf, so the *claim*
  "confirmed" is attested; nothing binds it to a real fork execution. A
  hand-edited `.confirmed.json` with `validation: "confirmed"` produces a
  perfectly valid bundle. A `poc_root` over
  `(id, wiring_marker, sha256(poc_bytes_minus_the_Generated_line))` would close
  this — deferred, since it needs the PoC files to still be on disk and that is a
  separate durability problem.
- **The root is not a stable identity for a vulnerability.** `finding.id` is
  positional, so enabling `--ast-scan` or adding one detector renumbers every
  downstream finding and changes the root even when the audited code is
  byte-identical. The root identifies *this report*, not *this bug*.
- **Determinism means "same engine + same input → same root", never "same input →
  same root forever."** A customer cannot re-derive a two-year-old root from
  today's binary.
- **No signature.** A bundle is unsigned; anyone can build one for any target
  name. Authorship comes only from whoever paid for the anchoring transaction.
- **CI cannot exercise the real corpus.** `eval/data/` is gitignored, so CI
  coverage is the two committed vectors. The 159-report local sweep in
  `test_vectors.py` skips there, and its skip reason says so.
- **No effect on measured detection accuracy** (`docs/EVAL-2-REPRODUCTION-REPORT.md`).
  Nothing here is part of the `eval/` ground truth.

## Not wired up

- **No `apps/auditor-api` endpoint.** The bundler operates on filesystem
  artifacts, not request bodies, and it is not clear what a caller would POST.
  Following the `services/family` precedent of landing a service without wiring
  it. Whoever wires it later uses the documented `sys.path.insert` recipe at
  `apps/auditor-api/main.py:131-149`.
- **No wiring into the TS audit graph** (`src/graph/nodes/`), and no registration
  in `build-graph.ts`.
- **`services/evidence/requirements.txt` is not in the `pip-audit` list** at
  `ci.yml:105-111`. Defensible — stdlib-only runtime, sole dependency
  `pytest==9.1.1` which three other requirement files already audit, and
  `services/family/requirements.txt` is already absent — but a real gap, recorded
  rather than left implicit.
- **The program has never been compiled or deployed.** See
  [`onchain/README.md`](onchain/README.md).
