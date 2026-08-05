# Findings in `core/` from establishing the ORC-2 call contract

Five defects surfaced while verifying how `apps/auditor-api` should invoke
`core/`. They are recorded here rather than fixed: every one lives in
`core/crates/*` or `core/README.md`, outside ORC-2's scope, and belongs to
whoever owns ENG-1.

Each entry states how it was verified. Nothing here is inferred from
documentation alone.

---

## ORC2-F1 — `--fuzz false` does not remove the Trident dependency

**Severity:** blocks any caller without `trident-cli` installed
**Files:** `core/crates/ares-cli/src/commands/scan.rs`, `core/crates/ares-trident/src/lib.rs`

`TridentTool::new()` is called at `scan.rs:86`. The `if fuzz` gate that decides
whether Trident is actually used is at `scan.rs:129`. So construction — which
resolves `trident` on `PATH` via `which::which("trident")` and errors if absent
— happens unconditionally, before the flag is consulted.

The resulting `trident` binding is not read anywhere between those two points:
the lines in between run hypothesis generation and cross-instruction analysis,
neither of which touches it.

**Verified:** `ares scan <path> --full-pipeline false --fuzz false --poc false`
aborted with `External tool missing: trident-cli not found. Install: cargo
install trident-cli`, before any analysis ran. After `cargo install trident-cli`
the same command succeeded, and the log shows the ordering plainly:
`Trident tool initialized` appears *before* `Fuzzing disabled. Skipping Trident
fuzz campaign.`

**Why it matters:** `--fuzz false` reads as "don't do the fuzzing part", and it
does skip the fuzzing *work* — but not the fuzzing *prerequisite*. A CI runner
or container that only wants static analysis still has to install and build a
fuzzer. The flag promises something it doesn't deliver.

**Note on workarounds:** setting `trident_path` in `ares.toml` bypasses the
`PATH` lookup entirely, and `TridentTool::new()` only checks `exists()` — it
does not verify the target is executable or actually Trident. Pointing it at any
existing file would therefore pass. That is recorded as an observation about the
current check, not as a recommendation.

---

## ORC2-F2 — `--full-pipeline` has no effect

**Severity:** misleading control surface
**File:** `core/crates/ares-cli/src/commands/scan.rs`

The flag is declared, logged (`Full Pipeline: false`), and never used as a
condition. Searching the file for `if full_pipeline`, `full_pipeline &&`, and
`!full_pipeline` returns nothing.

**Verified:** grep across `scan.rs` finds `full_pipeline` only in the parameter
list and in the log line. `true` and `false` produce identical execution.

**Why it matters:** the help text describes it as enabling the *"full
multi-agent pipeline (Mapper → Hypothesis → Fuzzer → Exploit → Triager →
Reporter)"*, which reads like the main switch between a light and a deep scan.
A caller sizing a time budget around it would be sizing it around nothing.

Related: LLM-as-Judge is also not gated by this flag. It runs whenever
`config.llm_provider` is not `Disabled`, independently of `--full-pipeline`.

---

## ORC2-F3 — arbitrary-CPI detection defeated by substring matching

**Severity:** false negative on a deliberately-planted vulnerability
**File:** `core/crates/ares-mapper/src/lib.rs`

`has_cpi_program_id_check` is computed as:

```rust
let has_cpi_check = body.as_ref().is_some_and(|b| {
    b.contains("program_id") || b.contains("key() !=") || b.contains("expected_program")
});
```

The hypothesis for arbitrary CPI then requires
`instruction.uses_cpi && !instruction.has_cpi_program_id_check`.

In `dataset/solana-common-attack-vectors/arbitrary-cpi-stub/src/lib.rs`, the
vulnerable construction is:

```rust
let ix = Instruction {
    program_id: *target_program.key,   // ← a struct field name
    ...
};
invoke(&ix, &[source.clone(), destination.clone()])?;
```

`uses_cpi` is correctly `true` (the body contains `invoke(`). But
`has_cpi_check` is *also* `true` — because the literal string `program_id`
appears, as the **name of the field being populated**, not as a validation.
`true && !true` is false, so the hypothesis is never raised.

The check that is supposed to detect the absence of validation is satisfied by
the very line that performs the unvalidated call.

**Verified:** scanning that stub reports `1 modules, 1 instructions, 1 CPI
calls` followed by `Generated 0 vulnerability hypotheses` and
`findings: []`, while
`dataset/solana-common-attack-vectors/ground_truth.json` declares:

```json
{
  "name": "arbitrary-cpi-stub",
  "expected_categories": ["arbitrary-cpi"],
  "expected_critical_high": 1,
  "notes": "Deterministic stub: invoke() without program_id validation"
}
```

**Why it matters:** this is the simplest possible positive case — a stub written
to be caught, with a comment in the source saying
`// VULNERABILITY: arbitrary-cpi`. Substring matching cannot distinguish a
security check from an identifier that happens to share its name, so this
pattern is unlikely to be limited to this one stub.

---

## ORC2-F4 — benchmark mixes micro- and macro-averaging under one label

**Severity:** published figures are not reconstructible
**File:** `core/crates/ares-cli/src/commands/benchmark/report.rs`

Recall accumulates across protocols and divides once —
`ares_total_tp / ares_total_expected`, a true micro-average.

Precision averages the per-protocol precisions —
`reals.iter().map(|r| r.precision).sum() / reals.len()`, a macro-average.

`core/README.md` presents both in one table labelled **Micro** Precision /
Micro Recall / Micro F1.

**Verified:** by reading the two computations in `report.rs`. Separately,
attempting to reconstruct the published Overall figures (P=0.96, R=0.92,
F1=0.94) from the published Segment B counts (TP=34, FP=7, FN=1) does not
close: micro precision of 0.96 with 7 false positives implies ~168 true
positives, and micro recall of 0.92 at that TP implies ~15 false negatives —
but Segment B accounts for only 1, leaving ~14 for Segment A, which is
described as achieving *"100% detection"*.

Segment A's raw TP/FP/FN are not published, so the Overall row cannot be
independently derived from anything in the repository.

**Also unlocated:** the Overall table itself was not found in
`generate_report`. `0.94` does not appear hardcoded anywhere under
`core/crates/*/src/`, so the figure is computed somewhere — but not, apparently,
by the function that produces the report the README shows.

**Why it matters:** GOLDEN RULE #3 requires that any published metric be
re-derivable from committed data. Mixing averaging methods under a single label
makes the number unreconstructible even in principle, independently of whether
the underlying measurements are sound. This is the substance of EVAL-2.

---

## ORC2-F5 — `core/README.md` documents a CLI that does not exist

**Severity:** low, but it misleads anyone building against it
**File:** `core/README.md`

| Documented | Actual (`ares scan --help`) |
|---|---|
| `ares scan --target ./path/to/program` | `<PATH>` is positional. `--target` exists but means *"scan only specific file or module"* |
| `ares scan --format json` | No `--format` on `scan`; it exists on `report` and `pdf` |

**Verified:** by comparing `core/README.md`'s Quick Start against `--help` output
from the built binary and the `clap` definitions in
`core/crates/ares-cli/src/main.rs`.

**Why it matters:** the ORC-2 contract was initially drafted from this section
and would have specified the wrong invocation. Anyone else integrating against
`core/` from the README will hit the same thing.

---

## ORC2-F6 — a non-existent path produces a fully-formed "successful" report

**Severity:** highest in this document — indistinguishable from a real clean scan
**File:** `core/crates/ares-cli/src/commands/scan.rs` and/or `core/crates/ares-mapper/src/lib.rs`

Scanning a path that does not exist on disk at all does not error. It exits 0
and writes a complete report:

```bash
$ ares scan /path/tidak/ada --fuzz false --poc false --output /tmp/ec2
$ echo $?
0
```

```json
{
  "target": { "name": "ada", "source_path": "/path/tidak/ada", ... },
  "findings": [],
  "summary": { "total_findings": 0, ... }
}
```

`target.name` is derived from the last path segment (`"ada"` from
`/path/tidak/ada`), which makes the report read as a real, clean result for a
target called "ada" — not as "the input path was invalid."

**Verified:** ran `ares scan` against a path confirmed not to exist, twice
independently (once during initial exploration, once to confirm), both times
exit 0 with a written report matching the shape of a genuine scan.

**Why it matters:** this compounds ORC2-F3 (a real vulnerability that reports
zero findings) with no way to tell them apart at the boundary a caller can
observe. Exit code, report existence, and report shape are all identical
between "scanned cleanly" and "the path was wrong." A caller cannot use any
combination of exit code + file presence to detect a bad invocation — the
*only* signal available is checking whether `metadata` / the implied module
count reflects a target that was actually read, which is not itself present in
the summary and would have to be inferred from `scan_duration_secs` and the
`tracing` log lines this contract already says are not part of the contract.

This is not a smaller version of ORC2-F3's mapper issue — it means the report
file's mere existence and well-formedness carries no information about whether
anything was scanned at all.

---



`datasets/README.md` describes a different dataset family (`sealevel-attacks`,
Neodyme workshop, incident reproductions — EVAL-3's scope) than the ARES-v3
benchmark dataset that carries the 0.94 claim
(`core/dataset/solana-common-attack-vectors/`). EVAL-2's Resources field points
at the former. This is left as-is: EVAL-2 is still in progress and its owner is
working against `datasets/README.md` as it stands.
