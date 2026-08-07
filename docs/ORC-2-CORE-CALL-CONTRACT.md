# ORC-2 — Core call contract: `apps/auditor-api` → `core/`

How the Python agent plane invokes the Rust engine, and what it can rely on
coming back. Every claim below was checked against the binary or the source, not
against `core/README.md` — that file documents a CLI that no longer matches the
code (see "Documentation drift" at the end).

## Decision: subprocess CLI, not REST or gRPC

The brief lists CLI, REST and gRPC as candidates. CLI wins for now.

**CLI.** `core/` already ships a working binary with a stable argument surface
and writes a machine-readable report. `apps/auditor-api` already runs an
external process per job (ORC-1's Arq worker does exactly this), so nothing new
has to be built on either side. `apps/auditor-api/README.md` also already
describes this shape: *"it calls the Rust `core/` via CLI/contract."*

**REST** would mean writing and operating an HTTP server inside `core/`. That
adds a long-running process to a component whose GOLDEN RULE #2 requires
determinism and no network in the detection path — an HTTP listener is the
opposite direction of travel. Rejected until there is a concrete need CLI
cannot meet.

**gRPC** would mean a protobuf schema plus generated stubs in two languages,
maintained in lockstep. The payload here is one JSON document per scan, read
once when the job finishes; that does not justify the schema-management cost.
Rejected as premature.

**What would change this decision:** a need to stream progress mid-scan (a scan
can run for up to an hour by default), or a need to run `core/` on a different
host from the API. Either would make CLI awkward and REST/gRPC worth revisiting.

## Invocation

```
ares scan <PATH> [OPTIONS]
```

`<PATH>` is **positional** — the Anchor project directory. Verified against
`ares scan --help` from the built binary.

| Option | Default | Notes |
|---|---|---|
| `-t, --target <TARGET>` | — | Narrows the scan to one file or module. **Not** the program path. |
| `--full-pipeline <bool>` | `true` | **Currently has no effect** — see finding ORC2-F4. |
| `--fuzz <bool>` | `true` | Gates the Trident fuzz campaign. Does **not** remove the Trident dependency — see ORC2-F2. |
| `--poc <bool>` | `true` | Generates proof-of-concept tests per finding. |
| `--max-duration <secs>` | `3600` | One hour by default. |
| `-o, --output <OUTPUT>` | `./ares-output` | Directory for the report. |

Global options that apply: `-c, --config <FILE>` (default `ares.toml`),
`-v, --verbose`, `--strict-policy <bool>` (default `true`).

**The caller must pass explicit values.** Relying on defaults means a one-hour
budget with fuzzing and PoC generation enabled — orders of magnitude heavier
than the ~90s the TypeScript CLI takes. `apps/auditor-api` should send:

```
ares scan <path> --fuzz false --poc false --max-duration <budget> --output <dir>
```

for an analysis-only pass, and only enable `--fuzz`/`--poc` for an explicitly
requested deep scan.

## Output

A JSON document at `<output>/ares-report-<target-name>.json`. `<target-name>`
is the directory name of `<PATH>`, so the caller should pass a per-job `--output`
directory rather than trying to predict the filename across concurrent jobs.

Nothing structured goes to stdout — stdout and stderr carry human-readable
`tracing` lines only. **The report file is the contract; the log stream is not.**

```json
{
  "target": {
    "name": "arbitrary-cpi-stub",
    "repository_url": null,
    "commit_hash": "b828426af3100a1262a618aeb31431ed22a3138e",
    "program_id": null,
    "source_path": "dataset/solana-common-attack-vectors/arbitrary-cpi-stub",
    "idl_path": null
  },
  "findings": [],
  "suppressed_findings": [],
  "metadata": {
    "generated_at": "2026-08-05T06:16:59.130710Z",
    "ares_version": "0.1.0",
    "scan_duration_secs": 0,
    "agent_pipeline": ["Mapper", "HypothesisGenerator", "FuzzerOrchestrator", "Triager"],
    "tools_used": ["trident-Trident 0.12.0", "cargo-audit", "rust-analyzer"]
  },
  "summary": {
    "total_findings": 0,
    "critical_count": 0, "high_count": 0, "medium_count": 0,
    "low_count": 0, "informational_count": 0,
    "false_positives_suppressed": 0,
    "poc_generated": 0, "tests_passed": 0, "tests_failed": 0,
    "total_economic_impact_lamports": 0,
    "max_single_exploit_lamports": 0
  }
}
```

That example is a real report, captured from a scan of
`dataset/solana-common-attack-vectors/arbitrary-cpi-stub`.

### Finding shape

From `Finding` in `core/crates/ares-core/src/lib.rs`:

| Field | Type | Notes |
|---|---|---|
| `id` | string | |
| `title` | string | |
| `description` | string | |
| `severity` | enum | `Critical` \| `High` \| `Medium` \| `Low` \| `Informational` — **PascalCase**, no `serde(rename_all)` on this enum |
| `category` | enum | 20 variants; serialised lower-case (`arbitrary-cpi`, `generic`, …) |
| `location` | object | `{ file, line_start?, line_end?, column_start?, column_end? }` |
| `proof_of_concept` | path or null | |
| `recommendation` | string | |
| `references` | string[] | |
| `confidence` | float | 0.0–1.0 |
| `validation` | enum or null | `confirmed` \| `refuted` \| `inconclusive`; `null` until `ares confirm` runs. Carries `#[serde(default)]`, so it may be absent entirely in older reports — the parser must treat missing and `null` the same. |

`suppressed_findings[]` wraps a `Finding` with `reason` and `suppressed_by`
(`"local_judge"` or `"llm_judge"`).

**Severity and category casing differ between the two enums.** A parser that
assumes one convention for both will silently fail to match one of them. Both
are closed sets; an unrecognised value should be surfaced, not coerced to a
default.

## Prerequisites the caller must satisfy

Verified by running the binary, not from documentation:

- **`trident-cli` must be on `PATH`** (or `trident_path` set in `ares.toml`)
  **even when `--fuzz false`**. Without it, every scan aborts with
  `External tool missing: trident-cli not found`. See ORC2-F2.
- **`<PATH>` must be an Anchor-shaped project** — a directory containing
  `programs/` or `src/`, with a `Cargo.toml`. A flat directory of `.rs` files
  is accepted and exits 0, but produces `0 modules, 0 instructions` and an
  empty `findings` array. **A successful exit with zero findings is not
  evidence of a clean target.** The caller should reject inputs that don't
  match the expected shape rather than reporting an empty report as a result.
- `ares.toml` is optional; its absence logs a warning and uses defaults.

## Failure modes the caller must handle

| Condition | Observed behaviour |
|---|---|
| Missing `trident-cli` | Aborts before analysis; no report file written |
| Path is not Anchor-shaped | Exits successfully, writes a report with 0 findings |
| **Path does not exist at all** | **Exits 0, writes a complete, well-formed report with 0 findings.** Verified directly: `ares scan /nonexistent/path ...` → exit code 0, `ares-report-<segment>.json` written with the same shape as a genuine scan. See ORC2-F6. |
| Scan exceeds `--max-duration` | Not yet verified |

**Exit code carries no information here.** It is 0 for a genuine clean scan, 0
for a wrong-shaped directory, and 0 for a path that was never on disk. **The
caller must verify the input path exists and is Anchor-shaped itself, before
invoking `ares scan`, and must not treat exit 0 plus a well-formed report as
evidence that a scan actually happened.** There is currently no field in the
report that reliably distinguishes these cases from the caller's side.

This is not a smaller concern alongside the others in this contract — it means
`apps/auditor-api` cannot safely trust a green result from `core/` without its
own pre-flight check on the input path.

## Unverified

Stated as gaps rather than guessed at:

- **Timeout behaviour.** Whether exceeding `--max-duration` writes a partial
  report, no report, or fails outright.
- **Concurrency.** Whether two `ares scan` processes can share one `--output`
  directory safely. Until confirmed, give each job its own directory.
- **Non-empty report shape.** Every report captured during this work had
  `findings: []` (see ORC2-F3 — a stub that should have produced a critical
  finding produced none). The `Finding` fields above come from the Rust struct
  definitions, not from an observed non-empty report.

**Exit codes are no longer in this list — they were tested and turned out to be
uninformative rather than unknown.** See "Failure modes" above.

## Documentation drift

`core/README.md`'s usage section does not match the binary:

| `core/README.md` | Actual |
|---|---|
| `ares scan --target ./path/to/program` | `<PATH>` is positional; `--target` narrows to a file/module |
| `ares scan --format json` | No `--format` on `scan` (it exists on `report` and `pdf`) |

The contract above is derived from `--help` output and the source. **When they
disagree, the binary is authoritative.**

## Related findings

Five defects in `core/` were found while establishing this contract. They live
in files outside this task's scope and are documented separately in
`docs/CORE-CONTRACT-FINDINGS.md` — no fixes are proposed here.
