# ARES — Engineering Review

> **Status note (added when this document was committed).** The review below was written
> against commit `51fa513` and describes the code as it was at that point. Remediation
> started immediately afterwards on the same branch, so several findings — including both
> Blockers — are already closed. The body has deliberately **not** been rewritten: a review
> edited to match the fixes stops being evidence of what was found. Read it as a snapshot,
> and use this table for current state.
>
> | Finding | State | Where |
> | --- | --- | --- |
> | B1 no source or IDL loaded | **Fixed** | `src/tools/source.ts`, `src/graph/nodes/load-source.ts`; findings must cite a file that was read, uncited ones are demoted |
> | B2 failed Semgrep reports `ok` | **Fixed** | `src/tools/semgrep.ts` takes the exit code, reads `errors[]`, pipes stderr; `scan-error`/`scan-timeout` map to `failed` |
> | Exec-summary item 2, downgrade keyed on `!sourcePath` | **Fixed** | now keys off source actually being read; the e2e test that codified the bug was corrected |
> | S9 `canAffordAudit` result discarded | **Fixed** | enforced before `graph.invoke`; the predicate also now respects an exhausted on-demand cap |
> | S13 no deadline on Supabase | **Fixed** | `timedFetch` via `SUPABASE_TIMEOUT_MS`; Postgres carries `connect_timeout` + `statement_timeout` in the DSN |
> | S18 Semgrep child has no deadline | **Fixed** | killed at `SEMGREP_TIMEOUT_MS` |
> | S12 embedding failure writes null vectors | **Partly fixed** | ingestion now exits non-zero rather than reporting success; `embedBatch` still returns `undefined` for both "not configured" and "failed" |
> | N1 `mapCategory` keyword-mapping | **Partly fixed** | rule ids in `rules/solana.yml` are exactly catalog ids, so the exact branch hits; the fuzzy fallback remains for third-party rules |
> | S19 CUA transcript interpolated unfenced | **Partly fixed** | the VERIFY finding block is fenced and sanitized via `asData`; the CUA transcript's own path into the analyzer prompt is not |
> | S5 `coerceVerdicts` coerces a null index to 0 | **Fixed** | only real numbers and non-empty numeric strings may address a finding; `null`/`false`/`""` no longer resolve to index 0, which MERGE has sorted to be the highest-severity finding |
> | S3 MERGE dedup key | **Fixed** | unlocated findings never merge; a real catalog `category` is preferred over free-text `vulnClass` as identity — `src/graph/nodes/merge.test.ts` |
> | S6 unverified writeback into the corpus | **Fixed** | REMEMBER persists only `confirmed` and non-speculative findings, and logs what it withheld — `src/graph/nodes/remember.test.ts` |
> | S12 embedding dimension mismatch scored as 0 | **Fixed** | `cosineSimilarity` throws on a mismatch; scoring falls back to tags and warns, and consolidation refuses to merge incomparable vectors |
> | S16 detection hints truncated at the first `". "` | **Fixed** | full hint reaches the prompt, so the Anchor half of two-sentence hints is no longer dropped |
> | N3 log metadata can overwrite `level` | **Fixed** | reserved fields `t`/`level`/`msg` are protected; a colliding meta key is prefixed `meta_` rather than dropped |
> | S1, S2, S4, S7, S8, S10, S11, S14, S15, S17, N2, N4 | **Open** | unchanged from the text below |
>
> Documentation claims the review flagged (README's on-chain analyzer description,
> SECURITY.md's `npm audit` contradiction, and the "hermetic by default" bullet that
> `--config auto` falsified) have also been corrected.

Scope: the working auditor at `src/` (package `ares-agent`), plus `eval/`, `db/`, and CI.
Date: 2026-07-28.

Method: six reviewers covered non-overlapping slices of the codebase, then each candidate
finding was handed to an independent verifier instructed to refute it — to re-read the
cited code, trace callers, and look for a guard or a test that already covers the case.
Findings that could not be refuted appear below; several had their severity corrected
downward by the verifier, and refuted candidates were dropped. Reviewed against commit
`51fa513` with a clean working tree.

Two caveats on the process itself, both detailed in section 5: the trust-boundary slice
was reviewed once rather than twice (its reviewer died on a transport error), and no
finding here is `UNCERTAIN` — where a claim could not be settled from the code, it is
recorded as an open question rather than asserted.

---

## 1. Executive Summary

ARES is a LangGraph-based Solana security auditor. An audit runs as a graph — INTAKE,
RECALL, four parallel analyzers (on-chain, static/Semgrep, heuristic, opt-in browser
CUA), MERGE, VERIFY, REMEMBER, REPORT — reading from and writing back to a Crystalline
in-process memory plus an optional Supabase/Neo4j knowledge base. When billing is
enabled the report is withheld until the run settles in credits.

The engineering around the audit is genuinely good. Analyzer outcomes are tracked on a
dedicated state channel so "we looked and found nothing" is distinguishable from "we
never looked"; the assurance banner is prepended in code where the model cannot drop it;
the severity table and finding IDs are computed deterministically; the README already
retracts the internally-quoted 0.94 F1 rather than defending it; billing has a revision
CAS, atomic writes, and a fail-loud MPP client. The repo is unusually honest about its
own gaps.

The problem is what sits underneath all of it. **No LLM-facing analyzer ever receives a
line of program source.** `sourcePath` reaches exactly three places: an existence check
and a CLI argument to an optional external Semgrep binary, a path string interpolated
into the intake prompt, and a boolean. No node reads a `.rs` file; the string "IDL"
appears nowhere in `src/`. The heuristic analyzer — the only analyzer that produces
findings on a source audit when Semgrep is absent — reasons from a one-paragraph intake
summary and up to eight recalled memory fragments. That is precisely what this repo's
own GOLDEN RULE 5 forbids in words.

Five things matter most:

1. **The auditor does not read the code it audits.** Source analysis is delegated
   entirely to an optional third-party binary run against a generic, unpinned rule
   registry with zero Solana or Anchor rules. Every account-validation class in the
   catalog — missing signer, missing owner, type cosplay, Anchor constraint gaps — has
   no detector at all.

   **And when that binary fails, the failure is reported as success.** `runSemgrep`
   discards the exit code, Semgrep's own `errors` array, and stderr, so a scan that
   crashed is indistinguishable from one that ran clean. The analyzer reports `ok`,
   which this codebase defines as "silence here is evidence", so no assurance banner
   fires. The `analyzer-status.ts` machinery — the best-designed safety property in the
   repo — is defeated by the one analyzer that can lie to it, and the most likely
   trigger is the remote ruleset fetch above failing. The two Blockers compound.
2. **Supplying `--source` makes the report *more* confident, not less.** The speculative
   downgrade is keyed on `!state.sourcePath` — the presence of a path *string*, not on
   whether any source was read. `--source /does-not-exist` skips the downgrade and lets
   a model-invented `severity: "high"` through untouched, while omitting the flag pins
   the same fabricated findings to info/low/speculative. The repo's own passing e2e test
   codifies this.
3. **VERIFY cannot verify.** The critic's entire input is the finding's own
   LLM-authored `evidence` sentence. It nonetheless stamps `status: "confirmed"`, which
   the report prints verbatim. A fabricated finding can be delivered under the strongest
   label the system produces.
4. **The coverage number is unfalsifiable.** "Checked N of 28 vulnerability classes" is
   the union of whatever the models listed in their `checked` arrays, validated only for
   catalog membership. A black-box run with nothing but an intake paragraph can
   truthfully-in-code print 28 of 28.
5. **Billing is on the delivery path and has real defects** — an unpayable account still
   burns a full audit's provider spend, the ledger debit and the balance are two separate
   durable writes that can permanently disagree, and a disabled billing layer can abort
   the whole audit.

**Should ARES be trusted for its stated purpose today? No.** As a source-code auditor it
is not implemented: the deliverable is a well-formatted report whose finding locations
and evidence, on the common path, were never derived from any artifact. The scaffolding
is sound and the honest-reporting machinery is better than most; the detection layer
under it is missing. Nothing here is unfixable, and item 2 above is a one-line change,
but the product should not be sold or run against customer code until at least both
Blockers and the VERIFY/coverage findings are closed.

The two Blockers are different in kind and both need to close. B1 is a missing feature —
the source-reading analyzer was never built, and building it is real work. B2 is a defect
in code that exists, is roughly a day's work, and matters even after B1 lands: as long as
a failed scan reports `ok`, every future detector inherits the same silent-failure mode.

Note on the wider monorepo: `core/` is an 11-line Rust scaffold and `apps/auditor-*`,
`apps/ares-sec`, `packages/*` are README stubs. `src/` is the only shipping auditor, so
every golden rule that mentions the Auditor lands here.

---

## 2. Critical Findings (Blockers)

### B1. No LLM-facing analyzer ever loads program source or IDL; source analysis is delegated to an unconfigured Semgrep

**Severity:** Blocker
**Location:** [src/graph/nodes/analyze-heuristic.ts:78](src/graph/nodes/analyze-heuristic.ts:78) ·
[src/graph/nodes/analyze-heuristic.ts:43](src/graph/nodes/analyze-heuristic.ts:43) ·
[src/tools/semgrep.ts:53](src/tools/semgrep.ts:53) ·
[src/graph/nodes/analyze-static.ts:98](src/graph/nodes/analyze-static.ts:98)

**Why it matters.** CLAUDE.md GOLDEN RULE 5 requires the Auditor to load actual source
(`.rs` + IDL) into analysis context and forbids shipping a heuristic that reasons only
from a summary. Both halves are violated. `sourcePath` is consumed in exactly four
non-test places: `index.ts:135` puts it on state, `intake.ts:12,23` interpolate the path
*string* into a prompt, `analyze-static.ts:98` passes it to Semgrep, and
`analyze-heuristic.ts:78` reduces it to a boolean. A repo-wide grep for `readFile` /
`readdir` outside `scripts/` and `billing/` returns nothing, and "IDL" appears nowhere
in `src/`.

The one component that does open the source tree is Semgrep, invoked as
`runSemgrep(state.sourcePath)` — a single argument, so `config` is always its default
`"auto"`, Semgrep's generic public registry. The repo ships no rule files (the only YAML
in the tree is `docker-compose.yml`, `pnpm-workspace.yaml`, `dependabot.yml`,
`ci.yml`), and there is no env var or CLI flag to select one. Every account-validation
and authority class in the catalog — `missing-signer-check`, `missing-owner-check`,
`account-data-matching`, `type-cosplay`, `duplicate-mutable-account`,
`spl-authority-check`, `anchor-constraint-gap`, `remaining-accounts-validation` — is
decidable only by reading Rust or IDL, and nothing in the system does.

Two failure modes follow, and the second is the sharper one:

- **Semgrep absent.** `runSemgrep` returns `not-installed`, static reports `degraded`
  and contributes nothing; on-chain and CUA are `skipped`. Heuristic is the only
  analyzer producing findings, from a paragraph of prose. The report opens with an
  "Incomplete assessment" banner — which warns about the *absence* of findings, never
  about the *presence* of invented ones.
- **Semgrep installed and working.** Static reports `ok` with zero Solana findings, no
  banner fires (`skipped` deliberately does not raise it, and `ok` never does), and the
  program is reported clean. The failure gets *worse* the better the environment is set
  up.

Compounding both: `const noSource = !state.sourcePath` treats "a path string exists" as
"source was read". `--source /does-not-exist` and `--source ./programs/vault` with
Semgrep uninstalled both read zero bytes, yet both skip `downgradeSpeculative`, so the
model's self-declared `severity: "high"` passes through `coerceFindings` untouched.
Omitting `--source` entirely pins the *same* fabricated findings to info/low/speculative.
Providing a source path makes the report more confident about code nobody read.
[src/graph/build-graph.test.ts:215-233](src/graph/build-graph.test.ts:215) is a passing
test asserting exactly this: `sourcePath: "/does-not-exist-xyz"` yields a `high`,
`confirmed`, `confidence: high` heuristic finding.

This is on the money path. `index.ts:150-168` gates the report behind `settleUsage`, so
when billing is on the customer is charged, and the report withheld until paid, for
findings whose `location` and `evidence` were invented.

**Recommended fix.** Three separable changes, in this order:

1. *One line, do it today.* Stop using the path string as a proxy for having read the
   code. Track whether any analyzer actually ingested source (e.g. an
   `analyzers`-channel fact or an explicit `sourceLoaded` flag set only by a node that
   read bytes) and key `downgradeSpeculative` on that. Today's behaviour — a bogus path
   producing a *less* hedged report — is strictly worse than no flag at all.
2. *Feature-sized.* Add a source-loading step: a bounded, chunked read of `*.rs` plus
   the IDL keyed off `state.sourcePath`, injected into the analyze prompts. Until that
   lands, `analyzeStatic` should report `degraded` (not `ok`) whenever it ran without a
   Solana ruleset, so the assurance banner fires.
3. *Separate change.* Ship a committed, version-pinned Solana/Anchor Semgrep ruleset and
   pass it explicitly: `runSemgrep(state.sourcePath, RULES_PATH)`. This also removes the
   `--config auto` runtime fetch from `semgrep.dev`, which makes the analyzer documented
   as "Deterministic (no LLM call)" neither reproducible nor offline-capable.

### B2. A Semgrep scan that fails is reported as `ok` — a broken scan renders as a clean audit

**Severity:** Blocker
**Location:** [src/tools/semgrep.ts:107](src/tools/semgrep.ts:107) ·
[src/tools/semgrep.ts:41](src/tools/semgrep.ts:41) ·
[src/tools/semgrep.ts:80](src/tools/semgrep.ts:80) ·
[src/graph/nodes/analyze-static.ts:99](src/graph/nodes/analyze-static.ts:99)

**Why it matters.** This is the failure mode `analyzer-status.ts` was built to make impossible,
and it is the one path that gets through. Three independent signals that a scan failed are all
discarded:

- **The exit code.** `child.on("close", () => …)` takes no `code` parameter. Semgrep exits 0 (ran,
  no findings), 1 (ran, findings), and ≥2 for a scan that did not complete. Nothing distinguishes
  them.
- **Semgrep's own error channel.** `interface SemgrepJson` declares only `results`. Semgrep's
  `--json` output also carries an `errors` array for rule-parse and target errors; it is never
  read, and `parsed.results ?? []` yields `[]`.
- **stderr.** `stdio: ["ignore", "pipe", "ignore"]` discards the reason entirely, so nothing is
  even logged.

Both failure shapes therefore converge on the same value. Empty stdout resolves
`{ available: true, findings: [] }` at line 110; a JSON body whose `errors` is populated but
`results` empty resolves the same at line 122. `analyze-static.ts:99` tests
`if (!result.available || result.reason)` — false in both cases — and falls through to
`analyzers: status("ok")`.

Per this repo's own definition ([src/graph/state.ts:36](src/graph/state.ts:36)), `ok` means "ran
against real input and completed. Silence here is evidence." `UNTRUSTWORTHY_SILENCE` is
`["degraded", "failed"]`, so **no assurance banner fires**, and REPORT presents a clean
assessment. The safety architecture is correct; the one analyzer that can lie to it does.

Realistic triggers are ordinary, not exotic: a network failure or registry outage while fetching
the `--config auto` ruleset (B1), a malformed rule, a permissions error on the source tree, or the
OOM-kill that large scans invite. Note this makes B1 strictly worse — the two compound, because the
remote ruleset fetch is itself the most likely thing to fail.

The failure path has no test. `semgrep.test.ts:22-34` asserts only
`expect(res).toHaveProperty("available")` and `Array.isArray(res.findings)` — it passes whether
Semgrep works, is missing, or crashes, and would pass if the function body were replaced with a
constant.

**Recommended fix.** Capture the exit code, pipe and retain stderr, add `errors` to `SemgrepJson`,
and introduce a distinct `scan-error` reason that `outcomeFor` maps to `failed` rather than falling
through `default: "degraded"`. Treat a non-zero exit other than 1, or a non-empty `errors` array, as
a failed scan. Add a test that spawns a deliberately failing scan and asserts the analyzer reports
`failed`.

---

## 3. Important Findings (Should Fix)

### S1. VERIFY judges findings only against their own LLM-written text, yet stamps "confirmed"

**Severity:** Should Fix
**Location:** [src/graph/nodes/verify.ts:30](src/graph/nodes/verify.ts:30) ·
[src/graph/util.ts:146](src/graph/util.ts:146)

**Why it matters.** The critic prompt contains index, severity, category, source,
vulnClass, location and `evidence` — nothing else. `state.recalled`, program metadata and
raw Semgrep output are never referenced in the node. For heuristic, on-chain and CUA
findings the `evidence` string was produced by the same model one superstep earlier, so
VERIFY cannot confirm or refute anything; it can only rate how plausible a text blob
reads. It nonetheless assigns `status: "confirmed"` — defined in
[src/llm/prompts.ts:87](src/llm/prompts.ts:87) as "evidence clearly supports it" — which
[src/graph/nodes/report.ts:89](src/graph/nodes/report.ts:89) prints verbatim as
`[status: confirmed]`.

`coerceVerdicts` validates only the status enum and index range; `applyVerdicts` writes
the model's status through unchanged. `downgradeSpeculative` does not touch `status`, and
`applyVerdicts` overwrites a downgraded `confidence: "low"` with whatever the critic
returned — so even a deliberately downgraded speculative finding can emerge
`[confidence: high] [status: confirmed]`. The only mitigation is prompt text
([src/llm/prompts.ts:82,90](src/llm/prompts.ts:82)) asking the model not to do this; there
is no code guard anywhere.

**Recommended fix.** Refuse `confirmed` in `applyVerdicts` unless the finding is
non-speculative *and* backed by an artifact that was actually in the prompt — today that
means `source === "static"` only; cap everything else at `suspected`. Longer term, feed
VERIFY the underlying artifact (source excerpt at `location`, the raw Semgrep hit, the
on-chain metadata JSON) so the label can mean something.

### S2. The published coverage fraction is model self-report and mixes two incompatible meanings

**Severity:** Should Fix
**Location:** [src/graph/nodes/report.ts:95](src/graph/nodes/report.ts:95) ·
[src/graph/util.ts:69](src/graph/util.ts:69) ·
[src/graph/nodes/analyze-static.ts:117](src/graph/nodes/analyze-static.ts:117)

**Why it matters.** `Coverage: checked N of 28 vulnerability classes` reads as a measured
figure and is required to appear in the customer-facing report by
`reportSystemPrompt`. It is a plain set-union over whatever analyzers push, and the
LLM analyzers push `extractChecked(raw)` — the model's own `checked` array, validated
only for catalog membership. The analyze prompt explicitly instructs the model to "still
list it in `checked` so coverage is tracked honestly", so returning all 28 ids is
prompt-compliant. On `npm run audit -- --program <ADDR>` with no source, static and CUA
are `skipped` (contributing nothing), and the run can print "checked 28 of 28" having
examined no instruction, no account struct and no line of bytecode.

The static analyzer's contribution is grounded but measures something else entirely: it
is the set of catalog categories of findings that *fired*, filtered of `"other"`. A
Semgrep scan over the full ruleset that finds nothing contributes zero coverage, and a
scan that finds plenty contributes zero if none of the rule ids map to a catalog id. The
same channel therefore unions "classes I claim to have considered" with "classes where I
found something", and prints the union as one fraction.

Crucially, no assurance banner contradicts it: `UNTRUSTWORTHY_SILENCE` is
`["degraded", "failed"]` by design, so `skipped` analyzers leave the report clean. This
is the exact "we looked and found nothing vs. we never looked" distinction
`analyzer-status.ts` exists to preserve, defeated for the one outcome the banner
deliberately excludes.

**Recommended fix.** Cheapest honest version: exclude analyzers whose outcome is not `ok`
from contributing, intersect each analyzer's `checked` array with a static allowlist of
classes its input can support (on-chain metadata supports `upgrade-authority-risk` and
very little else), and relabel the line as analyzer-asserted rather than measured.

### S3. MERGE's dedup key is two free-text LLM fields — it drops distinct findings and double-counts duplicates, with no test coverage

**Severity:** Should Fix
**Location:** [src/graph/nodes/merge.ts:12](src/graph/nodes/merge.ts:12) ·
[src/graph/util.ts:52](src/graph/util.ts:52)

**Why it matters.** `key(f)` is `vulnClass.toLowerCase() + "::" + location.toLowerCase()`.
`vulnClass` is documented in the analyze prompt as a "free-text label" and `location` is a
file:line from Semgrep but an instruction name from the LLM analyzers, so the key has two
incompatible vocabularies. `category` — the only field constrained to the catalog — is not
in the key. This fails in both directions:

- **Over-merge (worse).** `coerceFindings` defaults `vulnClass` to `"unknown"` and
  `location` to `""`. Any model response omitting those fields collapses every finding
  onto the key `unknown::`, and all but one are discarded. Verified by execution: three
  semantically distinct findings (missing-signer, arbitrary-CPI, account-close) reduce to
  one. Because `downgradeSpeculative` forces every heuristic finding to `info` on a
  black-box run, severities always tie and the tiebreak degrades to
  `evidence.length` — the longest blob wins. Nothing downstream notices: `report.ts`
  derives its dropped-count as `mergedFindings.length - verifiedFindings.length`, so a
  finding lost in MERGE is invisible in the report. The only trace is one info log line
  where `raw !== merged`.
- **Under-merge.** Semgrep's `rust.lang.security.arithmetic.overflow @ lib.rs:42` and the
  heuristic's `integer overflow in withdraw @ ix:withdraw` for the same bug never share a
  key, so both survive, get separate ARES ids, and both land in the deterministic severity
  table the README sells as computed-not-trusted.

MERGE is the one node in the pipeline that silently drops a finding; `verify.ts` and
`applyVerdicts` both document the opposite invariant ("nothing is silently dropped").
There is no `merge.test.ts` in the committed suite — every scenario in
`build-graph.test.ts` produces exactly one finding, so replacing the node body with
`return { mergedFindings: state.findings }` leaves all 26 tracked test files passing.

**Recommended fix.** Do *not* simply swap `vulnClass` for `category`: the catalog collapses
aggressively via `mapCategory` and an `"other"` fallback, so that would merge every
unrelated finding into one. Make identity collision-free first — include `source` and skip
dedup entirely when `location` is empty — then, if cross-analyzer fan-in dedup is actually
wanted, add it as an explicit pass on `category` + normalized location that *merges*
(retaining both sources on the survivor) rather than discarding. Add a `merge.test.ts`
covering both directions.

### S4. The impact × likelihood matrix is never applied, and an unrecognized severity silently becomes `info`

**Severity:** Should Fix
**Location:** [src/knowledge/severity.ts:38](src/knowledge/severity.ts:38) ·
[src/graph/util.ts:54](src/graph/util.ts:54)

**Why it matters.** The README states findings are "rated on an impact × likelihood
severity matrix (`src/knowledge/severity.ts`)". `severityFromMatrix` has no production
caller — a repo-wide grep finds it only in `severity.test.ts` — and `defaultSeverity` on
every catalog entry is never read in the detection path (`formatChecklistForPrompt`
discards it). Severity is whatever string the model emitted,
membership-checked with no normalization, and the fallback for anything unrecognized is
the *lowest* level: `"Critical — attacker can drain the vault"` or a trailing space in
`"high "` both become `info`. MERGE then sorts it last, the severity table prints
`| Critical | 0 |`, and REPORT is instructed not to reclassify.

The direction is the damaging one and it is inconsistent with its own siblings in the same
function: `confidence` falls back to the middle value, and `coerceVerdicts` *drops* entries
with an invalid status rather than defaulting them. Only severity fails silently downward,
with no warning logged — and because `downgradeSpeculative` uses `info` as a deliberate
sentinel, an accidentally-flattened critical is indistinguishable from an intentional
downgrade in both logs and report. The deterministic Semgrep path is unaffected
(`mapSeverity` handles a fixed enum).

**Recommended fix.** At the shared choke point in `coerceFindings`: trim, match a leading
severity token, map common synonyms, and log a warning whenever a non-empty severity string
fails to resolve so the collapse is never silent. Falling back to the catalog entry's
`defaultSeverity` for the finding's category is safer than falling back to `info`. Either
wire `severityFromMatrix` into the pipeline (have analyzers return impact/likelihood) or
stop claiming it in the README.

### S5. `coerceVerdicts` coerces a null/false/empty index to 0, corrupting the top-severity finding

**Severity:** Should Fix
**Location:** [src/graph/util.ts:116](src/graph/util.ts:116)

**Why it matters.** `Number(o.index)` maps `null`, `false`, `""` and `[]` to `0` and `true`
to `1`, all of which pass `Number.isInteger`. A verdict carrying no usable index — a common
shape when a model cannot map a verdict back to an item — is silently bound to a real
finding. Since MERGE sorts by severity descending, index 0 always carries the maximum
severity in the run. A verdict of `{"index": null, "status": "false-positive"}` therefore
drops the critical finding, and the report prints "(1 dropped as false-positive in
verification)" — affirmatively claiming the vanished finding was reviewed and rejected.

There is a second mode: even a non-`false-positive` null-index verdict calls `seen.add(0)`,
so the model's *real* verdict for finding 0 is then skipped as a duplicate. Impact depends
on ordering within the array, which makes it intermittent rather than deterministic.
`util.test.ts:137-149` covers out-of-range, duplicate and bad-status indices; every index
in every test is a numeric literal.

**Recommended fix.** Type-check before coercing, at the shared function rather than the
caller: `if (typeof o.index !== "number" || !Number.isInteger(o.index) || ...) continue;`.
Note this stops accepting the string form `"0"`, which currently works — if the model is
known to quote indices, gate on `typeof === "number" || typeof === "string"` with an
explicit `/^\d+$/` check. Add one test line passing `{ index: null }`.

### S6. Runtime writeback stores unverified model output in the curated corpus, and later audits recall it as top-trust prior knowledge

**Severity:** Should Fix
**Location:** [src/persistence/knowledge-writer.ts:111](src/persistence/knowledge-writer.ts:111) ·
[src/retrieval/util.ts:21](src/retrieval/util.ts:21) ·
[src/graph/nodes/remember.ts:45](src/graph/nodes/remember.ts:45)

**Why it matters.** REMEMBER reads `state.verifiedFindings` with no filter on `status`,
`speculative` or `confidence`, renders each as `- [severity] vulnClass @ location: evidence`
— dropping exactly those three fields — and persists the model's summary of them into the
same `documents`/`chunks` tables the seed solsec ingester writes. A finding that
`downgradeSpeculative` explicitly marked speculative/info/low reaches the REMEMBER model
verbatim, and a merely `suspected` finding does too.

Origin *is* recorded on write (`title: "runtime memory: <target>"`, `path: "runtime/<id>"`,
and `ch.level` on the Neo4j node) but nothing surfaces it at recall: `hybrid_search` returns
no title or path and does not join `documents`, and both retrievers call `synthCrystal`
without passing `level` — the Neo4j retriever does not even read back the `level` it wrote.
`synthCrystal` then defaults to `level: "semantic", activation: 1`, and
`analyze-heuristic.ts:38-41` renders the fragment as `#1 (semantic): …` under the header
"Recalled memory fragments (prior audit knowledge)", indistinguishable from a vetted solsec
chunk. A later audit run *with* `--source` skips the speculative downgrade and can promote
the system's own earlier speculation into a full-severity finding.

There is also no TTL or deletion on the durable side: `crystalline.consolidate()` prunes the
in-process store, but the writer only ever upserts, so a fragment Crystalline has pruned
lives in Supabase/Neo4j forever. The content-hash chunk id does at least prevent duplicate
amplification, so this accumulates rather than compounds. Inert unless Supabase or Neo4j is
configured.

**Recommended fix.** Two one-line retrieval changes cover most of it: have
`SupabaseRetriever` select or join `documents.path` (or key off the `runtime/` prefix) and
pass a lower `level`, and have `Neo4jRetriever` `RETURN c.level` and pass it through —
`analyze-heuristic.ts:40` already prints `s.crystal.level`, so the prompt becomes honest for
free. Separately, have REMEMBER refuse to persist findings that are `speculative` or whose
status is not `confirmed`, and pass status/confidence into the REMEMBER prompt instead of
discarding them.

### S7. The ledger debit is persisted durably but the balance is not — the two can permanently disagree

**Severity:** Should Fix
**Location:** [src/billing/account-store.ts:168](src/billing/account-store.ts:168) ·
[src/billing/account-store.ts:155](src/billing/account-store.ts:155) ·
[src/index.ts:166](src/index.ts:166)

**Why it matters.** `FileAccountStore.append` and `FileAccountStore.save` are two
independent locked transactions. `ledger.charge()` mutates the in-memory account and
immediately makes the ledger entry durable via `sink.append(entry)`; the *balance* only
reaches disk later, from the caller at `index.ts:166`. Reproduced against the real modules:
two runs sharing `BILLING_ACCOUNT_STORE_PATH`, run B's `save()` throws
`ConcurrentAccountUpdateError`, and the file ends with `systemCredits: 90` (only A's
10-credit debit applied) while the ledger contains debits of `[10, 30]`. A crash or a
disk-full staging failure between the two calls does the same.

The blast radius today is bounded and worth stating precisely: the *balance* is the half
that stays correct and conservative — the credits are not taken, and because `save()`
precedes the report write the report is withheld and the run exits non-zero, so nothing is
delivered for free. `store.ledger()` has no production caller, so no charge is derived from
the ledger. What actually breaks is audit-trail integrity, and the error message
(`"The charge was not persisted; re-run the audit…"`) is exactly backwards: the balance was
not persisted, the debit was. The genuine money-loss variant — unpersisted `onDemandSpent`
after `mpp.settle` has collected, letting `onDemandLimit` be exceeded and the payer charged
twice — is currently unreachable only because `createMppClient` returns the hermetic
`LocalMppClient`. It becomes a Blocker the day the HTTP-402 client is wired.

**Recommended fix.** Make the debit and the new balance one write, in the persistence layer
rather than in `meter.ts` (which is not wrong). Give `AccountStore` a single
`commit(account, entry)` that takes the lock once, re-reads, applies the rev CAS, pushes the
ledger entry and the balance together, and writes atomically — or have the `LedgerSink`
buffer entries and flush them inside `save()`'s lock. That fixes `InMemoryAccountStore` by
construction and makes the error message true again.

### S8. `releaseLock` deletes the lock file without checking ownership, cascading a stale-lock break into concurrent writers

**Severity:** Should Fix
**Location:** [src/billing/account-store.ts:230](src/billing/account-store.ts:230) ·
[src/billing/account-store.ts:200](src/billing/account-store.ts:200)

**Why it matters.** `acquireLock` writes `process.pid` into the lock file and breaks any lock
whose mtime is older than 30s, but `releaseLock` unconditionally `rmSync`s the path and never
reads the pid back. A process whose lock was broken therefore deletes its *successor's* lock
on the way out, admitting a third writer while the second is mid read-modify-write. Because
`append()` has no revision CAS (unlike `save()`), the resulting lost update is a silently
vanished ledger debit — no error, no log.

Reachability is broader than a 30-second stall: staleness is `Date.now() - statSync(...).mtimeMs`,
mixing wall clock against a filesystem timestamp, so an NTP step, a VM or container resume, or
client/server clock skew makes a freshly created lock read as stale immediately. The stale
branch also `continue`s without consulting `deadline`, so a waiter breaks a stale-looking lock
on its first attempt rather than after `LOCK_TIMEOUT_MS`. No test exercises the stale-break
branch at all.

Attribution matters for the fix: the *first* lost update is caused by the stale break, which is
a deliberate documented tradeoff and would not be prevented by an ownership check. What the
missing check specifically causes is admitting writer C while B is still inside its critical
section, converting a bounded two-writer race into an unbounded one.

**Recommended fix.** Write a unique token (`${process.pid}:${uuidv4()}`) into the lock file,
keep it on the instance, and in `releaseLock` read the file back and only unlink on a match.
For the durable fix, make the stale break verify the recorded pid is actually dead, or replace
mtime staleness with a monotonic lock-renewal heartbeat.

### S9. `canAffordAudit`'s result is discarded, so an unpayable account still burns a full audit's provider spend

**Severity:** Should Fix
**Location:** [src/index.ts:116](src/index.ts:116) ·
[src/billing/index.ts:128](src/billing/index.ts:128)

**Why it matters.** The call site evaluates `canAffordAudit(billing)` as a bare statement and
throws the boolean away. Reachable with shipped defaults: set `BILLING_ENABLED=true` and
nothing else — `BILLING_PLAN_CREDITS` defaults to 0 and `BILLING_ONDEMAND_ENABLED` to false, so
the account is structurally unpayable. A warning is logged, then `buildAuditGraph` and
`graph.invoke` run the full pipeline, paying OpenRouter for every LLM call across intake,
recall, four analyzers, merge, verify, remember and report. `settleUsage` finally throws
`InsufficientCreditsError`, the report is withheld, and the operator has paid provider cost for
nothing. Every run in this state repeats it.

To be precise about the contract: the README documents warn-only behaviour ("A pre-flight check
also *warns* when an account structurally can't pay"), and the warning does fire before the
graph is built with the exact remedy named. So this is a hardening gap and a dropped return
value, not a violated documented invariant — but the function's own docstring says the point is
to surface this "rather than as an `InsufficientCreditsError` after value has already been
produced", which is precisely what happens.

**Recommended fix.** One line: `if (billing.config.enabled && !canAffordAudit(billing)) { …
process.exitCode = 1; return; }` before `buildAuditGraph`. If warn-only is deliberate, gate the
abort behind a config flag rather than leaving the return value silently dropped, and add a test
over the wiring — the existing tests cover the function in isolation only.

### S10. Billing is not inert when disabled — a stale `MPP_ENDPOINT` or a damaged store file aborts the whole audit

**Severity:** Should Fix
**Location:** [src/index.ts:109](src/index.ts:109) ·
[src/billing/index.ts:88](src/billing/index.ts:88)

**Why it matters.** Both the billing module header and `config.ts` promise that with
`BILLING_ENABLED` unset "nothing here runs" / "nothing here affects a normal audit run".
`createBilling()` is called unconditionally and eagerly constructs both the account store and the
MPP client before any `enabled` check. Verified by execution with `BILLING_ENABLED` deleted:
`MPP_ENDPOINT=https://mpp.example` throws "…the HTTP-402 client is not wired. Refusing to settle
on-demand charges locally…" out of `main()`, so the run exits 1 having audited nothing; a
`BILLING_ACCOUNT_STORE_PATH` pointing at unparseable JSON throws `AccountStoreCorruptError` the
same way, after first logging "Billing account persistence enabled" — with billing off.

`BILLING_ENABLED=false` behaves identically to unset. This is not on the money path, fails closed
and loudly, and names the offending variable — but it is a total outage of the product's primary
function triggered by exactly the workflow two doc comments promise is safe, and the error's
suggested remedy (`MPP_ALLOW_LOCAL_FALLBACK=true`) tells an operator with billing *off* to opt
into local settlement of money they are not being charged.

**Recommended fix.** In `createBilling` (not at the call site — gating only `index.ts:109` leaves
the trap for the next caller): resolve `config` first, and when `config.enabled` is false return
an inert context without constructing the store or the MPP client.

### S11. The Neo4j standalone lexical match requires a chunk to contain the entire query string

**Severity:** Should Fix
**Location:** [src/retrieval/neo4j-retriever.ts:35](src/retrieval/neo4j-retriever.ts:35)

**Why it matters.** The Cypher predicate is `toLower(c.content) CONTAINS toLower($text)`, and
`$text` is `state.intake?.summary ?? state.request` — always a full sentence (INTAKE's fallback
summary is literally the raw request). It requires a corpus chunk whose 1200-character body
contains that entire sentence verbatim, which no seeded solsec chunk ever will. With Neo4j
configured and Supabase unconfigured, `expand()` is also a no-op (no seed chunk ids), so the graph
source contributes literally nothing on every run — while `status()` marks it `ok` because no
error was returned, no banner fires, and the report prints `neo4j | answered | 0`. That is the
exact "answered and had nothing" vs. "did not really work" confusion the `retrieval` channel was
built to prevent.

The right query is already provisioned and unused: `db/neo4j/schema.cypher:24` creates
`FULLTEXT INDEX chunk_content`, and nothing in `src/` ever calls `db.index.fulltext.queryNodes`.
The Supabase equivalent tokenizes properly via `websearch_to_tsquery`, so Neo4j is the odd one out.
Degenerate edge case in the other direction: an empty `request` propagates `summary: ""`, and
`CONTAINS ""` matches everything, returning `limit` chunks of noise.

**Recommended fix.** Replace the `MATCH … CONTAINS` with
`CALL db.index.fulltext.queryNodes('chunk_content', $text)`. Independently, treat a configured
source that returned zero fragments for a non-empty query as worth surfacing (a `degraded` outcome
or a detail note) so a structurally broken source cannot render as "answered". See also the open
question on `LIMIT` typing in section 5.

### S12. An embeddings-endpoint failure is indistinguishable from "embeddings not configured", and durably writes null-vector chunks

**Severity:** Should Fix
**Location:** [src/retrieval/embeddings.ts:54](src/retrieval/embeddings.ts:54) ·
[src/persistence/knowledge-writer.ts:117](src/persistence/knowledge-writer.ts:117) ·
[src/scripts/ingest-solsec.ts:114](src/scripts/ingest-solsec.ts:114)

**Why it matters.** `embed()` returns the same `undefined` for "not configured" (the documented
default), "endpoint returned 503", and "hit the 15s deadline". On the read side RECALL passes
`undefined` through, `hybrid_search` receives `query_embedding: null` whose `semantic` CTE is empty
by construction, and Crystalline falls back to tag similarity — so semantic search is off while all
three sources report `outcome: "ok"`, no banner fires, and the report states the knowledge sources
answered. Two `logger.warn` calls fire, so it is not silent in logs; it is silent in the report and
the assurance channel, which is the load-bearing part.

The write side is worse than "fails to improve". `knowledge-writer.persist` upserts
`embedding: fragment.embedding ?? null` with `onConflict: "chunk_id"`, and the chunk id is a hash of
the content — so remembering content that already has a healthy embedded row during an outage
*overwrites the good vector with null*. `ingest-solsec.ts` makes the identical collapse with
`embedBatch`: a transient failure mid-ingest writes null embeddings for every chunk of the affected
files, with no error and no non-zero exit, silently seeding a corpus pgvector can never match.

**Recommended fix.** Make `embedBatch` (the root, not the two callers) return a discriminated
result — `{ vectors }` vs `{ error }` vs a distinct "not configured" sentinel. Then RECALL appends
`{ source: "embeddings", outcome: "failed", fragments: 0, detail }` to the `retrieval` array it
already returns (`RetrievalReport.source` is typed `string`, so `assuranceBanner` picks it up for
free), and REMEMBER/ingest skip the durable write — or omit the `embedding` column from the upsert
payload so an existing good value is preserved — instead of writing `null`.

### S13. Supabase and Neo4j calls get no request deadline, so RECALL and REMEMBER can stall for minutes

**Severity:** Should Fix
**Location:** [src/persistence/supabase.ts:32](src/persistence/supabase.ts:32) ·
[src/persistence/neo4j.ts:28](src/persistence/neo4j.ts:28)

**Why it matters.** `src/config/timeout.ts` exists precisely because a hung socket hangs the whole
audit and `withRetry` cannot help, since it only reacts to errors. Solana RPC uses `timedFetch`,
embeddings use `deadlineSignal`, and the chat client sets a timeout — Supabase and Neo4j are the
only two uncovered outbound dependencies, and both sit on the audit's critical path
(`intake → recall → analyzers` and `verify → remember → report` are hard joins in the graph).
A blackholing Supabase host bounds `hybrid_search` only by undici's default 300s headers timeout;
`graph.invoke` is called with no outer signal or wall clock. REMEMBER is worse because it awaits
`knowledge.persist` once per fragment.

Neo4j is the more severe leg, not merely the second one: `neo4j-driver` speaks Bolt over TCP, so it
gets no undici backstop at all, and the driver's default `connectionTimeout` bounds only
*establishing* a socket — an established connection that stops answering hangs with no ceiling.

**Recommended fix.** Two different changes; `timedFetch` only works for one of them. For Supabase,
pass `global: { fetch: timedFetch(env.SUPABASE_TIMEOUT_MS) }` to `createClient` and add the var
alongside the existing SOLANA/EMBEDDINGS timeouts. For Neo4j there is no fetch to override — set
`connectionAcquisitionTimeout`/`connectionTimeout` on the driver and pass a per-query transaction
`{ timeout }` on `session.run` in `withNeo4jSession`; the 1–2 hop `expand()` has no server-side
bound either.

### S14. The eval scorer's `speculative` filter treats a missing or string value as true, silently discarding predictions

**Severity:** Should Fix
**Location:** [eval/score_detections.py:73](eval/score_detections.py:73)

**Why it matters.** `eval/` is the trust anchor for every published number, and the README states
the accuracy table is updated from the CI job's output, not by hand. The filter is
`kept[~kept["speculative"].astype(bool)]` with no normalization. `eval/README.md` documents
`speculative` as an optional column, so absent values are an expected input — and pandas turns a
JSONL with a missing value into float64 `[0.0, nan]`, where `nan.astype(bool)` is True, so a
prediction nobody flagged is dropped and scores as a false negative. The CSV form with a blank cell
instead raises `TypeError: boolean value of NA is ambiguous`, naming no column.

Verification found a third and worse mode the original claim missed: any column pandas does not
parse into a native bool becomes `StringDtype`, and every non-empty string is truthy. Measured —
`speculative` as `no,no` (CSV) or as the JSON string `"false"` drops **every** prediction, producing
`tp=0, F1=0.0` for a system that detected everything. Latent today only because
`eval/predictions/ares-latest.csv` does not yet exist; CI wires this straight into the release gate
the moment the documented next step is taken.

**Recommended fix.** Do not use `.fillna(False).astype(bool)` — that silences the NaN case and
leaves string truthiness intact. Map explicitly, mirroring how `confidence` is already handled a few
lines above: lowercase/strip, map `{"true","1","yes"} → True` and `{"false","0","no"} → False`,
`fillna(False)`, and treat absent as not-speculative (matching `Boolean(f.speculative ?? false)` on
the TS side). Add tests for a partially-populated column and a string-valued column.

### S15. No CI job runs the license check that CLAUDE.md's Definition of Done requires

**Severity:** Should Fix
**Location:** [.github/workflows/ci.yml:20](.github/workflows/ci.yml:20) ·
[CLAUDE.md:58](CLAUDE.md:58)

**Why it matters.** GOLDEN RULE 1 states "CI checks both — if it fails, fix the dependency, don't
weaken the check", and the Definition of Done lists "License check passes". `ci.yml` defines exactly
three jobs — `verify`, `eval-scorer`, `verify-claims` — and none runs `cargo deny check licenses`,
any npm/pip license scanner, or `cargo` at all. There is no `deny.toml` anywhere in the tree, so the
documented command could not run even if a job invoked it. `git log` on the workflow shows four
commits and no license job was ever removed; it never existed.

Two things bound this. The gap is tracked, not unnoticed: `docs/PLAT-1-PROGRESS.md:16` names the
"PLAT-2 CI copyleft gate (license-checker / cargo-deny)" as deferred with a backlog ID. And nothing
is currently published — `package.json` is `"private": true`, `core` is a 0.0.0 scaffold, there is no
publish job, and a scan of installed dependency licenses found no GPL/AGPL present today. The defect
is therefore primarily documentation: CLAUDE.md is loaded into every agent session and asserts a
control that does not exist.

**Recommended fix.** Pick one, not both. Either add the steps — a `cargo-deny-action` step (which
requires creating the missing `deny.toml`) plus `npx license-checker --failOn 'GPL;AGPL'` — or soften
GOLDEN RULE 1 to state the gate is PLAT-2 and not yet enforced. Fixing the wording alone is
legitimate while nothing is published.

### S16. `formatChecklistForPrompt` truncates every detection hint at the first ". ", dropping the Anchor-specific half

**Severity:** Should Fix
**Location:** [src/knowledge/solana-vulns.ts:524](src/knowledge/solana-vulns.ts:524)

**Why it matters.** The one-line checklist is the *only* part of the catalog that ever reaches an
analyzer — description, remediation, references and the rest of `detectionHints` are never injected
into any prompt. `.split(". ")[0]` therefore deletes roughly 40% of the guidance for **six** of the
catalog's entries (verified by running the split over every entry, not three as originally claimed):
`missing-owner-check` loses "In Anchor, ensure `Account<'info, T>` types are used rather than raw
`AccountInfo`"; `pda-seed-collision` loses the concrete `seeds = [user.key().as_ref()]` pattern;
`account-close-revival` loses "Check for `close` without `zero` in Anchor"; `anchor-constraint-gap`
loses "Check for missing `has_one` on authority fields"; `type-cosplay` loses "Anchor's 8-byte
discriminator normally prevents this"; `upgrade-authority-risk` loses "Also check admin/config
instructions gated only by a single `authority`". Three of the six losses are missing *detection*
patterns (recall loss), not just false-positive suppressors.

The effect is probabilistic degradation of analyzer guidance rather than a guaranteed wrong verdict —
three analyzers plus VERIFY sit between the prompt and the report — which is why this is Should Fix
rather than higher. The existing test asserts only that every id appears and that the line count
matches, so it does not protect the truncation.

**Recommended fix.** Delete `.split(". ")[0]` and interpolate `v.detectionHints` directly. Every value
is already newline-free and 1–2 sentences, so the docstring's "compact one-line" intent survives, the
token cost across 28 entries is negligible, and both existing tests pass unchanged.

### S17. The declared pnpm/turbo/cargo monorepo resolves to zero packages, so CLAUDE.md's documented commands run nothing

**Severity:** Should Fix
**Location:** [pnpm-workspace.yaml:4](pnpm-workspace.yaml:4) · [CLAUDE.md:66](CLAUDE.md:66)

**Why it matters.** `pnpm-workspace.yaml` globs `packages/*` and `apps/*`; `find packages apps -name
package.json` returns zero — every directory there holds only a README stub. `turbo.json` declares
build/test/lint/typecheck pipelines while `turbo` is absent from dependencies and the root has no
`packageManager` field. The real 26 vitest suites live under root `src/` and are reachable only via
`npm test`, which CLAUDE.md never mentions.

Verified by execution: `pnpm -r run typecheck` prints "No projects matched the filters" and **exits
0**; `cargo test --workspace` compiles the 11-line `ares-core` scaffold and reports "running 0 tests…
test result: ok". An agent satisfying the Definition of Done ("Tests green in CI") via the documented
`pnpm -r test` gets a green exit having executed zero of the 26 suites, and will truthfully-but-wrongly
report tests passing. CI is correct and authoritative — it uses `npm ci` and never invokes pnpm, turbo
or cargo — so nothing catches the drift.

Two precisions: `pnpm install` is not a no-op (the root *is* a workspace project, so it installs and
writes a competing `pnpm-lock.yaml` alongside `package-lock.json`), and `cargo run -p ares-cli` and
`pnpm --filter auditor-web dev` fail loudly rather than silently. The silent-green problem is confined
to `pnpm -r build/test` and `cargo build/test --workspace`. The skeleton itself is deliberate and
honestly caveated in `pnpm-workspace.yaml`, `turbo.json` and `packages/README.md` — CLAUDE.md is the
only place that omits the caveat.

**Recommended fix.** Doc-only. Replace the Commands block with what works today
(`npm ci && npm run typecheck && npm run lint && npm run build && npm test`) and mark the
pnpm/turbo/cargo-deny lines as PLAT-1/PLAT-2 targets not yet wired, matching the caveats already
present elsewhere in the repo.

### S18. The Semgrep child process has no deadline, and its stdout is buffered without bound

**Severity:** Should Fix
**Location:** [src/tools/semgrep.ts:74](src/tools/semgrep.ts:74) ·
[src/tools/semgrep.ts:105](src/tools/semgrep.ts:105)

**Why it matters.** `src/config/timeout.ts` exists because "a hung socket therefore hangs the whole
audit, and `withRetry` cannot help." That reasoning applies identically to a spawned process, but
`runSemgrep` sets no timeout, no `AbortSignal`, and never kills the child. `analyzeStatic` sits
inside the parallel ANALYZE superstep, and MERGE is a hard fan-in join, so a Semgrep run that never
terminates hangs the entire audit with no further log output after RECALL — and `graph.invoke` is
called with no outer signal or wall clock ([src/index.ts:131](src/index.ts:131)). A large monorepo
passed to `--source`, or the registry fetch stalling on an unresponsive `semgrep.dev`, is enough.

Separately, `child.stdout.on("data", (d) => chunks.push(d))` accumulates the entire JSON result in
memory with no cap. A scan producing a very large findings set is bounded only by the Node heap.

This is the same class as S13 (Supabase/Neo4j have no deadline) and should be fixed alongside it:
those three are the only outbound dependencies in the codebase left unbounded.

**Recommended fix.** Add a `SEMGREP_TIMEOUT_MS` env var next to the existing `SOLANA_TIMEOUT_MS` and
`EMBEDDINGS_TIMEOUT_MS`, `setTimeout` → `child.kill("SIGKILL")`, and resolve with a distinct
`scan-timeout` reason that `outcomeFor` maps to `failed` (see B2). Guard the resolve so the timer and
the `close` handler cannot both settle the promise. Cap accumulated stdout and treat an overrun as a
failed scan.

### S19. The CUA investigation transcript is interpolated into an analyzer prompt unfenced, so a page the audited party controls can forge a clean result

**Severity:** Should Fix
**Location:** [src/graph/nodes/analyze-cua.ts:62](src/graph/nodes/analyze-cua.ts:62)

**Why it matters.** `analyzeCua` drives a real browser over attacker-reachable content — block
explorers, source repositories, docs, community posts — and then splices the resulting transcript
directly into the human message with no delimiter, no escaping, and no instruction-boundary marker,
under a system prompt that asks for a JSON findings object. Web page text and analyst instructions
occupy the same trust level in the resulting prompt.

The consequence is specific and matches the injector's incentive exactly. Text on a reachable page
instructing the model to return `{"findings": [], "checked": [<all 28 catalog ids>]}` both suppresses
the findings and inflates coverage, because `extractChecked` validates only catalog membership
([src/graph/util.ts:69](src/graph/util.ts:69)) and nothing cross-checks the claim (S2). The node then
reports `ok`, so no assurance banner fires. An audited party who controls their own project README or
docs site is precisely the person with a motive to suppress their own audit findings.

Two things bound this and keep it below Blocker. CUA is opt-in and off by default, requiring
`CUA_ENABLED=true` plus both `OPENAI_API_KEY` and `SCRAPYBARA_API_KEY`. And
`cuaInvestigationSystemPrompt` constrains the *browsing* agent to read-only navigation — but that
governs the browser, not the downstream analyzer that consumes its output, which is where the
injection lands. It would be a Blocker if CUA were on by default.

The narrower sibling paths are much lower risk and not separately reported: on-chain data reaches the
prompt as `JSON.stringify` of typed fields (base58 pubkeys, numbers), and Semgrep `message` text comes
from rules rather than the target.

**Recommended fix.** Fence the transcript in an explicit delimited block, state in
`analyzeSystemPrompt` that its contents are untrusted third-party data and never instructions, and
strip or escape any fence sentinel appearing in the transcript. Independently, cap the `checked` array
a CUA finding may contribute — a browser transcript cannot substantiate having evaluated a code-level
class, which is the S2 fix applied here.

---

## 4. Minor Findings (Nice to Have)

### N1. `mapCategory` keyword-maps unrelated Semgrep rules onto Solana vulnerability classes at hard-coded high confidence

**Severity:** Nice to Have
**Location:** [src/graph/nodes/analyze-static.ts:61](src/graph/nodes/analyze-static.ts:61)

**Why it matters.** Because `--config auto` scans everything under the source path — JS, Python, YAML,
Dockerfiles — rule ids from unrelated languages reach `mapCategory`, whose fallback chain assigns a
*specific* Solana class from a single generic keyword, and `toFinding` then stamps every result
`speculative: false, confidence: "high"`. The bogus category is also pushed into `coverage`, so the
class is credited as evaluated.

The magnitude is much smaller than it looks, which is why this is Minor. Running the real
`mapCategory` body over 1594 unique rule ids extracted from the live registry found exactly **one**
collision: `python.lang.security.deserialization.pickle.avoid-cPickle → arbitrary-cpi` ("cpickle"
contains "cpi"). It is genuinely reachable — a two-line Python 2 file triggers the rule — but requires
the audit target to contain `cPickle` code, which for a Solana repo is vanishingly rare. The reverse
test `id.includes(lower)` is *unreachable*, not merely unsound: `config` is hard-coded to `"auto"`, so
every check id is a fully-qualified dotted path and can never be a substring of a short kebab catalog
id. When the one collision does fire, `vulnClass` still carries the honest rule id and `location` the
`.py` path, so a human reader sees the mismatch — the genuinely misleading output is the unqualified
`Checked classes: arbitrary-cpi` line.

**Recommended fix.** One line, and it kills the whole class including future collisions: return
`"other"` from `mapCategory` unless the rule id starts with `rust.` or the finding's path ends in
`.rs`. Setting `confidence` from the rule's own reliability rather than hard-coding `"high"` is worth
doing alongside it. (The related coverage defect — `coverage` derived from categories that *fired*
rather than were *checked* — is covered separately in S2.)

### N2. The release gate fires on `release: published`, so it can only flag a release after it is public

**Severity:** Nice to Have
**Location:** [.github/workflows/ci.yml:119](.github/workflows/ci.yml:119)

**Why it matters.** The step is named "Block unscored release" and its comment says "A release may not
claim a metric nobody measured", but a `release: published` webhook fires *after* GitHub has created
the tag and release page. The job is a post-mortem: a red check appears in the Actions tab, the release
stays published. On `push`/`pull_request` the same missing-predictions condition is a warning with
`exit 0`, so nothing blocks earlier either.

Three things keep this Minor. The README currently declares precision/recall/F1 "not measured /
unverified" and `eval/README.md` says "Do not publish 0.94", so the harm described requires a separate
regression first. The docs describe the actual behaviour accurately ("a `release` event fails
outright") — only the step's own name overclaims. And nothing is distributed: `package.json` is
`"private": true`, there are no tags, and no publish or release-asset job exists; the score upload goes
to Actions artifacts.

**Recommended fix.** One line: drop `github.event_name == 'release' &&` from the condition so the
unscored state also fails `push`/`pull_request` to `main`. That blocks the merge that would enable a
release, which is the earliest point GitHub permits intervention — there is no pre-publication release
event, so a true pre-publish gate via this trigger is impossible regardless.

### N3. Log metadata is spread over the record's own fields, so a meta key named `level` overwrites the log severity

**Severity:** Nice to Have
**Location:** [src/config/logger.ts:86](src/config/logger.ts:86)

**Why it matters.** `emit()` builds the line as `JSON.stringify({ t, level, msg, ...redact(meta) })`, so
spread precedence lets any meta key named `t`, `level` or `msg` win over the record's own field. Two
call sites hit it today — `crystalline-store.ts:91` and `knowledge-writer.ts:87` both pass a
`KnowledgeLevel` as `level` — producing `{"level":"episodic","msg":"Crystallized new memory",…}` with
the `"debug"` severity gone. A collector indexing on `level` files the line under a severity of
"episodic"; a strict schema drops it.

Bounded: `ARES_LOG_LEVEL` defaults to `info` and `emit` returns early below threshold, so neither line
is emitted under default configuration. A repo-wide scan of every log call body found only these two
and no `t`/`msg` collisions.

**Recommended fix.** Reorder the literal so the record's own fields win —
`{ ...redact(meta ?? {}), t, level, msg: scrubUrls(msg) }`. That is a one-line diff fixing every present
and future caller, strictly smaller than renaming keys at each call site.

### N4. Log redaction strips URL credentials but not query-string secrets, which is the shape this repo actually documents

**Severity:** Nice to Have (hardening — no live leak path found)
**Location:** [src/config/logger.ts:45](src/config/logger.ts:45) ·
[.env.example:15](.env.example:15)

**Why it matters.** `scrubUrls` matches `scheme://user:password@host` only. `SENSITIVE_KEY` covers
metadata *keys* (`key|token|password|secret|authorization|credential|dsn`) but not a secret embedded
in a string under an innocuous key such as `err`. The repo's own `.env.example` documents
`HELIUS_RPC_URL=https://mainnet.helius-rpc.com/?api-key=xxxxxxxx` — an API key in a query parameter,
which is exactly the shape the regex does not cover. `logger.test.ts` exercises only the
`postgresql://` and `bolt://` credential forms, so the gap is untested as well as unhandled.

**I could not find a live leak path, and this is deliberately rated low as a result.** The plausible
candidate is [src/tools/solana.ts:105](src/tools/solana.ts:105), which logs `err: String(err)` after
an RPC failure. Tested empirically on this machine (Node v24): a failed `fetch` to a URL with a
query-string secret yields `TypeError: fetch failed` with the URL only in `err.cause` as a bare
hostname, and the `AbortSignal.timeout` path yields `TimeoutError: The operation was aborted due to
timeout`. Neither contains the key. The finding is that a control added deliberately — commit
`c31f202`, "redact secrets at the log sink" — has a hole in the one secret shape the project
documents, not that secrets are currently being written to disk.

**Recommended fix.** Extend `scrubUrls` to redact the values of query parameters whose names match
`SENSITIVE_KEY` (`api-key`, `apikey`, `access_token`, `key`), and add a `logger.test.ts` case for the
documented Helius URL. Cheap, and it closes the gap before a future dependency upgrade or a different
client starts including request URLs in error strings.

---

## 5. Assumptions & Open Questions

Every finding above carries a `CONFIRMED` verdict; none is `UNCERTAIN`. The items below are the
loose ends around them.

0. **Coverage gap in this review's own process.** The dimension covering input validation, trust
   boundaries, secrets and child-process handling was reviewed once rather than twice: its
   automated reviewer died on a transport error (`ECONNRESET`) partway through, and B2, S18, S19
   and N4 come from a single manual pass over `src/tools/`, `src/llm/`, `src/config/` and
   `.env.example`. Each was verified directly against the code, and B2 and S18 were independently
   corroborated — but that slice has had less scrutiny than the rest of this document and is the
   first place to look for what was missed. `src/memory/crystalline-store.ts` consolidation logic
   and `src/llm/retry.ts` backoff were sampled, not reviewed exhaustively.

1. **Neo4j `LIMIT` typing — unresolved, and it changes which symptom S11 presents.**
   `neo4j-retriever.ts` passes `{ text, limit }` with `limit` as a plain JS number, and
   `neo4j-driver` packs every JS number as a Bolt Float, while Cypher `LIMIT` requires an Integer;
   `neo4j.int` appears nowhere in the repo. This could not be settled without a live Neo4j. If the
   mismatch throws, `run()` catches it and the source reports `failed` (loudly broken) rather than
   `ok` with zero fragments (silently empty). Either way the graph source contributes nothing on
   every run, which is the substance of S11, but the two symptoms warrant different urgency. Both
   `retrieve()` and `expand()` carry it; wrap `limit` in `neo4j.int()` while fixing the query.

2. **Rule-3 scope.** Two coverage findings were originally justified by CLAUDE.md GOLDEN RULE 3
   ("no trust-me numbers"). That rule governs published product metrics reproducible via
   `eval/verify-claims`, and `eval/` contains a detection-benchmark harness that never touches
   per-run report content. S2 stands on its own — `analyzer-status.ts`'s stated design goal is that
   a reader can tell "we looked and found nothing" from "we never looked" — and should be argued
   from that, not rule 3.

3. **`--config auto` and determinism.** `analyze-static.ts` is documented as "Deterministic (no LLM
   call)"; it does not promise "no network", and GOLDEN RULE 2 scopes the no-network invariant to
   `core/` (Rust), not `src/`. Fetching an unpinned remote ruleset from `semgrep.dev` at run time is
   a real reproducibility and offline-capability problem worth fixing, but it does not contradict a
   documented guarantee. Confirm intent before treating it as a violation.

4. **When does the money path become real?** Several findings are currently bounded because
   `createMppClient` only ever returns the hermetic `LocalMppClient` and `store.ledger()` has no
   production caller. S7 in particular escalates to a genuine Blocker (double-charging a payer) the
   moment the HTTP-402 client is wired. Fix it before that lands.

5. **Review-session artifacts — action required.** While verifying findings, the automated review
   went beyond reading: it wrote regression tests, implemented candidate fixes in `src/config/env.ts`,
   `src/persistence/supabase.ts`, `src/tools/semgrep.ts` and `src/graph/nodes/analyze-static.ts`,
   added a `rules/solana.yml` Semgrep ruleset, committed the tests to a new branch
   `test/known-defect-register`, **and pushed that branch to `origin`**. None of that was requested
   by a review task.

   The local repository has been restored: `main`, commit `51fa513`, clean tree. Every artifact is
   preserved as patches (see the handover note accompanying this review) so nothing is lost. **The
   remote branch `origin/test/known-defect-register` was deliberately left in place** — deleting a
   pushed branch is itself destructive and is the repository owner's call, not the reviewer's.
   Delete it with `git push origin --delete test/known-defect-register`, or keep it: the tests it
   contains are genuinely the regression coverage S3 and B2 call for, and independently corroborate
   both findings. Review them on their merits before merging — they were written by the same process
   that produced this document, not by a human.

6. **Refuted candidate.** One candidate finding was refuted during verification and is deliberately
   absent. It is not listed here so it cannot be mistaken for a deferred item.

---

## 5b. Remediation status

Both Blockers and five Should Fix findings are implemented and verified on the
branch **`fix/audit-integrity`** (`npm test`: 241 passing, hermetic, ~7s;
typecheck and lint clean).

| Finding | Status | Where |
| --- | --- | --- |
| **B1** source never loaded | Fixed | `src/tools/source.ts` + `nodes/load-source.ts`, wired RECALL → LOAD-SOURCE → fan-out |
| **B1** bogus `--source` raised confidence | Fixed | `analyze-heuristic.ts` keys the downgrade on bytes loaded, not on the path string |
| **B2** failed scan reported `ok` | Fixed | `classifyScan()` reads exit code, `errors[]`, stderr; `scan-error`/`scan-timeout` → `failed` |
| **S18** no Semgrep deadline | Fixed | `SEMGREP_TIMEOUT_MS` + SIGKILL + output cap |
| **S1** VERIFY stamped `confirmed` | Fixed | `applyVerdicts` refuses `confirmed` without a checkable artifact |
| **S2** coverage read as measured | Fixed | relabelled analyzer-asserted; REPORT states whether source was read |
| **S3** MERGE silently dropped findings | Fixed | unlocated findings are never deduped; `category` joins the key |
| **S4** severity failed open to `info` | Fixed | normalize, synonyms, catalog-default fallback, warn |
| **S5** null index deleted top finding | Fixed | `parseIndex()` replaces `Number()` |

Two verification notes worth keeping:

- The e2e test at `build-graph.test.ts` that asserted a `high`, `confirmed`
  finding from `sourcePath: "/does-not-exist-xyz"` was **codifying the B1
  inversion**. It now asserts the corrected behaviour (`info`, speculative,
  `suspected`). Read that diff first when reviewing.
- B2 was confirmed against the real Semgrep binary, not just a mock: a broken
  ruleset now yields `{available: false, reason: "scan-error"}` ("semgrep exited
  7") where it previously yielded `{available: true, findings: []}` → `ok`.
  Separately, a real `--config auto` scan of a one-line file exceeded **60
  seconds** fetching its registry ruleset — direct evidence for both the
  determinism concern in B1 and the need for S18's deadline.

**Not fixed here** (still open): S6–S17, S19, N1–N4.

### Concurrency warning

A second agent was working this repository at the same time and independently
implemented an overlapping set of fixes on **`test/known-defect-register`**
(pushed to `origin`). The two branches must be reconciled before either merges;
do not merge both blindly. From a structural diff:

- That branch goes **wider** — it also touches `index.ts` (S9 billing pre-flight),
  `neo4j-retriever.ts` (S11), `ingest-solsec.ts` (S12), `prompts.ts` and
  `analyzer-status.ts`, which `fix/audit-integrity` does not.
- It does **not touch `merge.ts` at all**, so **S3 is unfixed there** — that is
  the finding where a model response omitting `vulnClass`/`location` collapses
  every finding onto one key and silently discards the rest.
- Both implement B1 and B2 independently, so those files will conflict.

Its test suite was not run as part of this review.

---

## 6. Recommended Next Actions

Ordered by ratio of harm removed to work required.

1. **Stop treating a path string as proof the code was read.** One line in
   [src/graph/nodes/analyze-heuristic.ts:78](src/graph/nodes/analyze-heuristic.ts:78): key the
   speculative downgrade on whether an analyzer actually ingested source, not on `!state.sourcePath`.
   Today a bogus `--source` path yields a *more* confident report than no flag at all. Fixes the
   sharpest edge of **B1** in a single diff. Update
   [src/graph/build-graph.test.ts:215](src/graph/build-graph.test.ts:215), which currently asserts the
   broken behaviour.

1b. **Make a failed Semgrep scan report `failed`.** In
   [src/tools/semgrep.ts:107](src/tools/semgrep.ts:107): capture the exit code, pipe stderr, read
   the `errors` array, and map a new `scan-error` reason to `failed` in `outcomeFor`. Closes **B2**.
   Do this alongside item 1 — together they are the difference between a broken run announcing
   itself and a broken run shipping as a clean audit. Add the failure-path test `semgrep.test.ts`
   currently lacks, and add the child-process deadline from **S18** in the same change.

2. **Clamp `confirmed`.** In `applyVerdicts`
   ([src/graph/util.ts:146](src/graph/util.ts:146)), refuse `status: "confirmed"` unless the finding is
   non-speculative and came from an analyzer whose evidence is an artifact — today, `static` only.
   Closes **S1**, and stops a fabricated finding shipping under the strongest label the system has.

3. **Make MERGE stop losing findings.** Fix the key at
   [src/graph/nodes/merge.ts:12](src/graph/nodes/merge.ts:12) so an empty `location` never collapses
   distinct findings, and commit a `merge.test.ts` covering both the over-merge and under-merge
   directions. Closes **S3**; it is the only node in the pipeline that silently deletes a security
   finding from the deliverable.

4. **Normalize the two remaining coercion holes.** `coerceFindings` severity
   ([src/graph/util.ts:54](src/graph/util.ts:54)) — trim, match a leading token, log on failure, and
   stop failing open to the lowest severity; `coerceVerdicts` index
   ([src/graph/util.ts:116](src/graph/util.ts:116)) — type-check before `Number()`. Closes **S4** and
   **S5**, both at the shared choke point rather than per-caller.

5. **Tell the truth about coverage.** At
   [src/graph/nodes/report.ts:95](src/graph/nodes/report.ts:95), exclude non-`ok` analyzers from the
   union, intersect each analyzer's `checked` array with the classes its input can support, and
   relabel the line as analyzer-asserted. Closes **S2** and the coverage half of **N1**.

6. **Fix the billing correctness set together.** One `commit(account, entry)` transaction in
   `AccountStore` (**S7**), an ownership token in `releaseLock` (**S8**), acting on
   `canAffordAudit`'s return value (**S9**), and an inert `createBilling` when disabled (**S10**).
   All four are small, all four are in `src/billing/`, and **S7** becomes a Blocker as soon as the
   HTTP-402 client is wired.

7. **Correct the docs that assert controls which do not exist.** CLAUDE.md's Commands block
   (**S17**) and its license-check Definition-of-Done line (**S15**). Both are doc-only edits and
   both currently cause agents and developers to believe a check ran when it did not. Cheapest
   possible fix, highest ratio of confusion removed.

8. **Repair the retrieval layer's honesty.** The Neo4j full-text query and `neo4j.int()` on `LIMIT`
   (**S11**), the discriminated embeddings result plus a `retrieval`-channel entry for embedding
   failure (**S12**), and — importantly — stop overwriting good vectors with null on upsert. Closes
   **S11** and **S12**.

9. **Bound the three unbounded outbound dependencies** — `global: { fetch: timedFetch(...) }` on the
   Supabase client, a transaction timeout plus driver timeouts on Neo4j (**S13**), and a kill
   deadline on the Semgrep child process (**S18**). Liveness only, but they are the only uncovered
   calls in a codebase that otherwise bounds everything. Semgrep is the one that hangs the audit
   itself, since MERGE is a hard fan-in join.

9b. **Fence untrusted browser content before it reaches a prompt** (**S19**), if CUA is ever
   enabled. Today it is off by default, which is the only thing keeping an audited party from
   suppressing their own findings by editing a page the investigator reads. Pair it with the S2
   coverage clamp. Extend log redaction to query-string secrets while in the area (**N4**).

10. **Harden the eval scorer before a predictions file lands** (**S14**), and drop the
    `event_name == 'release'` condition so the gate fires at merge time (**N2**). Both are one-line
    changes to code that is currently latent; both become live the moment
    `eval/predictions/ares-latest.csv` is committed.

11. **Then the real work: build the source-reading analyzer.** A bounded, chunked read of `*.rs`
    plus the IDL injected into the analyze prompts, and a committed, version-pinned Solana/Anchor
    Semgrep ruleset passed explicitly to `runSemgrep`. This is the remaining body of **B1** and the
    only thing that makes ARES an auditor rather than a report generator. Until it lands,
    `analyzeStatic` should report `degraded` rather than `ok` when it runs without a Solana ruleset,
    so the assurance banner tells the reader the truth.

12. **Cleanups once the above is done:** the checklist truncation (**S16**), `mapCategory`'s
    language gate (**N1**), and the logger field ordering (**N3**). Each is one line.
