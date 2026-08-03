# PLAT-3 — ARES-v2 Salvage Analysis

Before ARES-v2 gets retired, here's a concrete inventory of what's in
`packages/engine`, `packages/observability`, and `packages/queue`, and
whether it's already covered in ares-auditor (the 4R3S-based codebase) or
a genuine gap.

**Scope note:** this task is preserving the source code so nothing is lost
on retirement — it does NOT wire any of this into the running build.
Nothing here changes ares-auditor's behavior; `tsconfig.json` only includes
`src/**`, so `legacy-ares-v2/` sits outside the build entirely. Actually
integrating any of this is real engineering work that belongs on ENG-3/
ENG-4 or a new ticket, not this consolidation task.

Raw source for all three packages is preserved at `legacy-ares-v2/` in this
repo (build artifacts stripped, source + package.json + README kept).

---

## observability — mostly redundant, one real gap

| Piece | Verdict |
|---|---|
| `logger.ts` (pino-based) | **Redundant.** Ares-auditor already has its own logger (`src/config/logger.ts`) — deliberately lighter, no pino dependency, by explicit design comment in the code. Porting this would be a step backward. |
| `sentry.ts` (error tracking) | **Genuine gap.** Ares-auditor has zero error-tracking/monitoring today. This is the one piece from this package actually worth carrying forward, whenever error tracking becomes a priority. |

## queue — genuinely missing, but confirm before porting

Ares-auditor is a synchronous CLI today — no queue infrastructure at all.
ARES-v2's `@ares/queue` is a real BullMQ + Redis job system (enqueue,
worker, retry/backoff, and a graceful inline-mode fallback when Redis isn't
configured).

**Open question before this gets prioritized:** the backlog's `ORC-1`
(Khashia's task — "Pull agent-py plane (LiteLLM, FastAPI, **Arq** worker,
tracing) into platform/orchestration") describes a *Python* queue system
via Arq, not this Node/BullMQ one. If that's meant to be the actual queue
going forward, porting this package would be duplicate infrastructure in
the wrong language. **Worth a quick check with Khashia before deciding
whether this gets ported, or just archived as reference.**

## engine — the big one, needs to become real tickets

This isn't a small utility — it's an entire alternate multi-agent security
engine: a 6-agent orchestrator, its own Zod findings schema with SARIF
export, pluggable sandbox execution (host-shell + Docker), and 18 discrete
assurance tools.

Direct comparison against what's in ares-auditor's `src/tools/` today:

| ARES-v2 engine tool | Status in ares-auditor |
|---|---|
| `solana-rpc-read.ts` | Partial overlap — `src/tools/solana.ts` |
| `program-account-analyzer.ts` | Partial overlap — `src/tools/solana.ts` |
| `run-semgrep.ts` | Covered — `src/tools/semgrep.ts` |
| `anchor-source-scanner.ts` (Rust static heuristics) | **Missing** |
| `cpi-graph-mapper.ts` (Anchor IDL → instruction map) | **Missing** |
| `secret-scanner.ts` (git-history secret sweep + entropy) | **Missing** |
| `token-concentration.ts` (SPL HHI / Gini concentration) | **Missing** |
| `program-upgrade-monitor.ts` (BPF loader / upgrade-authority checks) | **Missing** — notable: "upgrade-authority-risk" is already a listed vuln class in ares-auditor's coverage output with nothing behind it yet |
| `env-hygiene-check.ts` | **Missing** |
| `generate-pdf-report-tool.ts` | **Missing** — ares-auditor only emits markdown reports today |
| `merge-sarif.ts` / SARIF bridge | **Missing** |
| `account-state-snapshot.ts`, `git-clone-repo.ts`, `git-diff-summary.ts`, `merge-findings-tool.ts`, `unified-posture-report.ts`, `write-assurance-manifest-tool.ts`, `assurance-llm.ts` | **Missing** |

**Recommendation:** don't try to wire these in as part of PLAT-3. Flag the
highest-value ones as candidates for real ENG tickets:
- `program-upgrade-monitor.ts` — directly closes an already-advertised
  coverage gap (upgrade-authority-risk)
- `anchor-source-scanner.ts` + `cpi-graph-mapper.ts` — overlap heavily with
  ENG-4's scope ("Strengthen AST scanner for Anchor constraints")
- `secret-scanner.ts` — cheap, high-value, no overlap with anything already
  planned
- SARIF export (`merge-sarif.ts`) — worth considering if the REST API /
  CI-integration tasks (INT-1, INT-5) want a standard interchange format

**Correction, after checking ARES-v2's open Dependabot alerts:**
`generate-pdf-report-tool.ts` imports `jspdf@^4.2.1` and `jspdf-autotable`
directly. `jspdf` currently has **six open critical/high advisories** against
it in ARES-v2's repo: path traversal/LFI, HTML injection (×2 locations),
DoS via malicious GIF dimensions, DoS via malicious BMP dimensions, and a
ReDoS. **Do not port this tool as-is.** If PDF export is wanted later, that
ticket needs to either (a) confirm a patched jspdf version actually closes
these advisories, or (b) evaluate an alternative PDF library, before any
of this code gets wired in. Ares-auditor's existing markdown-only report
path has no such exposure and needs no changes.

Separately: `sandbox/host-shell.ts` executes commands via `execa` with
`shell: true` — an inherently code-execution-adjacent surface. I didn't
trace whether the `shell-quote` advisory in this same alert list resolves
through that specific path or elsewhere in the monorepo's dependency tree,
but given what this file does, I'd want that traced explicitly before this
sandbox/mutating-tools system is ever considered for porting — regardless
of the shell-quote question specifically.

---

## What I did NOT do here (deliberately out of scope)

- Did not wire any of this code into ares-auditor's actual build/pipeline
- Did not touch ARES-v2 itself — no delete, no archive yet
- Did not decide the queue-language question — that's Khashia's call

## Still needs your sign-off

1. ~~**Archive vs. delete ARES-v2**~~ — **Resolved:** confirmed archive
   (not delete). Team is still tidying up the repo before that happens.
2. **Confirm the queue-duplication question** with Khashia before anyone
   spends time porting BullMQ code that might be replaced by her Arq work.
3. **Decide whether to open real tickets** for the missing engine tools
   listed above, or leave them archived in `legacy-ares-v2/` indefinitely.

---

## Addendum — ARES-v2's open Dependabot alerts (280 total, `is:open`)

The repo's Security tab surfaced two things worth separating clearly,
since they carry very different urgency:

**A. Directly relevant to this salvage work.** Covered above —
`generate-pdf-report-tool.ts`'s `jspdf` dependency has six open
critical/high advisories. None of this reached ares-auditor's actual
`package.json` (only source was copied into `legacy-ares-v2/`, outside the
build), so nothing here affects what's being handed off. The correction is
purely about not recommending this tool for a future port without first
addressing those advisories.

**B. Not part of this task, but more urgent, and worth raising separately.**
The bulk of the 280 alerts — Next.js SSRF via WebSocket upgrades, axios
prototype-pollution MITM, node-tar decompression DoS, protobufjs arbitrary
code execution, a Vitest UI arbitrary file read/execute — live in
`apps/web`, `apps/worker`, and `deepagentsjs`, none of which this salvage
touched. But combined with the still-active "PayAI reconciliation" cron
job found in `.github/workflows`: **is that scheduled job actually running
against code with these open critical vulnerabilities right now?** That's
a live-production question, independent of whether/when the repo gets
formally retired. I'd flag this to whoever owns that job sooner rather
than folding it into this consolidation task — retiring the repo
eventually doesn't address a workflow that may still be executing against
vulnerable dependencies today.
