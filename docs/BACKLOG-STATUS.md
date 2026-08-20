# Backlog status (in-repo, git-derived)

> **The authoritative planning source is `docs/BACKLOG.xlsx`** (task IDs, scope,
> owners, and full status), which is maintained **outside this repository** and
> is not committed here — the same applies to `docs/PRD.md` and
> `docs/DEVELOPMENT_PLAN.md` that CLAUDE.md references.
>
> This file is a lightweight, **git-verifiable complement**: it records which
> backlog-ID'd tasks have actually **landed on `main` via a merged PR**, so
> anyone working in the tree has an in-repo view without the spreadsheet. It says
> nothing about tasks that are in-progress, blocked, or planned — for those, and
> for the canonical Status column, see the external backlog.
>
> Rows are derived from merged-PR titles/branches. "Merged PR" is the
> highest-numbered merged PR whose title or branch names that ID; a task can have
> more than one. Update this file when you merge an ID-bearing PR.

## Landed in the 2026-08-20 maintenance round

Reviewed and merged this round (see each PR for the deep-review notes):

| ID | Task | PR | Status |
|----|------|-----|--------|
| ENG-5 | Improve local judge (source-pattern probes, suppression scoring) | #165 | Merged |
| INT-3 | Expose scan/enrich as MCP agent tools (stdio server) | #177 | Merged |
| INT-5 | GitHub Action wrapping the consolidated CLI + severity gate | #167 | Merged |
| SEC-2 | War Room / Op Admiral polish | #174 | Merged |
| SEC-3 | Scope containment default-on + dangerous-tool gating | #178 | Merged |
| SEC-5 | Exact-match verify-claims against README literals | #179 | Merged |
| SVC-4 | Evidence bundling (Merkle) + on-chain anchoring | #176 | Merged |

Maintenance / dependency work merged the same round (no backlog ID):

| Change | PR | Status |
|--------|-----|--------|
| ares-sec CI: clear lint + typecheck failures blocking the `test` job | #180 | Merged |
| ares-sec dep group: drop the breaking `typescript` 7.0.2 bump, keep langchain/langsmith | #172 | Merged |
| npm root group (7 updates) | #173 | Merged |
| pyarrow / numpy / httpx2 bumps | #168 / #169 / #170 | Merged |
| ares-sec webui `oxlint` bump | #171 | Merged |
| Cover `supabase-retriever.ts` (RRF path) | #166 | Merged |

## Open follow-ups

| Item | Tracking | Note |
|------|----------|------|
| SEC-1 | issue #181 | Import is **not fully complete** — `apps/ares-sec/docs/index.html` is still missing, so `npm run prompt:audit` (last red step in ares-sec CI) can't pass. Restore it from the SEC-1 upstream; do not fabricate it. |

## All backlog IDs with at least one merged PR on `main`

Git-derived index (latest merged PR per ID). Presence here means "landed", not
"closed in the external backlog" — a task may still have open follow-up rows there.

| ID | Latest merged PR | Merged |
|----|------------------|--------|
| BIZ-1 | #73 | 2026-08-06 |
| BIZ-2 | #163 | 2026-08-18 |
| DET-1 | #115 | 2026-08-07 |
| DET-2 | #117 | 2026-08-07 |
| DET-3 | #139 | 2026-08-08 |
| DET-4 | #141 | 2026-08-08 |
| DET-5 | #142 | 2026-08-08 |
| ENG-1 | #41 | 2026-08-04 |
| ENG-2 | #69 | 2026-08-06 |
| ENG-3 | #77 | 2026-08-07 |
| ENG-5 | #165 | 2026-08-20 |
| EVAL-1 | #28 | 2026-07-30 |
| EVAL-2 | #70 | 2026-08-06 |
| EVAL-3 | #107 | 2026-08-07 |
| EVAL-4 | #131 | 2026-08-08 |
| EVAL-5 | #135 | 2026-08-08 |
| EVAL-6 | #141 | 2026-08-08 |
| INT-1 | #146 | 2026-08-12 |
| INT-2 | #156 | 2026-08-13 |
| INT-3 | #177 | 2026-08-20 |
| INT-5 | #167 | 2026-08-20 |
| KR-1 | #48 | 2026-08-04 |
| KR-3 | #76 | 2026-08-07 |
| KR-4 | #75 | 2026-08-07 |
| LAT-1 | #106 | 2026-08-07 |
| LAT-2 | #105 | 2026-08-07 |
| LAT-3 | #106 | 2026-08-07 |
| LAT-4 | #139 | 2026-08-08 |
| ORC-1 | #42 | 2026-08-04 |
| ORC-2 | #145 | 2026-08-08 |
| ORC-3 | #149 | 2026-08-12 |
| ORC-4 | #151 | 2026-08-12 |
| PLAT-1 | #74 | 2026-08-06 |
| PLAT-2 | #29 | 2026-07-30 |
| PLAT-3 | #137 | 2026-08-08 |
| PLAT-4 | #140 | 2026-08-08 |
| POC-1 | #35 | 2026-08-03 |
| POC-3 | #160 | 2026-08-18 |
| POC-4 | #139 | 2026-08-08 |
| SEC-1 | #116 | 2026-08-07 |
| SEC-2 | #174 | 2026-08-20 |
| SEC-3 | #178 | 2026-08-20 |
| SEC-5 | #179 | 2026-08-20 |
| SVC-1 | #150 | 2026-08-12 |
| SVC-4 | #176 | 2026-08-20 |
| UI-1 | #161 | 2026-08-18 |
