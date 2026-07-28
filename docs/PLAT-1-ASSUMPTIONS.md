# PLAT-1 — Assumptions pending your sign-off

I built both monorepo shells locally so you can review/push them rather than
waiting on every open decision. Nothing here is final — override any of it.

| Decision | What I assumed | Why | Still needs your call |
|---|---|---|---|
| Names | `ares-auditor`, `ares-sec` | These are the working names throughout the backlog | Confirm final / check trademark |
| ares-auditor license | Apache-2.0 | Carried over as-is — it's literally the same 4R3S codebase, renamed | Confirm you want continuity, not a fresh license choice |
| ares-auditor version | `0.1.0` (unchanged from 4R3S) | Same code, just renamed — resetting to 0.0.0 felt misleading | Confirm or override |
| ares-sec license | AGPL-3.0 | PLAT-2's gate implies AGPL is meant to live in Sec, not Auditor | Confirm this inference is correct — nothing in the backlog says AGPL explicitly, I inferred it |
| ares-sec version | `0.0.0` | New product, empty shell, no prior code | — |
| Billing code location | Stays in ares-auditor (`src/billing`) | BIZ-1/BIZ-2 are tagged "Platform" product in the backlog, not "ARES-Sec" | Confirm — I could be wrong about this split |
| GitHub org | **Not set** — left as a placeholder | This is genuinely yours to decide (I have no GitHub access anyway) | You tell me, or just push these yourself wherever they belong |
| Visibility | **Not set** | Same reason | Your call |

## Fixes applied — v0.1.1 (post-test)

Before handing this off, I ran the actual CI sequence locally (`npm ci` →
typecheck → lint → build → test) and it failed at the very first step.
Fixed and re-verified clean:

1. **`npm ci` failed outright.** `package.json` pinned `typescript@^7.0.2`,
   but the installed `typescript-eslint@8.65.0` only supports
   `typescript >=4.8.4 <6.1.0`. Repinned to `^5.9.3` and regenerated
   `package-lock.json`.
2. **2 typecheck/build errors in `src/config/env.ts`.** `POSTGRES_SSL` and
   `CUA_ENABLED` used a zod v3-era `.transform().default("false")` pattern;
   under the installed `zod@4.4.3` this requires `.default()` before
   `.transform()`. Reordered both.
3. **Lint crashed** for the same root cause as #1 — resolved once the
   TypeScript pin was fixed.

Verified clean afterward: `npm ci`, `npm run typecheck`, `npm run lint`,
`npm run build`, and `npm test` (138/138 passing, 20/20 files) all pass.
Bumped to `v0.1.1` since these are real fixes, not just a rename.

## What's NOT done yet (deliberately out of scope for PLAT-1)
- Salvaging `packages/engine`, `packages/observability`, `packages/queue` from
  ARES-v2 — that's PLAT-3, not this task. I have ARES-v2 extracted and ready
  to pull from when you want to move to that one.
- Actually pulling ARES-v3 in as `core/` with the 54 tests — that's ENG-1,
  and depends on which repo is actually "ARES-v3" (still unclear — is it a
  third codebase, or is 4R3S/ares-agent actually what's meant by that name in
  the backlog? Worth clarifying before ENG-1 starts).
- Pushing anything to GitHub — I can't reach GitHub from this environment.
  These are local, ready-to-push folders.
