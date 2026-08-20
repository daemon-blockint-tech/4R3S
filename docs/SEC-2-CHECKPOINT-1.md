# SEC-2 — Checkpoint 1: WarRoomPage consolidation + missing header

First-pass polish investigation across all 15 War Room + Op Admiral pages,
per direction to look for genuine issues myself before asking for
subjective feedback.

## Two real, confirmed findings — both in `WarRoomPage.tsx`

1. **A byte-for-byte duplicate `SEVERITY` color mapping** — identical to
   the shared `severityClass()` helper already in `packages/ui` (from
   `UI-1`). Two other pages (`BountyPage`, `EvidenceVaultPage`) already
   correctly use the shared version; `WarRoomPage` — ironically the
   flagship page this whole design system was extracted *from* — never
   got updated to match. Confirmed identical values before touching
   anything, so this consolidation carries zero risk of changing how
   anything actually renders.
2. **No `PageHeader` at all** — every other content page in the app uses
   one for a consistent title + description before diving into content.
   `WarRoomPage` jumps straight into a "Start a hunt" card instead. This
   isn't like `TerminalPage`'s justified omission (a real, intentional
   full-screen terminal UX) — `WarRoomPage` uses the exact same
   card-based layout structure the header-using pages do; it just never
   got one.

## What I checked and correctly ruled out, not just assumed fine

- `TerminalPage`'s missing header — genuinely justified, not a gap
- `AdmiralPage`'s toast-based error handling instead of `ErrorState` —
  reasonable, different pattern appropriate for a mutation-heavy page
- `WarRoomPage`'s lack of an explicit loading spinner — a working
  defensive pattern (optional chaining with fallbacks), not broken
- 4 other page-local `Record<string, string>` style constants
  (`KIND_TONE`, `NEXT_STATUS`, `STATUS_TONE`, `STATUS_COLOR`) — all
  genuinely different domain concepts (graph node kinds, workflow state
  transitions, operative activity status), not duplicates of anything
  shared
- Icon-only buttons for accessibility gaps — none found using the
  `size="icon"` pattern in this codebase

## The fix

- Removed the local `SEVERITY` constant; imported `severityClass` from
  `@/components/common` (the same shim every other page already uses)
- Replaced `SEVERITY[f.severity] ?? SEVERITY.info` with
  `severityClass(f.severity)` — behaviorally equivalent, plus a small
  correctness improvement: the shared helper also lowercases its input,
  which the original inline lookup didn't
- Added `<PageHeader title="War Room" description="..." />`, matching
  the exact label used in the app's own navigation (`nav.ts`) and the
  description tone already used by other pages (e.g. `BountyPage`)

## Verified

- Confirmed the `SEVERITY` values were byte-identical between
  `WarRoomPage` and the shared helper *before* consolidating, not
  assumed
- Real `tsc` typecheck run against the actual file (working around the
  same pre-existing, already-confirmed-unrelated `baseUrl` issue from
  earlier sessions): 3 `implicitly has an 'any' type` errors appear —
  confirmed via `git stash` that these are pre-existing, at the exact
  same relative position, unaffected by this change
- Brace/paren balance on the diff: perfectly even (`1`/`1`, `1`/`1`)

## To verify

```powershell
cd apps\ares-sec\webui
npx vite build
```

**Expected:** a successful build. (Typecheck via `tsc` will show the
pre-existing `baseUrl` config error and the 3 pre-existing, unrelated
`implicitly any` errors — both already confirmed unrelated to this
change.)
