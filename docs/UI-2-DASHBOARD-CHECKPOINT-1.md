# UI-2 — Checkpoint: dashboard accessibility fixes

First real application of `UI-2`'s foundation to actual pages, per the
task's own wording ("apply design system to dashboard, landing"). Same
systematic approach used for War Room/Op Admiral in `SEC-2`.

## Investigated first: raw HTML checkbox

Searched the whole app for raw `<input type="checkbox">`. Found one
match, in `tasks-list-client.tsx` — checked precisely and it's a false
positive: that's a CSS selector string (`.closest('input[type="checkbox"]...)`)
used for click-handling logic, not a rendered element. The file already
correctly uses the shared `Checkbox` component. Nothing to fix here.

## Icon-only button accessibility scan — 16 candidates, checked individually

Ran the same heuristic that found a real gap in `AdmiralPage` during
`SEC-2`, across the whole app this time. Broke down into three real
categories, not assumed uniform:

**2 false positives** — my regex mis-stripped a nested `<Link>` with
real, visible text (`task-page-client.tsx`, `settings-page-client.tsx`).
Confirmed by reading each directly; no fix needed.

**4 genuine, severe gaps — fixed.** Zero accessible name at all (no
`title`, no `aria-label`):
- `shared-header.tsx` — the sidebar toggle button (just a `Menu` icon)
- `task-details.tsx` (3 instances) — a PR-actions dropdown trigger and
  two sandbox-actions dropdown triggers (`MoreVertical` icon only)

**10+ instances of a real, disclosed, but *not* fixed here pattern** —
buttons with a `title` attribute but no `aria-label`
(`app-layout.tsx`, `task-chat.tsx`, `home-page-content.tsx`,
`task-sidebar.tsx`, `repo-layout.tsx`, `logs-pane.tsx`, and more within
`task-details.tsx` itself). `title` does provide *some* accessibility,
but screen-reader support for it is inconsistent — unlike `aria-label`,
which is reliably announced. This is different in kind from the 4 fixed
above (zero accessible name vs. a present-but-imperfect one), and
widespread enough across the codebase to look like a real, established
(if imperfect) pattern rather than a one-off oversight. Flagging as a
separate, larger, disclosed finding rather than folding a 10+-file batch
fix into this checkpoint without a chance to weigh in on it first.

## Verified

- `npx tsc --noEmit`: zero new errors in either modified file
  (`shared-header.tsx`, `task-details.tsx`)
- Structural balance on the diff: perfectly even (`1`/`1` braces,
  `0`/`0` parens)
- Each of the 16 candidates read directly in context before deciding —
  not batch-applied on a pattern match alone, learning from the one
  false positive caught during the equivalent War Room scan

## Not done here, deliberately

- The broader `title`-only pattern (noted above)
- Any other dashboard/landing page beyond what this scan covered —
  `home-page-content.tsx` itself (742 lines, the actual landing page
  content) was scanned for this specific pattern but not otherwise
  reviewed component-by-component the way War Room's pages were
