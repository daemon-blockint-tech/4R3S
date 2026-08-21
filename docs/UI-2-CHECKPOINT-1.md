# UI-2 — Checkpoint 1: all 11 overlapping components reconciled

`packages/ui` becomes the single source per direction from the senior;
`auditor-web`'s 11 overlapping components (of 24 total) converted to
shims. 15 `auditor-web`-only components (`accordion`, `alert-dialog`,
`alert`, `avatar`, `checkbox`, `drawer`, `dropdown-menu`, `label`,
`progress`, `radio-group`, `sheet`, `sidebar`, `skeleton`, `switch`,
`table`) are separate, later work — not touched here.

**Not yet done: actually wiring `@ares/ui` into `auditor-web` via
`pnpm install`.** Held off per direction — this requires `pnpm`, which
was paused pending the senior's confirmation on the earlier, separate
`nanoid`-override question. Everything here is real, verified code, but
none of it is *live* in `auditor-web` until that install happens.

## Three real, substantive findings during reconciliation — not just import-path swaps

**1. `sonner.tsx` — genuinely different theme systems, not just different code.**
`auditor-web` (Next.js) has its own custom, SSR-aware theme provider;
War Room (Vite) has none. The shared `Toaster` previously hardcoded
`next-themes`, which neither app's real theme system actually is. Fixed:
made it theme-agnostic (`theme` prop instead of an internal hook call),
each app supplies its own value. Removed the now-unused `next-themes`
dependency from `packages/ui/package.json`. `auditor-web`'s own
`sonner.tsx` became a small wrapper (calling its own `useTheme()` and
passing the result), not a bare re-export like the others.

**2. `badge.tsx` — a real, visible design change, not a safe refactor.**
`packages/ui`'s version is pill-shaped (`rounded-full`) with a
transparent border and 6 variants; `auditor-web`'s was `rounded-md` with
a visible border and 4. Adopting the shared look is the actual point of
`UI-2`, not an accident — but every badge in the app will look visibly
different, not just differently coded. Disclosed directly in the shim's
own comment for whoever reviews this.

**3. `select.tsx` — a real, potentially-breaking behavior conflict,
caught before it caused a problem.** `packages/ui` defaults
`SelectContent`'s `position` to `"item-aligned"`; `auditor-web`'s
previous version defaulted to `"popper"`. Checked every real usage in
both apps (24 across 10 files in `auditor-web`, 10 across 6 files in
War Room) — every single one is bare `<SelectContent>` with no explicit
`position` prop, meaning both apps silently depend on whichever default
applies. Changing the shared default either way would have silently
changed real, live dropdown positioning behavior. Fixed with a small
wrapper in `auditor-web`'s own shim defaulting to `"popper"` there
specifically, without touching the shared package's default or affecting
War Room.

## A real bug I introduced, then found and fixed properly

Converting `dialog`, `separator`, `tabs`, `select` to bare re-exports
initially dropped their original `"use client"` Next.js directive
without me noticing — checked systematically afterward (not just the
one file where I happened to catch it) and found the actual complete
picture: 19 of 24 components genuinely need it (anything wrapping a
Radix primitive), only `badge`/`button`/`card`/`input`/`textarea` don't.

Then found something more precise: `dialog`/`separator`/`tabs` already
had `"use client"` correctly committed in `packages/ui` since the
original `UI-1` extraction — my initial read of this was simply wrong.
The real, remaining gap was 4 files that genuinely never had it since
`UI-1`: `select`, `sonner`, `tooltip`, `scroll-area`. Added it directly
to `packages/ui`'s own source (not each app's shim) — the correct,
single-source fix, and completely inert for Vite/War Room either way.

## The rest — verified genuinely safe, no real differences

`button`, `input`, `separator`, `dialog`, `tooltip`: confirmed
byte-identical or functionally identical (import paths, or cosmetic
quote-style differences only). `card`: one tiny, real, barely-perceptible
spacing difference (`gap-1.5` vs `gap-2` in the header) — disclosed, not
hidden. `textarea`: confirmed programmatically (not just eyeballed) that
both versions contain the exact same set of Tailwind classes, just in a
different order.

## Verified

- `packages/ui`'s own `tsc --noEmit`: zero errors
- A full War Room `vite build`, run repeatedly through each change:
  consistently succeeds, CSS output byte-identical (`40.31 kB`) to every
  previous correct build in this app
- Every "safe swap" claim backed by an actual diff, not assumed —
  including one case (`textarea`) verified programmatically that two
  differently-ordered class strings are the exact same set

**Not verified: any of this actually working inside `auditor-web`
itself.** No `pnpm install` has run, so `@ares/ui` isn't linked there
yet, and nothing here has been build-tested from `auditor-web`'s own
side. That's the necessary next step once you have confirmation to
proceed with `pnpm`.
