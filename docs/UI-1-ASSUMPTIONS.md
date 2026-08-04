# UI-1 — Extract War Room tokens + components into packages/ui

## Scope decision, stated upfront

Real backlog row: *"Extract War Room tokens + components into permissive
UI package | Home: packages/ui | Ref: ares-sec webui (War Room)."*

**Extracted to `packages/ui` (genuinely shareable design-system layer):**
- `src/index.css` → design tokens (dark/light theme pairs, primitives →
  semantic layering, base element styles)
- 12 shadcn/ui primitives: `badge`, `button`, `card`, `dialog`, `input`,
  `scroll-area`, `select`, `separator`, `sonner`, `tabs`, `textarea`,
  `tooltip`
- `lib/utils.ts` (`cn()` helper)
- `common.tsx` — `PageHeader`, `EmptyState`, `LoadingState`, `ErrorState`,
  `Field`, plus `severityClass`/`riskClass` (kept — the Auditor side uses
  the same critical/high/medium/low vocabulary, genuinely reusable)

**Deliberately left in `apps/ares-sec/webui` (app-specific, not shared):**
- `nav.ts`, `AppShell.tsx`, `Header.tsx`, `Sidebar.tsx` — these compose
  ares-sec's *own* specific navigation/routes, not generic design-system
  pieces
- All of `pages/*.tsx`, `ApprovalModal.tsx` (confirmed via its actual
  imports — tied to ares-sec's own approval-gate domain logic)

**How it's wired in:** the original 12 component files + `utils.ts` +
`common.tsx` in `webui` are now thin re-export shims pointing at
`@ares/ui`, so all ~30 existing consuming files across `webui`'s pages
needed **zero import-path changes**. `index.css` now imports
`@ares/ui/styles.css` instead of defining tokens locally. This was a
deliberate scoping choice — rewriting every consuming file's imports to
point directly at `@ares/ui` is a bigger, riskier change explicitly
deferred to `UI-2`/`SEC-2` ("Apply design system to... War Room"), not
this task.

## A real blocker found, and the decision to fix it properly

Wiring `webui` to consume `packages/ui` via npm's `file:` protocol (no
real workspace linkage existed before this) surfaced a genuine TypeScript
error: `ForwardRefExoticComponent`/`RefAttributes` type mismatches,
because `packages/ui` and `webui` each had their own **physically
separate** copy of `react`, `lucide-react`, etc. TypeScript treats two
distinct physical copies as incompatible even at the identical version.

Tested and ruled out two narrower fixes before deciding on the real one:
- Removing `packages/ui`'s own `node_modules` entirely — traded 25 clear
  duplicate-type errors for 35 *worse*, silent `implicit any` errors
  (type resolution failing entirely, not just conflicting)
- `preserveSymlinks: true` in `webui`'s tsconfig — tested directly, no
  effect; the duplication lives in `packages/ui`'s own *physical*
  `node_modules`, not a symlink-resolution question

**Decision: activated real npm workspaces at the root** (`workspaces:
["packages/*", "apps/*", "apps/ares-sec/webui"]` — the explicit third
entry needed since `webui` nests one level deeper than the `apps/*` glob
reaches). This is the architecturally correct fix — matches what
`PLAT-1`'s own progress notes had already flagged as unfinished — but is
a bigger, repo-wide structural change than `UI-1`'s own scope, so it's
called out explicitly here rather than treated as a routine side effect.

## Three more real bugs, found chasing the fix through to a genuinely complete build

**1. `packages/ui`'s own internal imports used a TS-only path alias.**
`dialog.tsx` and all 12 components imported `cn`/`Button` via `@/...` —
resolves fine for TypeScript's type-checking, but `tsc`'s compiled output
does *not* rewrite these; the literal, unresolvable string `"@/lib/utils"`
shipped in `dist/*.js`, causing `[UNLOADABLE_DEPENDENCY]` at actual Vite
build time (JS runtime has no idea what `@/...` means without a bundler
alias). Fixed by converting all 12 internal cross-references to real
relative imports. `packages/ui` ships plain `tsc`-compiled JS with no
bundler step of its own — path aliases don't survive that.

**2. `TS5103: Invalid value for '--ignoreDeprecations'`, isolated
precisely.** This is genuinely unrelated to the workspace change — proven
by testing `tsc -p` (direct) vs `tsc -b` (project-reference build mode)
in isolation: identical config, identical version, `-p` succeeds, `-b`
fails, for any value tried. A real TypeScript `6.0.3` tooling bug/
limitation specific to `-b` mode + this option across project references.
Fixed by changing `webui`'s `build` script to invoke both referenced
projects directly via `-p` instead of `-b`.

**3. A confusing wrong-PATH detour, fully root-caused.** After the `-p`
fix, `npm run build` *still* failed — but the identical command via `npx`
succeeded. Traced to `webui` being nested *inside* another workspace
member's own directory (`apps/ares-sec`), an unusual arrangement that
confuses npm's automatic PATH setup for scripts: it was picking up
`apps/ares-sec`'s own separate, older `typescript@5.9.3` instead of the
correctly-hoisted root `6.0.3`. Confirmed precisely by explicitly
prepending the correct root `node_modules/.bin` to `PATH` — that alone
fixed it. Real fix: use `npx tsc -p ...` explicitly in the script, which
reliably resolves correctly regardless of this nesting quirk. Verified
with a fully reset, unpolluted `PATH` (not just re-running in an
already-correct shell) to be sure this wasn't another false positive.

**After all three fixes: the complete, real `npm run build` succeeds
end-to-end** — both `tsc -p` type-checks *and* the actual `vite build`,
producing real output (`dist/index.html`, a 40KB CSS bundle, a 765KB JS
bundle — one benign "consider code-splitting" warning, not an error).

## Two more things caught during full re-verification

**A false positive in `scripts/check-import-boundary.mjs` (built during
`SEC-1`).** Its own regex matched *any* line containing the substring
"ares-sec" — including this doc's own provenance comment in
`packages/ui/src/index.ts`. Fixed to only match actual
`import.../require(...)` statements targeting an ares-sec path, not
prose. Re-verified: still correctly catches a real injected violation,
still passes clean on the actual current state.

**Root's own `vitest.config.ts` had no `include`/`exclude` scoping at
all.** Harmless while `apps/*` were empty stubs; once `SEC-1` put real
test files under `apps/ares-sec`, root's test runner started silently
picking them up too — including `apps/ares-sec/dist`'s *compiled* test
output, causing 6 confusing duplicate "failed suite" entries even though
every individual test that ran still passed. Fixed by scoping root's
config to `src/**/*.{test,spec}.ts` only, explicitly excluding
`apps/**`/`packages/**`/`core/**` — each already manages its own tests
independently.

**One thing checked and found to be a non-issue:** an odd stdout line
(`"injected env (0) from .env // tip: ... [www.vestauth.com]"`) looked
similar in flavor to the hidden prompt-injection comment found in
`ares-sec` during `SEC-1`. Traced directly to `node_modules/dotenv/lib/main.js`
— this is the `dotenv` package's own known (if debatable) practice of
printing promotional "tip" messages on `.env` load. Legitimate, if
mildly obnoxious, third-party library behavior — not a security concern,
and not the same class of issue as the earlier finding. Worth checking
rather than assuming, but nothing to fix here.

## A real, disclosed vulnerability finding — not forced

`webui`'s own `npm audit` (never checked before — it's a separate
sub-package with its own dependencies) found 5 high-severity issues.
Traced `next`/`postcss`/`sharp` to an unused transitive dependency of the
`geist` font package (same class of issue as the `bigint-buffer`/
`spl-token` finding from `PLAT-2` — a heavy, vulnerable dependency pulled
in for functionality this code doesn't actually use). Ran the safe,
non-breaking `npm audit fix` — resolved 3 of 5. **The remaining 2
(`react-router` CSRF) need a breaking downgrade — deliberately not
forced**, same principle as the `langsmith` decision in `SEC-1`.

## What's still NOT done

- Full call-site migration of `webui`'s ~30 consuming files to import
  directly from `@ares/ui` instead of through the re-export shims —
  explicitly deferred to `UI-2`/`SEC-2`
- The `react-router` CSRF vulnerability fix (breaking change, needs
  someone with real context on `webui`'s router usage)
- `apps/auditor-web` doesn't consume `packages/ui` yet — it's still a
  README stub; nothing to wire up until real code lands there
- `AppShell`/`Header`/`Sidebar`/`nav.ts` extraction — deliberately scoped
  out as app-specific; worth revisiting once a second app (the Auditor
  dashboard) actually needs a comparable shell
- Nothing pushed to GitHub — same limitation as every prior task

## Verified before handing off

Full re-verification after every fix above, not just the last one:
- Root: `typecheck` ✅, `lint` ✅, `test` (32 files / 276 tests) ✅
- Root: `check-licenses.mjs` ✅ (153 packages, no GPL/AGPL), `check-import-boundary.mjs` ✅
  (179 files, correctly catches a real injected violation, no false positive)
- `packages/ui`: builds clean, 0 `tsc` errors, compiled output confirmed
  free of unresolved path aliases
- `apps/ares-sec`: test suite unaffected by the workspace change (32
  files / 348 tests, unchanged from `SEC-1`'s verification)
- `apps/ares-sec/webui`: the complete, real `npm run build` succeeds —
  both type-checks and the actual `vite build`, real `dist/` output
  produced
