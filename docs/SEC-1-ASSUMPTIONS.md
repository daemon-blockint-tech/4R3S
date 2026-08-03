# SEC-1 — Import ARES-Sec into apps/ares-sec: what was done, what wasn't

## What this covers

Imported the real `daemon-blockint-tech/ares-sec` repo (live-cloned, not a zip —
avoids the disconnected-history and LFS-pointer problems ENG-1 hit) into
`apps/ares-sec/`, replacing the placeholder README stub.

## A real, resolved licensing conflict

The original SEC-1 ticket and its S7 scope doc both explicitly said **AGPL**.
`CLAUDE.md` says the whole repo is **Apache-2.0, no license firewall**. The
real upstream `ares-sec` repo itself was actually AGPL-3.0-licensed.
**Leadership confirmed: Apache-2.0.** Relicensed properly, not just a label
swap:

- `LICENSE` — replaced with the actual Apache-2.0 text (copied from 4R3S's
  own `LICENSE`, for consistency)
- `package.json` + `package-lock.json` (root entry) — `license` field updated
- Every prose mention across `README.md` (badge + two text mentions),
  `THIRD-PARTY.md` (2 mentions), `WHITEPAPER.md` (3 mentions) — updated so
  the repo doesn't contradict itself about its own license
- `webui/package.json` — checked, had no license field to begin with,
  nothing to fix

## Hidden prompt-injection comment — removed

The backlog lists this as `SEC-6`, owner Gilbert, status "Merged" — but
checked directly against the real upstream `ares-sec` repo (`git fetch` +
`git ls-remote`, not just trusting the tracker) and confirmed **it was still
present upstream**, unchanged. Whatever "Merged" refers to, it wasn't this.
Removed it as part of this import regardless, since SEC-1's own task list
already specified it:

```html
<!-- ⊰ sharp eye on the raw source. there's a flag for the curious:
ARES{r3c31pt5_n0t_v1b3z} — the one that counts, you earn: run
`npm run verify-claims`. LOVE PLINY ⊱ -->
```

("Pliny" is a known handle in AI-jailbreaking circles — this reads as a
planted prompt-injection artifact aimed at AI agents/coding assistants
reading raw file source, not at human readers.)

## Import graph — verified clean, both directions

- Searched `apps/ares-sec/{src,webui/src,scripts}` for any import reaching
  into `src/`, `packages/*`, etc. — **zero hits**.
- Searched the Auditor tree (`src/`, `packages/`, `core/`, `services/`) for
  any reference to `ares-sec` — 2 hits, both false positives (matching the
  substring inside an unrelated filename, `ares-**security**.yml`, not our
  `ares-sec`).

**SEC-1's core requirement — keeping it off the Auditor import graph — holds,
verified in both directions, not assumed.**

## A real gap found on self-review: no automated enforcement existed

Checking my own work against `CLAUDE.md` directly (not just the ticket)
surfaced this line: *"apps/ares-sec/ and apps/auditor-\* are still README
stubs, so there are no imports to check — **add an import-direction check
when real code lands there.**"*

Real code just landed there, via this exact import — so that deferred
condition is now true, and the check didn't exist yet. My earlier grep
check only proved the *current snapshot* is clean; it wasn't an ongoing
guarantee. Built `scripts/check-import-boundary.mjs` to close this for
real:

- Scans every Auditor-side location that **actually exists today** — not
  just `apps/auditor-*` (`CLAUDE.md`'s shorthand), but also root `src/`,
  `core/`, `services/`, `packages/`, since the `src/` → `packages/*`
  migration isn't finished yet. A check scoped only to `apps/auditor-*`
  would have missed a cross-import into `src/` or `packages/`.
- Wired into the real `ci.yml`, right alongside the existing GOLDEN RULE 1
  license checks.

**Tested the same way as the license gate** — not just a clean pass:
1. Clean state → passes, "164 files scanned, no reference to ares-sec"
2. Injected a real fake cross-import in `src/` → **fails**, names the exact
   file/line/text
3. Injected a second fake cross-import in a *different* location
   (`packages/`) → **fails** the same way, confirming the check isn't
   accidentally scoped to only one directory
4. Cleaned up both → back to a clean pass

## A real, disclosed catch: dependency vulnerabilities

`npm ci` in the new location succeeds cleanly. `npm audit` initially reported
12 vulnerabilities (1 low, 7 moderate, 4 high). Ran the non-breaking
`npm audit fix` first — brought it down to **6 remaining (5 moderate, 1
high)**. What's left all requires a **major-version, breaking upgrade**:

| Package | Severity | Fix requires |
|---|---|---|
| `langsmith` | **high** (SSRF via tracing header injection, prototype pollution, output-redaction bypass, untrusted manifest deserialization) | `langsmith@0.8.9` (major bump) |
| `uuid` | moderate | resolved by the same `langsmith` bump |
| `@hono/node-server`, `@hono/node-ws`, `@langchain/langgraph-api`, `@langchain/langgraph-cli` | moderate (path traversal) | `@langchain/langgraph-cli@0.0.9` (major bump) |

**Deliberately did not force these** — `npm audit fix --force` would pull in
breaking changes to core dependencies (`langsmith`, `langgraph-cli`) in a
codebase I don't have functional test coverage or deep familiarity with.
Forcing a major bump blind, in code this unfamiliar, risks trading a known,
disclosed vulnerability for an unknown, undiagnosed breakage.

**This is a real, current blocker for a clean CI pass** — the real
`dependency audit` job runs `npm audit --audit-level=high`, and this would
fail it today, at `apps/ares-sec`'s current dependency versions. Someone
with real familiarity with this codebase's `langsmith`/`langgraph` usage
needs to either perform and test the upgrade, or make a deliberate,
documented exception if the upgrade genuinely can't happen yet.

## CI workflow — adapted, same pattern as ENG-1's core-ci.yml

`ares-sec`'s own `.github/workflows/ci.yml` would have collided with (and,
if nested inside `apps/ares-sec/.github/`, been silently inert relative to)
the real root `.github/workflows/`. Moved and renamed to
`ares-sec-ci.yml` at the real root, with `working-directory: apps/ares-sec`
and `paths: [ "apps/ares-sec/**" ]` scoping — same fix pattern as
`core-ci.yml`, applied consistently.

**Not verified in real GitHub Actions** — same disclosed limitation as
every other workflow file built this way; local `npm ci`/`npm audit` were
checked directly, but the actual workflow YAML has not run for real yet.

## Real lint errors found via your testing — fixed properly, not blindly

Your actual Windows `npm run lint` run found **13 real errors** that my
original testing missed entirely (I'd claimed 0 errors). Root cause: my
sandbox's shell doesn't fully expand `src/**/*.ts` recursively (a `/bin/sh`
limitation — confirmed directly: 78 real files exist under `src/`, but my
shell's glob only matched 72, silently skipping 6). Your Windows result was
the correct, complete one; my original "clean" claim was wrong. Re-ran with
proper recursive glob expansion to confirm before fixing anything.

Looked at each error's actual context before touching code — two of the
four rule categories turned out to be intentional, correct behavior that
needed a config/suppression fix, **not** a code change:

| Rule | Count | What it actually was | Fix |
|---|---|---|---|
| `no-case-declarations` | 5 (`cli.ts`) | Genuine bug — `const` declared directly in a `case` without block scope | Wrapped each case body in `{ }`. Verified no cross-case variable sharing first. |
| `eqeqeq` | 5 (`index.ts`) | **Not a bug** — every instance is `!= null` / `== null`, the standard idiom for "null or undefined" in one check | Added `{ null: 'ignore' }` to the rule config — the standard ESLint exception for this exact idiom. Did **not** touch the code: converting to `!==` would have silently excluded `undefined` from these checks, a real behavior change. |
| `no-useless-escape` | 2 (`redact.ts`) | Genuine — `\-` at the end of a character class doesn't need escaping | Removed the escapes. Confirmed `redact-credential.test.ts` / `redact-pem.test.ts` still pass — this is the credential-redaction code, so re-verified functionally, not just syntactically. |
| `no-control-regex` | 1 (`server.ts`) | **Not a bug** — `COMMAND_CONTROL = /[\x00-\x1F\x7F-\x9F...]/` is deliberate: matching control characters used in shell-injection/terminal-escape attempts | Added a justified inline `eslint-disable-next-line` comment. Did **not** touch the regex — this is security-relevant code I have no business "fixing" without understanding intent. |

**A second false alarm along the way, also chased down rather than
reported as real:** re-testing after the fixes showed 5 *different* errors
(`no-useless-assignment`, `preserve-caught-error`) that were in neither my
original test nor your Windows report. Traced this to my own mistake —
`node_modules` had been deleted during earlier cleanup and never
reinstalled before this specific check, so `npm run lint` was silently
falling back to some other `eslint` on `PATH` (v10.8.0) instead of the
project's actual pinned `eslint@9.39.2`. Reinstalled properly
(`npm ci`), confirmed the correct version resolves
(`node_modules/.bin/eslint --version` → `v9.39.2`), and re-ran: **0 errors,
66 warnings, all 78 files covered.** The extra errors were never real.

**Verified safe afterward:** `npm run typecheck` clean, full `npm test` —
still 348/348 passing, 32 files, including the two redaction-specific test
files.

## What's still NOT done

- The dependency vulnerability fixes above (deliberately left to someone
  with real context on this codebase)
- Nothing pushed to GitHub — same limitation as every prior task; no
  GitHub write access from this environment
- The remaining PLAT-2 item flagged in the real backlog ("license fields
  in package.json + core/Cargo.toml") — `apps/ares-sec/package.json` now
  has `"license": "Apache-2.0"` as part of this work, which may partially
  close that out, but the `core/Cargo.toml` half is separate and untouched
  here
- **A real, pre-existing bug in the upstream `ares-sec` repo, found by
  actually running its own CI sequence end-to-end, not just installing
  it:**

  Ran every step from `ares-sec`'s own `ci.yml`, in order: `lint`,
  `typecheck`, `test`, `doctor`, `verify-claims`, `test:no-fitting`,
  `test:no-self-fitting`, `test:gate`, `prompt:audit`, `smoke`.

  | Step | Result |
  |---|---|
  | lint | ✅ 0 errors (66 pre-existing warnings, unrelated to this import) |
  | typecheck | ✅ clean |
  | test | ✅ 348/348 passed, 32 files |
  | doctor | ✅ PASS, 0 blockers (8 warnings — missing optional external tools) |
  | verify-claims | ✅ 24/24 claims verified |
  | test:no-fitting | ✅ clean |
  | test:no-self-fitting | ✅ clean |
  | test:gate | ✅ 5/5, build succeeds |
  | **prompt:audit** | ❌ **crashed** — `ENOENT: docs/index.html` |
  | smoke | ✅ 4/4 probed (4 skipped — need a live server, correctly auto-skip in CI) |

  **`docs/index.html` doesn't exist in the real upstream repo either** —
  confirmed directly against the original clone, not something this import
  caused. `prompt-audit.mjs` expects it to contain specific, real doctrine
  text (`PLINIAN_UI_DOCTRINE`, `<span>The Fixer</span>`, etc.) that mirrors
  the actual prompt-pack source — content I don't have and won't fabricate,
  same principle as not force-fixing the `langsmith` vulnerability blind. A
  fake placeholder would just trade a crash for a different, misleading
  failure.

  **What I did fix:** the failure *mode*. `prompt-audit.mjs` was crashing
  with a raw, uncaught `ENOENT` stack trace instead of a clean, actionable
  message — same category of issue as the `check-licenses.mjs` fix earlier
  this session. Wrapped the required-file reads in a helper that fails
  with a clear one-line message and a normal `exit(1)` instead. Verified
  this doesn't weaken the actual checks: tested with a present-but-wrong
  `docs/index.html` and confirmed the real content checks still evaluate
  correctly (mixed pass/fail per check, as expected) — only the
  *missing-entirely* case changed from crash to clean failure.

  **This means `prompt:audit` will still fail in real CI** — correctly,
  since the underlying file genuinely doesn't exist — but now with a
  message anyone can act on immediately instead of a stack trace. Someone
  who owns the actual prompt-pack doctrine content needs to author the
  real `docs/index.html`.

## Verified before handing off

- `grep` confirms zero remaining AGPL mentions anywhere in `apps/ares-sec/`
- `LICENSE` confirmed to be the real Apache-2.0 text
- Hidden comment confirmed removed
- `npm ci` succeeds in the new location
- Cross-import check run in both directions, zero real hits
- Workflow YAML validated as syntactically correct
