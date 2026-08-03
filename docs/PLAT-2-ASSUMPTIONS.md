# PLAT-2 — License decision + CI license-gate: findings and sign-off needed

## A spec mismatch worth flagging first

PLAT-2's to-do explicitly names `cargo-deny` — a Rust-ecosystem tool. There
is no `Cargo.toml`/`Cargo.lock` anywhere in `ares-auditor`; it's 100%
TypeScript/npm. `cargo-deny` cannot gate anything here because there's no
Rust code for it to gate — this is the same category of issue as ENG-1
(the task spec assumes a codebase that doesn't match what's actually been
delivered).

**What this doc implements instead:** the same license-gate approach
already built and proven for PLAT-4 (`ares-shared`), adapted for a single
npm package instead of a workspace, applied directly to `ares-auditor`'s
own real dependency tree. If Rust code lands later (per ENG-1, once
ARES-v3 is clarified), `cargo-deny` becomes genuinely relevant *in
addition to* this — not instead of it.

## License decision

Per PLAT-1's assumption (still pending your confirmation there):
**Apache-2.0** for `ares-auditor`. This doc doesn't revisit that decision —
it enforces it going forward via CI.

## The actual audit — real findings, not a stub

Unlike `ares-shared`'s scaffold (which has zero real dependencies yet),
`ares-auditor` has a real, populated dependency tree — **163 total
production dependency instances** (including transitive). Running the
gate against it surfaced **3 genuine findings** that need a decision:

| Package | Version | Issue | Comes from |
|---|---|---|---|
| `rpc-websockets` | 9.3.9 | **`LGPL-3.0-only`** — confirmed directly from its own `package.json`, not inferred | `@solana/web3.js` (direct dependency) |
| `scrapybara` | 2.5.2 | No license declared in `package.json` at all | `@langchain/langgraph-cua` (the opt-in browser/CUA investigation feature) |
| `text-encoding-utf-8` | 1.0.2 | No license declared in `package.json` at all | `@solana/web3.js` → `borsh` |

**`rpc-websockets` is the one that actually matters.** LGPL-3.0 is
copyleft — outside the permissive allow-list by design. Whether this is
actually a problem depends on how it's used here (as an unmodified
dynamically-linked library dependency, LGPL typically doesn't force the
whole project to be LGPL — but that's a legal reading, not something this
script or I should adjudicate). **This needs an actual decision from
whoever owns the license call**, not a default assumption either way.

The other two are just undeclared metadata, not confirmed problem
licenses — worth a quick manual check of each project's actual repository
(linked in the table above via their `package.json`) to confirm what
license they're actually under, then either fixing the record or filing
an upstream issue.

**Also surfaced, out of scope for this task but worth knowing:** `npm
audit` on this same tree shows 3 high-severity findings — a `bigint-buffer`
buffer-overflow (`GHSA-3gc7-fjrx-p6mg`), pulled in via `@solana/spl-token`
→ `@solana/buffer-layout-utils`. This is a long-standing, widely-known gap
in the Solana ecosystem tooling with no clean patched fix currently
available (npm's suggested fix downgrades `@solana/spl-token` to a
pre-Token-2022 version, which isn't a real fix). This is a vulnerability
issue, not a license issue — flagging it here since it surfaced
incidentally during this audit, but it's a separate decision for whoever
owns dependency security, not part of PLAT-2's scope.

## What happens to CI right now

**Merging this will make CI fail immediately** on the existing codebase,
until the `rpc-websockets` question gets a real answer. That's the
intended behavior — PLAT-2 explicitly asked for "sign-off on failing CI
(not just warning)" — but it means this can't just be merged silently;
someone needs to actually decide on `rpc-websockets` first, or use the
exception mechanism below as a temporary, visible placeholder while that
decision is pending.

### Exception mechanism, for when a permissive-only stance is too strict

Added `license-exceptions.json` (empty by default) — a package can be
explicitly allowed through with a required reason, e.g.:

```json
[
  {
    "package": "rpc-websockets",
    "license": "LGPL-3.0-only",
    "reason": "Used as an unmodified dynamic dependency of @solana/web3.js — legal reviewed and confirmed acceptable under LGPL-3.0's linking terms",
    "approvedBy": "<name>",
    "date": "2026-08-01"
  }
]
```

Matching is on **package name AND license together** — if the dependency
updates to a different license later, the old exception stops applying
and the gate re-flags it, rather than silently continuing to pass forever
on a stale approval.

## Bugs found and fixed while building this

Running the exact same resolution approach from PLAT-4 against a real,
much larger, modern dependency tree (163 deps vs. the empty scaffolds in
`ares-shared`) surfaced problems that never showed up on the smaller test
set:

1. **Most modern packages block direct `package.json` subpath access** via
   their `exports` field (`chalk`, `commander`, `openai`, `zod`, all the
   `@solana/*` and `@langchain/*` packages, etc.) — the PLAT-4 version
   would have misreported all of these as resolution failures. Fixed by
   resolving each package's actual main entry point instead (which is
   essentially always exported) and walking up to find its `package.json`,
   rather than requesting the subpath directly.

2. **A real infinite loop**, found by testing against the actual tree, not
   assumed: packages that share a name with a Node.js core module —
   `buffer`, `events`, `process`, `string_decoder` are all real npm
   packages *and* real Node.js builtins. `require.resolve('buffer')`
   returns the bare string `"buffer"` (the core-module shortcut) instead
   of a file path. The directory-walk-up logic then never terminates,
   because `path.dirname(".")` returns `"."` again forever. **This hung
   for 90+ seconds before being traced and fixed** — confirmed by
   instrumenting the script line-by-line to find exactly which dependency
   triggered it. Fixed by detecting a non-absolute resolution result and
   forcing resolution to the real npm package via a trailing slash
   (`require.resolve('buffer/')`), a documented Node.js technique for
   this exact core-module-shadowing case.

3. **False positives on optional, correctly-uninstalled dependencies.**
   Packages like `svelte`, `vue`, `pg-native`, `@aws-sdk/credential-provider-node`
   are declared as optional peer dependencies by other packages (e.g. an
   AWS credential provider some `@langchain` package can optionally use)
   but were correctly never installed here since they're not needed. `npm
   ls --all` still lists them as tree edges with no `version` field. The
   script was treating these as resolution failures (false violations).
   Fixed by only checking dependencies that actually have a `version` in
   npm's own tree output — no installed code means no actual license
   exposure to check.

4. **Legacy `licenses` array format not read.** `eyes@0.1.8` has no modern
   `license` string field, but does have the pre-standardization
   `"licenses": ["MIT"]` array format. The script was reporting this as
   `UNKNOWN` (a false negative — an actually-permissive package flagged
   as needing review). Fixed by checking `licenses[]` as a fallback.

After all four fixes: 43 apparent violations → 3 genuine, verified ones.

## What's still NOT done

- **The actual license decision on `rpc-websockets`** — not mine to make.
- **`ares-sec`'s side of PLAT-2** (an AGPL-permitting gate, per PLAT-1's
  inferred license split) — `ares-sec` is still an empty shell with no
  code (confirmed directly, same as the SEC-1/UI-1 blockers), so there's
  nothing to gate there yet.
- **Manually confirming the real licenses** for `scrapybara` and
  `text-encoding-utf-8` from their actual source repos.
- **Nothing has been pushed to GitHub** — same limitation as every other
  task so far; no org access from this environment.

## Verified before handing off

Full local CI sequence run against the real codebase: `npm ci` →
`typecheck` → `license:check` → `lint` → `build` → `test` (138/138 still
passing, confirming nothing regressed). The exception mechanism was
tested in both directions — confirmed it suppresses exactly the one
exempted finding and nothing else, then reverted to the clean-file state
before handoff.
