# Dependabot Alert #114 — `extract-zip` unvalidated symlink path traversal

**Status: real, currently unpatched, low practical risk. Not something
this investigation could fix — documenting it clearly so it's tracked
rather than lost, and so it's clear this predates recent work rather than
being caused by it.**

## What GitHub's alert actually says

`extract-zip@2.0.1` does not validate symlink targets when extracting zip
archives. A malicious zip containing a symlink with a relative path like
`../../../etc/passwd` gets extracted without validation, allowing writes
outside the intended extraction directory. CVSS 8.6 (High).

**Patched version: `None`.** This is the single most important fact here
— there is currently no fixed version of `extract-zip` to upgrade to. If
anyone goes looking for a version bump that resolves this, they will not
find one, because it does not exist yet. That's not a search failure —
the ecosystem simply hasn't shipped a fix yet.

## Confirmed real, not a phantom/misconfigured alert

Checked directly against the actual lockfile, not just GitHub's summary:

```
apps/ares-sec/package-lock.json:4459:    "node_modules/extract-zip": {
apps/ares-sec/package-lock.json:4461:      "resolved": "https://registry.npmjs.org/extract-zip/-/extract-zip-2.0.1.tgz",
```

Genuinely present in the dependency tree, pulled in transitively:
`@langchain/langgraph-cli 1.4.4` → `extract-zip 2.0.1`.

## Where this actually came from — predates everything recent

```
e92a01d SEC-1 : Import ares sec
```

`@langchain/langgraph-cli` was already a dependency in `ares-sec`'s
**original** `package.json` at the exact moment `SEC-1` first imported
that codebase (as `^1.4.2`) — carried over during the import, not added
by it. Every commit since has been routine Dependabot version bumps
(`f2123f4`, `d2be1a1`), unrelated to any of the recent, unrelated feature
work in this repo. This is not something introduced by `ENG-3`, `ENG-4`,
`INT-1`, or `INT-5` — none of those touched `apps/ares-sec` at all.

## Why the practical risk is low, even though the CVSS score is High

`extract-zip` here is only reachable through two dev-only scripts:

```json
"langgraph:dev": "npx @langchain/langgraph-cli dev --studio-url ...",
"langgraph:up": "npx @langchain/langgraph-cli up",
```

These are local developer tooling commands, not anything that runs in
production or in CI. The actual exploit requires a malicious zip file to
be processed by `extract-zip` specifically — not something a normal
build/deploy/production flow exposes an attacker to. Real vulnerability,
but the actual blast radius today is a developer manually running
`langgraph:dev`/`langgraph:up` against an untrusted zip, not customer
data or production infrastructure.

## What can honestly be done right now

Not much beyond tracking it — since no patched version exists, there is
no version bump available that resolves this today. Options, roughly in
order of how much they actually help:

1. **Track the advisory for a fix.** The responsible default — watch for
   `extract-zip` or `@langchain/langgraph-cli` to ship a patched release.
2. **Consider whether `langgraph:dev`/`langgraph:up` need to stay in
   `package.json` at all**, if they're not in active use — removing an
   unused dev script removes the exposure entirely, but that's a real
   product/workflow decision, not something to do unilaterally here.
3. **Not recommended:** forcing an `npm overrides` pin to a hypothetical
   newer version — there isn't one yet, so there's nothing to pin to.

## What this document is, and isn't

This is an investigation and disclosure, not a fix — there is no code
change in this branch, because there is no fix currently available to
apply. The value here is making the "is this real, where did it come
from, can we fix it" questions answerable without needing to re-trace
all of this from scratch again later.
