# Security Policy

ARES-AGENT is a security tool, so we hold its own supply chain and runtime to
the same standard it applies to the programs it audits. This document covers how
to report issues and the current state of known dependency advisories.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for a security bug. Use GitHub's private
[**Report a vulnerability**](https://github.com/daemon-blockint-tech/4R3S/security/advisories/new)
flow. Include a description, affected version/commit, and reproduction steps.
We aim to acknowledge reports within a few business days.

## Runtime posture

- **Read-only by design.** ARES never signs, submits, or otherwise mutates
  on-chain state. On-chain access is limited to RPC reads, and the opt-in CUA
  browser analyzer is constrained by prompt to navigation and reading only
  (see `src/llm/prompts.ts` → `cuaInvestigationSystemPrompt`).
- **Secrets stay in the environment.** All credentials come from `.env`
  (git-ignored); only `OPENROUTER_API_KEY` is required.
- **Logs are redacted at the sink.** `src/config/logger.ts` drops any metadata
  value under a credential-shaped key (`key`, `token`, `password`, `secret`,
  `authorization`, `credential`, `dsn`) and strips `user:password@` credentials
  out of every URL it finds in a string, at any nesting depth — which is how the
  Postgres DSN would otherwise escape, inside a stringified driver error rather
  than under a conveniently-named field. All log output goes to stderr; stdout
  carries only the audit report.
- **Hermetic by default.** With Supabase/Neo4j/embeddings/Helius unset, ARES
  runs fully offline against the in-process Crystalline store, so a default run
  makes no outbound calls beyond the configured LLM endpoint. Semgrep is part of
  that guarantee: it is invoked with the committed ruleset in `rules/` and
  `--metrics=off`, never `--config auto`, which would resolve rules from the
  Semgrep registry over the network on every scan and report usage telemetry —
  an outbound disclosure about a client's unreleased program that this bullet
  would otherwise have promised did not happen.

## Known dependency advisories

Dependencies are monitored by Dependabot. CI runs no `npm audit` step — see the
note at the end of this section for why. The current tracked advisories:

### Resolved

- **`react-router` 7.12.0–8.2.x — RSC CSRF bypass** (`GHSA-qwww-vcr4-c8h2`, High).
  Reached transitively in `apps/ares-sec/webui` via `react-router-dom@7.18.1`.
  Upgraded to `react-router@8.3.0` (v8 drops the `react-router-dom` re-export
  package; imports now come from `react-router`). Only affects apps using
  unstable RSC APIs — the webui is a client-side Vite SPA and does not use them.

- **`brace-expansion` — DoS via unbounded expansion** (`GHSA-mh99-v99m-4gvg`,
  High). Reached transitively; a patched 5.0.8 was already permitted by the
  parent ranges, so the lock file was bumped to it. No manifest change.

### Resolved via `overrides`

- **`sharp` < 0.35.0 — libvips vulnerabilities** (`GHSA-f88m-g3jw-g9cj`, High).
  Reached transitively through `next` (optional dependency on `sharp@0.34.x`).
  Resolved with a root [`pnpm.overrides`](package.json) entry forcing
  `sharp >= 0.35.0` across the workspace lockfile (currently `0.35.3` / libvips
  8.18.3).

- **`postcss` — path traversal / arbitrary file read via `sourceMappingURL`**
  (`GHSA-6g55-p6wh-862q`, High, CVE-2026-45623; `GHSA-r28c-9q8g-f849`, High).
  Reached transitively through `next` (pinned to `postcss@8.4.31`). Resolved with
  a root [`pnpm.overrides`](package.json) entry forcing `postcss >= 8.5.23`
  across the workspace lockfile (currently `8.5.25`).

- **`dompurify` — XSS bypass** (Dependabot #98). Reached transitively through
  `streamdown`. Resolved with a root [`pnpm.overrides`](package.json) entry
  forcing `dompurify >= 3.4.12`.

- **`uuid` < 11.1.1 — missing buffer bounds check** (`GHSA-w5hq-g745-h8pq`,
  Moderate). Pulled in transitively through `jayson` (a `@solana/web3.js`
  dependency). Resolved with an npm [`overrides`](package.json) entry pinning
  `uuid` to `^11.1.1` across the tree; `jayson` imports only `uuid.v4()`, which
  is API-compatible with uuid 11. This also clears the downstream advisories on
  `jayson`, `@solana/web3.js`, `@solana/spl-token-group`, and
  `@solana/spl-token-metadata`.

### Resolved by dropping an unused dependency

- **`bigint-buffer` — buffer overflow in `toBigIntLE()`** (`GHSA-3gc7-fjrx-p6mg`,
  High). Reached via `@solana/spl-token` → `@solana/buffer-layout-utils` →
  `bigint-buffer`. No patched release of `bigint-buffer` exists, and npm's only
  offered "fix" was a semver-major downgrade of `@solana/spl-token`.

  It was resolved instead by removing `@solana/spl-token` from `package.json`.
  **Nothing in the repository ever imported it** — the only textual match
  outside the manifest was the string `spl_token::transfer` inside a Rust
  detection hint in the vulnerability catalog. Dropping it removes the entire
  transitive chain rather than mitigating it, with no code change and no
  downgrade.

  This document previously listed the advisory as accepted residual risk, on the
  reasoning that the vulnerable path "is reached only when parsing SPL token
  account layouts" and that ARES only parses trusted RPC responses. That
  reasoning was weaker than the truth and rested on a false premise: the package
  was never loaded at all. If SPL token parsing is added later, reintroduce the
  dependency deliberately and re-evaluate the advisory then.

### Python dependencies

`eval/requirements.txt` pins security floors on `pyarrow` (`>=23.0.1`,
`PYSEC-2026-113`) and `pytest` (`>=9.0.3`, `PYSEC-2026-1845`). Those floors exist
for advisories, not API needs — raise them when a later advisory lands, and do
not lower them to widen resolution. Note `pyarrow >=23` requires Python >=3.10;
CI runs 3.12.

### Audit gate

CI runs a blocking **`dependency audit`** job: `npm audit --audit-level=high`
plus `pip-audit` over `eval/requirements.txt`. This gate was previously absent
because the unfixable `bigint-buffer` advisory would have made every build red
for no actionable reason; with that advisory cleared at the root, the gate can
hold the line. If it goes red, fix the dependency or record a justified
exception here — do not weaken the check.

Dependabot is configured (`.github/dependabot.yml`) to hold TypeScript at major
and minor versions: typescript-eslint 8.x peer-caps TypeScript below 6.1 and
hard-throws on TS 7, so an unrestricted bump breaks `npm ci` and `npm run lint`
outright. Patch updates still flow, and the pin should be lifted once
typescript-eslint supports TS 7.
