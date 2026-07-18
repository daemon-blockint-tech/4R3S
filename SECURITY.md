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
  (git-ignored); only `OPENROUTER_API_KEY` is required and none are logged.
- **Hermetic by default.** With Supabase/Neo4j/embeddings/Helius unset, ARES
  runs fully offline against the in-process Crystalline store, so a default run
  makes no outbound calls beyond the configured LLM endpoint.

## Known dependency advisories

Dependencies are monitored by Dependabot and `npm audit` in CI. The current
tracked advisories:

### Resolved via `overrides`

- **`uuid` < 11.1.1 — missing buffer bounds check** (`GHSA-w5hq-g745-h8pq`,
  Moderate). Pulled in transitively through `jayson` (a `@solana/web3.js`
  dependency). Resolved with an npm [`overrides`](package.json) entry pinning
  `uuid` to `^11.1.1` across the tree; `jayson` imports only `uuid.v4()`, which
  is API-compatible with uuid 11. This also clears the downstream advisories on
  `jayson`, `@solana/web3.js`, `@solana/spl-token-group`, and
  `@solana/spl-token-metadata`.

### Accepted residual risk

- **`bigint-buffer` — buffer overflow in `toBigIntLE()`** (`GHSA-3gc7-fjrx-p6mg`,
  High). Transitive via `@solana/spl-token` → `@solana/buffer-layout-utils` →
  `bigint-buffer`. **No fixed version exists** — the advisory affects all
  published releases, and npm's only "fix" is a semver-major downgrade of
  `@solana/spl-token` that would break the SDK. We accept this residual because:
  - The advisory's CVSS 4.0 vector (`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`)
    is **availability-only** — no confidentiality or integrity impact — with
    proof-of-concept (`E:P`), not weaponized, exploit maturity.
  - The vulnerable `toBigIntLE()` path is reached only when parsing SPL token
    account layouts. ARES parses **trusted RPC responses read-only**, not
    attacker-controlled byte buffers, so the overflow is not reachable with
    adversarial input in normal operation.

  This will be cleared automatically once `@solana/buffer-layout-utils` drops
  `bigint-buffer` or a patched release ships; Dependabot will surface it.

CI does **not** run a blocking `npm audit` step, because the unfixable
`bigint-buffer` advisory would make every build red for no actionable reason.
Advisories are tracked through Dependabot and this document instead.
