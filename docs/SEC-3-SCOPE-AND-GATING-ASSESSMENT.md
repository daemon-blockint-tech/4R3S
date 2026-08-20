# SEC-3 — Scope-containment default-on + dangerous-tool gating: assessment

**Date:** 2026-08-20
**Scope:** `apps/ares-sec/` — the egress scope gate (`src/arsenal/index.ts`) and the capability
approval / dangerous-tool gate (`src/arsenal/approval.ts`), as wired by the engine
(`src/index.ts`, class `AresCommand`).
**Kind:** point-in-time security assessment + hardening. Both controls pre-date this audit and
already carry unit tests; this document records the gaps found and what this change does and does
not close.

## Summary

Both controls are **correctly implemented** where they act — the scope gate is enforced before
every tool handler runs (`Arsenal.execute()`), and the approval gate fails safe (deny) when it
can't get a decision. The gap in both cases is **default posture**: each control is markedly
weaker out of the box than a reader of `README.md`/`FEATURES.md` would assume, because each one
requires an external event (a target being registered, or an env flag) to actually engage.

## Finding 1 — Egress scope gate is fail-open until a target is registered

**Severity: High.** **Status: Fixed by this change (engine-level).**

- `Arsenal.scope` initializes to `null` (`src/arsenal/index.ts:199`, pre-change), and
  `scopeViolation()` treats `null` as "enforcement off" (`src/arsenal/index.ts:136`).
- The only production code that ever calls `setScope()` was `syncArsenalScope()`
  (`src/index.ts:546`, pre-change), itself only triggered by the `target:added` event
  (`src/index.ts:531`).
- **Consequence:** from `new AresCommand(...)` until the first `targetEnv.addTarget(...)` call,
  every networked built-in tool (`http_request`, `dns_lookup`, `nmap_scan`, …) could reach any
  public host — the gate simply hadn't been armed yet. A bare `Arsenal` used outside the engine
  (library/embedder use, or a test) has no containment at all, by design.
- `README.md:107` describes the feature as "✅ Stable (on by default)". The accurate reading was
  "on once a mission target is set" — this is the discrepancy SEC-3 named "default-on."

**Fix:** `AresCommand`'s constructor now calls `syncArsenalScope()` once, immediately after the
approval controller is wired (`src/index.ts`, after the former `:420`). With zero targets
registered this yields `{ allowedHosts: [], allowLoopback: true, allowPrivate: true }` — every
*public* host is refused, while loopback and RFC-1918/lab ranges keep working (zero regression for
local/lab workflows). `ARES_SCOPE_OPEN=1` restores the previous fully-unscoped behavior for a
deliberate unscoped run. The pure `scopeViolation()` function and a bare `Arsenal`'s `null` = off
default are **unchanged** — this is a shipping-product default, not a library contract change.

Traced all 38 built-in/external tools against the new default: none route a non-target third-party
host through a scope-inspected parameter, so the change produces no false-positive `SCOPE DENIED`.
One tool, `whois_lookup`, connects to a WHOIS server host it builds internally
(`src/arsenal/index.ts:663,730`) rather than through an inspected parameter — that egress was never
gated and remains ungated after this change (pre-existing behavior, unchanged; flagged as a
residual risk below).

## Finding 2 — Dangerous-tool gating: sound mechanism, incomplete default classification

**Severity: Medium.** **Status: Partially addressed (classification only; default posture kept
opt-in by design — see rationale below).**

- The `ApprovalController` gate (`src/arsenal/approval.ts`) is sound: fail-safe **deny** when a
  gated tool is neither pre-approved nor interactively approvable (`approval.ts:188`), and it is
  always wired by the engine (`src/index.ts:408-420`, pre-change numbering).
- But nothing is gated by default: built-ins ship with no `riskTier` unless
  `ARES_GATE_BUILTINS=1` (`src/index.ts:393-394`), and the specialist arsenal
  (metasploit/hydra/sqlmap/john/hashcat/…) isn't even registered unless `ARES_FULL_ARSENAL=1`
  (`src/index.ts:428`).
- The danger taxonomy itself (`SPICY_BUILTIN_TIERS`, pre-change) tiered only
  `password_spray`, `hash_crack`, `sqli_scan`, `xss_scan` — leaving two genuinely destructive
  built-in probes unclassified: **`ssti_test`** (payloads reach the class-introspection RCE gadget
  path, e.g. `{{self.__class__}}`) and **`lfi_test`** (reads `/etc/passwd`, `/etc/shadow`,
  `php://filter`).
- No interactive approver is wired anywhere in production (`src/index.ts` constructs the
  controller with `preApprovedTools` + `onWarning`/`onDecision` only — no `requestApproval`). This
  is fail-closed and therefore not itself a hole, but it means the only way a gated tool ever runs
  headlessly is the `ARES_APPROVED_TOOLS` allowlist.

**Fix — classification only.** `SPICY_BUILTIN_TIERS` (`src/arsenal/index.ts`) now also tiers
`lfi_test: 'intrusive'` and `ssti_test: 'dangerous'`. This makes both tools **correctly gated
whenever an operator opts into gating** (`ARES_GATE_BUILTINS=1`) — previously, turning gating on
still left these two RCE/file-disclosure-class probes running free. `open_redirect_test` and
`dir_bruteforce` were evaluated and deliberately left unclassified (neither is destructive/RCE/
credential-class; `dir_bruteforce` is additionally pinned ungated by an existing test). The
external CLI tools (`nmap_scan`/`nuclei_scan`/`ffuf_fuzz`) were left as-is — the adapter catalog
already tiers the equivalent adapters `active` (ungated) and changing that would be inconsistent
with the project's own classification, not a fix.

**Deliberately NOT changed: default runtime posture.** `ssti_test`/`lfi_test` remain **ungated by
default** (only gated once `ARES_GATE_BUILTINS=1` is set), and the built-in/opt-in-arsenal
env-gating scheme itself is unchanged. Rationale, backed by investigation:
- Both tools are in the exploiter operator's default toolkit (`src/operators/index.ts:99,110,121`),
  so a live agent run reaches for them during exploitation.
- No interactive approver exists in production, so classifying them as gated **by default** would
  turn every unattended/benchmark run's call to either tool into an automatic `APPROVAL REQUIRED`
  denial — silently disabling two of the exploiter's tools and changing agent trajectories in every
  normal run.
- This would violate the codebase's own explicit zero-regression invariant
  (`src/index.ts:388-392`, pre-change: "the headline benchmark and every prior run keep firing them
  freely").
- A default-deny posture is available today for anyone who wants it: set
  `ARES_GATE_BUILTINS=1` and put nothing in `ARES_APPROVED_TOOLS` — the classification landed here
  makes that combination correctly cover the RCE-class probes too. What changed is that the
  *option* now covers the right tools; the *default* stays deliberately conservative.

**Also added:** a startup `console.warn` in `AresCommand`'s constructor when `ARES_GATE_BUILTINS=1`
is set but neither an approver nor `ARES_APPROVED_TOOLS` exist — otherwise every gated call denies
silently with no operator-visible explanation of why. Pure notice, no decision-logic change.

## Finding 3 — Bare `Arsenal` with no approval controller has no gating

**Severity: Informational — accepted, documented.**

`if (this.approval && isGatedRisk(tool.riskTier))` (`src/arsenal/index.ts`, in `execute()`) means a
caller who constructs `new Arsenal()` directly and never calls `setApprovalController()` gets no
gating at all, regardless of any tool's `riskTier`. This is a deliberate library/embedder
invariant, pinned by an existing test (`arsenal-approval-gate.test.ts`, "no controller wired =
gating off"). The shipped engine (`AresCommand`) always wires a controller
(`src/index.ts:408-420`ish), so this branch is only reachable for a caller that built its own
`Arsenal` and explicitly skipped the controller. The doc comment at the gate site was extended to
state this explicitly (no logic change).

## Residual risks (not addressed by this PR — flagged for follow-up)

1. **`whois_lookup`'s outbound WHOIS server connection is never scope-checked** (Finding 1). It is
   a read-only OSINT lookup against a small, well-known set of registrar servers, not the mission
   target — low severity, but worth a scope carve-out or explicit allowlist if this framework is
   ever run against untrusted input.
2. **`SCOPE_TARGET_KEYS` is a fixed list of parameter names** (`url, target, host, hostname,
   domain, address, ip, endpoint, base_url, rhosts, rhost`). Every current built-in's target
   arrives under one of these, but a future/custom tool that reads its target from a differently
   named parameter would silently bypass the scope gate. No tool exploits this today — noted as a
   design constraint to watch when adding new tools.
3. **No interactive approver is wired in production** — gated tools can only run via the
   `ARES_APPROVED_TOOLS` allowlist. Fail-closed and therefore safe, but it means there is currently
   no human-in-the-loop UI path for approving a gated tool call at the moment it's requested. Out
   of scope for this change; noted for a future UI-integration task.
4. **Two dangling doc references found during this audit, unrelated to the two controls above:**
   - `README.md:164` and `SECURITY.md:37` reference `docs/SCOPE_AND_AUTHORIZATION.md`, which does
     not exist in the tree (confirmed via `npm run doctor`, which reports it `warn`ing as missing).
   - The root `CLAUDE.md` (lines ~44, ~115) states `apps/ares-sec/src/target/` is missing as part
     of the incomplete SEC-1 import. It is not — `src/target/index.ts` exists and is a working
     `TargetEnvironment` implementation. This note in `CLAUDE.md` is stale and should be corrected
     separately (shared repo-mechanics file, out of scope for an `apps/ares-sec`-only PR).

## What changed (file list)

- `apps/ares-sec/src/index.ts` — `scopeOpen` opt-out field; `syncArsenalScope()` seeded at
  construction and guarded by the opt-out; startup notice when gating is armed with no way to
  approve; env-contract doc comments.
- `apps/ares-sec/src/arsenal/index.ts` — `SPICY_BUILTIN_TIERS` gains `lfi_test`/`ssti_test`; two
  doc-comment refreshes (no logic change).
- `apps/ares-sec/src/arsenal/approval.ts` — doc-comment refresh mentioning the two new opt-in tiers
  (no logic change).
- `apps/ares-sec/src/__tests__/engine-scope-default.test.ts` — new; 6 cases pinning the engine's
  default-scope behavior, the opt-out, and that bare `Arsenal` is unchanged.
- `apps/ares-sec/src/__tests__/arsenal-approval-gate.test.ts` — new `describe` block (6 cases)
  pinning the taxonomy addition and its opt-in-only default.

## Verification

`cd apps/ares-sec && npm ci && npm run lint && npm run typecheck && npm test`. Confirmed against
the `main` baseline (dc5c97f): lint (5 pre-existing errors, all in files this change does not
touch), typecheck (57 pre-existing `server.ts` errors, byte-identical before/after), and the test
suite (6 pre-existing failures in unrelated static source-inspection tests, byte-identical
before/after) all show **zero regressions**; all 12 new tests pass. `npm run doctor`,
`npm run verify-claims`, and `npm run test:no-fitting` all pass clean. `npm run test:gate` (which
runs `npm run build` first) fails identically on `main` and on this branch, for the same
pre-existing `server.ts` TypeScript errors (unrelated to this change, tracked separately from
SEC-3) — not introduced or worsened here.
