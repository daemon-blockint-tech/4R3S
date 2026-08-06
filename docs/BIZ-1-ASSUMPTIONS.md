# BIZ-1 — Billing/credit metering integration with ORC-1

## Scope, as actually found (narrower than the original backlog line)

Original backlog: *"Port the billing/credit metering logic from the old
4R3S codebase... Integrate it with whatever orchestration layer Khashia's
ORC-1 produces."*

**What's actually true, checked directly rather than assumed:** the real
billing/credit logic already exists and is mature — `src/billing/`
(`account-store`, `credits`, `meter`, `pricing`, `profit`, `mpp`, each with
real tests). Nothing needed porting.

**What was actually missing:** `apps/auditor-api` (Kai's merged `ORC-1`)
wraps the TS CLI as a subprocess rather than reimplementing its logic —a
documented, deliberate design choice (see `main.py`'s own docstring). But
`worker.py` had an explicit, left-for-later note: `src/index.ts` exits `1`
for both a real audit failure *and* `InsufficientCreditsError` — so the
Python worker had no way to tell "out of credits" apart from "the audit
broke." That's the actual, precise gap this task closes.

## The fix

**`src/index.ts`** — the `InsufficientCreditsError` catch branch (which
already existed) now sets `process.exitCode = 2` instead of `1`. The
generic catch-all at the bottom of the file is untouched, still `1`. No
other exit code was in use anywhere in this codebase (checked directly),
so `2` doesn't collide with anything.

**`apps/auditor-api/worker.py`** — `_audit_and_record` now checks for
`returncode == 2` specifically and records status `payment_required`
instead of `failed`. The actual error message needed no changes: `logger.error`
already writes to stderr (confirmed directly), so `_last_error_line`'s
existing extraction logic picks up the real
`"Insufficient credits: need X, have Y..."` message unchanged.

**`apps/auditor-api/main.py`** — `AuditStatus`'s status field comment
updated to document the new value: `queued | running | done | failed |
payment_required`.

## Tests added

`test_auditor_api.py` had zero coverage for this distinction (confirmed
directly — no existing test references billing, payment, or returncode).
Added `TestBillingExitCodeDistinction` with two tests:
- Exit code 2 → recorded as `payment_required`, not `failed`
- Exit code 1 → still `failed` (guards specifically against the fix
  accidentally widening to swallow generic failures too)

## A real, separate bug found while smoke-testing — also fixed here

Doing a genuine end-to-end smoke test on an actual Windows machine (real
Docker Redis, real Arq worker, real FastAPI, real HTTP calls) surfaced a
pre-existing bug in `worker.py`, unrelated to the exit-code change above:
`create_subprocess_exec("npm", ...)` can never find `npm` on Windows,
since Windows only ever installs it as `npm.cmd` — there's no bare `npm`
file for a shell-less exec call to match. This isn't something the
exit-code fix caused; it would have broken *any* real audit request on
Windows, always, regardless of billing status. It just hadn't been
caught yet because nobody had run this on a real Windows machine before.

**Fix:** `NPM_BIN = shutil.which("npm") or "npm"` — resolves the correct,
real executable path on every platform (walks Windows' extension search
without needing a shell at all). Deliberately did *not* switch to
`create_subprocess_shell` instead, even though that would also "work" —
`source` is user-controlled (from the API request body), and safely
escaping it against `cmd.exe`'s notoriously tricky quoting rules is a real
risk not worth taking when `shutil.which` solves it cleanly with zero
shell involvement.

**Verified:** regression-tested on Linux first (23/23 still passing,
same suite), then confirmed live on the actual Windows machine — the
exact same real end-to-end smoke test now correctly returns
`payment_required` instead of failing with `[WinError 2] The system
cannot find the file specified`.

## Verified

- `apps/auditor-api`: full pytest suite, 23/23 passing (21 pre-existing +
  2 new)
- Root: `typecheck` clean, full test suite 34 files / 287 tests passing
  (no test asserted on the old exit-code-1-for-everything behavior)
- Confirmed CI needs zero changes — the existing `auditor-api` job already
  runs `python -m pytest -q` from the right directory; reproduced that
  exact invocation locally before calling this verified

**Also verified live, end-to-end — not just unit-level mocks.** Ran a
real Redis, a real Arq worker, and a real FastAPI server (`uvicorn`), and
drove it with actual HTTP requests, same rigor as `ORC-1`'s own
verification approach. A fake `npm` stood in for the real CLI (exiting 2
with the real `InsufficientCreditsError` message shape on stderr) to avoid
a real, costly LLM call — same trade-off `ORC-1`'s own doc made for this
exact scenario, which it explicitly left unverified end-to-end for that
reason. This closes that gap for the specific failure path this task
adds:

```
POST /audits  (real HTTP request)     → 202 Accepted, real job_id
                                         (real Arq worker picks it up from
                                         real Redis, runs the subprocess)
GET  /audits/{job_id}                 → 200 OK:
  {"status":"payment_required","report":null,
   "error":"Insufficient credits: need 500, have 120
   (on-demand exhausted or disabled)"}
```

Confirms the whole chain — TS exit code → Python worker interpretation →
Redis storage → FastAPI response — actually works together, not just each
piece in isolation.

## Related, still-open gap (not part of this task's scope)

`ORC-1`'s own assumptions doc flags `reportParkedRun()` (in `src/index.ts`,
called when a graph node throws mid-run and the checkpointer parks a
resumable run) as similarly unclassified — the worker currently treats
any nonzero exit from that path as a generic failure too. This is a
different moment in the process than what this task fixes (mid-run
interruption vs. post-run settlement failure), left here as a pointer for
whoever picks up more of this failure-classification work next.

## What's still NOT done — deliberately out of scope here

- **The API surface itself doesn't yet expose this distinction to a
  caller in a structured way beyond the status string** — e.g., `GET
  /audits/{job_id}` returns `status: "payment_required"` but doesn't (yet)
  return the specific `needed`/`available` numbers `InsufficientCreditsError`
  actually carries. Worth a follow-up if BIZ-2's tier/dashboard work wants
  to surface exact shortfall amounts to a user.
- **No opt-in/opt-out config for billing enforcement itself** — that's
  billing being *enabled or not* (root's own `billing.config`, unchanged
  here), separate from this task's actual scope (making an *already-enabled*
  billing failure distinguishable to the API layer).
- **BIZ-2's tier gating** doesn't exist yet — this task only makes the
  existing credit-exhaustion failure mode visible through the API; it
  doesn't add new gating logic.
