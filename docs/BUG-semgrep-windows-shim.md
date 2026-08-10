# BUG — `semgrep.test.ts`: 7 tests fail on Windows, pass on Linux/Mac

**OS correlation: this is a genuine, confirmed Windows-vs-Linux/Mac platform
difference, not a flaky or environment-specific fluke.** Verified failing on
a real Windows machine, verified passing (both before and after the fix) on
Linux. Root cause is specific, well-understood OS behavior — not something
that would resolve itself with a retry or a different machine of the same OS.

## Severity and status

**Low severity** — test-only issue. No evidence this reflects a real
production bug; `runSemgrep`'s actual behavior when semgrep genuinely isn't
installed is correct on every platform, including Windows. This is purely
about the test's own ability to *simulate* different semgrep behaviors.

**Status:** root cause identified, fix implemented, **confirmed working on a
real Windows machine** — both in isolation and as part of the full suite.

## Verification

- **Linux: 10/10 tests passing**, confirmed directly, multiple times
- **Windows: 10/10 tests passing**, confirmed directly on a real machine —
  both running this file in isolation and as part of the full 406-test
  suite
- **Before/after, same machine, full suite:** 10 tests failing → 3 tests
  failing. All 7 `semgrep.test.ts` failures are gone; the 3 that remain are
  unrelated, already-diagnosed, already-fixed-on-a-separate-branch issues
  (a path-separator assertion, a symlink/admin-rights limitation, and the
  `pathsMatch` separator bug) — not part of this fix's scope

## The actual error

```
AssertionError: expected 'not-installed' to be 'scan-error'

Expected: "scan-error"
Received: "not-installed"
```

Full list of the 7 failing tests, all in `src/tools/semgrep.test.ts`:
- `reports scan-error when semgrep exits non-zero`
- `reports scan-error when semgrep exits 0 but reports rule errors`
- `surfaces a failed scan as a failed analyzer, not 'ok'`
- `still reports success when semgrep genuinely finds nothing`
- `treats a scan that opened no files as failed, never ok`
- `keeps findings when a warn-level parse error accompanies a completed scan`
- `still fails the scan on an error-level entry`

Every failure has the same underlying shape: an assertion expecting a
*specific* simulated outcome (a particular exit code, particular stdout)
instead gets whatever `runSemgrep` reports when semgrep is entirely absent
(`"not-installed"`, `"degraded"`). This means the fake `semgrep` the test
sets up never actually ran at all.

## Root cause — three layers, all confirmed by direct testing, not assumed

**Layer 1 — the original design.** These tests fake a `semgrep` binary by
writing a real file to disk starting with `#!/bin/sh`, marking it executable
(`chmod 755`), and putting it on `PATH`. This is a standard, working
technique on Linux/Mac: the OS reads the `#!` line and knows to interpret
the file via `/bin/sh`.

**Windows has no concept of a shebang line at all.** There is no OS-level
mechanism that inspects a file's first line to decide how to run it. The
fake binary simply fails to launch, and `runSemgrep` correctly reports
`"not-installed"` — a legitimate response to what genuinely looks, from
Windows' perspective, like a missing executable.

**Layer 2 — the first fix attempt, and why it also failed.** Replaced the
shell script with a Windows-native `.cmd` batch file. Windows does
understand `.cmd` files — but production code invokes the binary via
`spawn(bin, args)` **without `shell: true`**, and a `.cmd` file requires
`cmd.exe` to interpret it. `spawn()` without a shell has no way to invoke
that interpreter automatically, regardless of the filename being exactly
correct. This is the **same root cause** as an earlier, separate finding in
`BIZ-1` (the `npm`/`npm.cmd` issue) — confirmed there directly, and it
applies identically here.

**Layer 3 — why production code can't just add `shell: true`.** The
argument list passed to `spawn()` includes a source path that, per
`BIZ-1`'s findings, can originate from an external caller (an API request
body), not just a trusted local CLI invocation. `shell: true` means that
value flows into an actual shell command line, and correctly escaping it
against shell-injection risk means implementing two different, both
genuinely tricky quoting schemes (POSIX vs. `cmd.exe`) correctly. This is a
real, disproportionate security cost for a test-only problem — evaluated
and deliberately rejected, not overlooked.

## The actual fix

Mock `child_process.spawn` directly at the JavaScript level (`vi.mock`)
instead of trying to create a real, OS-launchable fake binary. `runSemgrep`
never actually spawns any real process in these tests anymore, on any
platform — the mock intercepts the call and simulates the desired stdout,
stderr, and exit code using a plain `EventEmitter`. This removes the OS-level
question entirely, since no real OS-level process creation is involved.

## Verification, in full

- **Linux: 10/10 tests passing**, confirmed directly, multiple times
- **Windows: 10/10 tests passing**, confirmed directly on a real machine,
  both in isolation and as part of the full suite
- **Full suite, before this fix (real Windows machine): 10 tests failing.**
  After: **3 tests failing** — all 7 `semgrep.test.ts` failures resolved;
  the remaining 3 are unrelated, already-diagnosed issues tracked
  separately (not introduced by, or fixed by, this change)
- Two earlier attempts at this exact problem both looked reasonable and
  both failed when actually tested — this is the one that held up under
  real testing, not just reasoning about it

## Files changed

- `src/tools/semgrep.test.ts` — the fix described above
