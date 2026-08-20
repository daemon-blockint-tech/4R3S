# Accepted gaps (closed trackers)

This register records issues and security alerts that were **closed as accepted,
documented gaps** rather than resolved in code — so the knowledge is not lost
when the tracker closes. Each entry states the impact, why it was not fixed in
place, and the condition under which it should be reopened and fixed.

Closing a tracker here is deliberate: it means "known, understood, and
consciously deferred", not "forgotten". Do not treat an entry as resolved.

---

## 1. `apps/ares-sec/docs/index.html` is missing (was issue #181)

**Status:** deferred — needs the SEC-1 import completed.

**What.** `apps/ares-sec/docs/index.html` is absent from the repository. It is an
authored UI page that embeds the operator-prompt doctrine, and
`apps/ares-sec/scripts/prompt-audit.mjs` (`npm run prompt:audit`) treats it as a
**required** input and greps it for that doctrine (six of its checks depend on
it). The file was dropped during the incomplete SEC-1 import — the same class of
gap as `apps/ares-sec/src/target/` was.

**Impact.** `npm run prompt:audit` exits 1 with `required file missing`, so the
last step of the `ares-sec CI / test` job stays red. This does **not** block
`main`: `ares-sec-ci.yml` runs only on ares-sec PRs and manual dispatch, not on
push to `main`. Every other step of that job — `lint`, `typecheck`, `test`,
`doctor`, `verify-claims`, `test:no-fitting`, `test:no-self-fitting`,
`test:gate`, `smoke` — is green as of #180.

**Why it was not fixed here.** It is authored content, not code. It is not in
this repository's git history, is not covered by any `.gitignore` rule, and is
not a build artifact (the webui builds to `apps/ares-sec/webui/dist`, not
`docs/`). The documented upstream (`github.com/elder-plinius/ares`, the SEC-1
import source) is inaccessible (404). Fabricating the file to satisfy the greps,
or weakening / skipping `prompt-audit.mjs`, would defeat the doctrine-provenance
check the gate exists to enforce — both were explicitly declined.

**Reopen / fix when.** Restore the authored `apps/ares-sec/docs/index.html` from
the SEC-1 import source (whoever completed `src/target/` and the `bench/`
fixtures has it). Once restored, `prompt:audit` passes and the `test` job is
fully green with no further code change.

---

## 2. `extract-zip` unvalidated symlink path traversal (Dependabot #114)

**Status:** dismissed as tolerable risk — no upstream fix exists yet.

**What.** `extract-zip@2.0.1` (`GHSA-jmr9-qjv8-65gv`, CVSS 8.6 high) does not
validate symlink targets when extracting archives. It is present in
`apps/ares-sec` **transitively** via `@langchain/langgraph-cli`. **There is no
patched version of `extract-zip` published** (`first_patched_version: null`), so
there is nothing to bump to.

**Impact.** Real, but low practical blast radius: `extract-zip` is reachable here
only through the dev-only scripts `langgraph:dev` / `langgraph:up`, and the
exploit requires processing a malicious zip. It is not on any production, build,
or CI path. Full investigation:
[`DEPENDABOT-114-extract-zip-investigation.md`](DEPENDABOT-114-extract-zip-investigation.md).

**Why it was dismissed rather than fixed.** No fix exists to apply;
`@langchain/langgraph-cli` is in active developer use, so the dependency cannot
simply be removed; and the practical exposure is a developer running a dev
script against an untrusted archive. Dismissed with reason **`tolerable_risk`**.

**Reopen / fix when.** `extract-zip` (or `@langchain/langgraph-cli`) ships a
patched release — then bump it and let the alert re-open naturally, or re-enable
it manually. Until then, do not add an npm `overrides` pin to a hypothetical
version: there is nothing to pin to.

---

_Register opened 2026-08-20. Add an entry here whenever a tracker is closed as an
accepted gap rather than fixed, so the reason and the reopen condition survive
the close._
