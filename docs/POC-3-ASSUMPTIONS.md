# POC-3 — CTF executor sandbox hardening: what was done, what was verified, what wasn't

## The task, and the reading it settled on

Notion backlog row: *"Sandbox hardening (timeout, resource limits, cleanup, network
isolation)"* — `ID: POC-3`, Owner: Gilbert, `Depends On: POC-2`, Effort 3d,
Priority P2, Rationale *"Sandbox hardening (network isolation) — Firewall
Configuration skill"*, Scope *"S2 Confirmation Layer"*.

Two things about that metadata don't match where this work actually landed,
and both were resolved with the task owner (Gilbert) before implementation,
not assumed silently:

- **Scope mismatch.** "S2 Confirmation Layer" + "Depends On POC-2" points at
  the defensive `core/` Rust confirmation sandbox (`poc.rs` /
  `commands/confirm.rs`, the `solana-program-test` fork harness). The actual
  target hardened here is the **offensive CTF benchmark executor**
  (`apps/ares-sec/ctf/executor/ctf_executor.py`) — a different product, per
  `CLAUDE.md`'s GOLDEN RULE 1 product boundary. The task title's four knobs
  (timeout / resource limits / cleanup / network isolation) and the
  "Firewall Configuration" rationale map cleanly onto the CTF executor's
  Docker sandbox, not onto the Rust engine. Owner confirmed: harden the CTF
  executor.
- **ID collision.** `POC-3` was already used by a landed commit (`ebb9b65`,
  "make the PoC verdict carry information"). Flagged to the owner; owner's
  call was to reuse `POC-3` anyway (branch `feat/POC-3-Sandbox-Hardening`,
  commit prefix `POC-3:`) because it matches the live Notion task directly
  and is easier to cross-reference than minting a new ID the tracker
  doesn't have. This repo has precedent for a reused ID (`SEC-2` was also
  used twice for unrelated work).

"Firewall Configuration skill" is not an in-repo skill (zero hits anywhere in
the repo or in `~/.claude/skills`) — it reads as a rationale note pointing at
the general *approach* (host firewall / iptables configuration), which is
exactly what this work ended up needing, for reasons below.

## What was actually built

Two new files, one file modified, dependency-free by design:

- **`apps/ares-sec/ctf/executor/hardening.py`** (new) — does **not** `import
  docker`, so it's importable/testable even without the SDK installed (it
  wasn't, in this environment, until installed for Tier 2 testing). Contains
  `HardeningConfig` (env-overridable resource limits), `container_security_kwargs`
  (pure function building the `containers.run()` security kwargs),
  `network_create_kwargs`, the `egress_block_rule_args` / `run_iptables` /
  `list_iptables_rules` / `orphaned_ares_ctf_rule_delete_args` firewall
  helpers (see below), and the process-group kill / cleanup-handler helpers.
- **`apps/ares-sec/ctf/executor/requirements.txt`** (new) — declares
  `docker`, `httpx`, `pytest`, none of which had a requirements file before
  this (the executor couldn't even be `import`ed in a clean environment).
- **`apps/ares-sec/ctf/executor/test_hardening.py`** (new) — 37 tests, two
  tiers: a dependency-free pure tier (always runs) and a mocked-Docker
  integration tier (`pytest.importorskip("docker")`-guarded per test/fixture,
  not at module level — see "A real mistake, caught before it went anywhere"
  below for why that distinction mattered).
- **`apps/ares-sec/ctf/executor/ctf_executor.py`** (modified) —
  `DockerChallengeManager` now builds a per-run isolated network, applies
  resource/capability limits, applies a firewall egress-block rule, reaps
  orphans (containers, networks, *and* firewall rules) at startup, and
  guarantees teardown via `try/finally`. `ToolSandbox.execute()`'s timeout
  path now kills the whole process group, not just the shell PID.
  `main()` wires `register_cleanup_handlers` for atexit/SIGTERM/SIGINT.

### The five hardening measures, as actually implemented

1. **Resource limits** — `mem_limit`/`memswap_limit` (default `512m`, swap
   disabled), `nano_cpus` (default 1 CPU), `pids_limit` (default 256). All
   three env-overridable (`CTF_MEM_LIMIT`, `CTF_CPU_LIMIT`,
   `CTF_PIDS_LIMIT`), plus a per-challenge `docker.mem_limit` manifest
   override.
2. **Network isolation + egress block — two layers, not one** (see the next
   section for why one layer alone was proven insufficient):
   - Layer 1: per-run bridge network with
     `com.docker.network.bridge.enable_ip_masquerade=false`.
   - Layer 2: a `DOCKER-USER` iptables rule dropping **NEW** connections
     sourced from that network's subnet, tagged with an `ares-ctf:<name>`
     comment for later identification. Matching only `NEW` state (not the
     whole subnet) is what lets a challenge's published port keep working —
     inbound connections and their replies are `ESTABLISHED`/`RELATED`, not
     `NEW`; only container-initiated outbound connections get dropped.
3. **Capability restriction** — `cap_drop=["ALL"]`,
   `security_opt=["no-new-privileges:true"]`. Per-challenge `cap_add`
   passthrough exists for a future challenge that needs e.g. `SYS_PTRACE`.
   `read_only` rootfs is wired but **opt-in only, untested** (see "not done").
4. **Cleanup hardening** — `stop_challenge`/`cleanup_all` wrapped in
   `try/finally` so a failure stopping one container can't leave the
   registry stuck or skip later challenges' cleanup. `_reap_orphans()` runs
   at every `DockerChallengeManager.__init__` and removes leftover
   containers/networks by `ares.ctf.managed` label **and** leftover
   `DOCKER-USER` firewall rules by `ares-ctf:` comment tag (the label
   mechanism doesn't apply to firewall rules, since they aren't Docker
   objects — this was a real gap found and fixed during live testing, not
   part of the original design; see below).
   `ToolSandbox.execute()`'s timeout branch now kills the whole process
   group (`kill_process_group`), not just the shell PID, so a timed-out
   tool's children don't survive as orphans.
5. **Container wall-clock timeout** — a `threading.Timer` per challenge
   (`CTF_CONTAINER_TIMEOUT`, default 600s) force-stops the container
   independent of the agent loop's own `time_limit_seconds`, so a hung agent
   loop can't keep a container alive indefinitely.

## What was verified, concretely

**Tier 1+2 (pytest, no live daemon needed for Tier 1):**
```
cd apps/ares-sec/ctf/executor && python -m pytest test_hardening.py -v
```
37 passed. Ran once with the `docker` SDK absent (23 pure tests pass, 14
mocked-tier tests correctly *skip*, not silently pass-with-nothing) and once
after `pip install docker httpx` (all 37 pass) — both states checked, not
just the convenient one.

**Tier 3 (live smoke, Docker Desktop 29.7.2, linux/amd64, against the real
`pwn_bof_basic` challenge — the only one of 8 manifest entries with a
Dockerfile that actually builds; `sqli-basic`'s `Dockerfile` does `COPY
templates/` from a directory that doesn't exist in its build context, a
pre-existing bug unrelated to this work, left as found):**

Final run, 17/17 checks passed:
- Ingress: published port (9001→19001) reachable.
- **Functional**: the challenge binary's real banner ("SECURE TERMINAL ACCESS
  SYSTEM... Enter access code:") comes back over that connection — not just a
  bare TCP connect, actual proof `cap_drop=ALL` didn't silently break the
  challenge.
- Egress: `docker exec <c> timeout 3 bash -c 'echo > /dev/tcp/1.1.1.1/80'`
  → `rc=124` (packet silently dropped, consistent with the DROP rule, not a
  REJECT).
- `docker inspect`: non-zero `Memory`/`NanoCpus`/`PidsLimit`,
  `CapDrop=[ALL]`, `NetworkMode` is the per-run network (not `default`).
- `docker network inspect`: `Internal=false`,
  `enable_ip_masquerade=false`.
- Cleanup: `docker ps -a` / `docker network ls` empty of `ctf_*`/`ctf-run-*`
  after `stop_challenge`.
- Orphan reap: a deliberately-abandoned container+network (simulating a
  crash — popped from the registry without calling `stop_challenge`) is
  gone after the next `DockerChallengeManager()` init.

## A real mistake, caught before it went anywhere

First draft of `test_hardening.py` had `docker = pytest.importorskip("docker")`
at **module level**. `pytest.importorskip` at module scope skips the entire
*file* when the import fails — not just tests after that line — so with the
`docker` SDK absent (the actual state of this environment at the start of
this task), the very first test run reported **1 skipped**, silently
swallowing all 18 pure, dependency-free tests along with the ones that
legitimately needed Docker. Caught by actually reading the output instead of
assuming "skipped" meant "the Docker-dependent parts, as intended." Fixed by
moving `pytest.importorskip("docker")` inside each mocked-tier fixture/test
body, so only those specific tests skip.

## The most significant finding — the original network-isolation design didn't work, twice

The plan going in was `internal=True` on a per-run Docker network — the same
pattern the CTF's own (executor-unused) `docker-compose.yml` already uses for
its `ctf-internal` network. Flagged in advance as the single highest-risk
item requiring live verification before claiming done. It was verified, and
it failed:

1. **`internal=True` breaks ingress too, not just egress.** Live test: the
   published port become unreachable (`WinError 10061` /
   connection-refused). This is a real, documented Docker behavior
   (`internal` skips the DNAT chain for that network entirely), not a bug in
   this code — but it would have made every challenge unplayable had it
   shipped.
2. **Pivoted to disabling the network's IP masquerade instead**
   (`internal=False` + `enable_ip_masquerade=false`) — theoretically sound
   (DNAT/ingress and MASQUERADE/egress are separate iptables chains) and
   fixed ingress. But live-tested egress was **still not blocked**
   (`rc=0`, the outbound connection succeeded). Root-caused by directly
   inspecting the daemon's live iptables rules (via a privileged
   `--network host` helper container, since Docker Desktop hides its
   daemon's netns): a **pre-existing, broader MASQUERADE rule for the whole
   default IPAM pool** (`172.17.0.0/16`) was still translating our subnet's
   traffic, because that rule matches by source CIDR only, not by which
   bridge it came from. Disabling masquerade for one specific
   network doesn't remove a *different*, broader rule that happens to also
   cover its subnet.
3. **Final design: a `DOCKER-USER` iptables rule**, Docker's own sanctioned
   early-intercept chain for exactly this. Verified this actually works
   (Tier 3, egress check above) — and is what most plausibly matches the
   original "Firewall Configuration" rationale in the first place.

This means two of five measures (network isolation, cleanup) required a live
Docker daemon to validate at all — the pure-function unit tests alone would
have shipped a network policy that either broke every challenge or blocked
nothing, and looked correct in every mocked test the whole time.

## A second gap, found by testing cleanup honestly rather than assuming it worked

After landing the `DOCKER-USER` rule, ran the orphan-reap Tier-3 check (which
deliberately simulates a crashed process) and then manually inspected the
`DOCKER-USER` chain afterward — not because a test failed, but on the
principle of checking the thing I'd just claimed fixed. Found **two leftover
`ares-ctf:`-tagged DROP rules** from earlier test runs. `_reap_orphans()`
reaps containers and networks by Docker label, but a firewall rule isn't a
Docker object — it has no label to filter on, so the existing reap logic
silently missed it entirely. Fixed by adding `list_iptables_rules` +
`orphaned_ares_ctf_rule_delete_args` (parse `iptables -S DOCKER-USER`,
match the `ares-ctf:` comment tag, delete by full rule-spec) to
`_reap_orphans()`, with its own pytest coverage, then re-verified live: the
two pre-existing leftover rules were gone after the next
`DockerChallengeManager()` init, and a fresh end-to-end run left zero
residue of any kind (containers, networks, or firewall rules).

## Honest disclosure — what could not be fully verified

- **Production behavior on a native Linux Docker host is inferred, not
  tested.** All Tier 3 verification ran against Docker Desktop 29.7.2 on
  Windows (linux/amd64 containers via its VM). `run_iptables`/
  `list_iptables_rules` try a **direct local `iptables` call first** — the
  expected path when this executor runs as root on a real Linux CI/server
  host (this project's own `core/.docker/Dockerfile` already documents that
  model: *"Network access is restricted by host firewall rules"*) — and only
  fall back to a privileged `--network host` helper container
  (`nicolaka/netshoot`, ~180MB, pulled on first use) because Docker
  Desktop's daemon lives inside a hidden VM a local call can't reach. The
  direct-call path was never exercised in this environment (no local
  `iptables` binary on Windows), only the fallback path. On a real Linux
  host, whether the direct call succeeds outright, and whether that host
  has some equivalent broader pre-existing MASQUERADE/FORWARD rule the way
  Docker Desktop does, are both unverified.
- **The privileged-helper-container fallback assumes the Docker daemon
  permits privileged containers.** If a production host's daemon disables
  `--privileged` (a common hardening measure elsewhere), this fallback
  would fail closed to masquerade-only egress blocking (Layer 1 alone),
  which this same investigation showed is insufficient on at least one real
  environment. `run_iptables`/`list_iptables_rules` log a warning rather
  than raising in that case, so a challenge would still start, just with
  weaker isolation than intended, silently from the caller's perspective
  beyond the log line.

## What's still NOT done — deliberately out of scope

- **The two per-challenge opt-in knobs are wired but never exercised**:
  `docker.allow_egress` and `docker.read_only` have unit-test coverage for
  their code paths, but no manifest entry actually sets either, so their
  real-world behavior (e.g., does a `read_only` rootfs break some future
  challenge that writes to disk) is untested. Left off by default
  intentionally — `read_only` in particular was flagged in planning as the
  highest-breakage-risk knob.
- **6 of 8 manifest challenges still have no Dockerfile** (`sqli-blind`,
  `xss-stored`, `ssrf-metadata`, `format-string`, `rsa-weak`,
  `memory-dump`), and **`sqli-basic`'s Dockerfile doesn't build**
  (`COPY templates/` from a nonexistent directory). Both pre-existing,
  unrelated to this task, left exactly as found.
- **Multi-container challenges are still unsupported by the executor.**
  `xss-stored`/`ssrf-metadata` need `depends_on` + a second `ctf-internal`
  network per `docker-compose.yml`; `DockerChallengeManager` still only
  starts one container per challenge and ignores `depends_on`/`networks`
  manifest keys entirely — unchanged by this work, not regressed by it
  either (they were already unrunnable before).
- **CI wiring was deliberately left out of this change.** `ares-sec-ci.yml`
  is Node/npm-only today; adding a Python/Docker test job to it wasn't
  attempted here since it can't be verified from this environment (no way
  to confirm a GitHub Actions runner actually behaves like this Docker
  Desktop test environment, particularly for the iptables fallback path).

## Verified before handing off

- `python -m pytest test_hardening.py -v` → 37/37 passed (both with and
  without the `docker` SDK installed, checked separately).
- `python -c "import ctf_executor"` → succeeds cleanly.
- Live Tier 3 smoke against `pwn_bof_basic` → 17/17 checks passed, including
  a functional check (not just structural) that the challenge still works.
- Manual `iptables -L DOCKER-USER` inspection (before and after the orphan-
  rule fix) → confirmed the leftover-rule bug, then confirmed the fix
  reaps it.
- `docker ps -a` / `docker network ls` clean after every test run — no
  leaked containers or networks from this session's testing.
