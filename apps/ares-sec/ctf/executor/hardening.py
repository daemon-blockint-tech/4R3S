#!/usr/bin/env python3
"""
POC-3 — CTF sandbox hardening primitives.

This module is deliberately **dependency-free** — it does NOT import the
`docker` SDK — so it can be imported and unit-tested even where the SDK (or a
Docker daemon) is unavailable. It builds the security-relevant keyword
arguments that `ctf_executor.py` splats into `docker.containers.run()`, plus a
few small host-side teardown helpers.

The knobs mirror the repo's existing conventions:
  * env-overridable constant with a literal default and units in the comment,
    like `apps/auditor-web/lib/constants.ts` (`MAX_SANDBOX_DURATION`);
  * a memory cap expressed the way `apps/ares-sec/scripts/cybench-bench.mjs`
    does it (`--memory` == `--memory-swap`, i.e. swap disabled);
  * an `internal: true` bridge, the same network model already described in
    `apps/ares-sec/ctf/docker-compose.yml` (`ctf-internal`).
"""

import atexit
import logging
import os
import shlex
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("ctf_executor.hardening")

# Label stamped on every container/network this executor creates, so orphans
# from a crashed prior run can be found and reaped by filter.
ORPHAN_LABEL_KEY = "ares.ctf.managed"
ORPHAN_LABEL_VALUE = "true"
ORPHAN_LABEL = {ORPHAN_LABEL_KEY: ORPHAN_LABEL_VALUE}
# docker SDK filter form: filters={"label": ORPHAN_LABEL_FILTER}
ORPHAN_LABEL_FILTER = f"{ORPHAN_LABEL_KEY}={ORPHAN_LABEL_VALUE}"

# Prefixes used for names, so a human (or `docker ps | grep`) can spot them.
CONTAINER_PREFIX = "ctf_"
NETWORK_PREFIX = "ctf-run-"


def _env_str(name: str, default: str) -> str:
    """Return env var `name`, falling back to `default` if unset/blank."""
    val = os.environ.get(name)
    return val if val else default


def _env_int(name: str, default: int) -> int:
    """Return env var `name` as int, falling back to `default` on unset/garbage.

    Mirrors the `parseInt(process.env.X || 'default', 10) || default` idiom —
    a malformed override degrades to the safe default rather than raising.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    """Return env var `name` as float, falling back to `default` on garbage."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


@dataclass
class HardeningConfig:
    """Enforced sandbox limits, each env-overridable with a literal default.

    Defaults are sized for the tiny challenge servers that actually exist today
    (a Flask app / a socat listener), not the heavy agent-tools container in
    cybench-bench.mjs. Per-challenge overrides (manifest `docker.*`) are applied
    on top of these by the caller, not here.
    """

    # Memory cap (docker accepts the suffixed string form directly, e.g. "512m").
    # memswap is pinned equal to mem_limit => swap disabled, matching cybench.
    mem_limit: str = field(default_factory=lambda: _env_str("CTF_MEM_LIMIT", "512m"))
    # CPU cap in whole/fractional CPUs; converted to nano_cpus for the SDK.
    cpu_limit: float = field(default_factory=lambda: _env_float("CTF_CPU_LIMIT", 1.0))
    # Hard cap on process count inside the container (fork-bomb guard).
    pids_limit: int = field(default_factory=lambda: _env_int("CTF_PIDS_LIMIT", 256))
    # Hard wall-clock lifetime (seconds) for a challenge container, independent
    # of the agent loop's own per-challenge time_limit_seconds.
    container_timeout: int = field(
        default_factory=lambda: _env_int("CTF_CONTAINER_TIMEOUT", 600)
    )
    # Non-root UID:GID challenges run as by default. 65534:65534 is the
    # conventional Linux "nobody:nogroup" low-privilege pair -- used as a
    # bare numeric ID (not a username) so it works regardless of whether the
    # challenge image's /etc/passwd defines that user. A challenge that
    # genuinely needs root can override via the manifest's docker.user.
    container_user: str = field(default_factory=lambda: _env_str("CTF_CONTAINER_USER", "65534:65534"))

    @property
    def nano_cpus(self) -> int:
        """CPU cap in nano-CPU units (1 CPU == 1_000_000_000)."""
        return int(self.cpu_limit * 1_000_000_000)


def container_security_kwargs(
    cfg: HardeningConfig,
    *,
    network_name: str,
    allow_egress: bool = False,
    cap_add: Optional[List[str]] = None,
    read_only: bool = False,
    extra_mem_limit: Optional[str] = None,
    run_as_user: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the hardened kwargs to splat into `docker.containers.run()`.

    Pure function (no Docker, no I/O) — this is the primary unit-test surface.

    Args:
        cfg: baseline enforced limits.
        network_name: the per-run network to attach the container to. The
            caller is responsible for having created it with `internal=<not
            allow_egress>` — see `network_create_kwargs`. We only reference it
            here so the container never lands on the default bridge.
        allow_egress: per-challenge opt-in. Does NOT change what we return here
            (the network's `internal` flag is what blocks egress); it's accepted
            so callers can assert intent and so the signature documents the knob.
        cap_add: extra Linux capabilities a specific challenge needs (e.g.
            ["SYS_PTRACE"]). Added back on top of the ALL-drop.
        read_only: mount the rootfs read-only (+ tmpfs for /tmp). Opt-in only —
            default off, since it breaks any challenge that writes to disk.
        extra_mem_limit: per-challenge memory override (e.g. "2g") replacing the
            baseline mem_limit for both memory and memory-swap.
        run_as_user: overrides `cfg.container_user` (e.g. "root" for a
            challenge that genuinely needs it). Passing "" runs as whatever
            the image's own Dockerfile USER/default is, skipping the `user`
            kwarg entirely — an explicit opt-out, not just "unset".

    Returns:
        dict of docker-py `containers.run` kwargs (security-relevant only).
    """
    mem = extra_mem_limit or cfg.mem_limit
    user = cfg.container_user if run_as_user is None else run_as_user
    kwargs: Dict[str, Any] = {
        # --- Resource limits (measure #1) -------------------------------
        "mem_limit": mem,
        "memswap_limit": mem,  # == mem_limit => swap disabled (cybench pattern)
        "nano_cpus": cfg.nano_cpus,
        "pids_limit": cfg.pids_limit,
        # --- Network isolation (measure #2) -----------------------------
        # Attach to the caller-created per-run network. Egress is blocked by
        # that network's `internal` flag, not here.
        "network": network_name,
        # --- Capability restriction (measure #3) ------------------------
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        # --- Provenance / reaping (measure #4) --------------------------
        "labels": dict(ORPHAN_LABEL),
    }

    if user:
        kwargs["user"] = user

    if cap_add:
        kwargs["cap_add"] = list(cap_add)

    if read_only:
        kwargs["read_only"] = True
        # A read-only rootfs still needs a writable scratch area for most
        # servers; give an in-memory /tmp so nothing touches the host disk.
        kwargs["tmpfs"] = {"/tmp": ""}

    return kwargs


def network_create_kwargs(*, allow_egress: bool = False) -> Dict[str, Any]:
    """Kwargs for `docker.networks.create()` for a per-run challenge network.

    IMPORTANT — this does NOT use `internal=True`. That was the original
    design, but empirical testing against a live Docker daemon (Desktop
    29.7.2, linux/amd64) proved `internal=True` ALSO breaks published-port
    ingress (`-p hostPort:containerPort`) — not just outbound egress. Docker's
    `internal` flag skips the DNAT chain entirely for that network, so a
    challenge's exposed port becomes unreachable from the host too, which
    would make every challenge unplayable. This matches a known, documented
    Docker limitation (moby/moby#12871), not a bug in this code.

    Instead, egress is blocked by disabling the bridge's IP masquerade
    (`com.docker.network.bridge.enable_ip_masquerade=false`) while leaving
    `internal=False`. Ingress DNAT is a separate iptables chain from the
    masquerade/SNAT rule, so publishing still works; but outbound packets
    from the container leave with its private bridge-subnet source IP
    un-translated, so upstream routers drop them and no real internet
    connection can complete. `allow_egress=True` re-enables masquerade for a
    challenge that legitimately needs outbound access.
    """
    options: Dict[str, str] = {}
    if not allow_egress:
        options["com.docker.network.bridge.enable_ip_masquerade"] = "false"
    return {
        "driver": "bridge",
        "internal": False,
        "options": options,
        "labels": dict(ORPHAN_LABEL),
    }


def run_network_name(challenge_id: str, suffix: Any) -> str:
    """Deterministic per-run network name. `suffix` is typically int(time.time())."""
    return f"{NETWORK_PREFIX}{challenge_id}_{suffix}"


# ---------------------------------------------------------------------------
# Egress firewall (measure #2, layer 2) — a DOCKER-USER iptables rule.
#
# Empirically, disabling a network's IP masquerade (above) is NOT sufficient
# on its own: live testing against Docker Desktop 29.7.2 (linux/amd64)
# showed a pre-existing, broader MASQUERADE rule for the whole default IPAM
# pool (`172.17.0.0/16`) still translates and forwards a per-run network's
# outbound traffic, since that rule matches by source CIDR only, not by
# which bridge interface the traffic entered on. Disabling masquerade for
# one specific network doesn't remove a DIFFERENT, broader rule that also
# happens to cover its subnet.
#
# `DOCKER-USER` is Docker's own sanctioned chain for exactly this: rules
# placed here run in FORWARD before Docker's own forwarding logic, so they
# are not affected by the MASQUERADE ordering issue above. We match on
# connection state (NEW only) rather than blocking the whole subnet, so a
# challenge's *published port* keeps working — inbound connections and
# their replies are ESTABLISHED/RELATED, not NEW; only outbound connections
# the container itself initiates get dropped.
# ---------------------------------------------------------------------------

IPTABLES_HELPER_IMAGE = _env_str("CTF_IPTABLES_HELPER_IMAGE", "nicolaka/netshoot:latest")


def egress_block_rule_args(subnet: str, network_name: str):
    """Return (insert_args, delete_args) for iptables argv lists (no leading
    'iptables'), implementing a DOCKER-USER DROP of NEW connections sourced
    from `subnet`. `delete_args` matches the full rule spec (not a line
    number) so removal is safe regardless of what else has since been
    inserted into the chain by concurrent challenge runs.
    """
    comment = f"ares-ctf:{network_name}"
    match_spec = [
        "-s", subnet,
        "-m", "conntrack", "--ctstate", "NEW",
        "-m", "comment", "--comment", comment,
        "-j", "DROP",
    ]
    insert_args = ["-I", "DOCKER-USER", "1", *match_spec]
    delete_args = ["-D", "DOCKER-USER", *match_spec]
    return insert_args, delete_args


def run_iptables(client: Any, args: List[str]) -> bool:
    """Apply an iptables command against the Docker daemon's own netns.

    Tries a direct local `iptables` call first — the expected path when this
    executor runs as root on a native Linux host (its real target
    environment; see core/.docker/Dockerfile's own "Network access is
    restricted by host firewall rules" note). Falls back to a privileged
    `--network host` helper container when that doesn't work, which covers
    the case where the daemon's netns isn't the caller's own — notably
    Docker Desktop, whose dockerd lives inside a hidden VM a local
    `iptables` call can't reach.

    Best-effort: this is a defense-in-depth layer on top of the per-network
    masquerade toggle, not a hard requirement for a challenge to start.
    Failures are logged and swallowed (returns False) rather than raised.
    """
    try:
        subprocess.run(["iptables", *args], check=True, capture_output=True, timeout=10)
        return True
    except Exception as e:
        logger.info(f"Local iptables call failed ({e}); trying helper container")

    try:
        client.containers.run(
            IPTABLES_HELPER_IMAGE,
            ["iptables", *args],
            network_mode="host",
            privileged=True,
            remove=True,
        )
        return True
    except Exception as e:
        logger.warning(f"Could not apply egress firewall rule via helper container: {e}")
        return False


def list_iptables_rules(client: Any, chain: str) -> List[str]:
    """Return `iptables -S <chain>` output as a list of rule-spec lines.

    Same local-then-helper-container strategy as `run_iptables`. Returns []
    on total failure (logged), so a host with neither path available
    degrades to "nothing to reap" rather than crashing startup.
    """
    try:
        result = subprocess.run(
            ["iptables", "-S", chain], check=True, capture_output=True, timeout=10, text=True
        )
        return result.stdout.splitlines()
    except Exception as e:
        logger.info(f"Local iptables -S call failed ({e}); trying helper container")

    try:
        output = client.containers.run(
            IPTABLES_HELPER_IMAGE,
            ["iptables", "-S", chain],
            network_mode="host",
            privileged=True,
            remove=True,
        )
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return output.splitlines()
    except Exception as e:
        logger.warning(f"Could not list iptables rules for {chain}: {e}")
        return []


def orphaned_ares_ctf_rule_delete_args(rule_lines: List[str]) -> List[List[str]]:
    """Convert `-S`-style rule-spec lines carrying our `ares-ctf:` comment tag
    into `-D` delete-argv lists — i.e. every rule this module could have
    inserted, regardless of which run left it behind. Used at startup to
    reap firewall rules from a crashed prior process, the same way
    _reap_orphans reaps containers/networks by label.
    """
    deletes = []
    for line in rule_lines:
        if "ares-ctf:" not in line:
            continue
        # shlex, not str.split(): `-S` quotes the comment value for shell
        # round-tripping (e.g. `--comment "ares-ctf:foo"`) — a naive split
        # would leave literal quote characters in the token, which then
        # fails to match the actual (unquoted) rule when used with -D.
        parts = shlex.split(line)
        if not parts or parts[0] != "-A":
            continue
        deletes.append(["-D", *parts[1:]])
    return deletes


# ---------------------------------------------------------------------------
# Host-side subprocess teardown (measure #4: kill the process GROUP, not just
# the shell PID, so a timed-out tool doesn't leave orphaned children behind).
# POSIX-only; on Windows we fall back to a plain kill (current behaviour).
# ---------------------------------------------------------------------------

def posix_process_group_kwargs() -> Dict[str, Any]:
    """Popen/asyncio kwargs that put a child in its own process group.

    `start_new_session=True` calls setsid(2) so the child (and everything it
    spawns) shares a new process-group id we can signal as a unit. No-op on
    non-POSIX, where the concept doesn't exist.
    """
    if os.name == "posix":
        return {"start_new_session": True}
    return {}


def kill_process_group(proc: Any) -> None:
    """Kill `proc` and its whole process group (POSIX), else just the process.

    Best-effort: swallows the races where the process is already gone.
    """
    pid = getattr(proc, "pid", None)
    if pid is None:
        return
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OSError):
            # Fall through to a direct kill if the group is already reaped or
            # getpgid fails for any reason.
            pass
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass


def register_cleanup_handlers(cleanup_fn: Callable[[], None]) -> None:
    """Wire `cleanup_fn` to run on normal interpreter exit AND on SIGTERM/SIGINT.

    Intended to be called once, from `main()` only — never at import time —
    so importing this module (e.g. from tests) never installs global signal
    handlers as a side effect.

    `signal.signal` raises ValueError when called outside the main thread;
    that's swallowed so a caller running inside a worker thread degrades to
    atexit-only cleanup instead of crashing.
    """
    atexit.register(cleanup_fn)

    def _handler(signum: int, frame: Any) -> None:
        cleanup_fn()
        sys.exit(1)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass
