#!/usr/bin/env python3
"""
POC-3 — tests for sandbox hardening.

Two tiers:
  * Pure tier (this file's TestPure* / test_* functions without the
    `docker` importorskip guard) — exercises `hardening.py` directly. No
    Docker SDK, no daemon, runs anywhere `pytest` runs.
  * Mocked-integration tier (functions guarded by
    `pytest.importorskip("docker")`) — imports `ctf_executor` with
    `docker.from_env` monkeypatched to a `MagicMock`, and asserts the
    hardened kwargs actually reach `containers.run` / `networks.create`.
    No live daemon required; skipped entirely if the `docker` package
    isn't installed.
"""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hardening  # noqa: E402


# ---------------------------------------------------------------------------
# Pure tier — HardeningConfig
# ---------------------------------------------------------------------------

def test_hardening_config_defaults(monkeypatch):
    for var in ("CTF_MEM_LIMIT", "CTF_CPU_LIMIT", "CTF_PIDS_LIMIT", "CTF_CONTAINER_TIMEOUT"):
        monkeypatch.delenv(var, raising=False)
    cfg = hardening.HardeningConfig()
    assert cfg.mem_limit == "512m"
    assert cfg.cpu_limit == 1.0
    assert cfg.pids_limit == 256
    assert cfg.container_timeout == 600
    assert cfg.nano_cpus == 1_000_000_000


def test_hardening_config_env_overrides(monkeypatch):
    monkeypatch.setenv("CTF_MEM_LIMIT", "1g")
    monkeypatch.setenv("CTF_CPU_LIMIT", "2.5")
    monkeypatch.setenv("CTF_PIDS_LIMIT", "64")
    monkeypatch.setenv("CTF_CONTAINER_TIMEOUT", "120")
    cfg = hardening.HardeningConfig()
    assert cfg.mem_limit == "1g"
    assert cfg.cpu_limit == 2.5
    assert cfg.pids_limit == 64
    assert cfg.container_timeout == 120
    assert cfg.nano_cpus == 2_500_000_000


def test_hardening_config_garbage_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("CTF_CPU_LIMIT", "not-a-number")
    monkeypatch.setenv("CTF_PIDS_LIMIT", "also-garbage")
    monkeypatch.setenv("CTF_CONTAINER_TIMEOUT", "")
    cfg = hardening.HardeningConfig()
    assert cfg.cpu_limit == 1.0
    assert cfg.pids_limit == 256
    assert cfg.container_timeout == 600


# ---------------------------------------------------------------------------
# Pure tier — container_security_kwargs
# ---------------------------------------------------------------------------

def test_container_security_kwargs_baseline():
    cfg = hardening.HardeningConfig(mem_limit="512m", cpu_limit=1.0, pids_limit=256)
    kwargs = hardening.container_security_kwargs(cfg, network_name="ctf-run-foo_123")

    assert kwargs["mem_limit"] == "512m"
    assert kwargs["memswap_limit"] == "512m"  # pinned equal => swap disabled
    assert kwargs["nano_cpus"] == 1_000_000_000
    assert kwargs["pids_limit"] == 256
    assert kwargs["network"] == "ctf-run-foo_123"
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["labels"] == hardening.ORPHAN_LABEL
    assert "cap_add" not in kwargs
    assert "read_only" not in kwargs
    assert "tmpfs" not in kwargs


def test_container_security_kwargs_allow_egress_does_not_change_container_kwargs():
    """allow_egress is a documentation/assertion knob here — the actual egress
    block lives in the network's `internal` flag (network_create_kwargs),
    not in the container kwargs. Locks in that contract."""
    cfg = hardening.HardeningConfig()
    egress_off = hardening.container_security_kwargs(
        cfg, network_name="net", allow_egress=False
    )
    egress_on = hardening.container_security_kwargs(
        cfg, network_name="net", allow_egress=True
    )
    assert egress_off == egress_on


def test_container_security_kwargs_cap_add():
    cfg = hardening.HardeningConfig()
    kwargs = hardening.container_security_kwargs(
        cfg, network_name="net", cap_add=["SYS_PTRACE"]
    )
    assert kwargs["cap_add"] == ["SYS_PTRACE"]
    assert kwargs["cap_drop"] == ["ALL"]  # still dropped everything else


def test_container_security_kwargs_read_only():
    cfg = hardening.HardeningConfig()
    kwargs = hardening.container_security_kwargs(cfg, network_name="net", read_only=True)
    assert kwargs["read_only"] is True
    assert kwargs["tmpfs"] == {"/tmp": ""}


def test_container_security_kwargs_extra_mem_limit_overrides_both():
    cfg = hardening.HardeningConfig(mem_limit="512m")
    kwargs = hardening.container_security_kwargs(
        cfg, network_name="net", extra_mem_limit="2g"
    )
    assert kwargs["mem_limit"] == "2g"
    assert kwargs["memswap_limit"] == "2g"


# ---------------------------------------------------------------------------
# Pure tier — network_create_kwargs / run_network_name
# ---------------------------------------------------------------------------

def test_network_create_kwargs_default_disables_masquerade():
    """Egress is blocked via disabled IP masquerade, NOT `internal=True` —
    internal=True was empirically proven (Tier 3 smoke, Docker Desktop
    29.7.2) to also break published-port ingress. See the docstring on
    network_create_kwargs for the full explanation."""
    kwargs = hardening.network_create_kwargs()
    assert kwargs["internal"] is False
    assert kwargs["driver"] == "bridge"
    assert kwargs["options"]["com.docker.network.bridge.enable_ip_masquerade"] == "false"
    assert kwargs["labels"] == hardening.ORPHAN_LABEL


def test_network_create_kwargs_allow_egress_reenables_masquerade():
    kwargs = hardening.network_create_kwargs(allow_egress=True)
    assert kwargs["internal"] is False
    assert "com.docker.network.bridge.enable_ip_masquerade" not in kwargs["options"]


def test_run_network_name_format():
    name = hardening.run_network_name("web_sqli_basic", 1700000000)
    assert name == "ctf-run-web_sqli_basic_1700000000"
    assert name.startswith(hardening.NETWORK_PREFIX)


# ---------------------------------------------------------------------------
# Pure tier — egress_block_rule_args / run_iptables
#
# run_iptables() only duck-types its `client` argument (needs
# `.containers.run(...)`), so a MagicMock is enough — these don't need the
# real `docker` package and belong in the pure tier.
# ---------------------------------------------------------------------------

def test_egress_block_rule_args_insert_shape():
    insert_args, _ = hardening.egress_block_rule_args("172.30.0.0/24", "ctf-run-demo_1")
    assert insert_args[:3] == ["-I", "DOCKER-USER", "1"]
    assert "-s" in insert_args and "172.30.0.0/24" in insert_args
    assert "--ctstate" in insert_args and "NEW" in insert_args
    assert "ares-ctf:ctf-run-demo_1" in insert_args
    assert insert_args[-2:] == ["-j", "DROP"]


def test_egress_block_rule_args_delete_matches_insert_spec_without_position():
    insert_args, delete_args = hardening.egress_block_rule_args("172.30.0.0/24", "ctf-run-demo_1")
    assert delete_args[:2] == ["-D", "DOCKER-USER"]
    # Same match spec (everything after the chain name), no position number.
    assert delete_args[2:] == insert_args[3:]


def test_run_iptables_prefers_local_call(monkeypatch):
    calls = []
    monkeypatch.setattr(
        hardening.subprocess, "run",
        lambda cmd, **kw: calls.append(cmd) or MagicMock(returncode=0)
    )
    fake_client = MagicMock()

    ok = hardening.run_iptables(fake_client, ["-I", "DOCKER-USER", "1", "-j", "DROP"])

    assert ok is True
    assert calls and calls[0][0] == "iptables"
    fake_client.containers.run.assert_not_called()


def test_run_iptables_falls_back_to_helper_container_on_local_failure(monkeypatch):
    def raising_run(cmd, **kw):
        raise FileNotFoundError("no local iptables binary")

    monkeypatch.setattr(hardening.subprocess, "run", raising_run)
    fake_client = MagicMock()

    ok = hardening.run_iptables(fake_client, ["-I", "DOCKER-USER", "1", "-j", "DROP"])

    assert ok is True
    fake_client.containers.run.assert_called_once()
    _, kwargs = fake_client.containers.run.call_args
    assert kwargs.get("network_mode") == "host"
    assert kwargs.get("privileged") is True


def test_list_iptables_rules_prefers_local_call(monkeypatch):
    sample_output = (
        '-N DOCKER-USER\n'
        '-A DOCKER-USER -s 172.18.0.0/16 -m conntrack --ctstate NEW '
        '-m comment --comment "ares-ctf:ctf-run-demo_1" -j DROP\n'
    )
    monkeypatch.setattr(
        hardening.subprocess, "run",
        lambda cmd, **kw: MagicMock(stdout=sample_output, returncode=0)
    )
    fake_client = MagicMock()

    lines = hardening.list_iptables_rules(fake_client, "DOCKER-USER")

    assert any("ares-ctf:ctf-run-demo_1" in line for line in lines)
    fake_client.containers.run.assert_not_called()


def test_list_iptables_rules_falls_back_to_helper_container(monkeypatch):
    def raising_run(cmd, **kw):
        raise FileNotFoundError()

    monkeypatch.setattr(hardening.subprocess, "run", raising_run)
    fake_client = MagicMock()
    fake_client.containers.run.return_value = b"-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"

    lines = hardening.list_iptables_rules(fake_client, "DOCKER-USER")

    assert lines == ["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"]


def test_list_iptables_rules_returns_empty_on_total_failure(monkeypatch):
    monkeypatch.setattr(
        hardening.subprocess, "run",
        lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError())
    )
    fake_client = MagicMock()
    fake_client.containers.run.side_effect = RuntimeError("no docker access")

    assert hardening.list_iptables_rules(fake_client, "DOCKER-USER") == []


def test_orphaned_ares_ctf_rule_delete_args_extracts_only_tagged_rules():
    rule_lines = [
        "-N DOCKER-USER",
        '-A DOCKER-USER -s 172.18.0.0/16 -m conntrack --ctstate NEW '
        '-m comment --comment "ares-ctf:ctf-run-a_1" -j DROP',
        "-A DOCKER-USER -j RETURN",  # unrelated rule -- must be ignored
        '-A DOCKER-USER -s 172.19.0.0/16 -m conntrack --ctstate NEW '
        '-m comment --comment "ares-ctf:ctf-run-b_2" -j DROP',
    ]

    deletes = hardening.orphaned_ares_ctf_rule_delete_args(rule_lines)

    assert len(deletes) == 2
    assert deletes[0][:2] == ["-D", "DOCKER-USER"]
    # Quotes must be stripped -- iptables -S quotes the comment for shell
    # round-tripping, but -D needs the bare value to match the live rule.
    assert "ares-ctf:ctf-run-a_1" in deletes[0]
    assert '"ares-ctf:ctf-run-a_1"' not in deletes[0]
    assert "ares-ctf:ctf-run-b_2" in deletes[1]


def test_orphaned_ares_ctf_rule_delete_args_empty_when_no_tagged_rules():
    rule_lines = ["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"]
    assert hardening.orphaned_ares_ctf_rule_delete_args(rule_lines) == []


def test_run_iptables_returns_false_when_both_layers_fail(monkeypatch):
    monkeypatch.setattr(
        hardening.subprocess, "run",
        lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError())
    )
    fake_client = MagicMock()
    fake_client.containers.run.side_effect = RuntimeError("no docker access either")

    ok = hardening.run_iptables(fake_client, ["-I", "DOCKER-USER", "1", "-j", "DROP"])

    assert ok is False


# ---------------------------------------------------------------------------
# Pure tier — process-group helpers
# ---------------------------------------------------------------------------

def test_posix_process_group_kwargs_on_posix(monkeypatch):
    monkeypatch.setattr(hardening.os, "name", "posix")
    assert hardening.posix_process_group_kwargs() == {"start_new_session": True}


def test_posix_process_group_kwargs_on_windows(monkeypatch):
    monkeypatch.setattr(hardening.os, "name", "nt")
    assert hardening.posix_process_group_kwargs() == {}


def test_kill_process_group_terminates_real_subprocess():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        **hardening.posix_process_group_kwargs(),
    )
    try:
        hardening.kill_process_group(proc)
        proc.wait(timeout=5)
        assert proc.returncode is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_kill_process_group_is_idempotent_on_already_exited_process():
    proc = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        **hardening.posix_process_group_kwargs(),
    )
    proc.wait(timeout=5)
    # Must not raise even though the process (and possibly its group) is gone.
    hardening.kill_process_group(proc)


def test_kill_process_group_no_pid_is_a_noop():
    fake = MagicMock()
    fake.pid = None
    hardening.kill_process_group(fake)
    fake.kill.assert_not_called()


# ---------------------------------------------------------------------------
# Pure tier — register_cleanup_handlers
# ---------------------------------------------------------------------------

def test_register_cleanup_handlers_wires_atexit_and_signals(monkeypatch):
    registered_atexit = []
    registered_signals = {}

    monkeypatch.setattr(hardening.atexit, "register", registered_atexit.append)

    def fake_signal(sig, handler):
        registered_signals[sig] = handler

    monkeypatch.setattr(hardening.signal, "signal", fake_signal)

    def cleanup():
        pass

    hardening.register_cleanup_handlers(cleanup)

    assert cleanup in registered_atexit
    assert hardening.signal.SIGTERM in registered_signals
    assert hardening.signal.SIGINT in registered_signals


def test_register_cleanup_handlers_survives_signal_error(monkeypatch):
    """If signal.signal raises (e.g. not called from the main thread), the
    function must not propagate — atexit-only cleanup is an acceptable
    degradation, a crash on registration is not."""
    monkeypatch.setattr(hardening.atexit, "register", lambda fn: None)

    def raising_signal(sig, handler):
        raise ValueError("signal only works in main thread")

    monkeypatch.setattr(hardening.signal, "signal", raising_signal)

    hardening.register_cleanup_handlers(lambda: None)  # must not raise


# ---------------------------------------------------------------------------
# Mocked-integration tier — requires the `docker` package to be importable,
# but NOT a running daemon (docker.from_env is monkeypatched to a MagicMock).
#
# IMPORTANT: `pytest.importorskip` is called INSIDE each fixture/test body
# below, not at module level. A module-level importorskip would skip the
# *entire file* — including the pure tests above — whenever the `docker`
# package isn't installed, which defeats the whole point of having a
# dependency-free pure tier. Keeping the skip local means only these
# specific tests skip when `docker` is absent.
# ---------------------------------------------------------------------------

@pytest.fixture
def ctf_executor_module(monkeypatch):
    """Import ctf_executor with docker.from_env replaced before the module
    (or its DockerChallengeManager) ever talks to a real daemon.

    Also stubs `module.run_iptables` and `module.list_iptables_rules` to
    no-ops by default: fake Network mocks don't have real IPAM attrs, so the
    real run_iptables would otherwise hit its container-fallback path (since
    indexing a MagicMock's `.attrs` doesn't raise, it just returns more
    MagicMocks) and spuriously call `fake_client.containers.run` a second
    time — same story for list_iptables_rules, which DockerChallengeManager's
    __init__ (_reap_orphans) calls unconditionally, unmocked would ALSO fall
    back to the same `fake_client.containers.run` mock and break
    `assert_called_once()` in tests that don't care about the firewall path.
    Tests that DO care override these themselves afterward.
    """
    docker = pytest.importorskip("docker")
    fake_client = MagicMock()
    monkeypatch.setattr(docker, "from_env", lambda: fake_client)

    sys.modules.pop("ctf_executor", None)
    import ctf_executor as module  # noqa: E402
    module.run_iptables = MagicMock(return_value=True)
    module.list_iptables_rules = MagicMock(return_value=[])

    return module, fake_client


def test_start_challenge_applies_hardened_kwargs(ctf_executor_module, tmp_path):
    module, fake_client = ctf_executor_module

    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []

    fake_network = MagicMock()
    fake_network.name = "ctf-run-demo_1"
    fake_client.networks.create.return_value = fake_network

    fake_container = MagicMock()
    fake_container.id = "deadbeef"
    fake_client.containers.run.return_value = fake_container

    manager = module.DockerChallengeManager()
    challenge = {
        "id": "demo",
        "docker": {"image": "ares/demo:latest", "ports": ["8080:80"]},
    }

    result = manager.start_challenge(challenge)

    assert result["success"] is True
    fake_client.networks.create.assert_called_once()
    _, network_create_kwargs = fake_client.networks.create.call_args
    assert network_create_kwargs.get("internal") is False
    assert (
        network_create_kwargs["options"]["com.docker.network.bridge.enable_ip_masquerade"]
        == "false"
    )

    fake_client.containers.run.assert_called_once()
    _, run_kwargs = fake_client.containers.run.call_args
    assert run_kwargs["cap_drop"] == ["ALL"]
    assert run_kwargs["security_opt"] == ["no-new-privileges:true"]
    assert run_kwargs["network"] == "ctf-run-demo_1"
    assert "mem_limit" in run_kwargs
    assert "pids_limit" in run_kwargs


def test_start_challenge_honors_allow_egress_override(ctf_executor_module):
    module, fake_client = ctf_executor_module
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []
    fake_client.networks.create.return_value = MagicMock(name="ctf-run-open_1")
    fake_client.containers.run.return_value = MagicMock(id="c1")

    manager = module.DockerChallengeManager()
    challenge = {
        "id": "open",
        "docker": {
            "image": "ares/open:latest",
            "ports": ["8080:80"],
            "allow_egress": True,
        },
    }

    manager.start_challenge(challenge)

    _, network_create_kwargs = fake_client.networks.create.call_args
    assert network_create_kwargs.get("internal") is False
    assert "com.docker.network.bridge.enable_ip_masquerade" not in network_create_kwargs["options"]


def test_start_challenge_applies_egress_firewall_rule(ctf_executor_module, monkeypatch):
    module, fake_client = ctf_executor_module
    monkeypatch.setattr(module.time, "time", lambda: 1700000000.0)
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []

    fake_network = MagicMock()
    fake_network.name = "ctf-run-demo_1700000000"
    fake_network.attrs = {"IPAM": {"Config": [{"Subnet": "172.30.5.0/24"}]}}
    fake_client.networks.create.return_value = fake_network
    fake_client.containers.run.return_value = MagicMock(id="c1")

    module.run_iptables = MagicMock(return_value=True)

    manager = module.DockerChallengeManager()
    manager.start_challenge(
        {"id": "demo", "docker": {"image": "ares/demo:latest", "ports": ["8080:80"]}}
    )

    expected_insert, expected_delete = hardening.egress_block_rule_args(
        "172.30.5.0/24", "ctf-run-demo_1700000000"
    )
    module.run_iptables.assert_called_once_with(fake_client, expected_insert)
    assert manager.running_containers["demo"]["iptables_delete_args"] == expected_delete


def test_start_challenge_skips_egress_firewall_when_allow_egress(ctf_executor_module, monkeypatch):
    module, fake_client = ctf_executor_module
    monkeypatch.setattr(module.time, "time", lambda: 1700000000.0)
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []
    fake_network = MagicMock()
    fake_network.attrs = {"IPAM": {"Config": [{"Subnet": "172.30.5.0/24"}]}}
    fake_client.networks.create.return_value = fake_network
    fake_client.containers.run.return_value = MagicMock(id="c1")

    module.run_iptables = MagicMock(return_value=True)

    manager = module.DockerChallengeManager()
    manager.start_challenge({
        "id": "open",
        "docker": {"image": "ares/open:latest", "ports": ["8080:80"], "allow_egress": True},
    })

    module.run_iptables.assert_not_called()
    assert manager.running_containers["open"]["iptables_delete_args"] is None


def test_stop_challenge_removes_egress_firewall_rule(ctf_executor_module, monkeypatch):
    module, fake_client = ctf_executor_module
    monkeypatch.setattr(module.time, "time", lambda: 1700000000.0)
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []
    fake_network = MagicMock()
    fake_network.attrs = {"IPAM": {"Config": [{"Subnet": "172.30.5.0/24"}]}}
    fake_client.networks.create.return_value = fake_network
    fake_client.containers.run.return_value = MagicMock(id="c1")

    module.run_iptables = MagicMock(return_value=True)

    manager = module.DockerChallengeManager()
    manager.start_challenge(
        {"id": "demo", "docker": {"image": "ares/demo:latest", "ports": ["8080:80"]}}
    )
    module.run_iptables.reset_mock()

    manager.stop_challenge("demo")

    _, expected_delete = hardening.egress_block_rule_args("172.30.5.0/24", "ctf-run-demo_1700000000")
    module.run_iptables.assert_called_once_with(fake_client, expected_delete)


def test_stop_challenge_tears_down_container_and_network(ctf_executor_module):
    module, fake_client = ctf_executor_module
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []

    fake_network = MagicMock()
    fake_network.name = "ctf-run-demo_1"
    fake_client.networks.create.return_value = fake_network

    fake_container = MagicMock()
    fake_container.id = "deadbeef"
    fake_client.containers.run.return_value = fake_container

    manager = module.DockerChallengeManager()
    challenge = {"id": "demo", "docker": {"image": "ares/demo:latest", "ports": ["8080:80"]}}
    manager.start_challenge(challenge)

    manager.stop_challenge("demo")

    fake_container.stop.assert_called_once()
    fake_network.remove.assert_called_once()
    assert "demo" not in manager.running_containers


def test_cleanup_all_tears_down_even_if_one_challenge_errors(ctf_executor_module):
    module, fake_client = ctf_executor_module
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []

    fake_client.networks.create.side_effect = [
        MagicMock(name="ctf-run-a_1"),
        MagicMock(name="ctf-run-b_1"),
    ]
    broken_container = MagicMock(id="a")
    broken_container.stop.side_effect = RuntimeError("boom")
    ok_container = MagicMock(id="b")
    fake_client.containers.run.side_effect = [broken_container, ok_container]

    manager = module.DockerChallengeManager()
    manager.start_challenge({"id": "a", "docker": {"image": "x", "ports": []}})
    manager.start_challenge({"id": "b", "docker": {"image": "y", "ports": []}})

    manager.cleanup_all()  # must not raise despite "a" erroring

    assert manager.running_containers == {}


def test_init_reaps_orphaned_containers_and_networks(monkeypatch):
    docker = pytest.importorskip("docker")
    fake_client = MagicMock()
    monkeypatch.setattr(docker, "from_env", lambda: fake_client)

    orphan_container = MagicMock()
    orphan_network = MagicMock()
    fake_client.containers.list.return_value = [orphan_container]
    fake_client.networks.list.return_value = [orphan_network]

    sys.modules.pop("ctf_executor", None)
    import ctf_executor as module  # noqa: E402

    module.DockerChallengeManager()

    fake_client.containers.list.assert_called_once()
    list_kwargs = fake_client.containers.list.call_args.kwargs
    assert hardening.ORPHAN_LABEL_FILTER in list_kwargs.get("filters", {}).get("label", [])

    orphan_container.remove.assert_called_once()
    orphan_network.remove.assert_called_once()


def test_init_reaps_orphaned_firewall_rules(monkeypatch):
    docker = pytest.importorskip("docker")
    fake_client = MagicMock()
    monkeypatch.setattr(docker, "from_env", lambda: fake_client)
    fake_client.containers.list.return_value = []
    fake_client.networks.list.return_value = []

    sys.modules.pop("ctf_executor", None)
    import ctf_executor as module  # noqa: E402

    tagged_rule = (
        '-A DOCKER-USER -s 172.18.0.0/16 -m conntrack --ctstate NEW '
        '-m comment --comment "ares-ctf:ctf-run-orphan_1" -j DROP'
    )
    module.list_iptables_rules = MagicMock(return_value=["-N DOCKER-USER", tagged_rule])
    module.run_iptables = MagicMock(return_value=True)

    module.DockerChallengeManager()

    module.run_iptables.assert_called_once()
    _, delete_args = module.run_iptables.call_args[0]
    assert delete_args[:2] == ["-D", "DOCKER-USER"]
    assert "ares-ctf:ctf-run-orphan_1" in delete_args
