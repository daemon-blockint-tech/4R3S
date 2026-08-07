"""Tests for the auditor-api wrapper.

Scope note: these cover the pure logic — path resolution and stderr parsing —
and deliberately do not spin up Redis or invoke the audit CLI. An end-to-end
test would need a live Redis, a working OPENROUTER_API_KEY, and ~90s of real
LLM spend per run, which is not something CI should carry on every push.

Both tested behaviours are here because they broke during manual verification,
not because they looked risky in review:

* `REPO_ROOT` was wrong twice (`parents[1]` instead of `parents[2]`), and both
  times the symptom was a 422 that looked like operator error rather than a
  bug. `__file__` is a file, so `.parents[0]` is already the containing folder.
* `_last_error_line` returned the generic "Audit failed" because it read `msg`
  when index.ts puts the real cause in `err` — index.ts's own comments flag
  that exact gap ("the operator sees 'Audit failed' and nothing else").
"""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import main
import worker
from main import REPO_ROOT, AuditRequest
from worker import _last_error_line


class TestSourcePathResolution:
    def test_relative_path_resolves_against_repo_root(self, tmp_path, monkeypatch):
        # Self-contained: create the target file rather than depending on
        # package.json existing at REPO_ROOT, which is true today but is an
        # assumption about repo layout this test shouldn't need to make.
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        (tmp_path / "target.rs").write_text("// fixture")
        req = AuditRequest(source="target.rs")
        assert req.source == str(tmp_path / "target.rs")

    def test_repo_root_is_the_repo_not_the_apps_folder(self):
        # Pins the off-by-one directly against the real filesystem: if
        # REPO_ROOT ever drifts back to parents[1], this fails loudly instead
        # of surfacing as a confusing 422.
        assert (REPO_ROOT / "package.json").exists()
        assert REPO_ROOT.name != "apps"

    def test_absolute_path_inside_the_root_is_accepted(self, tmp_path, monkeypatch):
        # An absolute path is still fine — but only inside the allowed root.
        # This test used to assert that ANY absolute path passed through
        # unchanged, which is the behaviour that let an unauthenticated caller
        # name any directory on the host. The containment check replaced it.
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        target = tmp_path / "target.rs"
        target.write_text("// fixture")
        assert AuditRequest(source=str(target)).source == str(target)

    def test_absolute_path_outside_the_root_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path / "allowed")
        (tmp_path / "allowed").mkdir()
        outside = tmp_path / "someone-elses-repo"
        outside.mkdir()
        with pytest.raises(ValidationError, match="outside the allowed root"):
            AuditRequest(source=str(outside))

    def test_missing_path_is_rejected_before_it_reaches_the_queue(self):
        # A queue slot spent on a target that cannot succeed is a slot stolen
        # from one that could, and this queue is capped by daily LLM quota.
        with pytest.raises(ValidationError, match="does not exist"):
            AuditRequest(source="no/such/file.rs")


class TestErrorLineExtraction:
    def test_prefers_the_err_field_over_the_generic_message(self):
        stderr = json.dumps(
            {"level": "error", "component": "ares", "err": "Error: 401 Incorrect API key"}
        )
        assert _last_error_line(stderr) == "Error: 401 Incorrect API key"

    def test_falls_back_to_msg_when_there_is_no_err_field(self):
        stderr = json.dumps({"level": "error", "msg": "something broke"})
        assert _last_error_line(stderr) == "something broke"

    def test_skips_warnings_and_reports_the_error(self):
        # A run that hit rate limits emits a wall of retry warnings before the
        # actual failure; the warnings must not bury the cause.
        stderr = "\n".join([
            json.dumps({"level": "warn", "msg": "Transient LLM error; retrying"}),
            json.dumps({"level": "warn", "msg": "Transient LLM error; retrying"}),
            json.dumps({"level": "error", "err": "RateLimitCapacityError: 429"}),
        ])
        assert _last_error_line(stderr) == "RateLimitCapacityError: 429"

    def test_unparseable_stderr_still_yields_something_actionable(self):
        # Not every failure produces structured JSON — a crash before the
        # logger initialises writes plain text. Returning "" here would report
        # a failure with no cause at all.
        assert "boom" in _last_error_line("plain text boom")

    def test_empty_stderr_is_reported_as_missing_detail_not_as_success(self):
        assert _last_error_line("") == "no error detail captured"

    @pytest.mark.parametrize("scalar", ["42", '"text"', "null", "true", "[1,2,3]"])
    def test_json_scalars_do_not_crash_the_parser(self, scalar):
        # json.loads succeeds on these but returns int/str/None/bool/list, not a
        # dict — calling .get() on the result raised AttributeError, which
        # escaped run_audit and left the job reading "running" until its TTL
        # expired. npm writes non-JSON lines to stderr, so this is reachable.
        assert _last_error_line(scalar) != ""

    def test_a_scalar_line_does_not_hide_a_real_error_below_it(self):
        stderr = "\n".join([
            json.dumps({"level": "error", "err": "the real cause"}),
            "42",  # a scalar line after the error must be skipped, not fatal
        ])
        assert _last_error_line(stderr) == "the real cause"


class TestCorruptStoredStatus:
    """Covers the gap found during the ORC-1 low-level review: the GET
    endpoint trusted Redis's contents unconditionally. Nothing else writes
    to `audit-result:{job_id}` today, but a future writer bug, a manual
    redis-cli edit, or a partial write from a crashed worker should surface
    as a diagnosable error, not an unhandled 500 that looks unrelated."""

    class _FakeRedis:
        def __init__(self, stored: str):
            self._stored = stored

        async def get(self, key: str):
            return self._stored

        async def close(self):
            pass

    def _client_with_stored_value(self, monkeypatch, stored: str) -> TestClient:
        async def fake_create_pool(_settings):
            return self._FakeRedis(stored)

        monkeypatch.setattr(main, "create_pool", fake_create_pool)
        return TestClient(main.app)

    def test_well_formed_status_still_returns_normally(self, monkeypatch):
        stored = json.dumps({"job_id": "abc", "status": "done", "report": "ok", "error": None})
        client = self._client_with_stored_value(monkeypatch, stored)
        resp = client.get("/audits/abc")
        assert resp.status_code == 200
        assert resp.json()["status"] == "done"

    def test_corrupt_json_returns_502_not_an_unhandled_500(self, monkeypatch):
        client = self._client_with_stored_value(monkeypatch, "not valid json {{{")
        resp = client.get("/audits/abc")
        assert resp.status_code == 502
        assert "corrupt" in resp.json()["detail"]

    def test_json_missing_required_fields_returns_502(self, monkeypatch):
        # Valid JSON, wrong shape — e.g. a status written by a future schema
        # version that dropped a required field.
        client = self._client_with_stored_value(monkeypatch, json.dumps({"unexpected": "shape"}))
        resp = client.get("/audits/abc")
        assert resp.status_code == 502


class TestDroppedEnqueue:
    """arq's enqueue_job returns None when a job with that id already exists.
    Ignoring it answered 202 for a job nothing would ever run, leaving the
    caller polling a 404 with no sign the submission had been dropped."""

    def test_rejected_enqueue_returns_503_not_202(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        (tmp_path / "target.rs").write_text("// fixture")

        class _RefusingRedis:
            async def enqueue_job(self, *args, **kwargs):
                return None  # arq's "already queued" signal

            async def close(self):
                pass

        async def fake_create_pool(_settings):
            return _RefusingRedis()

        monkeypatch.setattr(main, "create_pool", fake_create_pool)
        client = TestClient(main.app)
        resp = client.post("/audits", json={"source": "target.rs"})
        assert resp.status_code == 503
        assert "already exists" in resp.json()["detail"]

    def test_accepted_enqueue_still_returns_202(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        (tmp_path / "target.rs").write_text("// fixture")

        class _AcceptingRedis:
            async def enqueue_job(self, *args, **kwargs):
                return object()  # any non-None Job stand-in

            async def close(self):
                pass

        async def fake_create_pool(_settings):
            return _AcceptingRedis()

        monkeypatch.setattr(main, "create_pool", fake_create_pool)
        client = TestClient(main.app)
        resp = client.post("/audits", json={"source": "target.rs"})
        assert resp.status_code == 202
        assert resp.json()["status"] == "queued"


class TestWorkerNeverLeavesJobStuck:
    """The failure mode all four fixes share: an unhandled exception in the
    worker meant no status was ever written, so the job read "running" until
    its 24h TTL expired and then 404'd. Nothing in the API surfaced a failure.
    """

    class _RecordingRedis:
        def __init__(self):
            self.writes: list[dict] = []

        async def set(self, key, value, ex=None):
            self.writes.append(json.loads(value))

    def test_unexpected_exception_still_records_a_failed_status(self, monkeypatch):
        redis = self._RecordingRedis()

        async def blow_up(*args, **kwargs):
            raise PermissionError("cannot exec npm")

        monkeypatch.setattr(worker, "_audit_and_record", blow_up)

        # The exception must still propagate — arq needs it for logging and
        # retry — but a status must be recorded before it does.
        with pytest.raises(PermissionError):
            asyncio.run(worker.run_audit({"redis": redis}, "job-1", "target.rs"))

        statuses = [w["status"] for w in redis.writes]
        assert statuses == ["running", "failed"]
        assert "PermissionError" in redis.writes[-1]["error"]


# --- timeout, cancellation, and the tree the audit actually runs in ----------
# Two defects that only make sense together. arq's default job_timeout is 300s,
# half of AUDIT_TIMEOUT_SECS, and arq enforces it by wrapping the job coroutine
# in asyncio.wait_for — so arq cancelled the job before the worker's own timeout
# branch could ever fire, and CancelledError is a BaseException that the
# worker's catch-all could not see. When that branch did fire, the kill it
# performed hit npm alone and not the audit npm had launched.
#
# The fixture below is a stand-in for `npm run audit` — running the real CLI
# needs a live OPENROUTER_API_KEY and ~90s of LLM spend per run, which is why
# this file's header rules it out — but the processes it spawns and the signals
# that kill them are real. What it reproduces is npm's process *shape*: a
# wrapper whose actual work happens in a grandchild. That shape is the bug.


def _npm_like_script(tmp_path: Path) -> tuple[Path, Path]:
    """Write a wrapper that launches its work in a grandchild, like npm does.

    Returns the script and the file it reports the grandchild's pid in.
    """
    pid_file = tmp_path / "grandchild.pid"
    script = tmp_path / "npm-like"
    script.write_text(
        "#!/bin/sh\n"
        # Ignores the `run audit -- --source ...` argv the worker passes, the
        # same way it ignores everything else npm does.
        "sh -c 'while :; do sleep 0.05; done' &\n"
        # Rename, not write-in-place: a reader must never see a partial pid.
        f'echo $! > "{pid_file}.tmp" && mv "{pid_file}.tmp" "{pid_file}"\n'
        "wait\n"
    )
    script.chmod(0o755)
    return script, pid_file


def _grandchild_pid(pid_file: Path, timeout: float = 5.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pid_file.exists():
            return int(pid_file.read_text())
        time.sleep(0.02)
    raise AssertionError("fixture never reported a grandchild pid")


def _process_is_gone(pid: int, timeout: float = 5.0) -> bool:
    """True once the pid is no longer a running process.

    A zombie counts as gone: the audit is dead, and whether anything has reaped
    it yet is a property of whatever init the CI runner uses, not of the worker
    under test. `os.kill(pid, 0)` succeeds for zombies, so ask ps for the state
    rather than asserting on a detail this code does not control. Polls because
    reparenting and reaping are not instantaneous; the full budget is only ever
    spent on a run that is about to fail anyway.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        state = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True
        ).stdout.strip()
        if not state or state.startswith("Z"):
            return True
        time.sleep(0.02)
    return False


def _force_reap(pid_file: Path) -> None:
    """A failed assertion must not leave a spin loop running past the suite."""
    try:
        os.kill(int(pid_file.read_text()), signal.SIGKILL)
    except (OSError, ValueError):
        pass


def _arq_job_timeout_s() -> float:
    """The timeout arq will actually enforce for WorkerSettings.

    Resolved through arq's own code rather than read off the class, because
    get_kwargs keeps only attributes that are Worker() parameters — a
    misspelled setting would be silently dropped and fall back to arq's default
    here exactly as it would in production, which is the whole failure mode.
    """
    from arq.utils import to_seconds
    from arq.worker import Worker, get_kwargs

    arq_default = inspect.signature(Worker).parameters["job_timeout"].default
    configured = get_kwargs(worker.WorkerSettings).get("job_timeout", arq_default)
    return to_seconds(configured)


class TestTimeoutKillsTheAuditAndNotJustNpm:
    class _RecordingRedis:
        def __init__(self):
            self.writes: list[dict] = []

        async def set(self, key, value, ex=None):
            self.writes.append(json.loads(value))

    def test_arq_does_not_cancel_the_job_before_the_worker_times_out(self):
        # If this inverts, every assertion below becomes unreachable in
        # production no matter how correct the kill path is.
        assert _arq_job_timeout_s() > worker.AUDIT_TIMEOUT_SECS

    def test_a_cancelled_job_records_a_status_and_kills_the_audit(self, tmp_path, monkeypatch):
        redis = self._RecordingRedis()
        script, pid_file = _npm_like_script(tmp_path)
        monkeypatch.setattr(worker, "NPM_BIN", str(script))

        async def cancel_mid_audit():
            task = asyncio.create_task(
                worker.run_audit({"redis": redis}, "job-cancelled", "target.rs")
            )
            # Poll off-loop so the subprocess actually gets to start; cancelling
            # before it exists would test nothing.
            await asyncio.to_thread(_grandchild_pid, pid_file)
            task.cancel()
            # Still has to propagate: arq decides retries from it.
            with pytest.raises(asyncio.CancelledError):
                await task

        try:
            asyncio.run(cancel_mid_audit())

            assert [w["status"] for w in redis.writes] == ["running", "failed"]
            assert "cancelled" in redis.writes[-1]["error"]
            assert _process_is_gone(_grandchild_pid(pid_file)), (
                "cancelling the job orphaned the audit it started"
            )
        finally:
            _force_reap(pid_file)

    def test_the_workers_own_timeout_wins_at_arqs_real_budget_ratio(self, tmp_path, monkeypatch):
        """Both defects in one run, at production's ratio.

        Drives the real coroutine inside the real wrapper arq uses —
        `asyncio.wait_for(task, job_timeout_s)` — with both budgets scaled by
        the same factor, so what is under test is the relationship between
        them rather than two numbers asserted apart. At arq's 300s default
        against AUDIT_TIMEOUT_SECS=600 the outer budget expires first: the kill
        never runs, the audit is orphaned, and nothing terminal is recorded.

        The outer wrapper is also what keeps a regression here loud. Killing
        the wrapper without its group leaves `await proc.wait()` pending
        forever — the survivor holds the inherited pipes open, and asyncio only
        resolves wait() once every pipe has disconnected — so without a bound
        this test would hang rather than fail.
        """
        redis = self._RecordingRedis()
        script, pid_file = _npm_like_script(tmp_path)
        monkeypatch.setattr(worker, "NPM_BIN", str(script))

        scaled_audit_timeout = 2
        scale = scaled_audit_timeout / worker.AUDIT_TIMEOUT_SECS
        arq_budget = _arq_job_timeout_s() * scale  # read before patching
        monkeypatch.setattr(worker, "AUDIT_TIMEOUT_SECS", scaled_audit_timeout)

        async def under_arqs_own_wrapper():
            await asyncio.wait_for(
                worker.run_audit({"redis": redis}, "job-both", "target.rs"),
                timeout=arq_budget,
            )

        try:
            asyncio.run(under_arqs_own_wrapper())

            assert [w["status"] for w in redis.writes] == ["running", "failed"]
            assert "was killed" in redis.writes[-1]["error"]
            assert _process_is_gone(_grandchild_pid(pid_file))
        finally:
            _force_reap(pid_file)


# --- source containment ------------------------------------------------------
# `source` was validated for existence only, so an unauthenticated caller could
# name any absolute path on the host; the worker then walked every .rs file under
# it into an LLM prompt and served the output back from GET /audits/<id>.


def test_source_outside_the_allowed_root_is_rejected(tmp_path):
    import main

    outside = tmp_path / "someone-elses-repo"
    outside.mkdir()
    with pytest.raises(ValidationError):
        main.AuditRequest(source=str(outside))


def test_parent_traversal_out_of_the_root_is_rejected():
    import main

    with pytest.raises(ValidationError):
        main.AuditRequest(source="../../..")


def test_a_path_inside_the_root_is_still_accepted():
    import main

    # eval/ is committed, so this exercises the accept path without a fixture.
    accepted = main.AuditRequest(source="eval")
    assert accepted.source.endswith("/eval")


def test_a_symlink_pointing_out_of_the_root_is_rejected(tmp_path, monkeypatch):
    import main

    secret = tmp_path / "secret"
    secret.mkdir()
    link = main.REPO_ROOT / ".ares-test-escape-link"
    try:
        link.symlink_to(secret, target_is_directory=True)
        with pytest.raises(ValidationError):
            main.AuditRequest(source=str(link))
    finally:
        if link.is_symlink():
            link.unlink()


class TestBillingExitCodeDistinction:
    """src/index.ts exits 2 specifically for InsufficientCreditsError, distinct
    from exit 1 for a generic audit failure — see the NOTE this replaced in
    worker.py. Before this, both looked identical to any caller polling the
    API: a bare "failed" status with no way to tell "out of credits" apart
    from "the audit itself broke"."""

    class _RecordingRedis:
        def __init__(self):
            self.writes: list[dict] = []

        async def set(self, key, value, ex=None):
            self.writes.append(json.loads(value))

    class _FakeProc:
        def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
            self.returncode = returncode
            self._stdout = stdout
            self._stderr = stderr

        async def communicate(self):
            return self._stdout, self._stderr

    def _stderr_line(self, err: str) -> bytes:
        return (json.dumps({"level": "error", "component": "ares", "err": err}) + "\n").encode()

    def test_exit_code_2_is_recorded_as_payment_required_not_failed(self, monkeypatch):
        redis = self._RecordingRedis()
        stderr = self._stderr_line("Insufficient credits: need 500, have 120 (on-demand exhausted or disabled)")

        async def fake_exec(*args, **kwargs):
            return self._FakeProc(returncode=2, stdout=b"", stderr=stderr)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        asyncio.run(worker.run_audit({"redis": redis}, "job-1", "target.rs"))

        statuses = [w["status"] for w in redis.writes]
        assert statuses == ["running", "payment_required"]
        assert "Insufficient credits" in redis.writes[-1]["error"]

    def test_exit_code_1_is_still_a_generic_failed_not_payment_required(self, monkeypatch):
        # The regression this guards against: accidentally widening the
        # returncode == 2 check to catch exit 1 too, collapsing the very
        # distinction this whole change exists to make.
        redis = self._RecordingRedis()
        stderr = self._stderr_line("some unrelated analyzer crash")

        async def fake_exec(*args, **kwargs):
            return self._FakeProc(returncode=1, stdout=b"", stderr=stderr)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        asyncio.run(worker.run_audit({"redis": redis}, "job-1", "target.rs"))

        statuses = [w["status"] for w in redis.writes]
        assert statuses == ["running", "failed"]
        assert "unrelated analyzer crash" in redis.writes[-1]["error"]
class TestCveSnapshotInfo:
    """GET /cve/snapshot reports the manifest of whichever advisory DB
    revision is actually loaded, so a report generated from a /cve/scan call
    can cite exactly which snapshot produced it (services/cve/README.md:
    refreshing the snapshot changes future results with no other record of
    which revision a past result came from)."""

    def test_returns_the_real_committed_snapshots_manifest(self):
        client = TestClient(main.app)
        resp = client.get("/cve/snapshot")
        assert resp.status_code == 200
        body = resp.json()
        assert body["advisory_count"] > 1000  # real snapshot has 1169 at plan time
        assert body["source"] == "https://github.com/rustsec/advisory-db.git"

    def test_snapshot_load_failure_is_503_not_a_crash(self, monkeypatch):
        # A missing/corrupt services/cve/snapshot/ must degrade this endpoint,
        # never the unrelated /audits endpoints in the same process — see
        # _get_advisory_db's docstring for why the load is lazy, not
        # module-import-time.
        monkeypatch.setattr(main, "_ADVISORY_DB", None)
        monkeypatch.setattr(main, "_ADVISORY_DB_LOAD_ERROR", None)

        def blow_up(*args, **kwargs):
            raise main.SnapshotError("simulated missing snapshot")

        monkeypatch.setattr(main.AdvisoryDB, "load", staticmethod(blow_up))
        client = TestClient(main.app)
        resp = client.get("/cve/snapshot")
        assert resp.status_code == 503
        assert "simulated missing snapshot" in resp.json()["detail"]


class TestCveScanNoLockfileIsSkippedNotFailed:
    """An on-chain (`--program <ADDRESS>`) target has no Cargo.lock at all.
    That must read as `skipped` — deliberately not applicable — never as an
    empty `ok` (which would look identical to "scanned, found nothing") and
    never as `failed` (which would look like a broken request)."""

    def test_absent_lockfield_is_skipped(self):
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={})
        assert resp.status_code == 200
        assert resp.json()["outcome"] == "skipped"

    def test_null_lockfile_is_skipped(self):
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={"lockfile": None})
        assert resp.json()["outcome"] == "skipped"

    def test_blank_lockfile_is_skipped_not_failed(self):
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={"lockfile": "   "})
        assert resp.json()["outcome"] == "skipped"


class TestCveScanMalformedLockfileFailsLoudly:
    def test_garbage_input_is_failed_with_a_detail(self):
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={"lockfile": "{ not toml or json"})
        body = resp.json()
        assert body["outcome"] == "failed"
        assert body["error"]

    def test_oversized_lockfile_is_rejected_before_parsing(self):
        # Content-in (not a path) means the request body itself must be
        # bounded, or a large POST could burn parse time before validation.
        client = TestClient(main.app)
        huge = "x" * (main._MAX_LOCKFILE_BYTES + 1)
        resp = client.post("/cve/scan", json={"lockfile": huge})
        assert resp.status_code == 422


class TestCveScanEmptyPackageArrayIsDegraded:
    def test_no_package_array_at_all_is_failed_not_degraded(self):
        # Distinct from an empty [] array below: this document isn't even
        # shaped like a lockfile, so it's a parse failure, not a clean scan
        # that happened to find zero dependencies.
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={"lockfile": "version = 4\n"})
        body = resp.json()
        assert body["outcome"] == "failed"

    def test_empty_package_array_is_degraded(self):
        client = TestClient(main.app)
        # A syntactically valid lockfile with a package array that resolved
        # to zero entries -- distinct from "not a lockfile" above.
        lockfile_text = "version = 4\npackage = []\n"
        resp = client.post("/cve/scan", json={"lockfile": lockfile_text})
        body = resp.json()
        assert body["outcome"] == "degraded"


class TestCveScanAgainstTheRealCommittedLockfile:
    """Ground truth: scan the repo's own core/Cargo.lock through the real
    HTTP surface, rather than only unit-testing match.py in isolation. This
    caught the exact 4 RustSec advisories core-ci.yml's `cargo audit --ignore
    ...` step already lists as accepted risk (RUSTSEC-2026-0187/0194/0195/
    0204), confirming this service reproduces that existing gate's findings
    independently rather than by construction."""

    def test_scanning_core_cargo_lock_finds_the_known_accepted_advisories(self):
        lockfile_path = REPO_ROOT / "core" / "Cargo.lock"
        if not lockfile_path.exists():
            pytest.skip("core/Cargo.lock not present in this checkout")
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={"lockfile": lockfile_path.read_text(encoding="utf-8")})
        body = resp.json()
        assert body["outcome"] == "ok"
        found_ids = {m["advisory_id"] for m in body["matches"]}
        for accepted in (
            "RUSTSEC-2026-0187",
            "RUSTSEC-2026-0194",
            "RUSTSEC-2026-0195",
            "RUSTSEC-2026-0204",
        ):
            assert accepted in found_ids

    def test_workspace_local_crates_are_excluded_from_the_scanned_count(self):
        lockfile_path = REPO_ROOT / "core" / "Cargo.lock"
        if not lockfile_path.exists():
            pytest.skip("core/Cargo.lock not present in this checkout")
        client = TestClient(main.app)
        resp = client.post("/cve/scan", json={"lockfile": lockfile_path.read_text(encoding="utf-8")})
        body = resp.json()
        assert body["dependencies_skipped_local"] >= 7  # ares-core, ares-mapper, etc.
