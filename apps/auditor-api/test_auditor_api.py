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
import json

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
