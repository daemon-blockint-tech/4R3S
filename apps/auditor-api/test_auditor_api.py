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

import json

import pytest
from pydantic import ValidationError

from main import REPO_ROOT, AuditRequest
from worker import _last_error_line


class TestSourcePathResolution:
    def test_relative_path_resolves_against_repo_root(self):
        # Not against the process working directory: `uvicorn main:app` is run
        # from apps/auditor-api/, so a caller-supplied repo-relative path would
        # otherwise be looked up one or two levels too deep.
        req = AuditRequest(source="package.json")
        assert req.source == str(REPO_ROOT / "package.json")

    def test_repo_root_is_the_repo_not_the_apps_folder(self):
        # Pins the off-by-one directly: if REPO_ROOT ever drifts back to
        # parents[1], this fails loudly instead of surfacing as a confusing 422.
        assert (REPO_ROOT / "package.json").exists()
        assert REPO_ROOT.name != "apps"

    def test_absolute_path_is_accepted_unchanged(self):
        absolute = str(REPO_ROOT / "package.json")
        assert AuditRequest(source=absolute).source == absolute

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
