"""Tests for mcp_server.py.

Scope: this covers the MCP adapter layer itself -- does each tool correctly
delegate to main.py's existing route functions and return the shape main.py
already produces? It deliberately does not re-test main.py's own business
logic (path containment, CVE matching, risk-scoring math) -- that's already
covered by test_auditor_api.py and services/cve, services/risk's own suites.
Duplicating it here would test the same logic twice while adding nothing
about whether the adapter wiring itself is correct.

No ARES_API_KEYS setup here (unlike test_auditor_api.py): these tools call
main.py's route functions directly, never through FastAPI's dependency
injection, so require_api_key never runs -- see mcp_server.py's module
docstring for why that's the deliberate, documented security posture for a
stdio-transport server.
"""
from __future__ import annotations

import asyncio

import main
import mcp_server


class TestToolRegistration:
    def test_all_six_tools_are_registered(self):
        tools = asyncio.run(mcp_server.server.list_tools())
        names = {t.name for t in tools}
        assert names == {
            "ares_submit_audit",
            "ares_get_audit_status",
            "ares_cve_scan",
            "ares_cve_snapshot_info",
            "ares_risk_score",
            "ares_risk_calibration",
        }


class TestCveScan:
    def test_no_lockfile_is_skipped_not_an_error(self):
        result = asyncio.run(mcp_server.ares_cve_scan())
        assert result.outcome == "skipped"

    def test_blank_lockfile_is_also_skipped(self):
        result = asyncio.run(mcp_server.ares_cve_scan(lockfile="   "))
        assert result.outcome == "skipped"


class TestCveSnapshotInfo:
    def test_returns_the_loaded_snapshot_metadata(self):
        # No fixture needed -- this loads the real vendored snapshot, same as
        # GET /cve/snapshot does. A load failure here would mean the vendored
        # snapshot itself is broken, which is exactly what this should catch.
        result = asyncio.run(mcp_server.ares_cve_snapshot_info())
        assert result.advisory_count > 0
        assert result.revision


class TestRiskScore:
    def test_delegates_to_the_same_owasp_scoring_main_uses(self):
        result = asyncio.run(
            mcp_server.ares_risk_score(
                # Values are each factor's lowest OWASP-defined score -- these
                # are discrete tables (e.g. motive: 1/4/9), not a linear 0-9
                # scale, so an arbitrary uniform value is not guaranteed valid
                # across every factor.
                likelihood={
                    "skill_level": 1,
                    "motive": 1,
                    "opportunity": 0,
                    "size": 2,
                    "ease_of_discovery": 1,
                    "ease_of_exploit": 1,
                    "awareness": 1,
                    "intrusion_detection": 1,
                },
                technical_impact={
                    "loss_of_confidentiality": 2,
                    "loss_of_integrity": 1,
                    "loss_of_availability": 1,
                    "loss_of_accountability": 1,
                },
            )
        )
        assert result.severity
        assert result.impact_basis == "technical"

    def test_unsupported_factor_raises_same_as_the_route(self):
        # main.score_risk_endpoint raises HTTPException(400, ...) for this --
        # calling it directly means we get the HTTPException itself, not a
        # 400 response. The real MCP protocol layer (server.run(), not this
        # direct call) converts any raised exception into an isError=True
        # tool result -- see mcp_server.py's module docstring.
        import pytest
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            asyncio.run(
                mcp_server.ares_risk_score(
                    likelihood={"not_a_real_factor": 3},
                    technical_impact={"loss_of_confidentiality": 3},
                )
            )


class TestRiskCalibration:
    def test_returns_a_diff_against_the_committed_catalog(self):
        result = asyncio.run(mcp_server.ares_risk_calibration())
        assert result.total > 0
        assert result.match_count + result.mismatch_count == result.total


class TestAuditSubmitAndStatus:
    """Same fake-Redis pattern as test_auditor_api.py's TestDroppedEnqueue /
    TestQueuedJobIsVisibleBeforeTheWorkerStarts -- no real Redis needed."""

    class _FakeRedis:
        def __init__(self):
            self.store: dict[str, str] = {}

        async def enqueue_job(self, *args, **kwargs):
            return object()  # any non-None Job stand-in

        async def set(self, key, value, ex=None):
            self.store[key] = value

        async def get(self, key):
            return self.store.get(key)

        async def close(self):
            pass

    def test_submit_then_poll_round_trip(self, monkeypatch, tmp_path):
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        (tmp_path / "target.rs").write_text("// fixture")

        redis = self._FakeRedis()

        async def fake_create_pool(_settings):
            return redis

        monkeypatch.setattr(main, "create_pool", fake_create_pool)

        accepted = asyncio.run(mcp_server.ares_submit_audit(source="target.rs"))
        assert accepted.status == "queued"

        status = asyncio.run(mcp_server.ares_get_audit_status(accepted.job_id))
        assert status.job_id == accepted.job_id
        assert status.status == "queued"

    def test_submit_with_callback_url_runs_the_submission_time_dns_check(
        self, monkeypatch, tmp_path
    ):
        """Gap found during review: test_auditor_api.py only covers
        worker.py's DELIVERY-time validate_webhook_url_async (the check run
        when the finished result is POSTed out). Nothing anywhere tested
        main.py's own SUBMISSION-time call to the same-named function inside
        submit_audit -- a different call site nothing exercised before this
        tool made that path reachable through a second entry point."""
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        (tmp_path / "target.rs").write_text("// fixture")

        redis = self._FakeRedis()

        async def fake_create_pool(_settings):
            return redis

        monkeypatch.setattr(main, "create_pool", fake_create_pool)

        calls = []

        async def fake_validate(url):
            calls.append(url)

        monkeypatch.setattr(main, "validate_webhook_url_async", fake_validate)

        accepted = asyncio.run(
            mcp_server.ares_submit_audit(
                source="target.rs", callback_url="https://example.com/hook"
            )
        )
        assert accepted.status == "queued"
        assert calls == ["https://example.com/hook"]

    def test_submit_with_a_dns_rejected_callback_url_raises_400(self, monkeypatch, tmp_path):
        """The scheme-only check (Pydantic validator, sync) and the DNS check
        (submit_audit's own call, async) are two separate gates -- this uses
        an https:// URL so it clears the first gate, then rejects at the
        second, to isolate which one actually fired."""
        monkeypatch.setattr(main, "REPO_ROOT", tmp_path)
        (tmp_path / "target.rs").write_text("// fixture")

        async def fake_reject(url):
            raise ValueError("callback_url resolves to a disallowed address: 127.0.0.1")

        monkeypatch.setattr(main, "validate_webhook_url_async", fake_reject)

        import pytest
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                mcp_server.ares_submit_audit(
                    source="target.rs", callback_url="https://looks-fine.example/hook"
                )
            )
        assert exc_info.value.status_code == 400
        assert "callback_url rejected" in exc_info.value.detail

    def test_unknown_job_id_raises_404_same_as_the_route(self, monkeypatch):
        import pytest
        from fastapi import HTTPException

        redis = self._FakeRedis()

        async def fake_create_pool(_settings):
            return redis

        monkeypatch.setattr(main, "create_pool", fake_create_pool)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(mcp_server.ares_get_audit_status("no-such-job"))
        assert exc_info.value.status_code == 404