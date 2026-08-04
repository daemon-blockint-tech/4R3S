"""
Arq worker for ARES audits.

Each job shells out to the production TS CLI (`npm run audit`) rather than
re-implementing its logic. See main.py for why. This module's job is entirely
about handling the CLI's real contract and real failure modes — not about
auditing anything itself.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from arq.connections import RedisSettings

REPO_ROOT = Path(__file__).resolve().parents[2]  # apps/auditor-api/worker.py -> 4R3S/
AUDIT_TIMEOUT_SECS = 600  # observed ~123s/target with source injection; generous margin
MAX_CONCURRENT_AUDITS = 2  # daily LLM quota is the real constraint, not CPU


async def run_audit(ctx, job_id: str, source: str) -> None:
    """Run one audit as a subprocess of the existing, production TS CLI.

    Records status under `audit-result:{job_id}` so the API can poll it,
    matching the CLI's own contract: exit code + stdout report text, not a
    structured JSON file (there isn't one — see src/index.ts).
    """
    redis = ctx["redis"]
    await _set_status(redis, job_id, status="running")

    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "run", "audit", "--", "--source", source,
            cwd=REPO_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=AUDIT_TIMEOUT_SECS
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            await _set_status(
                redis, job_id, status="failed",
                error=f"audit exceeded {AUDIT_TIMEOUT_SECS}s and was killed",
            )
            return
    except FileNotFoundError as err:
        # npm/node missing from the worker's PATH — an environment defect,
        # not an audit failure. Distinguish it so it isn't logged as "the
        # target failed" when actually the worker itself is misconfigured.
        await _set_status(
            redis, job_id, status="failed",
            error=f"could not invoke npm — worker environment issue: {err}",
        )
        return

    report = stdout.decode("utf-8", errors="replace").strip()
    stderr_text = stderr.decode("utf-8", errors="replace")

    if proc.returncode == 0:
        await _set_status(redis, job_id, status="done", report=report)
        return

    # NOTE: src/index.ts currently exits 1 for both a real audit failure and a
    # billing-settlement failure (InsufficientCreditsError) — it does not yet
    # distinguish them with a separate exit code. Distinguishing those two
    # cases would require a change to src/index.ts itself, which is out of
    # scope for ORC-1 (Home: apps/auditor-api) — that CLI is a separate,
    # already-shipping product surface and changing its contract is its own
    # task, not bundled here. This worker therefore reports every nonzero
    # exit as a generic failure for now; see docs/KR-1-FINDINGS.md-style
    # follow-up if the billing/failure distinction becomes needed later.
    await _set_status(
        redis, job_id, status="failed", error=_last_error_line(stderr_text)
    )


def _last_error_line(stderr_text: str) -> str:
    """Pick the most relevant line from structured stderr logs rather than
    dumping the whole stream. logger.ts writes JSON lines to stderr at info/
    warn/error; a wall of retry-backoff warnings should not bury the actual
    error a human needs to see first.

    Prefers `err` over `msg`: index.ts's top-level catch logs a generic `msg`
    ("Audit failed") with the real cause in `err` (its own comments call this
    out as a known gap — "the operator sees 'Audit failed' and nothing else").
    Confirmed live: an invalid API key surfaced as msg="Audit failed" with no
    further detail in this field alone."""
    for line in reversed(stderr_text.splitlines()):
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if entry.get("level") == "error":
            return entry.get("err") or entry.get("msg", line)
    return stderr_text.strip()[-500:] or "no error detail captured"


async def _set_status(
    redis, job_id: str, *, status: str, report: str | None = None, error: str | None = None
) -> None:
    payload = json.dumps({
        "job_id": job_id, "status": status, "report": report, "error": error,
    })
    await redis.set(f"audit-result:{job_id}", payload, ex=86400)  # 24h TTL


class WorkerSettings:
    functions = [run_audit]
    redis_settings = RedisSettings()
    max_jobs = MAX_CONCURRENT_AUDITS
