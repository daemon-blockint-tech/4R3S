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
        await _audit_and_record(redis, job_id, source)
    except Exception as err:
        # Last resort. Every path above this records a status before returning,
        # but anything unanticipated — a PermissionError from the subprocess, a
        # bug in the parsing helpers, an OSError — would otherwise leave the
        # job reading "running" until its TTL expired, with no failure visible
        # to whoever is polling. Record it, then re-raise so the exception
        # still reaches arq's logs and retry policy instead of being swallowed.
        await _set_status(
            redis, job_id, status="failed",
            error=f"worker failed unexpectedly: {type(err).__name__}: {err}",
        )
        raise


async def _audit_and_record(redis, job_id: str, source: str) -> None:
    """Invoke the CLI and record the outcome. Split from run_audit so the
    caller can wrap every failure path in one place."""
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
            # The process can exit on its own between the timeout firing and
            # this kill, in which case kill() raises ProcessLookupError
            # (verified: kill() on an already-reaped process does raise).
            # Letting that escape would replace a clean "timed out" status with
            # a crashed task and a job stuck at "running".
            try:
                proc.kill()
            except ProcessLookupError:
                pass
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

    if proc.returncode == 2:
        # src/index.ts now exits 2 specifically for InsufficientCreditsError
        # (exit 1 remains a generic audit failure). The actual message —
        # "Insufficient credits: need X, have Y..." — already reaches stderr
        # via logger.error there, so _last_error_line finds it unchanged;
        # this branch only needs to pick the right *status* label for it.
        await _set_status(
            redis, job_id, status="payment_required",
            error=_last_error_line(stderr_text),
        )
        return

    # NOTE: this used to be the only path for any nonzero exit, before
    # src/index.ts distinguished billing failures with exit code 2 above.
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
        # json.loads succeeds on bare scalars too: a stderr line containing
        # `42`, `"text"`, `null`, or `[1,2]` parses fine but is not a dict, and
        # calling .get() on it raised AttributeError. That exception escaped
        # this function, crashed run_audit before it could record a status, and
        # left the job reading "running" until its 24h TTL expired — a failure
        # with no error anywhere the caller could see. npm itself writes
        # non-JSON lines to stderr, so this is reachable in normal operation.
        if not isinstance(entry, dict):
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
