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
import os
import shutil
import signal
from pathlib import Path

from arq.connections import RedisSettings

REPO_ROOT = Path(__file__).resolve().parents[2]  # apps/auditor-api/worker.py -> 4R3S/
AUDIT_TIMEOUT_SECS = 600  # observed ~123s/target with source injection; generous margin
MAX_CONCURRENT_AUDITS = 2  # daily LLM quota is the real constraint, not CPU

NPM_BIN = shutil.which("npm") or "npm"


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
    except asyncio.CancelledError:
        # CancelledError is a BaseException in 3.8+, so the "last resort"
        # handler below never sees it. arq cancels the job task on worker
        # shutdown, on abort_job, and when its own job_timeout expires
        # (arq/worker.py wraps the coroutine in asyncio.wait_for), and every
        # one of those left the job reading "running" until its 24h TTL
        # expired — the exact hole that handler exists to close, reached by
        # the one exception class it cannot catch. Record a terminal status,
        # then re-raise so arq's retry policy still applies; a retry
        # overwrites this with "running" again on its next attempt.
        await _set_status(
            redis, job_id, status="failed",
            error="audit was cancelled before it finished",
        )
        raise
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
            NPM_BIN, "run", "audit", "--", "--source", source,
            cwd=REPO_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # npm is only a launcher: `npm run audit` executes the script
            # through an intermediate shell, so the process actually running
            # the audit is a grandchild. SIGKILL is not propagated to
            # descendants, so killing `proc` alone reaped npm and left that
            # grandchild alive — reparented to init, finishing all 13 graph
            # nodes, spending the LLM budget MAX_CONCURRENT_AUDITS exists to
            # cap, and billing a run this worker had already reported as
            # killed. setsid() puts the whole tree in one process group so
            # _kill_audit_tree can take all of it down at once.
            #
            # It also unblocks the `await proc.wait()` below, which is worse
            # than it looks: that survivor inherits this pipe pair, so the read
            # transports never see EOF, and asyncio only resolves wait()'s
            # future once *every* pipe has disconnected (base_subprocess.py
            # _try_finish -> _call_connection_lost). Reproduced: killing the
            # wrapper alone leaves wait() pending forever, so the "was killed"
            # status was never even written and the job held its worker slot
            # until arq cancelled it.
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=AUDIT_TIMEOUT_SECS
            )
        except asyncio.TimeoutError:
            _kill_audit_tree(proc)
            await proc.wait()
            await _set_status(
                redis, job_id, status="failed",
                error=f"audit exceeded {AUDIT_TIMEOUT_SECS}s and was killed",
            )
            return
        except asyncio.CancelledError:
            # Cancellation (arq shutdown, abort_job, or arq's own job_timeout)
            # used to skip the kill entirely, so a cancelled job orphaned its
            # audit tree just as surely as a timed-out one did. The caller
            # records the status; this only has to make sure nothing outlives
            # the job. No await here: the task is already unwinding, and the
            # group is SIGKILLed, so the loop's child watcher reaps npm without
            # this coroutine having to survive another suspension point.
            _kill_audit_tree(proc)
            raise
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


def _kill_audit_tree(proc) -> None:
    """SIGKILL everything npm spawned, not just npm.

    `start_new_session=True` made `proc` the leader of its own process group,
    so proc.pid doubles as the group id. POSIX keeps a pid reserved while a
    process group of that id still has members, so this stays correct even
    after asyncio has reaped npm and only the grandchild is left — which is
    precisely the case that matters, since npm exits the moment its own child
    is signalled but the audit does not.
    """
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        # The whole group can exit on its own between the timeout firing and
        # this call (verified: signalling an already-reaped process does
        # raise). That is the outcome we wanted; letting it escape would
        # replace a clean "timed out" status with a crashed task and a job
        # stuck at "running".
        pass


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
    # arq's own default is 300s — half of AUDIT_TIMEOUT_SECS — and arq enforces
    # it by wrapping the job coroutine in asyncio.wait_for. Leaving it at the
    # default made this module's entire timeout branch dead code: arq cancelled
    # at 300s, so the only path that kills the audit tree and records a `failed`
    # status for a slow audit could never run at any duration. arq's timeout is
    # meant to be the backstop here, not the budget; the margin is room for the
    # kill, the reap, and the status write after our own timeout fires.
    job_timeout = AUDIT_TIMEOUT_SECS + 60

