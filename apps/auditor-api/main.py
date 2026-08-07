"""
FastAPI surface for the ARES Auditor agent plane.

Design decision (documented, not silently assumed): this plane wraps the
existing, production-proven TypeScript CLI (`npm run audit`) as a subprocess
rather than re-implementing the 13-node LangGraph pipeline in Python. The TS
graph is the system CLAUDE.md calls "what actually works today" — duplicating
its logic in a second language risks drift between two implementations that
silently diverge over time. This mirrors the pattern already used for `core/`
(Rust), which is likewise called "via CLI/contract" rather than ported.

If this assumption is wrong — if the intent was a full reimplementation in
Python — this file is the wrong starting point and should be revisited before
building on top of it.
"""
from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError, field_validator

app = FastAPI(title="ares-auditor-api")

REDIS_SETTINGS = RedisSettings()  # host/port from env via arq defaults

REPO_ROOT = Path(__file__).resolve().parents[2]  # apps/auditor-api/main.py -> 4R3S/

# Every audit target must resolve inside this root. Default-deny, matching the
# Rust engine's policy boundary (`core/crates/ares-policy`). Override with
# ARES_ALLOWED_SOURCE_ROOT when the deployment stages checkouts elsewhere.
#
# NOTE, unresolved: this route is still UNAUTHENTICATED. Containment bounds what
# an anonymous caller can reach; it does not stop them from queueing work and
# spending LLM quota. Putting auth in front of it is a deployment-level decision
# (who the callers are, which scheme), so it is flagged here rather than guessed.
# Resolved per call, not captured at import: the root is derived from REPO_ROOT,
# and binding it once would freeze whatever the module saw first — which both
# defeats the env override for a process started before it was set, and silently
# ignores a REPO_ROOT a test relocates.
def allowed_source_root() -> Path:
    return Path(
        os.environ.get("ARES_ALLOWED_SOURCE_ROOT", str(REPO_ROOT))
    ).expanduser()


class AuditRequest(BaseModel):
    source: str

    @field_validator("source")
    @classmethod
    def source_must_exist(cls, v: str) -> str:
        # Resolve relative to the repo root, not to whatever directory the
        # server process happens to be started from — `uvicorn main:app` run
        # from apps/auditor-api/ checks relative paths against that folder,
        # not the repo root a caller naturally means (confirmed by running
        # this exact case: a corpus-relative path silently failed here first).
        # Absolute paths pass through untouched.
        path = Path(v)
        resolved = path if path.is_absolute() else (REPO_ROOT / path)
        # Fail before the job ever reaches the queue. A queue slot spent on a
        # target that cannot possibly succeed is a queue slot stolen from a
        # target that could — and this queue is capacity-constrained by daily
        # LLM quota, not by compute, so wasted slots are expensive.
        if not resolved.exists():
            raise ValueError(f"source path does not exist: {resolved}")

        # Containment. Existence was the only check, so `{"source":
        # "/Users/me/some-client-repo"}` — or `../../.ssh` — was accepted and the
        # worker then walked every `.rs` file under it into an LLM prompt and
        # served the result back from `GET /audits/<id>`. This route has no
        # authentication (see the module note below), so that was an unauthenticated
        # read of arbitrary host directories.
        #
        # `.resolve()` follows symlinks, which matters for the same reason it does
        # in `core/crates/ares-policy`: a link inside the allowed root otherwise
        # redirects the read anywhere on the host.
        root = allowed_source_root().resolve()
        real = resolved.resolve()
        if real != root and root not in real.parents:
            raise ValueError(
                f"source path is outside the allowed root {root}: {real}"
            )
        return str(real)


class AuditAccepted(BaseModel):
    job_id: str
    status: str = "queued"


class AuditStatus(BaseModel):
    job_id: str
    status: str  # queued | running | done | failed
    report: str | None = None
    error: str | None = None


@app.post("/audits", response_model=AuditAccepted, status_code=202)
async def submit_audit(req: AuditRequest) -> AuditAccepted:
    """Enqueue an audit. Returns immediately — an audit run takes minutes,
    not milliseconds, so this is fire-and-poll, not request-response."""
    job_id = str(uuid4())
    redis = await create_pool(REDIS_SETTINGS)
    try:
        job = await redis.enqueue_job("run_audit", job_id, req.source, _job_id=job_id)
    finally:
        await redis.close()

    # arq returns None when a job with this id already exists (it checks
    # job_key and result_key and bails out — see ArqRedis.enqueue_job).
    # Discarding that return value meant answering 202 with a job_id nothing
    # would ever process, so the caller would poll a 404 forever with no
    # indication the submission had been dropped. A uuid4 collision is
    # vanishingly unlikely, but checking costs nothing and the alternative
    # failure is silent.
    if job is None:
        raise HTTPException(
            status_code=503,
            detail=f"queue rejected job {job_id}: an entry with that id already exists",
        )

    return AuditAccepted(job_id=job_id)


@app.get("/audits/{job_id}", response_model=AuditStatus)
async def get_audit_status(job_id: str) -> AuditStatus:
    redis = await create_pool(REDIS_SETTINGS)
    try:
        job_status = await redis.get(f"audit-result:{job_id}")
    finally:
        await redis.close()

    if job_status is None:
        raise HTTPException(status_code=404, detail="unknown job_id")

    # Redis stores raw JSON strings the worker wrote; nothing else writes to
    # this key today, but decoupling the reader's failure mode from the
    # writer's contract means a future writer bug, a manual redis-cli edit, or
    # a partial write from a crashed worker surfaces as a diagnosable 502
    # instead of an unhandled 500 that looks like an unrelated server crash.
    try:
        return AuditStatus.model_validate_json(job_status)
    except ValidationError as err:
        raise HTTPException(
            status_code=502,
            detail=f"stored status for job {job_id} is corrupt: {err}",
        ) from err
