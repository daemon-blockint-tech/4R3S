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

from pathlib import Path
from uuid import uuid4

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError, field_validator

app = FastAPI(title="ares-auditor-api")

REDIS_SETTINGS = RedisSettings()  # host/port from env via arq defaults

REPO_ROOT = Path(__file__).resolve().parents[2]  # apps/auditor-api/main.py -> 4R3S/


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
        return str(resolved)


class AuditAccepted(BaseModel):
    job_id: str
    status: str = "queued"


class AuditStatus(BaseModel):
    job_id: str
    status: str  # queued | running | done | failed | payment_required
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
