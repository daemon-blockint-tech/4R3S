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
from pydantic import BaseModel, field_validator

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
        await redis.enqueue_job("run_audit", job_id, req.source, _job_id=job_id)
    finally:
        await redis.close()
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

    return AuditStatus.model_validate_json(job_status)
