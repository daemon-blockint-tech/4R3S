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

import hmac
import os
import sys
from pathlib import Path
from uuid import uuid4

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, HttpUrl, ValidationError, field_validator

# Sibling top-level module (see the sys.path note below for why that is the
# convention here). Reused rather than re-implemented so `audit-result:{id}`
# has exactly one writer: a record this API writes at submission time must be
# indistinguishable in shape and TTL from one the worker writes later, or a
# poller would have to know which process wrote what it is reading.
from worker import _set_status
from ssrf_guard import validate_url_scheme, validate_webhook_url_async

_bearer_scheme = HTTPBearer()


def _valid_api_keys() -> set[str]:
    # Read per call, not cached at import, for the same reason
    # allowed_source_root() below is: binding it once would freeze whatever
    # the process saw first, which defeats an env var set after import (e.g.
    # by a test) and survives a key rotation only after a restart nothing
    # here would tell the operator to perform.
    raw = os.environ.get("ARES_API_KEYS", "")
    return {key.strip() for key in raw.split(",") if key.strip()}


def _api_key_is_valid(presented: str, valid_keys: set[str]) -> bool:
    """Constant-time membership test.

    `presented in valid_keys` looks equivalent and is not: set lookup falls
    back to `str.__eq__`, which short-circuits on the first differing byte
    (and on length before that), so response timing leaks how much of a
    configured key a guess got right. compare_digest is the primitive that
    doesn't. Compared as utf-8 bytes because compare_digest rejects str
    containing non-ASCII, and the presented value is caller-controlled.
    """
    presented_bytes = presented.encode("utf-8")
    # `any` short-circuits, but only ever on a *match* — a wrong key is still
    # compared against every configured key in constant time each.
    return any(
        hmac.compare_digest(presented_bytes, key.encode("utf-8")) for key in valid_keys
    )


async def require_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> None:
    """Fails closed: an unconfigured deployment (ARES_API_KEYS unset or
    empty) rejects every request rather than serving as an open API. The
    alternative — treating "no keys configured" as "no auth required" — is
    exactly the kind of silent-open default that turns a forgotten env var
    into an unauthenticated queue, the failure mode this replaces."""
    valid_keys = _valid_api_keys()
    if not valid_keys:
        raise HTTPException(
            status_code=500,
            detail="server misconfigured: no API keys configured (ARES_API_KEYS)",
        )
    if not _api_key_is_valid(credentials.credentials, valid_keys):
        raise HTTPException(status_code=401, detail="invalid API key")


# The interactive docs and the schema they read are OFF unless explicitly
# enabled. `FastAPI(dependencies=[...])` applies to APIRoutes only — the
# `/openapi.json`, `/docs` and `/redoc` handlers are plain Starlette routes
# added by FastAPI itself, so require_api_key never runs for them. Verified
# before this line existed: both answered 200 with no credentials, publishing
# every route, model and field name of an otherwise authenticated API.
# Unlike ARES_API_KEYS this is read once at import, because it decides which
# routes get built at all rather than how a request is handled.
_DOCS_ENABLED = os.environ.get("ARES_ENABLE_DOCS", "").strip().lower() in {
    "1", "true", "yes", "on",
}

app = FastAPI(
    title="ares-auditor-api",
    dependencies=[Depends(require_api_key)],
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
)

REDIS_SETTINGS = RedisSettings()  # host/port from env via arq defaults

REPO_ROOT = Path(__file__).resolve().parents[2]  # apps/auditor-api/main.py -> 4R3S/

# Every audit target must resolve inside this root. Default-deny, matching the
# Rust engine's policy boundary (`core/crates/ares-policy`). Override with
# ARES_ALLOWED_SOURCE_ROOT when the deployment stages checkouts elsewhere.
#
# Resolved per call, not captured at import: the root is derived from REPO_ROOT,
# and binding it once would freeze whatever the module saw first — which both
# defeats the env override for a process started before it was set, and silently
# ignores a REPO_ROOT a test relocates.
def allowed_source_root() -> Path:
    return Path(
        os.environ.get("ARES_ALLOWED_SOURCE_ROOT", str(REPO_ROOT))
    ).expanduser()
# services/cve has no __init__.py or pyproject.toml -- consistent with the
# rest of this repo, where main.py/worker.py are themselves imported as
# top-level modules rather than as a package (see test_auditor_api.py's
# `import main` / `import worker`). A documented sys.path insertion is the
# same shape already in use, not a new pattern. This runs before the CI
# job's `working-directory: apps/auditor-api` step, so it must be derived
# from REPO_ROOT (itself __file__-relative) rather than assumed to be
# reachable from the process's cwd.
_CVE_SERVICE_DIR = REPO_ROOT / "services" / "cve"
if str(_CVE_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(_CVE_SERVICE_DIR))

from advisories import AdvisoryDB, SnapshotError  # noqa: E402
from lockfile import MalformedLockfile, parse_lockfile  # noqa: E402
from match import match_dependencies  # noqa: E402
from severity import severity_for_advisory  # noqa: E402


class AuditRequest(BaseModel):
    source: str
    # Optional: if set, the worker POSTs the final job result here instead of
    # (in addition to) the caller having to poll GET /audits/{job_id}. Kept
    # per-job rather than a standing registration — this API has no store
    # beyond the per-job, 24h-TTL Redis key, and a subscription that outlives
    # a single job would need real persistence this app doesn't have.
    callback_url: HttpUrl | None = None

    @field_validator("callback_url")
    @classmethod
    def callback_url_scheme_must_be_safe(cls, v: HttpUrl | None) -> HttpUrl | None:
        # Scheme only. The address check needs DNS, and a Pydantic validator
        # runs inline on the event loop — a blocking getaddrinfo here lets one
        # caller-supplied hostname on a slow nameserver stall every other
        # request in the process. submit_audit does that half off-thread; see
        # the call to validate_webhook_url_async there.
        if v is not None:
            try:
                validate_url_scheme(str(v))
            except ValueError as err:
                raise ValueError(f"callback_url rejected: {err}") from err
        return v

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
        # served the result back from `GET /audits/<id>`. Authentication (see
        # require_api_key above) narrows who can reach this at all, but does
        # not narrow what an authenticated caller can read — containment is
        # still the control that does that.
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
    status: str  # queued | running | done | failed | payment_required
    report: str | None = None
    error: str | None = None


@app.post("/audits", response_model=AuditAccepted, status_code=202)
async def submit_audit(req: AuditRequest) -> AuditAccepted:
    """Enqueue an audit. Returns immediately — an audit run takes minutes,
    not milliseconds, so this is fire-and-poll, not request-response."""
    # The half of the callback_url check that needs DNS, kept out of the
    # Pydantic validator so it can go off-thread (see
    # AuditRequest.callback_url_scheme_must_be_safe). Done here, before the
    # pool is opened and before anything is queued, so a rejected target
    # costs nothing: no queue slot, no Redis record to clean up. The worker
    # re-checks at delivery time because DNS can change in between.
    if req.callback_url is not None:
        try:
            await validate_webhook_url_async(str(req.callback_url))
        except ValueError as err:
            raise HTTPException(status_code=400, detail=f"callback_url rejected: {err}") from err

    job_id = str(uuid4())
    redis = await create_pool(REDIS_SETTINGS)
    try:
        job = await redis.enqueue_job(
            "run_audit",
            job_id,
            req.source,
            str(req.callback_url) if req.callback_url else None,
            _job_id=job_id,
        )

        # arq returns None when a job with this id already exists (it checks
        # job_key and result_key and bails out — see ArqRedis.enqueue_job).
        # Discarding that return value meant answering 202 with a job_id nothing
        # would ever process, so the caller would poll a 404 forever with no
        # indication the submission had been dropped. A uuid4 collision is
        # vanishingly unlikely, but checking costs nothing and the alternative
        # failure is silent. Raising inside the try still closes the pool.
        if job is None:
            raise HTTPException(
                status_code=503,
                detail=f"queue rejected job {job_id}: an entry with that id already exists",
            )

        # Record the queued state before answering 202. Nothing wrote this key
        # until the worker's `_set_status(..., "running")`, which only runs once
        # a slot frees — so with MAX_CONCURRENT_AUDITS=2 and AUDIT_TIMEOUT_SECS=600
        # a backlogged job answered 404 for up to ten minutes on the very route
        # this API tells callers to poll. 404 already means "unknown job_id", so
        # that made one code mean two things; a client treating it as terminal
        # reports the audit lost and re-submits, and since the id is a fresh
        # uuid4 that queues a SECOND full audit of the same target — doubling the
        # LLM spend the concurrency cap exists to limit. `queued` is a value
        # AuditStatus already documents and AuditAccepted already returns.
        await _set_status(redis, job_id, status="queued")
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


# --- CVE enrichment (offline advisory DB) -----------------------------------
#
# Deterministic and offline by construction: matches a Cargo.lock against a
# vendored RustSec advisory snapshot (services/cve/snapshot/), no LLM, no
# network call in this request path. The snapshot itself is refreshed only by
# a human running services/cve/refresh_snapshot.py manually -- never by this
# app -- which is what keeps this consistent with the "hermetic by default"
# posture in SECURITY.md.
#
# Scope: dependency-level advisories only. An on-chain (`--program <ADDRESS>`)
# audit target has no Cargo.lock at all, so it has nothing for this endpoint
# to check -- callers should not call /cve/scan for one, and the endpoint
# reports `skipped` (not an empty `ok`) if asked to anyway, so a broken
# integration can't look identical to "this target has no advisories."

_ADVISORY_DB: AdvisoryDB | None = None
_ADVISORY_DB_LOAD_ERROR: str | None = None

# Comfortably above the real committed core/Cargo.lock (~35 KB); this is a
# request-size ceiling, not a realistic-lockfile ceiling -- it exists so a
# large POST body can't burn parse time before any validation has run.
_MAX_LOCKFILE_BYTES = 2_000_000


def _get_advisory_db() -> AdvisoryDB:
    """Load the advisory snapshot once and cache it -- not per request. A
    load failure here must not take down the unrelated /audits endpoints
    (which is why this is a lazy, request-triggered load rather than a
    module-import-time one): a missing or corrupt services/cve/snapshot/
    would otherwise crash this entire file on import, taking the audit queue
    down with it for a reason that has nothing to do with auditing."""
    global _ADVISORY_DB, _ADVISORY_DB_LOAD_ERROR
    if _ADVISORY_DB is not None:
        return _ADVISORY_DB
    if _ADVISORY_DB_LOAD_ERROR is not None:
        raise HTTPException(status_code=503, detail=_ADVISORY_DB_LOAD_ERROR)
    try:
        _ADVISORY_DB = AdvisoryDB.load()
    except SnapshotError as exc:
        _ADVISORY_DB_LOAD_ERROR = str(exc)
        raise HTTPException(status_code=503, detail=_ADVISORY_DB_LOAD_ERROR) from exc
    return _ADVISORY_DB


class CveScanRequest(BaseModel):
    # Content in, not a path: AuditRequest.source_must_exist above resolves
    # a caller-supplied path against REPO_ROOT and checks existence, but does
    # not block traversal -- fine for an internal queueing endpoint, not
    # fine to repeat here. Taking the lockfile's literal text removes that
    # surface outright rather than trying to sandbox a path.
    lockfile: str | None = None

    @field_validator("lockfile")
    @classmethod
    def lockfile_is_size_bounded(cls, v: str | None) -> str | None:
        if v is not None and len(v.encode("utf-8")) > _MAX_LOCKFILE_BYTES:
            raise ValueError(
                f"lockfile exceeds the {_MAX_LOCKFILE_BYTES}-byte request limit"
            )
        return v


class CveMatch(BaseModel):
    crate: str
    version: str
    advisory_id: str
    title: str
    url: str | None
    aliases: list[str]
    cvss: str | None
    severity: str | None
    severity_basis: str
    informational: str | None


class CveScanResult(BaseModel):
    outcome: str  # ok | skipped | degraded | failed -- see README.md's status table
    snapshot_revision: str | None = None
    advisory_count: int | None = None
    dependencies_scanned: int = 0
    dependencies_skipped_local: int = 0
    matches: list[CveMatch] = []
    notes: list[str] = []
    error: str | None = None


class CveSnapshotInfo(BaseModel):
    revision: str
    revision_date: str
    advisory_count: int
    source: str


@app.post("/cve/scan", response_model=CveScanResult)
async def scan_lockfile(req: CveScanRequest) -> CveScanResult:
    """Match a Cargo.lock's dependencies against the vendored advisory
    snapshot. Returns `skipped` (not `failed`, not an empty `ok`) when no
    lockfile is provided, so a target that genuinely has none (on-chain) is
    visibly distinct from a broken request or a clean scan -- the same
    `ok`/`skipped`/`degraded`/`failed` vocabulary the TS analyzers use
    (README.md's "Analyzer status" table), applied here so a caller wiring
    this in later doesn't have to invent a second vocabulary."""
    if req.lockfile is None or not req.lockfile.strip():
        return CveScanResult(
            outcome="skipped",
            notes=["no lockfile provided -- nothing to match (e.g. an on-chain target has no Cargo.lock)"],
        )

    db = _get_advisory_db()

    try:
        dependencies = parse_lockfile(req.lockfile)
    except MalformedLockfile as exc:
        return CveScanResult(outcome="failed", error=str(exc))

    if not dependencies:
        # Parsed successfully -- has a `package` array -- but it's empty.
        # Distinct from "no lockfile was submitted" (skipped, above) and from
        # "not parseable at all" (failed, above): this is real input that
        # legitimately resolved to zero dependencies to check.
        return CveScanResult(
            outcome="degraded",
            snapshot_revision=db.manifest.get("revision"),
            advisory_count=len(db.advisories),
            notes=["lockfile parsed but contains zero [[package]] entries"],
        )

    result = match_dependencies(dependencies, db)
    matches = []
    for m in result.matches:
        severity, severity_basis = severity_for_advisory(m.cvss)
        matches.append(
            CveMatch(
                crate=m.crate,
                version=m.version,
                advisory_id=m.advisory_id,
                title=m.title,
                url=m.url,
                aliases=list(m.aliases),
                cvss=m.cvss,
                severity=severity,
                severity_basis=severity_basis,
                informational=m.informational,
            )
        )

    return CveScanResult(
        outcome="ok",
        snapshot_revision=db.manifest.get("revision"),
        advisory_count=len(db.advisories),
        dependencies_scanned=result.dependencies_scanned,
        dependencies_skipped_local=result.dependencies_skipped_local,
        matches=matches,
        notes=list(result.notes),
    )


@app.get("/cve/snapshot", response_model=CveSnapshotInfo)
async def get_snapshot_info() -> CveSnapshotInfo:
    """The manifest of the currently-loaded advisory snapshot, so a report
    can cite exactly which DB revision produced a given /cve/scan result --
    see services/cve/README.md: refreshing the snapshot changes future match
    results, and nothing reproduces a past result after a refresh except by
    knowing which revision it came from."""
    db = _get_advisory_db()
    return CveSnapshotInfo(
        revision=db.manifest["revision"],
        revision_date=db.manifest["revision_date"],
        advisory_count=db.manifest["advisory_count"],
        source=db.manifest["source"],
    )
