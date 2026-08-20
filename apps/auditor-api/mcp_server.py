"""
MCP (Model Context Protocol, stdio transport) server exposing ARES Auditor's
scan and enrich operations as agent tools -- for MCP clients such as Claude
Desktop, Claude Code, and Cursor.

Design decision (documented, not silently assumed): this is a thin adapter
over this app's existing FastAPI route functions in main.py -- it imports
and calls them directly as plain async functions rather than re-implementing
their logic or making an HTTP round-trip to a running server. This mirrors
both the pattern ARES-v2's apps/mcp-server used (a thin wrapper around
@ares/engine, "so there is a single source of truth") and the principle
main.py itself documents for wrapping the TS CLI instead of re-porting it.

Security posture (documented, not silently assumed): calling main.py's route
functions directly bypasses FastAPI's `require_api_key` dependency -- that
dependency is resolved by FastAPI's routing layer and never runs for a plain
Python call. This is deliberate for a stdio-transport server: stdio has no
network listener a remote, unauthenticated caller could reach in the first
place -- the trust boundary is "whoever can launch this subprocess" (the
same reasoning ARES-v2's Ref documented for its own stdio server, which
needed no per-call token either, only environment-level config). This
posture must be re-examined before this file ever grows a network transport
(SSE / streamable-http) -- at that point `require_api_key` would need to run
for real, which calling main.py's functions directly does not give you.

ares_submit_audit intentionally does NOT poll to completion -- audits take
minutes (AUDIT_TIMEOUT_SECS=600 in worker.py), not seconds, matching this
app's own "fire-and-poll, not request-response" design for /audits. Poll
ares_get_audit_status afterward instead of blocking a tool call for minutes.

Run from apps/auditor-api/ (same convention main.py/worker.py use --
see main.py's sys.path notes for why they are flat top-level modules):

    cd apps/auditor-api
    python mcp_server.py
"""
from __future__ import annotations

import main  # noqa: E402 -- see module docstring; run from apps/auditor-api/

from mcp.server.mcpserver import MCPServer

server = MCPServer(
    name="ares-auditor",
    version="0.1.0",
    instructions=(
        "ARES Auditor scan + enrich tools. ares_submit_audit queues a full "
        "audit and returns a job_id immediately -- an audit takes minutes, "
        "not seconds. Poll ares_get_audit_status(job_id) for the result; do "
        "not wait synchronously for ares_submit_audit to \"finish\". "
        "ares_cve_scan and ares_risk_score are fast, synchronous, and "
        "fully deterministic (no LLM, no network call)."
    ),
)


@server.tool(
    description=(
        "Queue a full ARES audit of a source path. Returns immediately with "
        "a job_id -- an audit takes minutes, not seconds. Poll "
        "ares_get_audit_status(job_id) for the result; do not wait "
        "synchronously in this call. source must resolve inside the "
        "server's allowed source root (ARES_ALLOWED_SOURCE_ROOT)."
    )
)
async def ares_submit_audit(
    source: str,
    callback_url: str | None = None,
) -> main.AuditAccepted:
    req = main.AuditRequest(source=source, callback_url=callback_url)
    return await main.submit_audit(req)


@server.tool(
    description="Poll the status/result of a previously submitted audit job."
)
async def ares_get_audit_status(job_id: str) -> main.AuditStatus:
    return await main.get_audit_status(job_id)


@server.tool(
    description=(
        "Match a Cargo.lock's dependencies against the vendored RustSec "
        "advisory snapshot. Deterministic and offline -- no LLM, no network "
        "call. Pass the lockfile's raw text content, not a path. Omit "
        "lockfile for an on-chain target that has none -- returns "
        "outcome='skipped', not an error."
    )
)
async def ares_cve_scan(lockfile: str | None = None) -> main.CveScanResult:
    req = main.CveScanRequest(lockfile=lockfile)
    return await main.scan_lockfile(req)


@server.tool(
    description=(
        "Get metadata (revision, revision date, advisory count) for the "
        "currently-loaded CVE advisory snapshot, so a report can cite "
        "exactly which DB revision produced an ares_cve_scan result."
    )
)
async def ares_cve_snapshot_info() -> main.CveSnapshotInfo:
    return await main.get_snapshot_info()


@server.tool(
    description=(
        "Score a risk vector using the OWASP Risk Rating Methodology. "
        "Deterministic -- no LLM, no network call. likelihood and "
        "technical_impact are factor-name -> 0-9 score maps per OWASP's "
        "tables; business_impact is optional and, when provided, its score "
        "determines impact_level/severity instead of technical_impact's."
    )
)
async def ares_risk_score(
    likelihood: dict[str, int],
    technical_impact: dict[str, int],
    business_impact: dict[str, int] | None = None,
) -> main.RiskScoreResult:
    req = main.RiskScoreRequest(
        likelihood=likelihood,
        technical_impact=technical_impact,
        business_impact=business_impact,
    )
    return await main.score_risk_endpoint(req)


@server.tool(
    description=(
        "Diff the vuln catalog's static default severities against what "
        "the OWASP-methodology templates would compute for the same "
        "categories. Only mismatches are returned -- a match just confirms "
        "agreement, which isn't actionable."
    )
)
async def ares_risk_calibration() -> main.RiskCalibrationResult:
    return await main.get_risk_calibration()


if __name__ == "__main__":
    server.run(transport="stdio")
