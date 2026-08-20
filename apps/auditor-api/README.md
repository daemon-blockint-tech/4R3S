# apps/auditor-api — agent plane (Python)

LiteLLM routing · FastAPI surface · Arq worker · tracing. **ORC-1** vendors the agent-py plane here; it calls the Rust `core/` via CLI/contract. Must stay optional — the core runs standalone.

Status: skeleton. **INT2** added auth and SSRF-guarded per-job webhooks.

| env var | default | meaning |
| --- | --- | --- |
| `ARES_API_KEYS` | *(unset)* | Comma-separated bearer tokens. Every route requires `Authorization: Bearer <key>`. **Unset means the API refuses every request** — it fails closed rather than serving openly. |
| `ARES_WEBHOOK_SIGNING_SECRET` | *(unset)* | When set, each webhook carries `X-ARES-Signature: sha256=<hmac>` over the raw body, so a receiver can tell a genuine callback from a forged one. |
| `ARES_ENABLE_DOCS` | off | Serves `/docs`, `/redoc` and `/openapi.json`. Off by default: FastAPI's global route dependencies do **not** cover those handlers, so enabling them publishes the full schema unauthenticated. |
| `ARES_ALLOWED_SOURCE_ROOT` | repo root | Containment root for `source` (pre-existing). |

Webhooks are **per-job, not a subscription**: set `callback_url` on `POST /audits` and the worker POSTs the final result there once. Delivery is best-effort and fires only for outcomes that actually end a job — a status the worker will retry does not notify, so a caller is never told "failed" about a job that then succeeds. `GET /audits/{job_id}` remains the source of truth. Targets are checked by `ssrf_guard.py` at submission *and* again immediately before delivery; https only, no redirects followed, and any address that isn't globally routable (private, loopback, link-local/metadata, CGNAT, IPv4-mapped equivalents) is refused.

## MCP server (agent tools)

`mcp_server.py` exposes this app's scan and enrich operations as MCP tools over stdio, for local clients such as Claude Desktop, Claude Code, and Cursor. It's a thin adapter — it calls this file's own route functions directly rather than re-implementing them or going over HTTP to a running server (see the module docstring for the full rationale).

| MCP tool | Backing route |
| --- | --- |
| `ares_submit_audit` | `POST /audits` |
| `ares_get_audit_status` | `GET /audits/{job_id}` |
| `ares_cve_scan` | `POST /cve/scan` |
| `ares_cve_snapshot_info` | `GET /cve/snapshot` |
| `ares_risk_score` | `POST /risk/score` |
| `ares_risk_calibration` | `GET /risk/calibration` |

`ares_submit_audit` does not block until the audit finishes — an audit takes minutes (`AUDIT_TIMEOUT_SECS=600`), not seconds. It returns a `job_id` immediately; poll `ares_get_audit_status` for the result.

**Security posture:** calling route functions directly bypasses the `require_api_key` dependency above — there is no per-call auth token for this surface. This is deliberate for stdio: the trust boundary is "whoever can launch this subprocess," not a network caller. Re-examine this before adding any network transport (SSE / streamable-http) to `mcp_server.py`.

```bash
cd apps/auditor-api
pip install -r requirements.txt
python mcp_server.py
```

Wiring into Claude Desktop / Cursor (`claude_desktop_config.json` / `.cursor/mcp.json`):
```jsonc
{
  "mcpServers": {
    "ares-auditor": {
      "command": "python",
      "args": ["/absolute/path/to/4R3S/apps/auditor-api/mcp_server.py"]
    }
  }
}
```
