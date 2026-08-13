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
