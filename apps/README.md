# apps/ — deployables

- `auditor-api/` — Python agent plane (LiteLLM · FastAPI · Arq worker · tracing).
- `auditor-web/` — Next.js dashboard + landing.
- `ares-sec/` — offensive framework (Apache-2.0, **separate app**, deferred to P3).

**Product & safety boundary (CLAUDE.md #1):** `apps/ares-sec` must **not** be imported by the Auditor apps. Direction is `apps → packages → core`.
