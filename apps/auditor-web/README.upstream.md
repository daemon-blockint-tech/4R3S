# apps/auditor-web — ARES Auditor dashboard (Next.js)

Dashboard and landing for **ARES Auditor**: audit tasks, findings, reports, auth, and agent orchestration UI.

**INT-4** · Status: **UI shell landed** (adapted from [vercel-labs/coding-agent-template](https://github.com/vercel-labs/coding-agent-template), Apache-2.0).

## What this is

The Vercel **coding-agent-template** provides the UX patterns we want:

- Task sidebar with live status
- Multi-agent selection and connectors
- OAuth (GitHub / Vercel)
- shadcn/ui + Tailwind + Next.js App Router
- Drizzle + Postgres for sessions/tasks

It is **rebranded and vendored** here as the starting point for the ARES dashboard. Backend wiring to the root `src/` LangGraph auditor (`npm run audit`) is follow-up work.

## Quick start

From the monorepo root:

```bash
cd apps/auditor-web
pnpm install
pnpm db:push
pnpm dev
```

Open http://localhost:3000

Copy env vars from `README.upstream.md` into `.env.local` (OAuth, `POSTGRES_URL`, `JWE_SECRET`, `ENCRYPTION_KEY`).

## Attribution

UI foundation from [vercel-labs/coding-agent-template](https://github.com/vercel-labs/coding-agent-template) (Apache-2.0). See `LICENSE` in this directory and `README.upstream.md` for upstream docs.

## Next steps (product)

1. Replace repo/coding task form with **Solana program / source path** audit intake
2. Wire jobs to root auditor (`npm run audit`) instead of Vercel Sandbox coding agents
3. Render ARES report + severity matrix in task detail
4. Supabase Auth + RBAC for browser access to knowledge base

## Scripts

```bash
pnpm dev
pnpm build
pnpm typecheck
pnpm db:push
pnpm db:studio
```
