# ARES Auditor Web

Next.js dashboard for **ARES Auditor** — tasks, auth, and (planned) Solana audit reports.

UI components use **[shadcn/ui](https://ui.shadcn.com/)** ([source](https://github.com/shadcn-ui/ui)) — copy-paste Radix + Tailwind primitives, not an npm component library. The coding-agent template shell is Apache-2.0; shadcn components are MIT (see `NOTICE`).

## Quick start

```bash
cd apps/auditor-web
pnpm install
cp .env.local.example .env.local   # fill POSTGRES_URL, JWE_SECRET, OAuth — see below
pnpm db:push
pnpm dev
```

Open http://localhost:3000

## Environment

Create `.env.local`:

```env
POSTGRES_URL=postgres://ares:ares_dev_password@localhost:5432/ares
JWE_SECRET=<random-32+-chars>
ENCRYPTION_KEY=<random-32+-chars>
NEXT_PUBLIC_AUTH_PROVIDERS=github
NEXT_PUBLIC_GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

Start Postgres from the monorepo root: `npm run db:up`

User docs: [Dashboard guide](https://github.com/daemon-blockint-tech/4R3S/blob/main/docs/user/guides/dashboard.mdx) · [GitHub OAuth](https://github.com/daemon-blockint-tech/4R3S/blob/main/docs/user/guides/github-auth.mdx)

## shadcn/ui

Configured in `components.json` (style: **new-york**, Tailwind v4, RSC). Existing components live in `components/ui/`.

**Add or update components** from the official registry (backed by [shadcn-ui/ui](https://github.com/shadcn-ui/ui.git)):

```bash
pnpm ui:add button          # add a new component
pnpm ui:add sidebar table   # multiple components
pnpm ui:diff button         # compare local file vs registry
pnpm ui:update button       # overwrite with latest registry version
```

Equivalent without scripts:

```bash
pnpm dlx shadcn@latest add sidebar
pnpm dlx shadcn@latest diff dialog
```

Browse components: [ui.shadcn.com/docs/components](https://ui.shadcn.com/docs/components)

**Do not** clone `shadcn-ui/ui` into this app — the CLI copies only the files you need into `components/ui/`.

### Brand assets

| File | Use |
| ---- | --- |
| `ARES.png` | Wordmark (header, home hero) |
| `favicon.png` | Tab / PWA icon (`app/icon.png`) |
| `ares-icon.png` | Optional marketing icon |

## Scripts

```bash
pnpm dev
pnpm build
pnpm typecheck
pnpm db:push
pnpm db:studio
```

## Attribution

- Shell: [vercel-labs/coding-agent-template](https://github.com/vercel-labs/coding-agent-template) (Apache-2.0) — see `README.upstream.md`
- Components: [shadcn-ui/ui](https://github.com/shadcn-ui/ui) (MIT)
