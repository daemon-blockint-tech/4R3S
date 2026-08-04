# User documentation (Mintlify)

End-user documentation for **ARES Auditor**, built with [Mintlify](https://mintlify.com).

## Local preview

Requires [Mintlify CLI](https://www.mintlify.com/docs/cli/install) (Node.js 20+):

```bash
npm i -g mint
cd docs/user
mint dev
```

Open http://localhost:3000

Validate before deploy:

```bash
mint validate
mint broken-links
```

## Deploy from this monorepo

1. Create a project at [mintlify.com/start](https://mintlify.com/start) and connect the `4R3S` GitHub repository.
2. In [Git Settings](https://app.mintlify.com/settings/deployment/git-settings), enable **docs.json is in a subdirectory** and set the path to:

   ```
   /docs/user
   ```

   See Mintlify [Monorepo setup](https://mintlify.com/docs/deploy/monorepo).

3. Push to the connected branch — Mintlify deploys automatically.

## Structure

```
docs/user/
├── docs.json              # Site config + navigation
├── index.mdx              # Introduction
├── quickstart.mdx
├── configuration.mdx
├── guides/
│   ├── audit-pipeline.mdx
│   ├── knowledge-base.mdx
│   ├── neo4j.mdx
│   ├── github-auth.mdx
│   ├── web3-auth.mdx
│   └── dashboard.mdx
└── reference/
    ├── environment.mdx
    └── cli.mdx
```

## Mintlify MCP (for authors)

Add the Mintlify docs MCP for component and authoring help:

- Search: `https://mintlify.com/docs/mcp`
- Admin (content management): `https://mcp.mintlify.com`

Install the skill:

```bash
npx skills add https://mintlify.com/docs
```

## Internal vs user docs

| Path | Audience |
| ---- | -------- |
| `docs/user/` | **Users** — Mintlify site |
| `docs/` (other `.md` files) | **Contributors** — engineering notes, not published to Mintlify |
