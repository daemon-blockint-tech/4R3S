# PLAT-1 — `src/*` → `packages/*` migration map

**Status:** planning. The shipping TS auditor lives entirely in **root `src/`** today
(one npm package, 99 `.ts` files). `packages/*` is still a README stub. This doc is the
agreed source→target mapping and the safe migration order, so parallel work doesn't
collide at merge time. Update it as decisions land.

> Tooling note: the repo standardized on **npm** (`pnpm-workspace.yaml` and `turbo.json`
> were removed — they were an inert skeleton with no real packages behind them). PLAT-1
> re-introduces workspace tooling deliberately: **npm workspaces** in the root
> `package.json` (`"workspaces": ["packages/*"]`), and optionally Turborepo once there is
> more than one real package to orchestrate.

## Current `src/` layout (what actually ships)

| `src/` dir     | files | role                                                        |
|----------------|-------|-------------------------------------------------------------|
| `config/`      | 7     | shared config kernel — imported ~62× across the tree        |
| `knowledge/`   | 6     | canonical vuln catalog                                      |
| `retrieval/`   | 11    | retrieval over the catalog/memory                           |
| `memory/`      | 4     | agent memory store                                          |
| `llm/`         | 5     | LLM adapters / prompts                                      |
| `graph/`       | 27    | LangGraph agent pipeline (the orchestration)                |
| `persistence/` | 8     | Postgres / Supabase / Neo4j persistence                     |
| `billing/`     | 16    | billing + credits (BIZ-1)                                   |
| `tools/`       | 9     | agent tools                                                 |
| `scripts/`     | 5     | CLI scripts (migrate, ingest, eval-predict, export-catalog) |
| `index.ts`     | 1     | app entry                                                   |

## Proposed source → target mapping

| `src/` (today)                       | `packages/*` (target)      | notes / decision needed                                        |
|--------------------------------------|----------------------------|----------------------------------------------------------------|
| `config`                             | `@ares/config`             | leaf everyone depends on → **migrate FIRST**                   |
| `knowledge` + `retrieval` + `memory` | `@ares/knowledge`          | CLAUDE.md defines knowledge as "vuln catalog + memory + retrieval" — confirm the 3 fold into one package |
| `graph` (+ `tools`?)                 | `@ares/orchestration`      | the LangGraph pipeline is the orchestration layer             |
| `billing`                            | `@ares/billing`            | direct                                                          |
| `llm`                                | ❓ `@ares/orchestration` or own | **DECIDE** — not named in CLAUDE.md's package list        |
| `persistence`                        | ❓ own `@ares/persistence` or fold into config/orchestration | **DECIDE** — not named in CLAUDE.md's list |
| `tools`                              | ❓ `@ares/orchestration` or own | **DECIDE**                                              |
| `scripts`, `index.ts`                | stay app-level (root CLI / `apps/auditor-api`) | not packages                              |
| — (no `src/report` today)            | `@ares/report`             | **EXTRACT** — report generation currently lives inside `graph`/`tools`; there is no `src/report` to move |
| — (not from `src/`)                  | `@ares/ui`                 | shared design system belongs to `apps/auditor-web`, **not** `src/` — clarify scope before creating it |

### Open decisions (resolve before moving files)
1. `llm`, `persistence`, `tools` — which package each lands in (none are named in CLAUDE.md's target list).
2. `report` — has no `src/report`; decide where report generation is extracted from.
3. `ui` — comes from `apps/auditor-web`'s design system, not `src/`. Keep or drop from the PLAT-1 scope.
4. Confirm `memory` + `retrieval` fold into `@ares/knowledge`.

## Migration order (incremental — CI green at every step, no big-bang)

1. **Enable npm workspaces** — add `"workspaces": ["packages/*"]` to root `package.json`; keep root `src/` building as-is meanwhile.
2. **`@ares/config` first** — it's the shared kernel (~62 importers). Move it, give it `package.json` (`name: "@ares/config"`) + a `tsconfig` that extends root, add an exports map. Rewrite `../config` importers to `@ares/config`. Prove `npm run build`/`test` green.
3. **One clean vertical next** — `@ares/knowledge` (with memory + retrieval). Same recipe. Green CI before continuing.
4. **Remaining packages one at a time** — `orchestration`, `billing`, then whatever the open decisions settle.
5. **Update CI** — `ci.yml` currently runs `tsc` over root `src/`. Switch the build/test/lint/typecheck steps to run across workspaces (`npm run build --workspaces`, or Turbo if re-introduced). Keep the two golden-rule gates intact: `scripts/check-import-boundary.mjs` (auditor packages must not import `apps/ares-sec`) and `scripts/check-licenses.mjs`.

## Guardrails
- **Mechanical, not behavioral.** Moving files + rewriting imports must not change detection logic or output. Keep determinism where it applies.
- **One package per PR.** Each step should be reviewable and independently green — this is what keeps merges safe while the rest of the team keeps shipping into `src/`.
- **`src/` keeps growing until this starts.** New services (CVE enrichment, BIZ-1 billing) are landing in `src/`; the longer PLAT-1 waits, the larger the migration. Prefer starting the `config` step soon over a big-bang later.
