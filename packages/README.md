# packages/ — shared permissive TypeScript packages

Consumed `apps → packages → core`. All Apache-2.0.

Migration target for the current root `src/` (PLAT-1 move — **not done yet**):

| From (`src/`) | To (`packages/`) |
|---|---|
| `knowledge` + `memory` + `retrieval` | `packages/knowledge` |
| `report` | `packages/report` |
| `graph` + `llm` | `packages/orchestration` |
| `billing` | `packages/billing` |
| `config` | `packages/config` |
| (new) shared design system | `packages/ui` |

> Not yet moved — the repo still builds from root `src/` under npm, so CI stays green. Devs continue the migration here, updating imports as they go.
