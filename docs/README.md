# docs/

Repo-facing docs. `CLAUDE.md` (repo root) is the contributor + Claude Code guide.

- `PLAT-1-ASSUMPTIONS.md` — monorepo-shell assumptions (salvaged from the deleted orphan `master` branch).
- `PLAT-1-PROGRESS.md` — what the skeleton did and what's left for the team.

> The full internal specs (PRD, Development Plan, Backlog, commercial model) are maintained by the team and are **not** committed here — this repo is **public**, so publishing them is a deliberate call for the lead. Add sanitized versions when ready.

### `docs/internal/` (local / team-only)

Engineering design notes for `apps/auditor-web` (rate limiting, observability, reliability, etc.) live under `docs/internal/`. Same policy as above: **not intended for public release** until the lead sanitizes or redacts. Prefer `apps/auditor-web/docs/` for contributor-facing app docs if a file must ship in-repo without redaction.
