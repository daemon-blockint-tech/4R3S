# ARES Auditor (TypeScript agent, root `src/`) — deployable image.
#
# The audit pipeline is a CLI, not a server: one invocation audits one target
# and exits. So this image has no CMD of its own — the target is supplied at
# `docker run` time, exactly as `npm run audit -- …` supplies it locally.
#
# Two things beyond `dist/` have to be in the image, because the code resolves
# them from disk relative to its own module URL rather than from a bundle:
#
#   - `rules/solana.yml` — semgrep's ruleset. `tools/semgrep.ts` resolves it as
#     `../../rules/solana.yml` from its own file, which is the repo root from
#     `src/tools/` and equally the repo root from `dist/tools/`. It must
#     therefore sit next to `dist/`, not inside it.
#   - `db/` — the Supabase/Neo4j schema `scripts/migrate.ts` applies, resolved
#     the same way via REPO_ROOT.
#
# semgrep itself is a real runtime dependency, not a nicety. Without it the
# `static` analyzer degrades to "semgrep not installed" and the audit loses the
# one evidence source that `applyVerdicts` will let stand as `confirmed`
# unconditionally — the image would still run, and would quietly produce weaker
# audits. Pinned by version so the same image tag scans the same way twice.

# ── builder ──────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS builder
WORKDIR /app

# Install against the lockfile before copying sources so edits to `src/` don't
# invalidate the dependency layer.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ── runtime ──────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime

# Pinned rather than floating: an unpinned scanner makes the same image tag
# produce different findings over time, which breaks the reproducibility the
# eval harness (`verify-claims`) depends on. Override at build time to upgrade.
ARG SEMGREP_VERSION=1.172.0

ENV NODE_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# `--break-system-packages` is required on Debian bookworm (PEP 668): the image
# has no other Python consumer, so installing into the system interpreter is
# the intended outcome here rather than a workaround being forced.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
 && pip3 install --no-cache-dir --break-system-packages "semgrep==${SEMGREP_VERSION}" \
 && apt-get purge -y python3-pip \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Production dependencies only — the builder already consumed the dev ones.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist/ ./dist/
# Siblings of dist/, per the module-relative resolution described above.
COPY rules/ ./rules/
COPY db/ ./db/

# Drop privileges. The audit reads a mounted target and writes nothing outside
# stdout, so it never needs root; `node` (uid 1000) ships with the base image.
USER node

# Fail fast and legibly if the image is ever built without its scanner, rather
# than silently degrading every `static` analysis at audit time.
RUN semgrep --version > /dev/null

# No CMD: the target is the argument. Mount the code and name it, e.g.
#   docker run --rm --env-file .env -v "$PWD/target:/target:ro" ares-auditor \
#     --source /target --ephemeral
ENTRYPOINT ["node", "dist/index.js"]
