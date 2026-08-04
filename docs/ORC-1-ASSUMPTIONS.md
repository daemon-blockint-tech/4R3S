# ORC-1 — Pull the agent-py plane into apps/auditor-api: what was done, what was verified, what wasn't

## The dependency is resolved, but it delivered scaffolding only

PLAT-1 is merged, and it did land `pnpm-workspace.yaml`, `turbo.json`,
`packages/README.md`, and the `apps/auditor-api/README.md` stub. What it did
**not** land is anything inside those folders: `packages/` holds only a README,
`apps/auditor-api/` held only a 261-byte README, and PLAT-1's own Resources
field still reads *"Remaining: src/->packages/* migration"*. So ORC-1 started
from an addressed but empty folder, not from a partially-populated one.

## The central decision: wrapper, not reimplementation

The brief says "pull the agent-py plane (LiteLLM, FastAPI, Arq worker,
tracing)". Its `Ref` field points at *"github ARES (agent-py: ...)"*, and
`CLAUDE.md` annotates this app as *"(from ARES)"* — but no repository name or
URL for that source is recorded in `CLAUDE.md`, `apps/README.md`,
`packages/README.md`, or any `docs/*.md`, and a search of the accessible
org/user repositories did not surface it. Per the mentor's direction, the work
was therefore based on what is in this repo: `src/graph/` and `src/llm/`, the
`Repo` field of the same task.

Given that, there were two ways to build this plane:

**A. Port the pipeline into Python.** Re-implement the 13-node LangGraph flow
(`resetAccumulators → intake → loadSource → recall → [4 parallel analyzers] →
merge → verify → remember → report`), the `GraphDeps` injection pattern, and
`chat-openrouter.ts` + `retry.ts` in Python.

**B. Wrap the existing CLI.** Put FastAPI and an Arq worker in front of
`npm run audit`, invoking the TypeScript graph as a subprocess.

**B was chosen.** Reasons, in the order they carried weight:

1. `CLAUDE.md` states plainly: *"What actually works today. The shipping
   auditor is the TypeScript agent at root `src/`."* That code has 281 passing
   tests and is what produced every measured F1 figure to date. Duplicating its
   logic in a second language creates two implementations that can silently
   diverge, with no test that would catch the divergence.
2. The pattern already exists in this repo. `apps/auditor-api/README.md` says
   this plane *"calls the Rust `core/` via CLI/contract"* — the same
   subprocess-boundary approach, not a port. Applying it to the TS CLI as well
   is consistent rather than novel.
3. It is reversible. Deleting this app leaves the auditor exactly as it is
   today; nothing about the existing audit path changes.

**If that reading of the intent is wrong** — if a full Python reimplementation
was meant — this is the wrong foundation and should be revisited before more is
built on it. That risk is stated here rather than buried.

## What was actually built

| File | Role |
|---|---|
| `apps/auditor-api/main.py` | FastAPI surface. `POST /audits` validates and enqueues; `GET /audits/{job_id}` polls. |
| `apps/auditor-api/worker.py` | Arq worker. Runs `npm run audit -- --source <path>` as a subprocess and records status/report/error to Redis. |
| `apps/auditor-api/requirements.txt` | Runtime + test pins. |
| `apps/auditor-api/test_auditor_api.py` | Tests for path resolution and stderr parsing. |
| `docker-compose.yml` | Added a `redis` service — Arq requires Redis and the repo had none. |
| `.github/workflows/ci.yml` | Added an `auditor-api (python)` job. |

Design points worth recording:

- **`POST /audits` returns 202, not 200.** A run takes ~75-90s observed, so
  this is fire-and-poll. Returning 200 with a synchronous body would tie an
  HTTP connection to a minutes-long LLM job.
- **`max_jobs = 2` on the worker.** The binding constraint on this queue is
  the daily LLM quota, not CPU. Unbounded concurrency would have parallel
  audits competing for the same quota and failing each other — the exact
  failure mode observed earlier in `eval/run_ares_batch.ts` batches (8 of 10
  targets lost to 429s).
- **Path validation happens before enqueue.** A queue slot spent on a target
  that cannot succeed is a slot stolen from one that could.
- **A 600s subprocess timeout with an explicit kill.** Without it a stalled
  audit occupies a worker slot indefinitely.

## Fixes required by the move, found by running it

Both of these were found during manual verification, not in review — worth
recording because both presented as operator error rather than as bugs:

1. **`REPO_ROOT` depth, twice.** `Path(__file__).resolve().parents[1]` resolves
   to `apps/`, not the repo root, because `__file__` is a file and
   `.parents[0]` is already its containing directory. Corrected to
   `parents[2]` in both `worker.py` and `main.py`. Symptom in `main.py` was a
   422 with a path one level short (`/4R3S/apps/eval/data/...`), which reads
   like a bad request rather than a wrong constant.
2. **`_last_error_line` read the wrong field.** It returned `msg`, which for
   `index.ts`'s top-level handler is the generic string `"Audit failed"`; the
   real cause sits in `err`. `index.ts`'s own comments call this gap out
   ("the operator sees 'Audit failed' and nothing else"). Now prefers `err`.

Both are pinned by tests so they cannot silently return.

## What could NOT be verified — and why

- **The failure path with the `_last_error_line` fix applied.** The generic
  `"Audit failed"` was reproduced live with an invalid API key (job completed
  in 1.22s, status `failed`), and the fix was verified against a simulated log
  line matching `index.ts`'s exact shape. It was **not** re-run end-to-end
  after the fix: doing so costs another real audit against the daily quota,
  and the root cause was already established by reading `index.ts` directly.
- **`reportParkedRun()`.** `index.ts` calls this when a graph node throws
  mid-run, and it may write output the worker should classify differently from
  a plain failure. Its contents were not read; the worker currently treats any
  nonzero exit as a generic failure.
- **Behaviour under concurrent load.** `max_jobs = 2` is reasoned from the
  observed quota constraint, not measured. No load test was run.
- **Cost per audit in currency.** Not measured; no figure is stated anywhere
  here, since a fabricated baseline would poison later comparisons.

## Verified before handing off

```
docker compose up -d redis            → ares-redis healthy, redis-cli ping → PONG
uvicorn main:app --reload             → Application startup complete
arq worker.WorkerSettings             → Starting worker for 1 functions: run_audit
POST /audits  (missing path)          → 422, rejected before enqueue
POST /audits  (real corpus file)      → 202 + job_id
GET  /audits/{id}                     → status done, full report returned
                                         (two runs: 87.03s and 74.49s)
POST /audits  (invalid API key)       → status failed in 1.22s, not a false success
python -m pytest -q                   → 9 passed
python -c "import yaml; yaml.safe_load(...)"  → ci.yml and docker-compose.yml valid
```

The successful run's report confirms the source-injection fix from KR-4/Option A
is intact through this path: findings cite concrete line numbers with quoted
code (`line 96`, `line 48-49`, `line 75`), satisfying GOLDEN RULE 5 ("the
Auditor must load actual source into analysis context").

## What's still NOT done

- **Tracing.** Named in the brief, not implemented. Needs a tooling decision
  (OpenTelemetry or otherwise) and instrumentation points; adding a library
  before that decision would be premature.
- **LiteLLM.** Also named in the brief, deliberately not added. Under the
  wrapper design no LLM call happens in Python — every model call is inside
  the TS graph the worker invokes. Pinning an unused LLM client would add an
  install and audit surface with no caller. If this plane later needs its own
  model access (summarisation, a chat endpoint), that is when it earns a place.
- **Dockerfile.** Not written; the app currently runs from a local Python
  environment.
- **Result storage is Redis with a 24h TTL.** Fine for development, but
  reports vanish after a day and do not survive a Redis flush. A durable store
  is a separate decision.
- **`packages/orchestration`.** ORC-1's `Home` is `apps/auditor-api`, and that
  is where this landed. The shared TS package remains a README stub.

## Open question for review

The queue-language question raised in `docs/PLAT-3-SALVAGE-ANALYSIS.md` —
whether Arq (Python) or ARES-v2's BullMQ (Node) is the queue going forward — is
answered by this work in practice: **this plane uses Arq**. If that settles the
duplication concern, the BullMQ package need not be ported and can be archived
as reference. Flagged here because that document records the decision as
pending.
