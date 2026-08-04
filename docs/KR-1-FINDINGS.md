# KR-1 — Validate Crystalline memory: findings and fall-back decision

## The question

KR-1's brief: validate spreading activation / decay / consolidation, **or**
fall back to plain hybrid retrieval. Default is fall-back unless the cognitive
mechanisms are shown to earn their complexity.

## What was actually done

Read `src/memory/crystalline-store.ts` and `types.ts` in full, then wrote
characterization tests (`crystalline-inertness.test.ts`) pinning what each
mechanism does in the **shipped configuration** — not what the code is
theoretically capable of. Each test passed against the code as it stood before
any change, so the gaps below are demonstrated, not asserted.

## What was found

| Mechanism | Status in shipped config | Why |
|---|---|---|
| **Spreading activation** | Never fires | No caller anywhere in `src/` invokes `link()`. `remember.ts` calls `crystallize()` without `links`, so every crystal ships with `links: []`. |
| `spreadDepth` parameter | Inert beyond on/off | `recall()` read it only as `spreadDepth > 0`; depth 1 and depth 5 produced identical results. Not a bug in the traversal — the parameter was never wired to a hop count. |
| **Merge** (consolidation) | Never fires | `findMerges()` skips any crystal without an embedding. Runs configured Crystalline-only (no `EMBEDDINGS_MODEL`) mean `embed()` returns `undefined` for everything, so nothing is ever comparable. |
| **Prune** (consolidation) | Fires only for `sensory`/`working` | `consolidate()` returns early for those two levels; `episodic`/`semantic` are never revisited for decay. `remember.ts` defaults writes to `episodic`, so most memory is never pruned regardless of activation. |
| **Promote** (consolidation) | Fires, rarely | Requires `accessCount >= 3` on an episodic crystal. Confirmed live in one 9-audit batch (`promoted: 3`), zero in the other eight. |

Cross-cutting: `consolidate()` reported `merged: 0, pruned: 0` identically whether
the cause was "nothing needed doing" or "structurally could not do anything."
The two conditions are indistinguishable from the log line alone.

## Why this isn't just "unused code"

Two of the mechanisms actively worked against a goal this codebase otherwise
holds. `decayedActivation()` is keyed off `Date.now() - lastActivated`, so
activation — and therefore recall score — depended on wall-clock time and
audit ordering. Two `recall()` calls milliseconds apart over identical data
did not score identically at the float level (caught while writing the
inertness tests themselves — see the `toBeCloseTo` comment in
`crystalline-inertness.test.ts`). This is the same non-reproducibility problem
`eval/` exists to catch, just at the unit level instead of the F1 level.

## Decision: fall back (recall only, for now)

Answered the three gating questions from repo evidence rather than treating
them as open:

1. **Is cognitive memory a sold product differentiator?** Not found in
   `CLAUDE.md`, `core/README.md`, or `eval/README.md` — only in code comments
   describing internal architecture. Treated as an implementation detail.
2. **Is `EMBEDDINGS_MODEL` planned to be mandatory?** `CLAUDE.md`: "Postgres,
   Supabase (pgvector), Neo4j — all optional; the engine runs without them."
   No document states embeddings will become required.
3. **Is there a plan to populate `links`?** No backlog item, doc, or code
   references calling `link()`.

All three point the same direction: the mechanisms don't fail from being
half-built, they fail because both of their prerequisites are either optional
or unplanned. Complexity is paid continuously; the benefit never arrives.

## What changed

`recall()` simplified to pure similarity/tag scoring. Removed:
decayed-activation weighting (`act * 0.4 + sim * 0.6` → `sim`), the
spreading-activation block, and the `topIds` construction that fed it. Kept
unchanged: the dimension-mismatch fallback to tag scoring (unrelated to
decay/spreading, and valuable on its own), storage/CRUD (`crystallize`,
`load`, `forget`, `persist`), and `decayedActivation()` as a private method —
`consolidate()`'s prune step still uses it.

`minActivation`, `spreadDepth`, `spreadDecay` remain on `RecallQuery` for
call-site compatibility but are no longer read by `recall()`.

One existing test (`crystalline-store.test.ts`, "spreads activation from a
recalled crystal to a linked neighbor") asserted the removed behavior and was
replaced with its inverse: a linked neighbor must **not** be surfaced by an
unrelated query, confirming links no longer affect scoring.

## Verified before handing off

```
npx tsc --noEmit                                          → clean
npx vitest run crystalline-store.test.ts crystalline-inertness.test.ts
                                                            → 13/13 passed
npm test (full suite)                                      → 281/281, 33 files
```

Sole caller of `recall()` (`src/retrieval/crystalline-retriever.ts`) never
passed `minActivation`/`spreadDepth`/`spreadDecay`, so no call site required
updating.

## What's still NOT done

- **`consolidate()` untouched.** Prune/merge remain as described above. A
  second pass could either simplify consolidation the same way, or — a
  lighter option — leave the mechanism as-is and just make it report *why*
  it produced zero (no embeddings / wrong level) instead of a bare zero. Not
  decided here.
- **Storage/CRUD (`crystallize`, `load`, `forget`) kept as-is.** Fall-back was
  scoped to the cognitive envelope (decay/spreading), not the underlying
  store, which `remember.ts` and the recall node both still depend on.
- **No sign-off requested before making this change.** The three gating
  questions were answered from repo evidence rather than confirmed with the
  team. If any assumption above is wrong (embeddings becoming mandatory,
  a `links`-populating task landing later), this decision should be revisited.
