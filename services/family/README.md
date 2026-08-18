# services/family — program-family clustering + fork flag propagation

Groups Solana programs whose source is similar enough to be copies of one
another, and carries a vulnerability known in one member across to the rest as an
explicitly **unverified** signal.

Deterministic by construction: no LLM, no network, no randomness — integer
hashing over string slices and set arithmetic. See "Hermetic by default" in
[`SECURITY.md`](../../SECURITY.md).

## Why winnowing, and what "port" meant here

The task card (`Ref: ARES-AGENT python family/clone clustering`) names a source
that is not in this repository, and `docs/DEVELOPMENT_PLAN.md` — cited by
`services/README.md` for the §S3 spec — does not exist either. The reading used
is the one `services/risk` established for the same situation: implement a
**named, citable, external methodology** rather than invent a formula.

That methodology is winnowing, from Schleimer, Wilkerson & Aiken, *"Winnowing:
Local Algorithms for Document Fingerprinting"* (SIGMOD 2003) — the algorithm
behind MOSS. Chosen over MinHash and SimHash for two reasons: it was designed for
source-code clone detection specifically, and it is fully deterministic. MinHash
needs hash permutations and SimHash needs random projections, and a clustering
result that shifts between runs cannot be re-derived from committed data
(GOLDEN RULE 3).

## Scope

- **`fingerprint.py`** implements winnowing's two parameters and their published
  relationship: `k` (noise threshold — matches shorter than this are never
  reported), `t` (guarantee threshold — matches this long or longer are always
  detected), window `w = t - k + 1`. Parameters that break the guarantee (`t < k`)
  raise rather than returning an empty set that would read as "no similarity".
- **`cluster.py`** does single-linkage clustering over pairwise Jaccard
  similarity of fingerprint sets, then propagates flags within each family.

## What this detects, and what it does not

Fingerprints are taken over source stripped of comments with whitespace
collapsed. So it detects **verbatim copies** and **copies with reformatting,
reindentation, or rewritten comments**.

It does **not** detect a copy whose identifiers were renamed. Changing
`vault_balance` to `pool_balance` changes the k-grams and therefore the
fingerprints. Catching those (type-2 clones, in the literature) needs
tokenisation with identifier normalisation — a larger claim than this module
makes. It is stated here because a detector that silently misses renamed forks,
while a caller assumes otherwise, is worse than one whose limits are written
down.

## Boilerplate, and a bug this had before the tests caught it

Anchor programs share a lot of text: `use anchor_lang::prelude::*`,
`declare_id!`, `#[program]`, a `#[derive(Accounts)]` struct. The first
implementation scored two entirely unrelated programs at **0.76** on that shared
preamble alone — past the 0.55 threshold — and a `critical` vulnerability flag
propagated between them. The boilerplate was most of the text, so it was most of
the fingerprints.

The fix is the one MOSS uses for shared assignment template code: discard
fingerprints appearing in more than `DEFAULT_MAX_DOCUMENT_FREQUENCY` (0.5) of the
corpus before comparing.

**This needs a corpus.** Document frequency is meaningless with two programs —
every shared fingerprint appears in 100% of them, so filtering would discard
exactly the evidence of copying it exists to preserve. Below
`MIN_CORPUS_FOR_DF_FILTER` (4) the filter is skipped and boilerplate is *not*
separated from copying. That is a limitation of a small corpus, not something the
algorithm can resolve: with two files there is no way to tell a shared preamble
from a shared origin. A caller comparing a handful of programs should widen the
corpus or raise `threshold`.

## Propagation never produces a finding

Carrying a flag from A to B produces a statement about B that was never observed
in B. That is the claim the rest of this repository is built to refuse — GOLDEN
RULE 3, the verify-claims gate, `analyze-heuristic.ts`'s `speculative` demotion
for a finding citing a file the run never read, `known-programs.ts`'s downgrade.

So an inherited flag is returned as an `InheritedFlag`, never a `Finding`:

- `unverified: bool = True`, on a frozen dataclass, so a caller cannot clear the
  marker before rendering.
- `evidence` opens with `"Not observed in {program}"` and names the inference,
  rather than describing the fork's code.
- `similarity` is the **pairwise** score against the specific program the flag
  came from, not a cluster average — under single linkage those differ, and a
  cluster-level number would hide a weak transitive link.

There is no similarity above which an inherited flag becomes confirmed. Even
byte-identical source can differ in the account constraints its deployment
enforces, and a fork may carry the fix. Confirming requires reading the fork,
which is what the auditor pipeline does and what this service deliberately does
not attempt.

Callers must render these as "worth checking because it resembles X", never as
"present in B". Flattening them into the same list as observed findings undoes
the point of the separate type.

## Clustering method, and its known cost

Single-linkage: two programs join a family if their pairwise similarity clears
the threshold, and families merge transitively. Chosen because "was copied from"
is itself transitive — if B forked A and C forked B, C belongs in A's family even
where C and A have drifted past the threshold directly.

The cost is chaining: a long series of small drifts can put two dissimilar
programs in one family. Accepted deliberately, and the reason `links` is returned
alongside `clusters` — a family on its own does not show why its members were
joined, and the per-pair scores are what let a reader find the weak link.

## Not wired up

Nothing calls this yet. There is no endpoint in `apps/auditor-api` and no CI job,
unlike `services/cve` and `services/risk`. Wiring it in needs a decision this
service should not make on its own: which corpus of programs to cluster against
(the committed `core/dataset/solana-common-attack-vectors/` is the only
source-code corpus in the repo; `eval/data/corpus/` is gitignored), and how an
`InheritedFlag` should appear in a report given that it is explicitly not a
finding.

## Tests

```
cd services/family && python -m pytest -q     # 30 passed
```

Mutation-checked: disabling the boilerplate filter fails 7 tests, and making
`similarity` return 1.0 for two empty sets fails 1. Both restore to green.
