# Solana Vulnerability Taxonomy + Coverage Tracking

Add a structured ~20-class Solana vulnerability catalog, wire it as a checklist into all analyzers, track which classes were evaluated via a new `coverage` state channel, and tag every finding with a catalog `category`. Also create a new `analyze-cua.ts` LLM analyzer node.

## 1. New: `src/knowledge/solana-vulns.ts`

- Export `VulnEntry` interface: `{ id, title, category, defaultSeverity, cwe?, description, detectionHints, remediation, references }`
- Export `VULN_CATALOG: VulnEntry[]` — 20 entries covering: `missing-signer-check`, `missing-owner-check`, `account-data-matching`, `arbitrary-cpi`, `non-canonical-bump`, `pda-seed-collision`, `account-reinitialization`, `missing-reload-after-cpi`, `integer-overflow-underflow`, `precision-loss`, `account-close-revival`, `duplicate-mutable-account`, `missing-rent-exemption`, `sysvar-spoofing`, `anchor-constraint-gap`, `unchecked-cpi-return`, `authority-mismanagement`, `oracle-price-manipulation`, `insecure-init-order`, `spl-authority-check`
- Export `VULN_IDS: Set<string>` — derived from catalog
- Export `getVuln(id): VulnEntry | undefined`
- Export `isVulnId(id): boolean`
- Export `formatChecklistForPrompt(): string` — compact numbered list: `1. <id> — <title> (<one-line hint>)`

## 2. New: `src/knowledge/solana-vulns.test.ts`

- Unique ids (no duplicates)
- Every entry has non-empty required fields (title, description, detectionHints, remediation)
- Every `defaultSeverity` is a valid `Severity` value
- `formatChecklistForPrompt()` output contains every id
- `isVulnId` / `getVuln` behave correctly

## 3. Modify: `src/graph/state.ts`

- Add `category: string` to `Finding` interface (catalog id or `"other"`)
- Add `coverage: string[]` channel to `AresStateAnnotation` with union/dedupe reducer: `(prev, next) => [...new Set([...prev, ...next])]`, default `() => []`

## 4. Modify: `src/graph/util.ts`

- `coerceFindings(raw, source)`: accept both array root **and** object with `.findings` array; coerce `category` via `isVulnId`, else `"other"`
- Add `extractChecked(raw): string[]` — reads `.checked` array, filters to valid catalog ids via `isVulnId`

## 5. Modify: `src/llm/prompts.ts`

- `analyzeSystemPrompt`: inject `formatChecklistForPrompt()` output; instruct model to work through the checklist, tag each finding with a `category` id from the catalog, and return `{ "findings": [...], "checked": ["<ids>"] }`. Remove false reference to "instruction analysis / vulnerability checks" tool output.

## 6. New: `src/graph/nodes/analyze-cua.ts`

- LLM-based analyzer that reads source code directly (via `readFile` on `state.sourcePath`) and reasons about it using the checklist prompt
- Follows same pattern as `analyze-onchain.ts`: gate (no sourcePath → empty) → read source → LLM with `analyzeSystemPrompt` → `coerceFindings` + `extractChecked` → return `{ findings, coverage, iterations: 1 }`
- `source: "onchain"` won't fit — need to extend `Finding["source"]` to include `"cua"` or reuse `"heuristic"`. **Decision: extend `Finding["source"]` to `"onchain" | "static" | "heuristic" | "cua"`.**

## 7. Modify: `src/graph/nodes/analyze-onchain.ts`, `analyze-heuristic.ts`

- Parse with `coerceFindings` (now handles object form) + `extractChecked`
- Update human prompt text to ask for `{ findings, checked }` shape
- Return `{ findings, coverage: checked, iterations: 1 }`

## 8. Modify: `src/graph/nodes/analyze-static.ts`

- Best-effort map each Semgrep `ruleId` to a catalog id (heuristic substring match against `VULN_IDS`, else `"other"`)
- Set `category` on each finding
- Report `coverage` for the classes its rules can detect (the mapped ids)

## 9. Modify: `src/graph/nodes/report.ts`

- Include coverage line in human prompt: checked ids vs `VULN_CATALOG.length`
- Include each finding's `category` in the findings listing

## 10. Modify: `src/graph/build-graph.ts`

- Import and wire `makeAnalyzeCuaNode(deps)` into the fan-out/fan-in (addNode + addEdge from recallPhase → analyzeCua → mergePhase)

## 11. Modify: tests

### `src/graph/util.test.ts`
- `coerceFindings`: object-with-`.findings` form works; invalid `category` → `"other"`; valid `category` preserved
- `extractChecked`: filters to valid catalog ids; handles missing `.checked`

### `src/graph/build-graph.test.ts`
- Fake chat ANALYZE response returns `{ findings: [{…, category: "integer-overflow-underflow"}], checked: ["integer-overflow-underflow", "missing-signer-check"] }`
- Assert findings carry a valid `category`
- Assert `coverage` is populated and deduped
- Assert graph still runs end-to-end

## 12. Git

- `git fetch origin main && git checkout -B claude/workshop-langchain-review-7naxo5 origin/main`
- Implement all changes
- `npm run typecheck && npm run lint && npm test`
- Push with `-u`, open draft PR

## File change summary

| File | Action |
|------|--------|
| `src/knowledge/solana-vulns.ts` | **New** — catalog + helpers |
| `src/knowledge/solana-vulns.test.ts` | **New** — integrity tests |
| `src/graph/state.ts` | **Mod** — `category` on Finding, `coverage` channel, extend `source` |
| `src/graph/util.ts` | **Mod** — `coerceFindings` object form + category, `extractChecked` |
| `src/llm/prompts.ts` | **Mod** — checklist injection in `analyzeSystemPrompt` |
| `src/graph/nodes/analyze-cua.ts` | **New** — CUA analyzer node |
| `src/graph/nodes/analyze-onchain.ts` | **Mod** — new parsing + coverage |
| `src/graph/nodes/analyze-heuristic.ts` | **Mod** — new parsing + coverage |
| `src/graph/nodes/analyze-static.ts` | **Mod** — category mapping + coverage |
| `src/graph/nodes/report.ts` | **Mod** — coverage in prompt |
| `src/graph/build-graph.ts` | **Mod** — wire CUA node |
| `src/graph/util.test.ts` | **Mod** — new coerce/extract tests |
| `src/graph/build-graph.test.ts` | **Mod** — new fake response shape + assertions |
