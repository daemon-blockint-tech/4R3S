/**
 * Emit `eval/predictions/ares-latest.csv` by running ARES over the corpus that
 * `eval/fetch_datasets.py` writes, so `score_detections.py` has something to
 * score. Each `*.rs` under the corpus dir is one audit target; its `target_id`
 * is the file's basename, matching the ground truth vocabulary.
 *
 * The CSV schema is the Predictions table in eval/README.md: one row per
 * `verifiedFindings` entry, carrying the fields the scorer filters and matches
 * on (`category`, `confidence`, `status`, `speculative`, `severity`).
 *
 * Rows are appended per target rather than buffered to the end: a full corpus
 * run is dozens of paid LLM audits, and a crash at target 150 must not discard
 * the first 149. Re-running overwrites from scratch — there is no resume.
 */
import { appendFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { basename, extname, join } from "node:path";
import { parseArgs } from "node:util";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";
import { defaultChat } from "../llm/chat-openrouter.js";
import { CrystallineStore } from "../memory/crystalline-store.js";
import { createStore } from "../persistence/store.js";
import { createMemoryCheckpointer } from "../persistence/checkpointer.js";
import { closeNeo4j } from "../persistence/neo4j.js";
import { createKnowledgeWriter } from "../persistence/knowledge-writer.js";
import { createHybridRetriever } from "../retrieval/index.js";
import { setCuaOverride } from "../tools/cua.js";
import { buildAuditGraph } from "../graph/build-graph.js";
import type { Finding } from "../knowledge/finding.js";

export interface PredictionRow {
  target_id: string;
  category: string;
  confidence: string;
  status: string;
  speculative: boolean;
  severity: string;
}

export const CSV_HEADER =
  "target_id,category,confidence,status,speculative,severity";

/**
 * One row per finding — the scorer dedups on `(target_id, category)` itself and
 * filters on `status`/`speculative` first, so collapsing here would drop the
 * fields that decide which of two same-class findings survives.
 */
export function predictionRows(
  findings: Finding[],
  targetId: string,
): PredictionRow[] {
  return findings.map((f) => ({
    target_id: targetId,
    category: f.category,
    confidence: f.confidence,
    status: f.status ?? "",
    speculative: f.speculative,
    severity: f.severity,
  }));
}

/** RFC-4180 field quoting: only when the value carries a comma, quote, or newline. */
function csvField(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function rowToCsvLine(row: PredictionRow): string {
  return [
    row.target_id,
    row.category,
    row.confidence,
    row.status,
    String(row.speculative),
    row.severity,
  ]
    .map(csvField)
    .join(",");
}

export function toCsv(rows: PredictionRow[]): string {
  return [CSV_HEADER, ...rows.map(rowToCsvLine)].join("\n") + "\n";
}

/**
 * Recover each corpus file's ground-truth `target_id` from the index
 * `fetch_datasets.py` writes alongside the `.rs` files.
 *
 * The filename is a lossy encoding of the id (`:` becomes `_` to stay
 * filesystem-safe), so deriving the id from the basename yields `a_b_c` where
 * the ground truth says `a:b:c` — every row misses, and a full corpus run
 * reports F1 0.0 for a system that detected correctly. Missing index is fatal
 * rather than a fallback to the basename, because that fallback is exactly the
 * silent-zero failure.
 */
async function loadTargetIndex(corpusDir: string): Promise<Record<string, string>> {
  const indexPath = join(corpusDir, "index.json");
  try {
    return JSON.parse(await readFile(indexPath, "utf8")) as Record<string, string>;
  } catch {
    throw new Error(
      `${indexPath} not found or unreadable. Re-run \`python eval/fetch_datasets.py\` ` +
        `to write it; without it a corpus filename cannot be mapped back to the ` +
        `ground-truth target_id and every prediction would miss.`,
    );
  }
}

interface Cli {
  corpus: string;
  out: string;
  limit?: number;
}

function parseCli(): Cli {
  const { values } = parseArgs({
    options: {
      corpus: { type: "string", default: "eval/data/corpus" },
      out: { type: "string", default: "eval/predictions/ares-latest.csv" },
      limit: { type: "string" },
    },
  });
  const limit = values.limit ? Number(values.limit) : undefined;
  if (limit !== undefined && (!Number.isInteger(limit) || limit <= 0)) {
    throw new Error(`--limit must be a positive integer, got "${values.limit}"`);
  }
  return { corpus: values.corpus, out: values.out, limit };
}

async function main(): Promise<void> {
  const cli = parseCli();
  setCuaOverride(false);

  let entries: string[];
  try {
    entries = await readdir(cli.corpus);
  } catch {
    throw new Error(
      `corpus directory not found: ${cli.corpus}. Run \`python eval/fetch_datasets.py\` first.`,
    );
  }
  const targetIndex = await loadTargetIndex(cli.corpus);
  let targets = entries
    .filter((name) => extname(name) === ".rs")
    .sort()
    .map((name) => {
      const stem = basename(name, ".rs");
      const id = targetIndex[stem];
      if (!id) {
        throw new Error(
          `corpus file ${name} has no entry in index.json; re-run \`python eval/fetch_datasets.py\``,
        );
      }
      return { id, path: join(cli.corpus, name) };
    });
  if (targets.length === 0) {
    throw new Error(`no .rs files under ${cli.corpus}`);
  }
  if (cli.limit !== undefined) targets = targets.slice(0, cli.limit);

  const store = createStore();
  const crystalline = new CrystallineStore(store);
  await crystalline.start();
  const graph = buildAuditGraph({
    deps: {
      chat: defaultChat,
      crystalline,
      retriever: createHybridRetriever(crystalline),
      knowledge: createKnowledgeWriter(),
    },
    // Ephemeral: eval runs are one-shot per target and need no cross-run resume,
    // so there is no reason to require Postgres to score the model.
    checkpointer: createMemoryCheckpointer(),
    store,
  });

  await mkdir(join(cli.out, ".."), { recursive: true });
  await writeFile(cli.out, CSV_HEADER + "\n");

  let audited = 0;
  let rowsWritten = 0;
  let failed = 0;
  for (const target of targets) {
    try {
      const result = await graph.invoke(
        {
          request: `Audit the following Solana target.\nSource: ${target.path}`,
          sourcePath: target.path,
        },
        {
          configurable: { thread_id: `eval:${target.id}` },
          recursionLimit: env.ARES_MAX_ITERATIONS * 4,
        },
      );
      const rows = predictionRows(result.verifiedFindings ?? [], target.id);
      if (rows.length > 0) {
        await appendFile(cli.out, rows.map(rowToCsvLine).join("\n") + "\n");
        rowsWritten += rows.length;
      }
      audited += 1;
      logger.info(
        {
          component: "eval.predict",
          target: target.id,
          findings: rows.length,
          progress: `${audited + failed}/${targets.length}`,
        },
        "Target audited",
      );
    } catch (err) {
      // One target's failure must not abort the run — a clean target contributes
      // no predictions anyway, so a skipped one only understates recall for it,
      // which is visible in the target count below. Losing the whole corpus to a
      // single RPC blip would be worse.
      failed += 1;
      logger.error(
        { component: "eval.predict", target: target.id, err: String(err) },
        "Target failed; skipped",
      );
    }
  }

  logger.info(
    {
      component: "eval.predict",
      audited,
      failed,
      rows: rowsWritten,
      out: cli.out,
    },
    "Predictions written",
  );
  if (audited === 0) {
    throw new Error("every target failed; wrote no predictions");
  }
}

// Only run when invoked directly, so the pure helpers above stay importable by
// the test without triggering a corpus run.
if (import.meta.url === `file://${process.argv[1]}`) {
  main()
    .catch((err) => {
      logger.error({ component: "eval.predict", err: String(err) }, "eval-predict failed");
      process.exitCode = 1;
    })
    .finally(() => closeNeo4j());
}
