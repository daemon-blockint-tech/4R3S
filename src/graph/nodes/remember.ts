/**
 * REMEMBER node — decide which findings are worth persisting and write them
 * into Crystalline memory (embedding the content when an embedder is
 * configured). Runs a light consolidation pass afterward so promotions/merges
 * happen incrementally.
 */
import { rememberSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { LEVEL_ORDER, type KnowledgeLevel } from "../../memory/types.js";
import { embed } from "../../retrieval/embeddings.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, MemoryWrite } from "../state.js";
import { chatJson } from "../util.js";

interface RawWrite {
  level?: number | string;
  content?: string;
  body?: string;
  tags?: string[];
}

/** Normalize a numeric (1–5) or named level onto a KnowledgeLevel. */
function toLevel(level: number | string | undefined): KnowledgeLevel {
  if (typeof level === "number" && level >= 1 && level <= 5) {
    return LEVEL_ORDER[level - 1]!;
  }
  if (typeof level === "string" && LEVEL_ORDER.includes(level as KnowledgeLevel)) {
    return level as KnowledgeLevel;
  }
  return "episodic";
}

export function makeRememberNode(deps: GraphDeps) {
  return async function remember(state: AresState): Promise<AresStateUpdate> {
    const findings = state.verifiedFindings;
    if (findings.length === 0) {
      return { memoryWrites: [], iterations: 0 };
    }

    const human = [
      state.intake ? `Target: ${state.intake.target}` : "",
      "Findings:",
      findings
        .map((f) => `- [${f.severity}] ${f.vulnClass} @ ${f.location}: ${f.evidence}`)
        .join("\n"),
      "",
      "Return a JSON array of memory fragments worth persisting for future audits.",
      "Each: { level (1-5), content (short), tags (string[]) }.",
    ]
      .filter(Boolean)
      .join("\n");

    const raw = await chatJson<RawWrite[]>(
      deps.chat,
      rememberSystemPrompt(),
      human,
      [],
    );

    const memoryWrites: MemoryWrite[] = [];
    for (const w of Array.isArray(raw) ? raw : []) {
      const content = String(w.content ?? w.body ?? "").trim();
      if (!content) continue;
      const level = toLevel(w.level);
      const tags = Array.isArray(w.tags) ? w.tags.map(String) : [];
      memoryWrites.push({ level, content, tags });

      const embedding = await embed(content);
      const metadata = { target: state.intake?.target, source: "remember" };
      await deps.crystalline.crystallize(level, content, {
        embedding,
        tags,
        metadata,
      });

      // Also persist durably to the hybrid KB (Supabase/Neo4j) when wired, so
      // this knowledge survives the process and is recallable in future audits.
      // Best-effort: the writer never throws, but guard anyway so a KB hiccup
      // can't abort the audit.
      if (deps.knowledge?.enabled) {
        try {
          await deps.knowledge.persist({ content, level, tags, embedding, metadata });
        } catch (err) {
          logger.warn(
            { component: "node.remember", err: String(err) },
            "Durable knowledge writeback failed (non-fatal)",
          );
        }
      }
    }

    // Incremental consolidation (decay/prune/promote/merge).
    try {
      await deps.crystalline.consolidate();
    } catch (err) {
      logger.warn(
        { component: "node.remember", err: String(err) },
        "Consolidation pass failed (non-fatal)",
      );
    }

    logger.info(
      {
        component: "node.remember",
        written: memoryWrites.length,
        durable: Boolean(deps.knowledge?.enabled),
      },
      "Memory write complete",
    );
    return { memoryWrites, iterations: 1 };
  };
}
