import { describe, it, expect } from "vitest";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { InMemoryStore, MemorySaver } from "@langchain/langgraph";

import { CrystallineStore } from "../memory/crystalline-store.js";
import { CrystallineRetriever } from "../retrieval/crystalline-retriever.js";
import { HybridRetriever } from "../retrieval/hybrid-retriever.js";
import { buildAuditGraph } from "./build-graph.js";

/**
 * Fake chat model — routes on the phase keyword in the system prompt. Only the
 * `invoke` method is used by the nodes, so a partial object is sufficient.
 */
function makeFakeChat(): BaseChatModel {
  return {
    async invoke(messages: Array<{ content: unknown }>) {
      const sys = String(messages[0]?.content ?? "");
      if (sys.includes("INTAKE")) {
        return {
          content: JSON.stringify({
            target: "TargetProgram1111111111111111111111111111111",
            depth: "standard",
            concerns: ["overflow"],
            summary: "audit target program",
          }),
        };
      }
      if (sys.includes("ANALYZE")) {
        return {
          content: JSON.stringify({
            findings: [
              {
                vulnClass: "arithmetic-overflow",
                location: "ix:1",
                severity: "high",
                evidence: "unchecked add",
                remediation: "use checked_add",
                category: "integer-overflow-underflow",
              },
            ],
            checked: ["integer-overflow-underflow", "missing-signer-check"],
          }),
        };
      }
      if (sys.includes("REMEMBER")) {
        return {
          content: JSON.stringify([
            { level: 4, content: "arithmetic overflow in ix:1", tags: ["overflow"] },
          ]),
        };
      }
      if (sys.includes("REPORT")) {
        return { content: "## Executive Summary\nOne high-severity finding." };
      }
      return { content: "{}" };
    },
  } as unknown as BaseChatModel;
}

describe("audit graph (end to end)", () => {
  it("runs all phases and produces a report with merged findings", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const graph = buildAuditGraph({
      deps: { chat: makeFakeChat(), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });

    const result = await graph.invoke(
      // Source path that doesn't exist → static analyzer degrades to no findings;
      // no program address → on-chain analyzer contributes nothing. Only the
      // heuristic analyzer produces a finding, via the fake chat.
      { request: "audit source", sourcePath: "/does-not-exist-xyz" },
      { configurable: { thread_id: "test-e2e-1" } },
    );

    expect(result.report).toContain("Executive Summary");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.mergedFindings.length).toBeGreaterThanOrEqual(1);
    expect(result.mergedFindings[0]!.severity).toBe("high");
    expect(result.mergedFindings[0]!.source).toBe("heuristic");
    expect(result.mergedFindings[0]!.category).toBe("integer-overflow-underflow");
    expect(result.coverage.length).toBeGreaterThanOrEqual(1);
    expect(result.coverage).toContain("integer-overflow-underflow");
    expect(result.coverage).toContain("missing-signer-check");
    // CUA is opt-in and unconfigured in the test env: the 4th analyzer runs
    // as part of the fan-out but contributes nothing.
    expect(result.findings.some((f) => f.source === "cua")).toBe(false);
    // intake + heuristic + remember + report each count one LLM turn.
    expect(result.iterations).toBeGreaterThanOrEqual(4);
  });

  it("persists a crystal in the REMEMBER phase", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const graph = buildAuditGraph({
      deps: { chat: makeFakeChat(), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });

    await graph.invoke(
      { request: "audit source", sourcePath: "/does-not-exist-xyz" },
      { configurable: { thread_id: "test-e2e-2" } },
    );

    // The remembered fragment (level 4 = semantic) should now be recallable.
    const recalled = await crystalline.recall({ query: "overflow", tags: ["overflow"] });
    expect(recalled.length).toBeGreaterThanOrEqual(1);
  });
});
