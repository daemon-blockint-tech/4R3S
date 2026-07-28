import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { InMemoryStore, MemorySaver } from "@langchain/langgraph";

/**
 * Stub Semgrep to "not installed" — the CI condition.
 *
 * Now that LOAD-SOURCE lets a test point at a real source tree, `analyzeStatic`
 * would otherwise spawn a real `semgrep` on any developer machine that has one
 * and fetch its ruleset over the network, so the suite's hermeticity would
 * depend on who is running it. These tests are about graph wiring, not Semgrep;
 * `src/tools/semgrep.test.ts` covers the scanner itself.
 */
vi.mock("../tools/semgrep.js", () => ({
  runSemgrep: async (sourcePath?: string) => {
    if (!sourcePath) {
      return {
        available: false,
        findings: [],
        note: "no source path provided",
        reason: "no-source" as const,
      };
    }
    if (!existsSync(sourcePath)) {
      return {
        available: false,
        findings: [],
        note: `source path not found: ${sourcePath}`,
        reason: "path-missing" as const,
      };
    }
    return {
      available: false,
      findings: [],
      note: "semgrep not installed",
      reason: "not-installed" as const,
    };
  },
}));

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
                speculative: false,
                confidence: "high",
              },
            ],
            checked: ["integer-overflow-underflow", "missing-signer-check"],
          }),
        };
      }
      if (sys.includes("VERIFY")) {
        return {
          content: JSON.stringify({
            verdicts: [
              {
                index: 0,
                status: "confirmed",
                confidence: "high",
                reason: "unchecked add is concretely evidenced",
              },
            ],
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

/**
 * Fake chat whose ANALYZE output is tagged with a caller-controlled label, so a
 * test can tell which run produced which finding and which coverage entry.
 * `failing.verify` makes the VERIFY phase throw, simulating an interrupted run.
 */
function makeTaggedChat(
  tag: { location: string; checked: string },
  failing: { verify: boolean } = { verify: false },
): BaseChatModel {
  return {
    async invoke(messages: Array<{ content: unknown }>) {
      const sys = String(messages[0]?.content ?? "");
      if (sys.includes("INTAKE")) {
        return {
          content: JSON.stringify({
            target: tag.location,
            depth: "standard",
            concerns: [],
            summary: `audit ${tag.location}`,
          }),
        };
      }
      if (sys.includes("ANALYZE")) {
        return {
          content: JSON.stringify({
            findings: [
              {
                vulnClass: "arithmetic-overflow",
                location: tag.location,
                severity: "high",
                evidence: "unchecked add",
                remediation: "use checked_add",
                category: tag.checked,
                speculative: false,
                confidence: "high",
              },
            ],
            checked: [tag.checked],
          }),
        };
      }
      if (sys.includes("VERIFY")) {
        if (failing.verify) throw new Error("simulated interruption");
        return { content: JSON.stringify({ verdicts: [] }) };
      }
      if (sys.includes("REMEMBER")) return { content: "[]" };
      if (sys.includes("REPORT")) return { content: "## Executive Summary" };
      return { content: "{}" };
    },
  } as unknown as BaseChatModel;
}

describe("audit graph (state isolation across runs)", () => {
  it("does not carry a previous audit's findings into the next run on the same thread", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    // A single mutable tag drives the fake, so both runs share one graph — and
    // therefore one checkpointed thread, exactly as repeated CLI runs do.
    const tag = { location: "ix:run-a", checked: "integer-overflow-underflow" };
    const graph = buildAuditGraph({
      deps: { chat: makeTaggedChat(tag), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });
    // The default thread id is a single constant for every CLI run.
    const config = { configurable: { thread_id: "ares-default" } };

    const first = await graph.invoke({ request: "audit A" }, config);
    expect(first.findings).toHaveLength(1);
    expect(first.coverage).toEqual(["integer-overflow-underflow"]);

    tag.location = "ix:run-b";
    tag.checked = "missing-signer-check";
    const second = await graph.invoke({ request: "audit B" }, config);

    // The second audit must see only its own findings — not run A's appended
    // by the concat reducer on top of the restored checkpoint.
    expect(second.findings).toHaveLength(1);
    expect(second.findings.map((f) => f.location)).toEqual(["ix:run-b"]);
    expect(second.mergedFindings.map((f) => f.location)).toEqual(["ix:run-b"]);
    expect(second.verifiedFindings.map((f) => f.location)).toEqual(["ix:run-b"]);

    // Same for the union-reduced coverage channel: run A's class must not be
    // reported as evaluated by run B.
    expect(second.coverage).toEqual(["missing-signer-check"]);

    // And the summed iteration counter restarts rather than doubling.
    expect(second.iterations).toBe(first.iterations);
  });

  it("keeps the partial findings of an interrupted run when it is resumed", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const tag = { location: "ix:partial", checked: "integer-overflow-underflow" };
    // VERIFY throws on the first attempt, interrupting the run after the
    // analyzers have already written their findings.
    const failing = { verify: true };
    const chat = makeTaggedChat(tag, failing);
    const graph = buildAuditGraph({
      deps: { chat, crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });
    const config = { configurable: { thread_id: "ares-default" } };

    await expect(graph.invoke({ request: "audit A" }, config)).rejects.toThrow(
      "simulated interruption",
    );

    // The run is parked at the failed node with its findings checkpointed.
    const parked = await graph.getState(config);
    expect(parked.next).toEqual(["verifyPhase"]);
    expect(parked.values.findings).toHaveLength(1);

    failing.verify = false;
    const resumed = await graph.invoke(null, config);

    // Resuming picks up at the pending task, so the reset node — already
    // completed — must not re-run and wipe the work done before the failure.
    expect(resumed.findings.map((f) => f.location)).toEqual(["ix:partial"]);
    expect(resumed.coverage).toEqual(["integer-overflow-underflow"]);
    expect(resumed.report).toContain("Executive Summary");
  });
});

describe("source loading (GOLDEN RULE 5)", () => {
  it("puts the program's actual source in front of the analyzers, and keeps findings first-class", async () => {
    // The counterpart to the bogus-path case below. With real code on disk,
    // LOAD-SOURCE reads it, the heuristic analyzer receives it, and its
    // findings keep the severity the model assigned instead of being demoted.
    const dir = mkdtempSync(join(tmpdir(), "ares-e2e-src-"));
    writeFileSync(
      join(dir, "lib.rs"),
      "pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }",
    );
    try {
      const store = new InMemoryStore();
      const crystalline = new CrystallineStore(store);
      const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
      const graph = buildAuditGraph({
        deps: { chat: makeFakeChat(), crystalline, retriever },
        checkpointer: new MemorySaver(),
        store,
      });

      const result = await graph.invoke(
        { request: "audit source", sourcePath: dir },
        { configurable: { thread_id: "test-e2e-src" } },
      );

      // Source genuinely reached state — this is the rule the auditor exists to
      // satisfy, and nothing in the pipeline used to do it.
      expect(result.sourceFiles.length).toBeGreaterThanOrEqual(1);
      expect(result.sourceFiles[0]!.path).toBe("lib.rs");
      expect(result.sourceFiles[0]!.content).toContain("withdraw");

      // Real source read → no black-box demotion.
      expect(result.mergedFindings[0]!.severity).toBe("high");
      expect(result.mergedFindings[0]!.speculative).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

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
      // Source path that doesn't exist → LOAD-SOURCE reads zero bytes and the
      // static analyzer fails; no program address → on-chain contributes
      // nothing. Only the heuristic analyzer produces a finding, via the fake
      // chat — and because no code was actually read, that finding must be
      // presented as speculation.
      { request: "audit source", sourcePath: "/does-not-exist-xyz" },
      { configurable: { thread_id: "test-e2e-1" } },
    );

    expect(result.report).toContain("Executive Summary");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.mergedFindings.length).toBeGreaterThanOrEqual(1);
    expect(result.mergedFindings[0]!.source).toBe("heuristic");
    expect(result.mergedFindings[0]!.category).toBe("integer-overflow-underflow");

    // No source was loaded, so the heuristic finding is speculative regardless
    // of the severity the model claimed. This previously asserted "high": a
    // path string that pointed at nothing was treated as proof the code had
    // been read, so passing a bogus --source produced a *more* confident report
    // than omitting the flag entirely.
    expect(result.sourceFiles).toEqual([]);
    expect(result.mergedFindings[0]!.severity).toBe("info");
    expect(result.mergedFindings[0]!.speculative).toBe(true);

    expect(result.coverage.length).toBeGreaterThanOrEqual(1);
    expect(result.coverage).toContain("integer-overflow-underflow");
    expect(result.coverage).toContain("missing-signer-check");
    // VERIFY critic pass ran and the finding survived — but `confirmed` is
    // refused for a heuristic finding, whose "evidence" the same model wrote a
    // superstep earlier and which the critic has no artifact to check against.
    expect(result.verifiedFindings.length).toBeGreaterThanOrEqual(1);
    expect(result.verifiedFindings[0]!.status).toBe("suspected");
    // CUA is opt-in and unconfigured in the test env: the 4th analyzer runs
    // as part of the fan-out but contributes nothing.
    expect(result.findings.some((f) => f.source === "cua")).toBe(false);
    // intake + heuristic + verify + remember + report each count one LLM turn.
    expect(result.iterations).toBeGreaterThanOrEqual(5);
  });

  it("marks the report as incomplete when an analyzer could not run", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const graph = buildAuditGraph({
      deps: { chat: makeFakeChat(), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });

    // Same degraded run as above: the source path does not exist, so static
    // analysis cannot run. Before analyzer status was propagated, this produced
    // a report indistinguishable from a clean one.
    const result = await graph.invoke(
      { request: "audit source", sourcePath: "/does-not-exist-xyz" },
      { configurable: { thread_id: "test-e2e-3" } },
    );

    const byAnalyzer = Object.fromEntries(
      result.analyzers.map((a) => [a.analyzer, a.outcome]),
    );
    expect(byAnalyzer).toEqual({
      onchain: "skipped", // no program address
      static: "failed", // source path missing
      heuristic: "ok",
      cua: "skipped", // opt-in, unconfigured in tests
    });

    // The warning is prepended in code, so it is present regardless of what the
    // model wrote — the fake report body contains no such wording.
    expect(result.report.startsWith("> **Incomplete assessment")).toBe(true);
    expect(result.report).toContain("static failed");
    expect(result.report).toContain("not evidence that none exist");
  });

  it("records which knowledge sources answered, without calling absence a failure", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const graph = buildAuditGraph({
      deps: { chat: makeFakeChat(), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });

    const result = await graph.invoke(
      { request: "audit source", sourcePath: "/does-not-exist-xyz" },
      { configurable: { thread_id: "test-e2e-4" } },
    );

    // Supabase and Neo4j are unconfigured in the test env: that is the
    // documented default mode, so it must read as skipped rather than failed.
    expect(
      Object.fromEntries(result.retrieval.map((r) => [r.source, r.outcome])),
    ).toEqual({ crystalline: "ok", supabase: "skipped", neo4j: "skipped" });

    // The banner fires for the failed static analyzer, but must not accuse the
    // knowledge base of anything.
    expect(result.report).not.toContain("Knowledge sources unavailable");
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
