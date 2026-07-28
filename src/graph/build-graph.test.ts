import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
                // Cites a real file: the grounded-source tests write `lib.rs`,
                // and `citesLoadedFile` demotes any finding pointing at a file
                // that was never loaded. In the black-box tests nothing is
                // loaded, so this is demoted regardless of what it names.
                vulnClass: "arithmetic-overflow",
                location: "lib.rs:2",
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
    // The path does not exist, so no source reached the model: whatever severity
    // it claimed, the finding is a hypothesis about code nobody read. It must be
    // demoted. A supplied-but-unreadable path used to skip this demotion, because
    // the check keyed off `sourcePath` being set rather than source being read.
    expect(result.source?.available).toBe(false);
    expect(result.mergedFindings[0]!.severity).toBe("info");
    expect(result.mergedFindings[0]!.speculative).toBe(true);
    expect(result.mergedFindings[0]!.source).toBe("heuristic");
    expect(result.mergedFindings[0]!.category).toBe("integer-overflow-underflow");
    expect(result.coverage.length).toBeGreaterThanOrEqual(1);
    expect(result.coverage).toContain("integer-overflow-underflow");
    expect(result.coverage).toContain("missing-signer-check");
    // VERIFY critic pass ran: the finding survived, and its status/confidence
    // are set from the verdict.
    expect(result.verifiedFindings.length).toBeGreaterThanOrEqual(1);
    expect(result.verifiedFindings[0]!.status).toBe("confirmed");
    expect(result.verifiedFindings[0]!.confidence).toBe("high");
    // CUA is opt-in and unconfigured in the test env: the 4th analyzer runs
    // as part of the fan-out but contributes nothing.
    expect(result.findings.some((f) => f.source === "cua")).toBe(false);
    // intake + heuristic + verify + report each count one LLM turn. REMEMBER
    // makes no call here: this run has no readable source, so its only finding
    // is speculative and nothing is eligible for durable memory.
    expect(result.iterations).toBeGreaterThanOrEqual(4);
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

  it("persists a crystal in the REMEMBER phase when the finding is grounded", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const graph = buildAuditGraph({
      deps: { chat: makeFakeChat(), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });

    // Real source on disk, so the finding is grounded rather than speculative.
    // REMEMBER only persists confirmed, non-speculative findings, so a
    // black-box run (the previous form of this test) legitimately writes
    // nothing — durable memory is replayed into later audits and must not be
    // seeded from findings nobody confirmed.
    const dir = mkdtempSync(join(tmpdir(), "ares-e2e-src-"));
    try {
      writeFileSync(
        join(dir, "lib.rs"),
        "pub fn deposit(a: u128) {\n    let b = a as u64;\n}\n",
      );

      await graph.invoke(
        { request: "audit source", sourcePath: dir },
        { configurable: { thread_id: "test-e2e-2" } },
      );

      // The remembered fragment (level 4 = semantic) should now be recallable.
      const recalled = await crystalline.recall({ query: "overflow", tags: ["overflow"] });
      expect(recalled.length).toBeGreaterThanOrEqual(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("withholds unconfirmed findings from durable memory", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const retriever = new HybridRetriever(new CrystallineRetriever(crystalline));
    const graph = buildAuditGraph({
      deps: { chat: makeFakeChat(), crystalline, retriever },
      checkpointer: new MemorySaver(),
      store,
    });

    // No readable source → the finding is demoted to speculative, so however
    // the critic labelled it, nothing may enter memory that future audits recall.
    const result = await graph.invoke(
      { request: "audit source", sourcePath: "/does-not-exist-xyz" },
      { configurable: { thread_id: "test-e2e-5" } },
    );

    expect(result.verifiedFindings.length).toBeGreaterThanOrEqual(1);
    expect(result.memoryWrites).toEqual([]);
    const recalled = await crystalline.recall({ query: "overflow", tags: ["overflow"] });
    expect(recalled).toEqual([]);
  });
});
