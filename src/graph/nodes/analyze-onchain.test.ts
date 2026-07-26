import { describe, it, expect, vi, beforeEach } from "vitest";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import type { ProgramInfo } from "../../tools/solana.js";

// The node imports loadProgram directly, so the RPC boundary is mocked here.
const loadProgram = vi.hoisted(() => vi.fn<(a: string) => Promise<ProgramInfo>>());
vi.mock("../../tools/solana.js", () => ({ loadProgram }));

const { makeAnalyzeOnchainNode } = await import("./analyze-onchain.js");
const { CrystallineStore } = await import("../../memory/crystalline-store.js");
const { CrystallineRetriever } = await import("../../retrieval/crystalline-retriever.js");
const { HybridRetriever } = await import("../../retrieval/hybrid-retriever.js");
const { InMemoryStore } = await import("@langchain/langgraph");

function chatReturning(content: string): BaseChatModel {
  return { async invoke() { return { content }; } } as unknown as BaseChatModel;
}

function deps(chat: BaseChatModel) {
  const store = new InMemoryStore();
  const crystalline = new CrystallineStore(store);
  return {
    chat,
    crystalline,
    retriever: new HybridRetriever(new CrystallineRetriever(crystalline)),
  };
}

const state = {
  request: "audit",
  programAddress: "Prog1111111111111111111111111111111111111111",
  findings: [],
  analyzers: [],
  coverage: [],
  recalled: [],
  mergedFindings: [],
  verifiedFindings: [],
  memoryWrites: [],
  report: "",
  iterations: 0,
  intake: undefined,
  sourcePath: undefined,
} as any;

describe("analyzeOnchain outcome reporting", () => {
  beforeEach(() => loadProgram.mockReset());

  it("reports skipped when there is no program address", async () => {
    const node = makeAnalyzeOnchainNode(deps(chatReturning("{}")));
    const out = await node({ ...state, programAddress: undefined });
    expect(out.analyzers).toEqual([
      { analyzer: "onchain", outcome: "skipped", detail: "no program address supplied" },
    ]);
    expect(loadProgram).not.toHaveBeenCalled();
  });

  it("reports failed — not clean — when the RPC read errors", async () => {
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: false,
      executable: false,
      error: "Error: fetch failed",
    });
    const node = makeAnalyzeOnchainNode(deps(chatReturning("{}")));
    const out = await node(state);

    expect(out.findings).toEqual([]);
    // This is the case the fix exists for: zero findings, but the chain was
    // never read, so the outcome must not be an "ok" that reads as clean.
    const report = (out.analyzers as Array<{ outcome: string; detail?: string }>)[0]!;
    expect(report.outcome).toBe("failed");
    expect(report.detail).toContain("fetch failed");
  });

  it("distinguishes a genuinely absent program from an RPC failure", async () => {
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: false,
      executable: false,
    });
    const node = makeAnalyzeOnchainNode(deps(chatReturning("{}")));
    const out = await node(state);

    const report = (out.analyzers as Array<{ outcome: string; detail?: string }>)[0]!;
    expect(report.outcome).toBe("degraded");
    expect(report.detail).toContain("not found on chain");
  });

  it("reports ok when the program is read and the response parses", async () => {
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: true,
      executable: true,
      owner: "BPFLoaderUpgradeab1e11111111111111111111111",
      loader: "upgradeable",
      dataLen: 36,
    });
    const node = makeAnalyzeOnchainNode(
      deps(chatReturning(JSON.stringify({ findings: [], checked: ["missing-signer-check"] }))),
    );
    const out = await node(state);

    expect(out.analyzers).toEqual([{ analyzer: "onchain", outcome: "ok", detail: undefined }]);
    expect(out.coverage).toEqual(["missing-signer-check"]);
  });

  it("reports degraded when the model response does not parse", async () => {
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: true,
      executable: true,
      dataLen: 36,
    });
    const node = makeAnalyzeOnchainNode(deps(chatReturning("not json at all")));
    const out = await node(state);

    const report = (out.analyzers as Array<{ outcome: string; detail?: string }>)[0]!;
    expect(report.outcome).toBe("degraded");
    expect(report.detail).toContain("not valid JSON");
  });
});
