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

  it("reports degraded when the upgrade authority could not be read", async () => {
    // The gap this closes: `loadProgram` sets no `error` and `exists` stays
    // true when the ProgramData read times out, so every existing guard passes
    // and `authorityFindings` returns [] — byte-identical to a program whose
    // authority is genuinely renounced. Reporting `ok` there publishes a live
    // hot upgrade key as a clean on-chain review, in a report that tells the
    // reader on-chain silence is evidence.
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: true,
      executable: true,
      owner: "BPFLoaderUpgradeab1e11111111111111111111111",
      loader: "upgradeable",
      dataLen: 36,
      upgradeAuthorityUnresolved: "AbortError: The operation was aborted",
    });
    const node = makeAnalyzeOnchainNode(
      deps(chatReturning(JSON.stringify({ findings: [], checked: [] }))),
    );
    const out = await node(state);

    const report = (out.analyzers as Array<{ outcome: string; detail?: string }>)[0]!;
    expect(report.outcome).toBe("degraded");
    expect(report.detail).toContain("upgrade authority could not be read");
    expect(report.detail).toContain("not evidence there is none");
  });

  it("an unresolved authority outranks a parseable model response", async () => {
    // Ordering matters: the model parsing fine says nothing about whether the
    // chain was read. A clean parse must not restore `ok`.
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: true,
      executable: true,
      loader: "upgradeable",
      dataLen: 36,
      upgradeAuthorityUnresolved: "ProgramData account returned no data",
    });
    const node = makeAnalyzeOnchainNode(
      deps(chatReturning(JSON.stringify({ findings: [], checked: ["missing-signer-check"] }))),
    );
    const out = await node(state);

    expect((out.analyzers as Array<{ outcome: string }>)[0]!.outcome).toBe("degraded");
  });

  it("a renounced authority is still ok — resolved, and genuinely none", async () => {
    // The other side: `degraded` must not fire for a program that was read
    // successfully and simply has no upgrade authority, or the banner would
    // print on every immutable program forever and stop meaning anything.
    loadProgram.mockResolvedValue({
      address: state.programAddress,
      exists: true,
      executable: true,
      loader: "upgradeable",
      dataLen: 36,
      upgradeAuthority: null,
      upgradeAuthorityKind: "renounced",
    });
    const node = makeAnalyzeOnchainNode(
      deps(chatReturning(JSON.stringify({ findings: [], checked: [] }))),
    );
    const out = await node(state);

    expect((out.analyzers as Array<{ outcome: string }>)[0]!.outcome).toBe("ok");
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

describe("deterministic authority posture", () => {
  const base: ProgramInfo = {
    address: state.programAddress!,
    exists: true,
    executable: true,
    owner: "BPFLoaderUpgradeab1e11111111111111111111111",
    loader: "upgradeable",
    dataLen: 36,
    programDataAddress: "PData111111111111111111111111111111111111111",
  };

  it("flags a single-key upgrade authority as a confirmable, non-speculative finding", async () => {
    loadProgram.mockResolvedValue({
      ...base,
      upgradeAuthority: "Auth11111111111111111111111111111111111111111",
      upgradeAuthorityKind: "single-key",
    });
    const out = await makeAnalyzeOnchainNode(
      deps(chatReturning('{"findings":[],"checked":[]}')),
    )(state);

    const f = out.findings!.find((x) => x.deterministic);
    expect(f).toBeDefined();
    expect(f!.category).toBe("upgrade-authority-risk");
    expect(f!.speculative).toBe(false);
    expect(f!.source).toBe("onchain");
    // The catalog's distinction is single-key vs multisig/renounced, so the
    // evidence has to name which one was observed.
    expect(f!.evidence).toMatch(/System Program/);
    expect(out.coverage).toContain("upgrade-authority-risk");
  });

  it("reports a renounced authority as no finding at all", async () => {
    loadProgram.mockResolvedValue({
      ...base,
      upgradeAuthority: null,
      upgradeAuthorityKind: "renounced",
    });
    const out = await makeAnalyzeOnchainNode(
      deps(chatReturning('{"findings":[],"checked":[]}')),
    )(state);
    // Immutable is the safe state; flagging it is the noise that made the
    // previous ruleset unusable.
    expect(out.findings!.filter((f) => f.deterministic)).toEqual([]);
  });

  it("does not claim a program-controlled authority is a multisig", async () => {
    loadProgram.mockResolvedValue({
      ...base,
      upgradeAuthority: "Auth11111111111111111111111111111111111111111",
      upgradeAuthorityKind: "program-controlled",
      upgradeAuthorityOwner: "Squads11111111111111111111111111111111111111",
    });
    const out = await makeAnalyzeOnchainNode(
      deps(chatReturning('{"findings":[],"checked":[]}')),
    )(state);

    const f = out.findings!.find((x) => x.deterministic)!;
    expect(f.severity).toBe("info");
    expect(f.evidence).not.toMatch(/multisig/i);
    expect(f.evidence).toMatch(/not checked here/i);
  });

  it("survives an unparseable model response", async () => {
    loadProgram.mockResolvedValue({
      ...base,
      upgradeAuthority: "Auth11111111111111111111111111111111111111111",
      upgradeAuthorityKind: "single-key",
    });
    const out = await makeAnalyzeOnchainNode(deps(chatReturning("not json")))(state);
    // The one class this analyzer settles without a model must not depend on one.
    expect(out.findings!.filter((f) => f.deterministic)).toHaveLength(1);
    expect(out.analyzers?.[0]?.outcome).toBe("degraded");
  });
});
