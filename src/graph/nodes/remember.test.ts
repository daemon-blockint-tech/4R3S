import { describe, it, expect, vi } from "vitest";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { InMemoryStore } from "@langchain/langgraph";

import { CrystallineStore } from "../../memory/crystalline-store.js";
import type { KnowledgeWriter } from "../../persistence/knowledge-writer.js";
import type { AresState } from "../state.js";
import { makeRememberNode } from "./remember.js";

function fakeChat(payload: unknown): BaseChatModel {
  return {
    async invoke() {
      return { content: JSON.stringify(payload) };
    },
  } as unknown as BaseChatModel;
}

function baseState(over: Partial<AresState> = {}): AresState {
  return {
    request: "audit",
    programAddress: undefined,
    sourcePath: undefined,
    intake: {
      target: "Prog111",
      depth: "standard",
      concerns: [],
      summary: "audit target",
    },
    recalled: [],
    findings: [],
    mergedFindings: [],
    verifiedFindings: [
      {
        vulnClass: "pda-collision",
        location: "ix:init",
        severity: "high",
        evidence: "seed reuse",
        remediation: "add discriminator",
        source: "heuristic",
        category: "other",
        speculative: false,
        confidence: "high",
        status: "confirmed",
      },
    ],
    memoryWrites: [],
    report: "",
    iterations: 0,
    coverage: [],
    ...over,
  } as AresState;
}

describe("REMEMBER node", () => {
  it("persists remembered fragments to the durable knowledge writer", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const persist = vi.fn().mockResolvedValue({ docId: "d", chunkId: "c" });
    const knowledge: KnowledgeWriter = { enabled: true, persist };

    const node = makeRememberNode({
      chat: fakeChat([{ level: 4, content: "pda collision pattern", tags: ["pda"] }]),
      crystalline,
      retriever: undefined as never,
      knowledge,
    });

    const update = await node(baseState());
    expect(update.memoryWrites).toHaveLength(1);
    expect(persist).toHaveBeenCalledTimes(1);
    expect(persist.mock.calls[0]![0]).toMatchObject({
      content: "pda collision pattern",
      level: "semantic",
      tags: ["pda"],
      metadata: { target: "Prog111", source: "remember" },
    });
  });

  it("does not call the writer when it is disabled", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const persist = vi.fn();
    const knowledge: KnowledgeWriter = { enabled: false, persist };

    const node = makeRememberNode({
      chat: fakeChat([{ level: 4, content: "x", tags: [] }]),
      crystalline,
      retriever: undefined as never,
      knowledge,
    });

    await node(baseState());
    expect(persist).not.toHaveBeenCalled();
  });

  it("continues the audit when the writer throws", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const knowledge: KnowledgeWriter = {
      enabled: true,
      persist: vi.fn().mockRejectedValue(new Error("kb down")),
    };

    const node = makeRememberNode({
      chat: fakeChat([{ level: 4, content: "y", tags: [] }]),
      crystalline,
      retriever: undefined as never,
      knowledge,
    });

    // Writeback failure is swallowed; the node still returns its writes.
    const update = await node(baseState());
    expect(update.memoryWrites).toHaveLength(1);
  });

  it("no-ops with no verified findings", async () => {
    const store = new InMemoryStore();
    const crystalline = new CrystallineStore(store);
    const persist = vi.fn();
    const node = makeRememberNode({
      chat: fakeChat([]),
      crystalline,
      retriever: undefined as never,
      knowledge: { enabled: true, persist },
    });

    const update = await node(baseState({ verifiedFindings: [] }));
    expect(update.memoryWrites).toEqual([]);
    expect(persist).not.toHaveBeenCalled();
  });
});
