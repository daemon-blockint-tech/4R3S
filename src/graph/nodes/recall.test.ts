import { describe, it, expect } from "vitest";
import { InMemoryStore } from "@langchain/langgraph";

import { CrystallineStore } from "../../memory/crystalline-store.js";
import { CrystallineRetriever } from "../../retrieval/crystalline-retriever.js";
import { HybridRetriever } from "../../retrieval/hybrid-retriever.js";
import { synthCrystal } from "../../retrieval/util.js";
import type { ScoredCrystal } from "../../memory/types.js";
import type { HybridQuery, Retriever } from "../../retrieval/types.js";
import { makeRecallNode } from "./recall.js";
import type { AresState } from "../state.js";

function stateFor(request: string): AresState {
  return { request, recalled: [] } as any;
}

function nodeOver(crystalline: CrystallineStore, extra?: Retriever) {
  const retriever = extra
    ? // Wrap so the recall node also sees fragments that are not store-native.
      ({
        name: "test",
        async retrieve(q: HybridQuery) {
          const [a, b] = await Promise.all([
            new HybridRetriever(new CrystallineRetriever(crystalline)).retrieve(q),
            extra.retrieve(q),
          ]);
          return [...a, ...b];
        },
      } as any)
    : new HybridRetriever(new CrystallineRetriever(crystalline));
  return makeRecallNode({ chat: {} as any, crystalline, retriever });
}

describe("RECALL activation", () => {
  it("increments access count on the fragments it recalls", async () => {
    const crystalline = new CrystallineStore(new InMemoryStore());
    const c = await crystalline.crystallize("episodic", "overflow in ix:1", {
      tags: ["overflow"],
    });
    expect(c.accessCount).toBe(0);
    // Snapshot the number: InMemoryStore hands back live references, so `c`
    // itself is mutated when the crystal is activated.
    const activationBefore = c.activation;

    const recall = nodeOver(crystalline);
    const out = await recall(stateFor("what about overflow bugs"));
    expect(out.recalled?.length).toBeGreaterThanOrEqual(1);

    const after = await crystalline.load(c.id, "episodic");
    expect(after?.accessCount).toBe(1);
    // Activation is boosted, not merely preserved.
    expect(after!.activation).toBeGreaterThan(activationBefore);
  });

  it("makes episodic→semantic promotion reachable, which it was not before", async () => {
    const crystalline = new CrystallineStore(new InMemoryStore());
    const c = await crystalline.crystallize("episodic", "overflow in ix:1", {
      tags: ["overflow"],
    });
    const recall = nodeOver(crystalline);

    // semanticPromotionAccess is 3: three recalls should qualify the crystal.
    for (let i = 0; i < 3; i++) {
      await recall(stateFor("what about overflow bugs"));
    }
    expect((await crystalline.load(c.id, "episodic"))?.accessCount).toBe(3);

    const report = await crystalline.consolidate();
    expect(report.promoted).toEqual([
      { crystalId: c.id, from: "episodic", to: "semantic" },
    ]);
    expect(await crystalline.load(c.id, "episodic")).toBeUndefined();
    expect((await crystalline.load(c.id, "semantic"))?.content).toBe("overflow in ix:1");
  });

  it("does not try to activate fragments synthesized from Supabase/Neo4j", async () => {
    const crystalline = new CrystallineStore(new InMemoryStore());
    // A knowledge-base chunk has no crystal in the store; activating it would be
    // a pointless write, and must not throw.
    const kb: Retriever = {
      name: "kb",
      async retrieve(): Promise<ScoredCrystal[]> {
        return [
          {
            crystal: synthCrystal({
              id: "chunk-1",
              content: "kb chunk about overflow",
              metadata: { source: "supabase" },
            }),
            score: 1,
          },
        ];
      },
    };

    const recall = nodeOver(crystalline, kb);
    const out = await recall(stateFor("overflow"));

    expect(out.recalled?.some((s) => s.crystal.id === "chunk-1")).toBe(true);
    // Nothing was written to the semantic namespace on their behalf.
    expect(await crystalline.load("chunk-1", "semantic")).toBeUndefined();
  });
});
