/**
 * KR-1 evidence: which parts of the cognitive envelope actually fire.
 *
 * These are characterization tests. They pass against the code as it stands and
 * exist to make the gaps re-derivable rather than asserted — the same standard
 * eval/ applies to accuracy numbers. Each one pins a mechanism that is either
 * unreachable in the shipped configuration or narrower than its documentation.
 *
 * Run: npx vitest run src/memory/crystalline-inertness.test.ts
 */
import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryStore } from "@langchain/langgraph";

import { CrystallineStore } from "./crystalline-store.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("spreading activation", () => {
  let store: CrystallineStore;

  beforeEach(async () => {
    store = new CrystallineStore(new InMemoryStore());
    await store.start();
  });

  it("contributes nothing when crystals carry no links", async () => {
    // remember.ts calls crystallize() without `links`, and no caller anywhere in
    // src/ invokes link(). Every crystal written in a real run therefore has
    // links: [], which is the shape reproduced here.
    await store.crystallize("semantic", "signer checks", { tags: ["signer"] });
    await store.crystallize("semantic", "owner checks", { tags: ["owner"] });

    const off = await store.recall({ query: "signer", tags: ["signer", "owner"], spreadDepth: 0 });
    const on = await store.recall({ query: "signer", tags: ["signer", "owner"], spreadDepth: 1 });

    expect(on.map((h) => h.score)).toEqual(off.map((h) => h.score));
  });

  it("ignores spreadDepth beyond on/off, even with links present", async () => {
    // recall() reads spreadDepth only as `spreadDepth > 0`; it is never used as
    // a hop count, so depth 1 and depth 5 are the same traversal.
    const hub = await store.crystallize("semantic", "signer checks", { tags: ["signer"] });
    const mid = await store.crystallize("semantic", "owner checks", { tags: ["owner"] });
    const far = await store.crystallize("semantic", "bump checks", { tags: ["bump"] });
    await store.link(hub.id, "semantic", mid.id, 1, "related");
    await store.link(mid.id, "semantic", far.id, 1, "related");

    const q = { query: "signer", tags: ["signer", "owner", "bump"] };
    const depth1 = await store.recall({ ...q, spreadDepth: 1 });
    const depth5 = await store.recall({ ...q, spreadDepth: 5 });

    expect(depth5.map((h) => h.score)).toEqual(depth1.map((h) => h.score));
  });
});

describe("consolidation", () => {
  it("cannot merge crystals that have no embedding", async () => {
    // findMerges() skips any crystal without an embedding. Runs configured
    // Crystalline-only (no embeddings provider) therefore never merge, however
    // duplicated the content is.
    const store = new CrystallineStore(new InMemoryStore());
    await store.start();
    await store.crystallize("semantic", "missing owner check");
    await store.crystallize("semantic", "missing owner check");

    const report = await store.consolidate();
    expect(report.merged).toEqual([]);
  });

  it("merges the same pair once embeddings are present", async () => {
    // Contrast to the above: the mechanism is correct, its input is absent.
    const store = new CrystallineStore(new InMemoryStore());
    await store.start();
    await store.crystallize("semantic", "missing owner check", { embedding: [1, 0, 0] });
    await store.crystallize("semantic", "missing owner check", { embedding: [1, 0, 0] });

    const report = await store.consolidate();
    expect(report.merged).toHaveLength(1);
  });

  it("prunes decayed working memory but leaves decayed episodic memory in place", async () => {
    // Pruning is gated on level, not on activation: consolidate() returns early
    // for sensory/working and never revisits decay for episodic/semantic. An
    // episodic crystal at effectively zero activation survives indefinitely,
    // and remember.ts defaults writes to episodic.
    const store = new CrystallineStore(new InMemoryStore(), { activationHalfLifeMs: 1 });
    await store.start();
    const ephemeral = await store.crystallize("working", "transient note");
    const durable = await store.crystallize("episodic", "transient note");
    await sleep(50); // ≫ 1ms half-life: activation is far below pruneThreshold

    const report = await store.consolidate();

    expect(report.pruned).toContain(ephemeral.id);
    expect(report.pruned).not.toContain(durable.id);
    expect(await store.load(durable.id, "episodic")).toBeDefined();
  });
});
