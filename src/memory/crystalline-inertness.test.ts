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

describe("tag scoring", () => {
  let store: CrystallineStore;

  beforeEach(async () => {
    store = new CrystallineStore(new InMemoryStore());
    await store.start();
  });

  it("gives a crystal whose tags are all blank no signal, not maximum signal", async () => {
    // `"anything".includes("")` is true in JS, so an empty-string tag used to
    // score a perfect 1.0 against any query and surface an unrelated crystal at
    // the top of every recall. remember.ts stores tags the model produced, so a
    // blank entry is reachable input.
    await store.crystallize("semantic", "completely unrelated", { tags: [""] });

    const hits = await store.recall({ query: "solana owner check", tags: [""] });

    expect(hits).toHaveLength(0);
  });

  it("scores a blank tag as absent rather than counting it against the total", async () => {
    // One real tag alongside a blank one should score as a full match on the
    // real tag, not 0.5 for "one of two tags matched".
    await store.crystallize("semantic", "owner checks", { tags: ["owner", ""] });

    const hits = await store.recall({ query: "owner", tags: ["owner", ""] });

    expect(hits).toHaveLength(1);
    expect(hits[0]!.score).toBe(1);
  });

  it("finds a tag match that sits past the first page of a level", async () => {
    // Tag filtering happens after the store returns rows, so a single capped
    // read filtered an arbitrary slice: this exact shape (250 non-matching
    // crystals, then one match) returned zero results before searchLevel
    // paginated.
    for (let i = 0; i < 250; i++) {
      await store.crystallize("semantic", `noise ${i}`, { tags: ["noise"] });
    }
    await store.crystallize("semantic", "needle in the haystack", { tags: ["needle"] });

    const hits = await store.recall({ query: "needle", tags: ["needle"] });

    expect(hits).toHaveLength(1);
    expect(hits[0]!.crystal.content).toContain("needle");
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
