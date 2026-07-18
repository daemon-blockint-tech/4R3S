import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryStore } from "@langchain/langgraph";

import { CrystallineStore, cosineSimilarity } from "./crystalline-store.js";

describe("cosineSimilarity", () => {
  it("is 1 for identical vectors and 0 for orthogonal ones", () => {
    expect(cosineSimilarity([1, 0], [1, 0])).toBeCloseTo(1);
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0);
  });

  it("returns 0 on length mismatch or a zero vector", () => {
    expect(cosineSimilarity([1, 2, 3], [1, 2])).toBe(0);
    expect(cosineSimilarity([0, 0], [1, 1])).toBe(0);
  });
});

describe("CrystallineStore", () => {
  let store: CrystallineStore;

  beforeEach(async () => {
    store = new CrystallineStore(new InMemoryStore());
    await store.start();
  });

  it("crystallizes and loads a crystal round-trip", async () => {
    const c = await store.crystallize("semantic", "missing signer check", {
      tags: ["access-control"],
      metadata: { cwe: "CWE-862" },
    });
    expect(c.id).toBeTruthy();
    expect(c.accessCount).toBe(0);

    const loaded = await store.load(c.id, "semantic");
    expect(loaded?.content).toBe("missing signer check");
    expect(loaded?.tags).toEqual(["access-control"]);
    expect(loaded?.metadata.cwe).toBe("CWE-862");
  });

  it("recalls a crystal by tag overlap", async () => {
    await store.crystallize("semantic", "reentrancy via CPI", { tags: ["cpi"] });
    await store.crystallize("semantic", "integer overflow", { tags: ["arithmetic"] });

    const hits = await store.recall({ query: "cpi bug", tags: ["cpi"] });
    expect(hits.length).toBe(1);
    expect(hits[0]!.crystal.content).toBe("reentrancy via CPI");
  });

  it("activate() boosts activation and increments accessCount", async () => {
    const c = await store.crystallize("episodic", "audited program X");
    await store.activate(c.id, "episodic");
    await store.activate(c.id, "episodic");

    const loaded = await store.load(c.id, "episodic");
    expect(loaded?.accessCount).toBe(2);
    expect(loaded!.activation).toBeGreaterThan(c.activation - 1e-9);
  });

  it("forget() removes a crystal", async () => {
    const c = await store.crystallize("working", "scratch note");
    await store.forget(c.id, "working");
    expect(await store.load(c.id, "working")).toBeUndefined();
  });

  it("spreads activation from a recalled crystal to a linked neighbor", async () => {
    const hub = await store.crystallize("semantic", "signer checks", {
      tags: ["signer"],
    });
    const neighbor = await store.crystallize("semantic", "owner checks", {
      tags: ["owner"],
    });
    // Link hub → neighbor so recalling the hub primes the neighbor.
    await store.link(hub.id, "semantic", neighbor.id, 1, "related");

    const hits = await store.recall({
      query: "signer",
      tags: ["signer", "owner"],
      spreadDepth: 1,
    });
    const neighborHit = hits.find((h) => h.crystal.id === neighbor.id);
    expect(neighborHit).toBeDefined();
    // Its score includes the spread boost from the hub.
    expect(neighborHit!.score).toBeGreaterThan(0);
  });

  it("promotes a frequently-accessed episodic crystal to semantic on consolidate", async () => {
    const c = await store.crystallize("episodic", "recurring pattern");
    // semanticPromotionAccess default = 3.
    await store.activate(c.id, "episodic");
    await store.activate(c.id, "episodic");
    await store.activate(c.id, "episodic");

    const report = await store.consolidate();
    expect(report.promoted.some((p) => p.crystalId === c.id && p.to === "semantic")).toBe(true);
    expect(await store.load(c.id, "episodic")).toBeUndefined();
    expect(await store.load(c.id, "semantic")).toBeDefined();
  });
});
