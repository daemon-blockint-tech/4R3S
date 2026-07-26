import { describe, it, expect } from "vitest";

import { synthCrystal } from "./util.js";

describe("synthCrystal", () => {
  it("wraps a KB fragment in the Crystal shape with warm defaults", () => {
    const c = synthCrystal({ id: "doc-1", content: "audit finding text" });
    expect(c.id).toBe("doc-1");
    expect(c.content).toBe("audit finding text");
    // Synthetic fragments default to the semantic level and are fully warm.
    expect(c.level).toBe("semantic");
    expect(c.activation).toBe(1);
    expect(c.accessCount).toBe(0);
    expect(c.links).toEqual([]);
    // Marked synthetic so RECALL knows there is no crystal in the store to
    // activate for this fragment.
    expect(c.metadata).toEqual({ synthetic: true });
    expect(c.tags).toEqual([]);
    expect(c.createdAt).toBeGreaterThan(0);
    expect(c.lastActivated).toBe(c.createdAt);
  });

  it("preserves supplied level, embedding, metadata, and tags", () => {
    const c = synthCrystal({
      id: "doc-2",
      content: "graph fragment",
      level: "procedural",
      embedding: [0.1, 0.2, 0.3],
      metadata: { source: "neo4j" },
      tags: ["cpi", "reentrancy"],
    });
    expect(c.level).toBe("procedural");
    expect(c.embedding).toEqual([0.1, 0.2, 0.3]);
    // Supplied metadata is kept, with the synthetic marker added alongside it.
    expect(c.metadata).toEqual({ source: "neo4j", synthetic: true });
    expect(c.tags).toEqual(["cpi", "reentrancy"]);
  });
});
