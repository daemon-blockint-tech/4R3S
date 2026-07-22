import { describe, it, expect, vi } from "vitest";

import { HybridRetriever } from "./hybrid-retriever.js";
import { synthCrystal } from "./util.js";
import type { ScoredCrystal } from "../memory/types.js";
import type { CrystallineRetriever } from "./crystalline-retriever.js";
import type { SupabaseRetriever } from "./supabase-retriever.js";
import type { Neo4jRetriever } from "./neo4j-retriever.js";
import type { HybridQuery } from "./types.js";

function scored(id: string, score: number, chunkId?: string): ScoredCrystal {
  return {
    crystal: synthCrystal({
      id,
      content: `content-${id}`,
      metadata: chunkId ? { chunk_id: chunkId } : {},
    }),
    score,
  };
}

function fakeCrystalline(results: ScoredCrystal[]): CrystallineRetriever {
  return { name: "crystalline", retrieve: vi.fn(async () => results) } as unknown as CrystallineRetriever;
}

describe("HybridRetriever", () => {
  it("returns Crystalline-only results when no other source is configured", async () => {
    const retriever = new HybridRetriever(
      fakeCrystalline([scored("a", 1), scored("b", 0.5)]),
    );
    const out = await retriever.retrieve({ text: "q", limit: 8 });
    expect(out.map((r) => r.crystal.id)).toEqual(["a", "b"]);
  });

  it("uses the standalone Neo4j retrieve() path (not only expand)", async () => {
    const neo4jRetrieve = vi.fn(async () => [scored("graph-1", 2)]);
    const neo4jExpand = vi.fn(async () => []);
    const neo4j = {
      name: "neo4j",
      retrieve: neo4jRetrieve,
      expand: neo4jExpand,
    } as unknown as Neo4jRetriever;

    const retriever = new HybridRetriever(
      fakeCrystalline([scored("a", 1)]),
      undefined,
      neo4j,
    );
    const out = await retriever.retrieve({ text: "q", limit: 8 });

    // The standalone graph match must appear in the merged output.
    expect(neo4jRetrieve).toHaveBeenCalledTimes(1);
    expect(out.map((r) => r.crystal.id)).toContain("graph-1");
  });

  it("expands Supabase seed chunks through Neo4j", async () => {
    const supabase = {
      name: "supabase",
      retrieve: vi.fn(async () => [scored("s1", 1, "chunk-1")]),
    } as unknown as SupabaseRetriever;
    const neo4jExpand = vi.fn(async () => [scored("n1", 1, "chunk-2")]);
    const neo4j = {
      name: "neo4j",
      retrieve: vi.fn(async () => []),
      expand: neo4jExpand,
    } as unknown as Neo4jRetriever;

    const retriever = new HybridRetriever(
      fakeCrystalline([]),
      supabase,
      neo4j,
    );
    await retriever.retrieve({ text: "q", limit: 8 });

    // expand() is seeded with the Supabase candidate's chunk_id.
    expect(neo4jExpand).toHaveBeenCalledTimes(1);
    const [seedIds] = neo4jExpand.mock.calls[0]!;
    expect(seedIds).toEqual(["chunk-1"]);
  });

  it("ranks a fragment surfaced by multiple sources above single-source ones", async () => {
    // "shared" appears in both crystalline and neo4j → its weighted score sums.
    const crystalline = fakeCrystalline([scored("shared", 1), scored("solo", 1)]);
    const neo4j = {
      name: "neo4j",
      retrieve: vi.fn(async () => [scored("shared", 1)]),
      expand: vi.fn(async () => []),
    } as unknown as Neo4jRetriever;

    const retriever = new HybridRetriever(crystalline, undefined, neo4j);
    const out = await retriever.retrieve({ text: "q", limit: 8 });
    expect(out[0]!.crystal.id).toBe("shared");
  });

  it("respects the result limit", async () => {
    const many = Array.from({ length: 20 }, (_, i) => scored(`c${i}`, 20 - i));
    const retriever = new HybridRetriever(fakeCrystalline(many));
    const out = await retriever.retrieve({ text: "q", limit: 5 } as HybridQuery);
    expect(out).toHaveLength(5);
  });
});
