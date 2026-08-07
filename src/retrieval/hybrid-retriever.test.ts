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
  return {
    name: "crystalline",
    retrieve: vi.fn(async () => ({ fragments: results })),
  } as unknown as CrystallineRetriever;
}

/** Fragments only — the shape the merge assertions care about. */
async function fragmentIds(
  retriever: HybridRetriever,
  query: HybridQuery,
): Promise<string[]> {
  const { fragments } = await retriever.retrieve(query);
  return fragments.map((r) => r.crystal.id);
}

describe("HybridRetriever", () => {
  it("returns Crystalline-only results when no other source is configured", async () => {
    const retriever = new HybridRetriever(
      fakeCrystalline([scored("a", 1), scored("b", 0.5)]),
    );
    expect(await fragmentIds(retriever, { text: "q", limit: 8 })).toEqual(["a", "b"]);
  });

  it("uses the standalone Neo4j retrieve() path (not only expand)", async () => {
    const neo4jRetrieve = vi.fn(async () => ({ fragments: [scored("graph-1", 2)] }));
    const neo4jExpand = vi.fn(async () => ({ fragments: [] }));
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
    const ids = await fragmentIds(retriever, { text: "q", limit: 8 });

    // The standalone graph match must appear in the merged output.
    expect(neo4jRetrieve).toHaveBeenCalledTimes(1);
    expect(ids).toContain("graph-1");
  });

  it("expands Supabase seed chunks through Neo4j", async () => {
    const supabase = {
      name: "supabase",
      retrieve: vi.fn(async () => ({ fragments: [scored("s1", 1, "chunk-1")] })),
    } as unknown as SupabaseRetriever;
    const neo4jExpand = vi.fn(async () => ({
      fragments: [scored("n1", 1, "chunk-2")],
    }));
    const neo4j = {
      name: "neo4j",
      retrieve: vi.fn(async () => ({ fragments: [] })),
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
      retrieve: vi.fn(async () => ({ fragments: [scored("shared", 1)] })),
      expand: vi.fn(async () => ({ fragments: [] })),
    } as unknown as Neo4jRetriever;

    const retriever = new HybridRetriever(crystalline, undefined, neo4j);
    const ids = await fragmentIds(retriever, { text: "q", limit: 8 });
    expect(ids[0]).toBe("shared");
  });

  it("counts one source at most once per fragment", async () => {
    // The graph bucket is two queries concatenated, and its Cypher used to
    // return one row per mentioned entity, so the same chunk arrived several
    // times over. Each copy added the full graph weight (0.6), which is how a
    // chunk with many :MENTIONS edges outranked everything else by arithmetic
    // rather than relevance. Crystalline's weight is 0.9, so only
    // double-counting can put "dup" first.
    const neo4j = {
      name: "neo4j",
      retrieve: vi.fn(async () => ({ fragments: [scored("dup", 1)] })),
      expand: vi.fn(async () => ({ fragments: [scored("dup", 1)] })),
    } as unknown as Neo4jRetriever;

    const retriever = new HybridRetriever(
      fakeCrystalline([scored("solo", 1)]),
      undefined,
      neo4j,
    );
    const { fragments } = await retriever.retrieveWithStatus({
      text: "q",
      limit: 8,
    });

    expect(fragments.map((f) => f.crystal.id)).toEqual(["solo", "dup"]);
    expect(fragments[1]!.score).toBeCloseTo(0.6);
  });

  it("respects the result limit", async () => {
    const many = Array.from({ length: 20 }, (_, i) => scored(`c${i}`, 20 - i));
    const retriever = new HybridRetriever(fakeCrystalline(many));
    const ids = await fragmentIds(retriever, { text: "q", limit: 5 });
    expect(ids).toHaveLength(5);
  });

  it("reports each source's outcome, distinguishing unconfigured from failed", async () => {
    const supabase = {
      name: "supabase",
      // A configured source that errored returns no fragments — the same shape
      // as having nothing to say, which is why the error has to be carried.
      retrieve: vi.fn(async () => ({ fragments: [], error: "rpc exploded" })),
    } as unknown as SupabaseRetriever;

    const retriever = new HybridRetriever(fakeCrystalline([scored("a", 1)]), supabase);
    const { sources } = await retriever.retrieveWithStatus({ text: "q", limit: 8 });

    expect(sources).toEqual([
      { source: "crystalline", outcome: "ok", fragments: 1 },
      { source: "supabase", outcome: "failed", fragments: 0, detail: "rpc exploded" },
      { source: "neo4j", outcome: "skipped", fragments: 0, detail: "not configured" },
    ]);
  });

  it("marks the graph failed when only its expansion query errors", async () => {
    const neo4j = {
      name: "neo4j",
      retrieve: vi.fn(async () => ({ fragments: [] })),
      expand: vi.fn(async () => ({ fragments: [], error: "bolt closed" })),
    } as unknown as Neo4jRetriever;
    const supabase = {
      name: "supabase",
      retrieve: vi.fn(async () => ({ fragments: [scored("s1", 1, "chunk-1")] })),
    } as unknown as SupabaseRetriever;

    const retriever = new HybridRetriever(fakeCrystalline([]), supabase, neo4j);
    const { sources } = await retriever.retrieveWithStatus({ text: "q", limit: 8 });

    const graph = sources.find((s) => s.source === "neo4j")!;
    expect(graph.outcome).toBe("failed");
    expect(graph.detail).toBe("bolt closed");
  });
});
