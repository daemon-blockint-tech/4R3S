/**
 * Tests for the Supabase retriever.
 *
 * `hybrid-retriever.test.ts` covers the orchestration *around* this source, but
 * with a hand-built stand-in (`as unknown as SupabaseRetriever`), so none of the
 * code in `supabase-retriever.ts` ran under test before this file — including
 * the RRF path the task title names.
 *
 * The behaviour worth pinning is the three-way distinction this retriever
 * signals purely through the presence of an `error` field:
 *
 *   `{fragments: []}`             → not configured. A normal state.
 *   `{fragments: [], error: ...}` → configured but failed. Surfaces a banner.
 *
 * `hybrid-retriever.ts` reads that difference to report `skipped` versus
 * `failed` (its own test calls this "distinguishing unconfigured from failed").
 * A regression that attached an `error` to the unconfigured path would turn
 * "Supabase was never set up" into "Supabase is broken" in every report from a
 * deployment that simply does not use it — and nothing would have caught it.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Same shape as knowledge-writer.test.ts: hoisted mock, replaced by path.
const supabaseMock = vi.hoisted(() => ({
  getSupabase: vi.fn<() => unknown>(() => undefined),
}));

vi.mock("../persistence/supabase.js", () => supabaseMock);

import { SupabaseRetriever } from "./supabase-retriever.js";

/** A Supabase client whose `rpc` resolves to whatever the test dictates. */
function clientReturning(response: unknown) {
  const rpc = vi.fn(async () => response);
  return { client: { rpc }, rpc };
}

/** A Supabase client whose `rpc` throws, for the catch path. */
function clientThrowing(message: string) {
  const rpc = vi.fn(async () => {
    throw new Error(message);
  });
  return { client: { rpc }, rpc };
}

const ROW = {
  chunk_id: "chunk-1",
  doc_id: "doc-1",
  entity_id: "entity-1",
  content: "PDA seed collision in vault init",
  score: 0.82,
};

beforeEach(() => {
  supabaseMock.getSupabase.mockReset().mockReturnValue(undefined);
});

describe("SupabaseRetriever: not configured is not the same as failed", () => {
  it("returns no fragments and no error when Supabase is absent", async () => {
    // The distinction the whole file exists to protect. An `error` here would
    // make an unconfigured deployment look like a broken one.
    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments).toEqual([]);
    expect(result.error).toBeUndefined();
  });

  it("does not call the RPC at all when Supabase is absent", async () => {
    const { client, rpc } = clientReturning({ data: [], error: null });
    // Deliberately NOT installed as the return value: getSupabase stays
    // undefined, so reaching the RPC would mean the guard was skipped.
    await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(rpc).not.toHaveBeenCalled();
    expect(client).toBeDefined(); // keeps the fixture meaningful to a reader
  });

  it("reports an error when the RPC returns one", async () => {
    const { client } = clientReturning({
      data: null,
      error: { message: "relation hybrid_search does not exist", code: "42P01" },
    });
    supabaseMock.getSupabase.mockReturnValue(client);

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments).toEqual([]);
    expect(result.error).toBeDefined();
    expect(result.error).toContain("hybrid_search RPC failed");
  });

  it("reports an error when the RPC throws rather than resolving", async () => {
    // A network-level failure takes the catch path, not the `error` branch.
    // Both must surface an error; a thrown exception that returned a bare empty
    // result would read as "configured, searched, found nothing".
    supabaseMock.getSupabase.mockReturnValue(clientThrowing("socket hang up").client);

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments).toEqual([]);
    expect(result.error).toContain("socket hang up");
  });

  it("does not throw out of retrieve() on an unexpected failure", async () => {
    // The caller is a graph node mid-audit; an exception escaping here would
    // fail the whole run over an optional source.
    supabaseMock.getSupabase.mockReturnValue(clientThrowing("boom").client);

    await expect(new SupabaseRetriever().retrieve({ text: "x" })).resolves.toBeDefined();
  });
});

describe("SupabaseRetriever: RPC arguments", () => {
  it("passes the query text, the embedding, and the limit", async () => {
    const { client, rpc } = clientReturning({ data: [], error: null });
    supabaseMock.getSupabase.mockReturnValue(client);

    await new SupabaseRetriever().retrieve({
      text: "pda seed collision",
      embedding: [0.1, 0.2, 0.3],
      limit: 5,
    });

    expect(rpc).toHaveBeenCalledWith("hybrid_search", {
      query_text: "pda seed collision",
      query_embedding: [0.1, 0.2, 0.3],
      match_count: 5,
    });
  });

  it("passes a null embedding rather than omitting it, so the SQL takes its lexical-only path", async () => {
    // db/supabase/0001_hybrid_search.sql declares
    // `query_embedding vector(1536) default null` and guards its vector branch
    // with `where query_embedding is not null`. Passing null is what degrades
    // RRF to text-only ranking; omitting the key or sending undefined is not
    // the same thing to PostgREST.
    const { client, rpc } = clientReturning({ data: [], error: null });
    supabaseMock.getSupabase.mockReturnValue(client);

    await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(rpc).toHaveBeenCalledWith(
      "hybrid_search",
      expect.objectContaining({ query_embedding: null }),
    );
  });

  it("defaults the limit to 20 when the caller states none", async () => {
    const { client, rpc } = clientReturning({ data: [], error: null });
    supabaseMock.getSupabase.mockReturnValue(client);

    await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(rpc).toHaveBeenCalledWith(
      "hybrid_search",
      expect.objectContaining({ match_count: 20 }),
    );
  });
});

describe("SupabaseRetriever: mapping rows to fragments", () => {
  it("carries doc_id, chunk_id and entity_id into metadata for the Neo4j stage", async () => {
    // The graph stage expands these; losing them silently would leave Neo4j
    // with nothing to expand and no error to explain why.
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: [ROW], error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments).toHaveLength(1);
    const meta = result.fragments[0]!.crystal.metadata as Record<string, unknown>;
    expect(meta.doc_id).toBe("doc-1");
    expect(meta.chunk_id).toBe("chunk-1");
    expect(meta.entity_id).toBe("entity-1");
    expect(meta.source).toBe("supabase");
  });

  it("marks fragments synthetic so RECALL does not try to activate them", async () => {
    // synthCrystal sets this; asserted here because a fragment that looked
    // native would send RECALL looking for a crystal that does not exist.
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: [ROW], error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    const meta = result.fragments[0]!.crystal.metadata as Record<string, unknown>;
    expect(meta.synthetic).toBe(true);
  });

  it("uses chunk_id as the fragment id, which is what dedup keys on", async () => {
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: [ROW], error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments[0]!.crystal.id).toBe("chunk-1");
  });

  it("keeps the row's score", async () => {
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: [ROW], error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments[0]!.score).toBe(0.82);
  });

  it("treats a null score as 0 rather than dropping the row", async () => {
    // hybrid-retriever normalises with `Math.max(...scores, 1e-9)` as a floor,
    // so a 0 lands last rather than dividing by zero. Dropping the row instead
    // would lose a result the database chose to return.
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: [{ ...ROW, score: null }], error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments).toHaveLength(1);
    expect(result.fragments[0]!.score).toBe(0);
  });

  it("omits entity_id from metadata when the row has none", async () => {
    // Absent, not null: an entity_id of null would be a claim that the chunk
    // maps to no entity, where the truth is that this chunk is not linked yet.
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: [{ ...ROW, entity_id: null }], error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    const meta = result.fragments[0]!.crystal.metadata as Record<string, unknown>;
    expect(meta.entity_id).toBeUndefined();
  });

  it("returns no fragments when data is null, without throwing", async () => {
    // PostgREST can answer with a null body and no error.
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: null, error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments).toEqual([]);
    expect(result.error).toBeUndefined();
  });

  it("maps every row, preserving order", async () => {
    const rows = [
      { ...ROW, chunk_id: "c1", score: 0.9 },
      { ...ROW, chunk_id: "c2", score: 0.5 },
      { ...ROW, chunk_id: "c3", score: 0.1 },
    ];
    supabaseMock.getSupabase.mockReturnValue(
      clientReturning({ data: rows, error: null }).client,
    );

    const result = await new SupabaseRetriever().retrieve({ text: "pda" });

    expect(result.fragments.map((f) => f.crystal.id)).toEqual(["c1", "c2", "c3"]);
  });
});

describe("SupabaseRetriever: identity", () => {
  it('names itself "supabase", which is the key hybrid-retriever reports under', async () => {
    expect(new SupabaseRetriever().name).toBe("supabase");
  });
});
