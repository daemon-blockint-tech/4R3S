import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the backend factories so we can exercise the writer without real
// Supabase/Neo4j. Each test toggles configuration via these mocks.
const supabaseMock = vi.hoisted(() => ({
  hasSupabase: vi.fn(() => false),
  getSupabase: vi.fn<() => unknown>(() => undefined),
}));
const neo4jMock = vi.hoisted(() => ({
  hasNeo4j: vi.fn(() => false),
  withNeo4jSession: vi.fn(async () => undefined),
}));

vi.mock("./supabase.js", () => supabaseMock);
vi.mock("./neo4j.js", () => neo4jMock);

import {
  HybridKnowledgeWriter,
  NullKnowledgeWriter,
  createKnowledgeWriter,
} from "./knowledge-writer.js";

beforeEach(() => {
  supabaseMock.hasSupabase.mockReturnValue(false);
  supabaseMock.getSupabase.mockReturnValue(undefined);
  neo4jMock.hasNeo4j.mockReturnValue(false);
  neo4jMock.withNeo4jSession.mockReset().mockResolvedValue(undefined);
});

const fragment = {
  content: "PDA seed collision in vault init",
  level: "semantic" as const,
  tags: ["pda", "vault"],
  metadata: { target: "Prog111" },
};

describe("NullKnowledgeWriter", () => {
  it("is disabled and persists nothing", async () => {
    const writer = new NullKnowledgeWriter();
    expect(writer.enabled).toBe(false);
    expect(await writer.persist()).toBeUndefined();
  });
});

describe("HybridKnowledgeWriter", () => {
  it("reports disabled and no-ops when no backend is configured", async () => {
    const writer = new HybridKnowledgeWriter();
    expect(writer.enabled).toBe(false);
    expect(await writer.persist(fragment)).toBeUndefined();
  });

  it("skips empty content", async () => {
    supabaseMock.hasSupabase.mockReturnValue(true);
    const writer = new HybridKnowledgeWriter();
    expect(await writer.persist({ ...fragment, content: "   " })).toBeUndefined();
  });

  it("writes documents + chunks to Supabase and returns join ids", async () => {
    const upsert = vi.fn().mockResolvedValue({ error: null });
    const from = vi.fn(() => ({ upsert }));
    supabaseMock.hasSupabase.mockReturnValue(true);
    supabaseMock.getSupabase.mockReturnValue({ from });

    const writer = new HybridKnowledgeWriter();
    expect(writer.enabled).toBe(true);
    const ids = await writer.persist(fragment);

    expect(ids).toBeDefined();
    expect(ids!.docId).toMatch(/^[0-9a-f]{32}$/);
    expect(ids!.chunkId).toMatch(/^[0-9a-f]{32}$/);
    // documents then chunks.
    expect(from).toHaveBeenCalledWith("documents");
    expect(from).toHaveBeenCalledWith("chunks");
    expect(upsert).toHaveBeenCalledTimes(2);
  });

  it("produces deterministic, stable ids for the same content+target", async () => {
    const upsert = vi.fn().mockResolvedValue({ error: null });
    supabaseMock.hasSupabase.mockReturnValue(true);
    supabaseMock.getSupabase.mockReturnValue({ from: () => ({ upsert }) });

    const writer = new HybridKnowledgeWriter();
    const a = await writer.persist(fragment);
    const b = await writer.persist(fragment);
    expect(a).toEqual(b);
  });

  it("does not throw when Supabase upsert returns an error", async () => {
    const upsert = vi.fn().mockResolvedValue({ error: { message: "boom" } });
    supabaseMock.hasSupabase.mockReturnValue(true);
    supabaseMock.getSupabase.mockReturnValue({ from: () => ({ upsert }) });

    const writer = new HybridKnowledgeWriter();
    // Supabase failed but nothing was written anywhere → undefined, no throw.
    expect(await writer.persist(fragment)).toBeUndefined();
  });

  it("writes to Neo4j when configured", async () => {
    neo4jMock.hasNeo4j.mockReturnValue(true);
    neo4jMock.withNeo4jSession.mockImplementation(async (fn: (s: unknown) => Promise<unknown>) => {
      const session = { run: vi.fn().mockResolvedValue({}) };
      return fn(session);
    });

    const writer = new HybridKnowledgeWriter();
    expect(writer.enabled).toBe(true);
    const ids = await writer.persist(fragment);
    expect(ids).toBeDefined();
    expect(neo4jMock.withNeo4jSession).toHaveBeenCalledTimes(1);
  });

  it("does not throw when the Neo4j write fails", async () => {
    neo4jMock.hasNeo4j.mockReturnValue(true);
    neo4jMock.withNeo4jSession.mockRejectedValue(new Error("graph down"));
    const writer = new HybridKnowledgeWriter();
    expect(await writer.persist(fragment)).toBeUndefined();
  });
});

describe("createKnowledgeWriter", () => {
  it("returns a HybridKnowledgeWriter", () => {
    expect(createKnowledgeWriter()).toBeInstanceOf(HybridKnowledgeWriter);
  });
});
