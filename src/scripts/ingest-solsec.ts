/**
 * Ingest the solsec knowledge base into the hybrid retrieval backends.
 *
 * Pipeline:
 *   1. Clone/pull SOLSEC_REPO_URL into a local cache.
 *   2. Chunk every markdown file.
 *   3. Embed chunks (when embeddings are configured) and upsert
 *      documents + chunks into Supabase (pgvector + full-text).
 *   4. Extract lightweight entities (headings, linked terms) and upsert
 *      Document/Chunk/Entity nodes + relations into Neo4j, keyed by the same
 *      doc_id / chunk_id / entity_id so the two stores join.
 *
 * Idempotent (upserts by id). Backends that aren't configured are skipped.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, mkdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, relative, extname } from "node:path";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";
import { getSupabase, hasSupabase } from "../persistence/supabase.js";
import { hasNeo4j, withNeo4jSession, closeNeo4j } from "../persistence/neo4j.js";
import { embedBatch } from "../retrieval/embeddings.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CACHE_DIR = resolve(HERE, "..", "..", ".cache", "solsec");
const CHUNK_SIZE = 1200;

function sha(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 32);
}

function cloneOrPull(): void {
  if (existsSync(join(CACHE_DIR, ".git"))) {
    logger.info({ component: "ingest" }, "Updating solsec cache");
    spawnSync("git", ["-C", CACHE_DIR, "pull", "--ff-only"], { stdio: "ignore" });
    return;
  }
  logger.info({ component: "ingest", repo: env.SOLSEC_REPO_URL }, "Cloning solsec");
  const res = spawnSync(
    "git",
    ["clone", "--depth", "1", env.SOLSEC_REPO_URL, CACHE_DIR],
    { stdio: "inherit" },
  );
  if (res.status !== 0) {
    throw new Error("git clone failed — is git installed and the repo reachable?");
  }
}

async function walkMarkdown(dir: string, acc: string[] = []): Promise<string[]> {
  for (const entry of await readdir(dir)) {
    if (entry === ".git") continue;
    const full = join(dir, entry);
    const s = await stat(full);
    if (s.isDirectory()) {
      await walkMarkdown(full, acc);
    } else if (extname(entry).toLowerCase() === ".md") {
      acc.push(full);
    }
  }
  return acc;
}

function chunkText(text: string): string[] {
  const paras = text.split(/\n\s*\n/);
  const chunks: string[] = [];
  let buf = "";
  for (const p of paras) {
    if ((buf + "\n\n" + p).length > CHUNK_SIZE && buf) {
      chunks.push(buf.trim());
      buf = p;
    } else {
      buf = buf ? `${buf}\n\n${p}` : p;
    }
  }
  if (buf.trim()) chunks.push(buf.trim());
  return chunks.filter((c) => c.length > 0);
}

/** Naive entity extraction: markdown headings + link labels. */
function extractEntities(text: string): string[] {
  const entities = new Set<string>();
  for (const m of text.matchAll(/^#{1,6}\s+(.+)$/gm)) {
    entities.add(m[1]!.trim());
  }
  for (const m of text.matchAll(/\[([^\]]+)\]\([^)]+\)/g)) {
    entities.add(m[1]!.trim());
  }
  return [...entities].filter((e) => e.length > 2 && e.length < 80).slice(0, 20);
}

interface ChunkRecord {
  chunk_id: string;
  doc_id: string;
  content: string;
  chunk_index: number;
  embedding: number[] | null;
  entities: string[];
}

async function ingestFile(
  path: string,
  root: string,
): Promise<{ doc_id: string; title: string; rel: string; chunks: ChunkRecord[] }> {
  const rel = relative(root, path);
  const doc_id = sha(rel);
  const content = await readFile(path, "utf8");
  const title = rel.replace(/\.md$/i, "");
  const pieces = chunkText(content);

  const embeddings = await embedBatch(pieces);
  const chunks: ChunkRecord[] = pieces.map((piece, i) => ({
    chunk_id: sha(`${rel}#${i}`),
    doc_id,
    content: piece,
    chunk_index: i,
    embedding: embeddings?.[i] ?? null,
    entities: extractEntities(piece),
  }));

  return { doc_id, title, rel, chunks };
}

async function upsertSupabase(
  docs: Array<{ doc_id: string; title: string; rel: string; chunks: ChunkRecord[] }>,
): Promise<void> {
  const supabase = getSupabase();
  if (!supabase) return;

  const documentRows = docs.map((d) => ({
    doc_id: d.doc_id,
    title: d.title,
    path: d.rel,
  }));
  const chunkRows = docs.flatMap((d) =>
    d.chunks.map((c) => ({
      chunk_id: c.chunk_id,
      doc_id: c.doc_id,
      content: c.content,
      chunk_index: c.chunk_index,
      embedding: c.embedding,
    })),
  );

  const { error: docErr } = await supabase
    .from("documents")
    .upsert(documentRows, { onConflict: "doc_id" });
  if (docErr) throw new Error(`documents upsert failed: ${docErr.message}`);

  // Chunk upserts in batches to stay within payload limits.
  for (let i = 0; i < chunkRows.length; i += 200) {
    const batch = chunkRows.slice(i, i + 200);
    const { error } = await supabase
      .from("chunks")
      .upsert(batch, { onConflict: "chunk_id" });
    if (error) throw new Error(`chunks upsert failed: ${error.message}`);
  }
  logger.info(
    { component: "ingest", documents: documentRows.length, chunks: chunkRows.length },
    "Supabase upsert complete",
  );
}

async function upsertNeo4j(
  docs: Array<{ doc_id: string; title: string; rel: string; chunks: ChunkRecord[] }>,
): Promise<void> {
  if (!hasNeo4j()) return;
  await withNeo4jSession(async (session) => {
    for (const d of docs) {
      await session.run(
        `MERGE (doc:Document { doc_id: $doc_id })
         SET doc.title = $title, doc.path = $path`,
        { doc_id: d.doc_id, title: d.title, path: d.rel },
      );
      for (const c of d.chunks) {
        // Entity ids are derived in JS (stable slug hash) so the graph joins
        // to the same entity_id used elsewhere.
        const entities = c.entities.map((name) => ({
          id: sha(name.toLowerCase()),
          name,
        }));
        await session.run(
          `MATCH (doc:Document { doc_id: $doc_id })
           MERGE (ch:Chunk { chunk_id: $chunk_id })
           SET ch.content = $content, ch.chunk_index = $chunk_index
           MERGE (doc)-[:HAS_CHUNK]->(ch)
           WITH ch
           UNWIND $entities AS ent
           MERGE (e:Entity { entity_id: ent.id })
           SET e.name = ent.name
           MERGE (ch)-[:MENTIONS]->(e)`,
          {
            doc_id: d.doc_id,
            chunk_id: c.chunk_id,
            content: c.content,
            chunk_index: c.chunk_index,
            entities,
          },
        );
      }
    }
  });
  logger.info({ component: "ingest", documents: docs.length }, "Neo4j upsert complete");
}

async function main(): Promise<void> {
  if (!hasSupabase() && !hasNeo4j()) {
    logger.warn(
      { component: "ingest" },
      "Neither Supabase nor Neo4j configured — nothing to ingest. Set credentials in .env.",
    );
    return;
  }

  await mkdir(dirname(CACHE_DIR), { recursive: true });
  cloneOrPull();

  const files = await walkMarkdown(CACHE_DIR);
  logger.info({ component: "ingest", files: files.length }, "Found markdown files");

  const docs = [];
  for (const f of files) {
    docs.push(await ingestFile(f, CACHE_DIR));
  }

  await upsertSupabase(docs);
  await upsertNeo4j(docs);
  await closeNeo4j();
  logger.info({ component: "ingest" }, "Ingestion complete");
}

main().catch((err) => {
  logger.error({ component: "ingest", err: String(err) }, "Ingestion failed");
  process.exitCode = 1;
});
