/**
 * Embeddings — pluggable, OpenAI-compatible embedding function.
 *
 * Used by the ingestion pipeline (embed chunks) and at query time (embed the
 * audit intake for semantic search). Optional: when no embeddings endpoint is
 * configured, callers fall back to lexical/tag scoring, so the agent still runs.
 */
import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

/** True when an embeddings endpoint is configured. */
export function hasEmbeddings(): boolean {
  return Boolean(env.EMBEDDINGS_BASE_URL && env.EMBEDDINGS_API_KEY);
}

interface EmbeddingResponse {
  data: Array<{ embedding: number[] }>;
}

/**
 * Embed a batch of texts. Returns one vector per input, or `undefined` if
 * embeddings are not configured or the request fails (never throws).
 */
export async function embedBatch(
  texts: string[],
): Promise<number[][] | undefined> {
  if (!hasEmbeddings() || texts.length === 0) return undefined;
  try {
    const res = await fetch(`${env.EMBEDDINGS_BASE_URL}/embeddings`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.EMBEDDINGS_API_KEY}`,
      },
      body: JSON.stringify({ model: env.EMBEDDINGS_MODEL, input: texts }),
    });
    if (!res.ok) {
      logger.warn(
        { component: "embeddings", status: res.status },
        "Embedding request failed; falling back to lexical scoring",
      );
      return undefined;
    }
    const json = (await res.json()) as EmbeddingResponse;
    return json.data.map((d) => d.embedding);
  } catch (err) {
    logger.warn(
      { component: "embeddings", err: String(err) },
      "Embedding request errored; falling back to lexical scoring",
    );
    return undefined;
  }
}

/** Embed a single text. Returns `undefined` on failure / when not configured. */
export async function embed(text: string): Promise<number[] | undefined> {
  const out = await embedBatch([text]);
  return out?.[0];
}
