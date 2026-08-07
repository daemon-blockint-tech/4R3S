/**
 * ARES environment configuration.
 *
 * Loads variables from `.env` and validates them with zod so that
 * missing or malformed config fails fast at startup instead of
 * surfacing as cryptic downstream errors.
 */
import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

/**
 * A boolean flag read from the environment; only the exact string "true"
 * enables it.
 *
 * `fallback` is the *output* (boolean) value, not the raw string: zod 4 returns
 * a `.default()` directly when the variable is unset, short-circuiting the
 * transform, so the default has to be the transformed type.
 */
const boolFlag = (fallback = false) =>
  z
    .string()
    .transform((v) => v === "true")
    .default(fallback);

const schema = z.object({
  // OpenRouter / LLM
  OPENROUTER_API_KEY: z.string().min(1, "OPENROUTER_API_KEY is required"),
  OPENROUTER_BASE_URL: z
    .string()
    .url()
    .default("https://openrouter.ai/api/v1"),
  OPENROUTER_MODEL: z.string().default("anthropic/claude-sonnet-4.5"),
  OPENROUTER_REFERRER: z.string().default("ares-agent"),
  // Per-request deadline for LLM calls. Report synthesis is the slowest phase,
  // so this is generous — it exists to bound a hung socket, not to cut work off.
  OPENROUTER_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),

  // Solana
  SOLANA_RPC_URL: z.string().url().default("https://api.mainnet-beta.solana.com"),
  SOLANA_COMMITMENT: z
    .enum(["processed", "confirmed", "finalized"])
    .default("confirmed"),
  // Optional Helius RPC — when set, overrides SOLANA_RPC_URL for on-chain reads.
  HELIUS_RPC_URL: z.string().url().optional(),
  /** Per-request deadline for RPC reads. */
  SOLANA_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),

  // Postgres
  POSTGRES_HOST: z.string().default("localhost"),
  POSTGRES_PORT: z.coerce.number().default(5432),
  POSTGRES_DB: z.string().default("ares"),
  POSTGRES_USER: z.string().default("ares"),
  POSTGRES_PASSWORD: z.string().default("ares_dev_password"),
  POSTGRES_SSL: boolFlag(),
  /**
   * Connect and statement deadline for Postgres. Neither the `pg` pool nor
   * PostgresSaver applies one by default, so a wedged server would hang the
   * checkpoint write at every superstep boundary.
   */
  POSTGRES_TIMEOUT_MS: z.coerce.number().int().positive().default(30_000),

  // Supabase (hybrid keyword + vector retrieval). Optional — falls back to
  // Crystalline-only recall when unset.
  SUPABASE_URL: z.string().url().optional(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional(),
  /** Per-request deadline for Supabase reads (the `hybrid_search` RPC). */
  SUPABASE_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),

  // Neo4j (knowledge-graph expansion + relationship reranking). Optional.
  NEO4J_URI: z.string().optional(),
  NEO4J_USER: z.string().optional(),
  /**
   * Deadline for Neo4j connect, pool acquisition and query execution. Bolt runs
   * over raw TCP, so unlike the HTTP clients there is no fetch to wrap and no
   * undici backstop; without this a dead peer hangs RECALL indefinitely.
   */
  NEO4J_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),
  NEO4J_PASSWORD: z.string().optional(),

  // Embeddings (OpenAI-compatible endpoint). Optional — semantic search and
  // ingestion require it; recall degrades to tag/lexical scoring without it.
  EMBEDDINGS_BASE_URL: z.string().url().optional(),
  EMBEDDINGS_API_KEY: z.string().optional(),
  EMBEDDINGS_MODEL: z.string().default("text-embedding-3-small"),
  EMBEDDINGS_DIM: z.coerce.number().int().positive().default(1536),
  /** Per-request deadline for embedding calls. */
  EMBEDDINGS_TIMEOUT_MS: z.coerce.number().int().positive().default(15_000),

  /**
   * Deadline for a Semgrep scan. The spawn is a local subprocess, so no fetch
   * deadline covers it; without this a hung scan never settles and the parallel
   * ANALYZE superstep never fans in.
   */
  SEMGREP_TIMEOUT_MS: z.coerce.number().int().positive().default(120_000),

  // Seed knowledge base.
  SOLSEC_REPO_URL: z
    .string()
    .url()
    .default("https://github.com/sannykim/solsec.git"),

  // Computer Use Agent (CUA) — browser-driving investigation analyzer.
  // OPTIONAL and opt-in (CUA_ENABLED / --cua). Note: the CUA model is OpenAI's
  // computer-use-preview, invoked directly — NOT via OpenRouter — so it needs
  // its own OPENAI_API_KEY, separate from OPENROUTER_API_KEY.
  OPENAI_API_KEY: z.string().optional(),
  SCRAPYBARA_API_KEY: z.string().optional(),
  CUA_ENABLED: boolFlag(),
  CUA_ENVIRONMENT: z.enum(["web", "ubuntu", "windows"]).default("web"),
  CUA_TIMEOUT_HOURS: z.coerce.number().positive().default(1),
  CUA_RECURSION_LIMIT: z.coerce.number().int().positive().default(100),

  // ARES runtime
  ARES_MAX_ITERATIONS: z.coerce.number().int().positive().default(12),
  /**
   * Character budget for source loaded into analyzer context. A real Anchor
   * workspace exceeds any usable context window, so this is a hard constraint,
   * not a tuning knob; the report states when it truncated.
   */
  ARES_SOURCE_BUDGET_CHARS: z.coerce.number().int().positive().default(120_000),
  // Optional. Unset (the default) derives a per-target thread id so audits of
  // different targets never share checkpointed state; see `config/thread.ts`.
  ARES_THREAD_ID: z.string().optional(),
  ARES_LOG_LEVEL: z
    .enum(["debug", "info", "warn", "error"])
    .default("info"),
});

export type AresEnv = z.infer<typeof schema>;

function loadEnv(): AresEnv {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid ARES configuration:\n${issues}`);
  }
  return parsed.data;
}

/**
 * Loopback hosts, where an API key is a placeholder the server ignores.
 *
 * LM Studio, Ollama and llama.cpp all accept any string — their own docs tell
 * you to send `lm-studio` or `not-needed`.
 */
const LOOPBACK = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"]);

/**
 * True when the model endpoint and the key can never work together.
 *
 * A remote endpoint reached with a local placeholder key is not a judgement
 * call — it is a guaranteed 401. The combination arises from exactly the edit
 * that produced it here: a `.env` carrying both an OpenRouter block and an
 * LM Studio block, where one of the two `OPENROUTER_BASE_URL` lines is removed
 * or commented out and the key from the *other* block survives. Nothing then
 * reports the pairing until an LLM node dies several layers down, as
 * `401 Missing Authentication header` — a message about the request, not about
 * the configuration that built it.
 *
 * Deliberately narrow, and a warning rather than a failure: only a NON-loopback
 * host with a key outside the `sk-` family trips it. A real OpenRouter or OpenAI
 * key passes; every local placebo (`lm-studio`, `local`, `none`, `not-needed`)
 * fails. A rule that fired on anything less certain would be noise, and this
 * codebase has already retired two checks for exactly that.
 */
export function modelEndpointMismatch(
  baseUrl: string,
  apiKey: string,
): string | undefined {
  let host: string;
  try {
    host = new URL(baseUrl).hostname;
  } catch {
    return `OPENROUTER_BASE_URL is not a valid URL: ${baseUrl}`;
  }
  if (LOOPBACK.has(host)) return undefined;
  if (apiKey.startsWith("sk-")) return undefined;
  return (
    `OPENROUTER_BASE_URL points at ${host} (remote) but OPENROUTER_API_KEY is ` +
    `${JSON.stringify(apiKey.slice(0, 12))} — a local placeholder, not a remote ` +
    `key. This pairing always fails with 401. Point the base URL at your local ` +
    `server, or supply the key for ${host}.`
  );
}

export const env = loadEnv();

/**
 * The mismatch for the loaded config, or undefined.
 *
 * Computed here but NOT logged here: `config/logger.ts` imports this module, so
 * importing the logger back would be a cycle. Callers report it — see
 * `logStartupConfig` in `index.ts`, which prints the effective endpoint anyway.
 */
export const modelEndpointWarning = modelEndpointMismatch(
  env.OPENROUTER_BASE_URL,
  env.OPENROUTER_API_KEY,
);


/**
 * Postgres connection string built from individual env vars.
 *
 * User and password are percent-encoded. A generated password containing `@`,
 * `/`, `?` or `#` would otherwise terminate the authority component early — a
 * password of `kf9@qa2.internal/x` silently resolves to host `qa2.internal`,
 * presenting ARES credentials to a host the operator never configured.
 *
 * The deadline travels in the DSN because `PostgresSaver.fromConnString` only
 * accepts `{schema}` and exposes no pool config; `pg` reads `connect_timeout`
 * and passes `options` through to the server.
 */
export const postgresConnectionString = (): string => {
  const {
    POSTGRES_USER,
    POSTGRES_PASSWORD,
    POSTGRES_HOST,
    POSTGRES_PORT,
    POSTGRES_DB,
    POSTGRES_TIMEOUT_MS,
  } = env;
  const user = encodeURIComponent(POSTGRES_USER);
  const password = encodeURIComponent(POSTGRES_PASSWORD);
  const connectSeconds = Math.max(1, Math.ceil(POSTGRES_TIMEOUT_MS / 1000));
  // encodeURIComponent, not URLSearchParams: the latter encodes the space in
  // `-c statement_timeout=…` as `+`, which pg's decodeURIComponent leaves as a
  // literal plus and the server then rejects.
  const options = encodeURIComponent(`-c statement_timeout=${POSTGRES_TIMEOUT_MS}`);
  return (
    `postgresql://${user}:${password}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}` +
    `?connect_timeout=${connectSeconds}&options=${options}`
  );
};
