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
  OPENROUTER_MODEL: z.string().default("anthropic/claude-3.5-sonnet"),
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

export const env = loadEnv();

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
