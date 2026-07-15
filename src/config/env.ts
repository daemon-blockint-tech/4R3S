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

const schema = z.object({
  // OpenRouter / LLM
  OPENROUTER_API_KEY: z.string().min(1, "OPENROUTER_API_KEY is required"),
  OPENROUTER_BASE_URL: z
    .string()
    .url()
    .default("https://openrouter.ai/api/v1"),
  OPENROUTER_MODEL: z.string().default("anthropic/claude-3.5-sonnet"),
  OPENROUTER_REFERRER: z.string().default("ares-agent"),

  // Solana
  SOLANA_RPC_URL: z.string().url().default("https://api.mainnet-beta.solana.com"),
  SOLANA_COMMITMENT: z
    .enum(["processed", "confirmed", "finalized"])
    .default("confirmed"),

  // Postgres
  POSTGRES_HOST: z.string().default("localhost"),
  POSTGRES_PORT: z.coerce.number().default(5432),
  POSTGRES_DB: z.string().default("ares"),
  POSTGRES_USER: z.string().default("ares"),
  POSTGRES_PASSWORD: z.string().default("ares_dev_password"),
  POSTGRES_SSL: z
    .string()
    .transform((v) => v === "true")
    .default("false"),

  // ARES runtime
  ARES_MAX_ITERATIONS: z.coerce.number().int().positive().default(12),
  ARES_THREAD_ID: z.string().default("ares-default"),
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

/** Postgres connection string built from individual env vars. */
export const postgresConnectionString = (): string => {
  const { POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB } =
    env;
  return `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}`;
};
