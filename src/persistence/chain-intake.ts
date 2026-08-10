/**
 * Chain-intake persistence.
 *
 * `tools/solana.ts` reads a program account from Helius (or the default RPC)
 * once per audit and discards the result when the run ends. This module keeps
 * those reads: one row per (address, fetch) so a later run can reuse a recent
 * read instead of paying for another RPC round-trip, and so there is a record
 * of what the chain looked like at the moment a finding was made.
 *
 * ## Staleness is the whole problem
 *
 * On-chain state changes. An upgrade authority can be renounced, transferred to
 * a multisig, or handed to a fresh keypair between two audits of the same
 * program. A cached read is therefore a claim about the present derived from
 * the past, and serving one as if it were fresh would put a false statement
 * into a report with no error and no warning attached.
 *
 * So `recall` never returns a row on its own terms: it returns the row plus its
 * age, and refuses rows older than the caller's stated tolerance. A caller that
 * wants to report an upgrade authority as current has to ask for a tolerance
 * tight enough to justify that, and gets nothing rather than something stale.
 * `services/cve/snapshot/manifest.json` reaches the same conclusion for its own
 * snapshot ("only the manifest's revision field tells a reader which snapshot a
 * stored result came from"); this is that idea applied per-row.
 *
 * ## Postgres here is not like Supabase elsewhere
 *
 * `persistence/knowledge-writer.ts` can ask `hasSupabase()` because Supabase
 * credentials are absent until someone sets them. Postgres has defaults in
 * `config/env.ts` (`localhost`, `ares`, …), so it is *always* nominally
 * configured and "is it configured" is not an answerable question — only "did
 * the connection work". Every function here therefore treats an unreachable
 * database as a miss, logs once, and lets the audit continue. Chain-intake
 * caching is an optimisation; it must never be the reason an audit fails.
 */
import { Pool } from "pg";

import { env, postgresConnectionString } from "../config/env.js";
import { logger } from "../config/logger.js";
import type { ProgramInfo } from "../tools/solana.js";

/** Which RPC produced a row. Recorded because the two are not interchangeable. */
export type RpcSource = "helius" | "default";

/** A stored read, with the age that determines whether it is usable. */
export interface CachedIntake {
  address: string;
  program: ProgramInfo;
  rpcSource: RpcSource;
  fetchedAt: Date;
  /** Milliseconds between `fetchedAt` and the moment of the lookup. */
  ageMs: number;
}

let pool: Pool | undefined;
let poolFailed = false;

/**
 * Lazily create the connection pool.
 *
 * Returns `undefined` once a connection has failed, so a database that is not
 * running costs one failed attempt per process rather than one per audit. The
 * flag is deliberately not reset on a timer: a run that started without
 * Postgres should behave consistently for its whole duration rather than
 * silently switching to cached reads partway through and producing findings
 * that came from two different regimes.
 */
function getPool(): Pool | undefined {
  if (poolFailed) return undefined;
  if (pool) return pool;
  try {
    pool = new Pool({
      connectionString: postgresConnectionString(),
      connectionTimeoutMillis: env.POSTGRES_TIMEOUT_MS,
      max: 4,
    });
    pool.on("error", (err) => {
      // An idle-client error does not mean the next query fails, so this does
      // not set poolFailed — it would turn one transient blip into a
      // process-lifetime opt-out of caching.
      logger.warn(
        { component: "chain-intake", err: err.message },
        "Postgres pool error (idle client); caching continues",
      );
    });
    return pool;
  } catch (err) {
    poolFailed = true;
    logger.warn(
      { component: "chain-intake", err: err instanceof Error ? err.message : String(err) },
      "Could not create Postgres pool; chain-intake caching disabled for this process",
    );
    return undefined;
  }
}

/** DDL for the table. Idempotent, so the migrate script can run it every time. */
export const CHAIN_INTAKE_DDL = `
CREATE TABLE IF NOT EXISTS chain_intake (
  id          BIGSERIAL PRIMARY KEY,
  address     TEXT        NOT NULL,
  rpc_source  TEXT        NOT NULL CHECK (rpc_source IN ('helius', 'default')),
  payload     JSONB       NOT NULL,
  run_id      TEXT,
  fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lookups are always "the most recent read for this address", so the index is
-- on (address, fetched_at DESC) rather than address alone.
CREATE INDEX IF NOT EXISTS chain_intake_address_fetched_idx
  ON chain_intake (address, fetched_at DESC);
`;

/**
 * Create the table if it does not exist.
 *
 * Returns whether the schema is ready. A false result is not fatal: callers
 * degrade to uncached RPC reads.
 */
export async function ensureChainIntakeSchema(): Promise<boolean> {
  const p = getPool();
  if (!p) return false;
  try {
    await p.query(CHAIN_INTAKE_DDL);
    return true;
  } catch (err) {
    logger.warn(
      { component: "chain-intake", err: err instanceof Error ? err.message : String(err) },
      "Could not create chain_intake schema; caching disabled",
    );
    return false;
  }
}

/**
 * Store one read. Rows accumulate rather than being upserted: an audit trail
 * that overwrites the previous value cannot answer "what did this look like
 * when that finding was made", which is half the reason to keep it.
 */
export async function recordIntake(
  program: ProgramInfo,
  rpcSource: RpcSource,
  runId?: string,
): Promise<boolean> {
  const p = getPool();
  if (!p) return false;
  try {
    await p.query(
      `INSERT INTO chain_intake (address, rpc_source, payload, run_id)
       VALUES ($1, $2, $3::jsonb, $4)`,
      [program.address, rpcSource, JSON.stringify(program), runId ?? null],
    );
    return true;
  } catch (err) {
    logger.warn(
      {
        component: "chain-intake",
        address: program.address,
        err: err instanceof Error ? err.message : String(err),
      },
      "Could not record chain intake; the audit is unaffected",
    );
    return false;
  }
}

/**
 * Most recent stored read for `address`, if one is fresh enough.
 *
 * `maxAgeMs` is required rather than defaulted. A default would let a caller
 * reuse a read without having decided how old is too old for what it is about
 * to claim, which is the failure this module exists to prevent — and the
 * tolerance that suits "has this program been seen before" (hours) is not the
 * one that suits "who can upgrade it right now" (minutes, if at all).
 */
/**
 * Whether a row of the given age may be served under the given tolerance.
 *
 * Extracted as a pure function because it could not otherwise be tested: inside
 * `recallIntake` the unreachable-database check runs first, so with no Postgres
 * every tolerance returns a miss and a test asserting on the tolerance passes
 * for the wrong reason. Mutation testing caught exactly that — deleting the
 * zero-tolerance guard left the suite green.
 *
 * `maxAgeMs <= 0` means "tolerate no staleness", which reads as "do not use the
 * cache". A bare `ageMs > maxAgeMs` would not honour that: a row fetched in the
 * same millisecond gives `0 > 0`, false, and would be served.
 */
export function isWithinTolerance(ageMs: number, maxAgeMs: number): boolean {
  if (maxAgeMs <= 0) return false;
  return ageMs <= maxAgeMs;
}

export async function recallIntake(
  address: string,
  maxAgeMs: number,
): Promise<CachedIntake | undefined> {
  // Checked before touching the pool so a caller that asked for a live read
  // does not pay a connection attempt to be told what it already specified.
  if (!isWithinTolerance(0, maxAgeMs)) return undefined;

  const p = getPool();
  if (!p) return undefined;
  try {
    const res = await p.query<{
      address: string;
      rpc_source: string;
      payload: ProgramInfo;
      fetched_at: Date;
    }>(
      `SELECT address, rpc_source, payload, fetched_at
         FROM chain_intake
        WHERE address = $1
        ORDER BY fetched_at DESC
        LIMIT 1`,
      [address],
    );

    const row = res.rows[0];
    if (!row) return undefined;

    // Age is computed against the row's timestamp rather than filtered in SQL
    // with `now() - interval`, so the age travels with the result and a caller
    // can put it in a report instead of implying the read was live.
    const ageMs = Date.now() - row.fetched_at.getTime();
    if (!isWithinTolerance(ageMs, maxAgeMs)) {
      logger.debug(
        { component: "chain-intake", address, ageMs, maxAgeMs },
        "Cached chain intake rejected as stale",
      );
      return undefined;
    }

    // rpc_source is CHECK-constrained in the DDL, but a row written by an older
    // schema (or by hand) could still hold something else. Narrowing here keeps
    // a bad row from being presented to callers as a valid RpcSource.
    const rpcSource: RpcSource =
      row.rpc_source === "helius" || row.rpc_source === "default"
        ? row.rpc_source
        : "default";
    if (rpcSource !== row.rpc_source) {
      logger.warn(
        { component: "chain-intake", address, stored: row.rpc_source },
        "Stored rpc_source is not a recognised value; treating as 'default'",
      );
    }

    return { address: row.address, program: row.payload, rpcSource, fetchedAt: row.fetched_at, ageMs };
  } catch (err) {
    logger.warn(
      {
        component: "chain-intake",
        address,
        err: err instanceof Error ? err.message : String(err),
      },
      "Could not read chain intake; falling through to a live RPC read",
    );
    return undefined;
  }
}

/** Close the pool. Call on shutdown; safe to call when no pool was created. */
export async function closeChainIntake(): Promise<void> {
  if (!pool) return;
  const p = pool;
  pool = undefined;
  await p.end();
}

/** Reset module state. Test-only — production has one pool per process. */
export function __resetChainIntakeForTests(): void {
  pool = undefined;
  poolFailed = false;
}
