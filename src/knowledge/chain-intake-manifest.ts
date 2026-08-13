/**
 * Chain-intake manifest.
 *
 * A JSON record of what one audit read from chain, written next to the run's
 * other artifacts. It exists so a reader of a report can answer "where did the
 * on-chain facts in this come from, and when" without access to the database —
 * the same job `services/cve/snapshot/manifest.json` does for the advisory
 * snapshot, and the shape here deliberately mirrors it (`generated_by`,
 * timestamps, and a `notes` array that states limitations rather than leaving
 * them for the reader to discover).
 *
 * The notes are not boilerplate. Every one of them is a statement a reader
 * would otherwise have to guess at, and getting any of them wrong changes how
 * much weight the report deserves.
 */
import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import { logger } from "../config/logger.js";
import type { ProgramInfo } from "../tools/solana.js";
import type { RpcSource } from "../persistence/chain-intake.js";

/** One address as it was read during this run. */
export interface ManifestEntry {
  address: string;
  /** Where this particular read came from. */
  origin: "live-rpc" | "cache";
  rpcSource: RpcSource;
  /** ISO 8601. For a cached entry this is when the *original* read happened. */
  fetchedAt: string;
  /** Age at the moment it was used, for cached entries. */
  ageMsAtUse?: number;
  exists: boolean;
  executable: boolean;
  upgradeAuthorityKind?: ProgramInfo["upgradeAuthorityKind"];
  /** Present when the read failed or was incomplete. */
  error?: string;
}

export interface ChainIntakeManifest {
  generated_by: string;
  generated_at: string;
  run_id?: string;
  entry_count: number;
  entries: ManifestEntry[];
  notes: string[];
}

/** Build a manifest entry from a program read. */
export function manifestEntry(
  program: ProgramInfo,
  origin: ManifestEntry["origin"],
  rpcSource: RpcSource,
  fetchedAt: Date,
  ageMsAtUse?: number,
): ManifestEntry {
  return {
    address: program.address,
    origin,
    rpcSource,
    fetchedAt: fetchedAt.toISOString(),
    ...(ageMsAtUse === undefined ? {} : { ageMsAtUse }),
    exists: program.exists,
    executable: program.executable,
    ...(program.upgradeAuthorityKind === undefined
      ? {}
      : { upgradeAuthorityKind: program.upgradeAuthorityKind }),
    ...(program.error === undefined ? {} : { error: program.error }),
  };
}

/**
 * Notes that apply to every manifest.
 *
 * Written as fixed text rather than assembled conditionally so that a reader
 * comparing two manifests sees the same caveats in both, and so a caveat cannot
 * silently disappear because a branch did not fire.
 */
function standardNotes(entries: readonly ManifestEntry[]): string[] {
  const cached = entries.filter((e) => e.origin === "cache");
  const notes = [
    "On-chain state is mutable. Every field here describes the account at its " +
      "fetchedAt timestamp, not at the time this manifest was read. An upgrade " +
      "authority in particular can be renounced or transferred at any time.",
    "upgradeAuthorityKind 'program-controlled' means the authority is a PDA, " +
      "which is checkable. It does NOT mean a multisig or timelock: whether the " +
      "owning program enforces a threshold was not verified.",
    "An entry with exists=true and no error is not evidence that every field " +
      "was resolved — see the error field and tools/solana.ts for which reads " +
      "can fail independently of the main account read.",
    "This manifest records reads, not findings. It says nothing about whether " +
      "anything was wrong with the programs listed.",
  ];

  if (cached.length > 0) {
    notes.push(
      `${cached.length} of ${entries.length} entries were served from the ` +
        "chain_intake cache rather than a live RPC call. Their fetchedAt is the " +
        "original read time and ageMsAtUse is how stale the value already was " +
        "when this run used it.",
    );
  } else {
    // Stated explicitly rather than omitted: absence of a cache note otherwise
    // reads as "no caching happened" when it could equally mean the writer
    // forgot to mention it.
    notes.push("All entries came from live RPC reads; none were served from cache.");
  }

  return notes;
}

/** Assemble a manifest. Pure — does no IO, so it is cheap to assert against. */
export function buildManifest(
  entries: readonly ManifestEntry[],
  runId?: string,
): ChainIntakeManifest {
  return {
    generated_by: "src/knowledge/chain-intake-manifest.ts",
    generated_at: new Date().toISOString(),
    ...(runId === undefined ? {} : { run_id: runId }),
    entry_count: entries.length,
    entries: [...entries],
    notes: standardNotes(entries),
  };
}

/**
 * Write a manifest to disk.
 *
 * Returns whether the write succeeded. A failed manifest write is logged and
 * reported, never thrown: the audit's findings are already computed by the time
 * this runs, and losing the provenance record is worse than losing the audit
 * only if the audit is then presented as if the record existed. Callers should
 * surface a false return rather than ignore it.
 */
export async function writeManifest(
  path: string,
  manifest: ChainIntakeManifest,
): Promise<boolean> {
  try {
    await mkdir(dirname(path), { recursive: true });
    // Trailing newline: these files are read with `cat` and diffed in review.
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    logger.info(
      { component: "chain-intake", path, entries: manifest.entry_count },
      "Chain-intake manifest written",
    );
    return true;
  } catch (err) {
    logger.warn(
      {
        component: "chain-intake",
        path,
        err: err instanceof Error ? err.message : String(err),
      },
      "Could not write chain-intake manifest",
    );
    return false;
  }
}
