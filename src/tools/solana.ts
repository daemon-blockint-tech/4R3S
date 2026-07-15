/**
 * Solana on-chain tool.
 *
 * Loads a program account (via Helius RPC when configured, else the default
 * Solana RPC) and returns a compact, LLM-friendly description of what's on
 * chain: whether the address is an executable program, its loader/owner, data
 * size, and — for upgradeable programs — the program data account and upgrade
 * authority. Invalid addresses and RPC errors are reported, not thrown.
 */
import { Connection, PublicKey } from "@solana/web3.js";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

/** BPF Upgradeable Loader — programs owned by this are upgradeable. */
const BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";

export interface ProgramInfo {
  address: string;
  exists: boolean;
  executable: boolean;
  owner?: string;
  loader?: "upgradeable" | "legacy" | "unknown";
  dataLen?: number;
  upgradeAuthority?: string | null;
  programDataAddress?: string;
  error?: string;
}

let connection: Connection | undefined;

function getConnection(): Connection {
  if (!connection) {
    const url = env.HELIUS_RPC_URL ?? env.SOLANA_RPC_URL;
    connection = new Connection(url, env.SOLANA_COMMITMENT);
    logger.debug(
      { component: "solana", helius: Boolean(env.HELIUS_RPC_URL) },
      "Solana connection created",
    );
  }
  return connection;
}

/** Fetch and summarize a program account. Never throws. */
export async function loadProgram(address: string): Promise<ProgramInfo> {
  let pubkey: PublicKey;
  try {
    pubkey = new PublicKey(address);
  } catch {
    return { address, exists: false, executable: false, error: "invalid address" };
  }

  try {
    const conn = getConnection();
    const acct = await conn.getAccountInfo(pubkey);
    if (!acct) {
      return { address, exists: false, executable: false };
    }

    const owner = acct.owner.toBase58();
    const loader =
      owner === BPF_UPGRADEABLE_LOADER
        ? "upgradeable"
        : acct.executable
          ? "legacy"
          : "unknown";

    const info: ProgramInfo = {
      address,
      exists: true,
      executable: acct.executable,
      owner,
      loader,
      dataLen: acct.data.length,
    };

    // For upgradeable programs, the account data points at a ProgramData
    // account holding the bytecode + upgrade authority.
    if (loader === "upgradeable" && acct.data.length >= 36) {
      try {
        const programDataKey = new PublicKey(acct.data.subarray(4, 36));
        info.programDataAddress = programDataKey.toBase58();
        const programData = await conn.getAccountInfo(programDataKey);
        if (programData && programData.data.length >= 45) {
          // Layout: [0..4] enum, [4..12] slot, [12] option, [13..45] authority.
          const hasAuthority = programData.data[12] === 1;
          info.upgradeAuthority = hasAuthority
            ? new PublicKey(programData.data.subarray(13, 45)).toBase58()
            : null;
        }
      } catch (err) {
        logger.debug(
          { component: "solana", err: String(err) },
          "Could not resolve program data account",
        );
      }
    }

    return info;
  } catch (err) {
    logger.warn(
      { component: "solana", address, err: String(err) },
      "Failed to load program from RPC",
    );
    return { address, exists: false, executable: false, error: String(err) };
  }
}
