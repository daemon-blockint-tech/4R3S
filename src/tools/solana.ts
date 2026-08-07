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
import { timedFetch } from "../config/timeout.js";

/** BPF Upgradeable Loader — programs owned by this are upgradeable. */
const BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";

/** Accounts owned by the System Program are plain keypairs, not PDAs. */
const SYSTEM_PROGRAM = "11111111111111111111111111111111";

/**
 * Who can replace the deployed program.
 *
 * The distinction the catalog's `upgrade-authority-risk` entry actually draws is
 * "single key" vs "multisig/timelock or renounced", not "upgradeable or not" —
 * nearly every live program is upgradeable, so flagging that alone is noise.
 *
 * `program-controlled` is deliberately not called "multisig": the owner tells us
 * the authority is a PDA rather than a keypair, which is checkable, but not that
 * the owning program enforces a threshold or a timelock. Claiming that would be
 * asserting something we did not verify.
 */
export type AuthorityKind =
  /** No upgrade authority: the program is immutable. */
  | "renounced"
  /** A plain keypair — one signature replaces the program. */
  | "single-key"
  /** Owned by some program, so a PDA. Which program, and what it enforces, is not checked here. */
  | "program-controlled";

export interface ProgramInfo {
  address: string;
  exists: boolean;
  executable: boolean;
  owner?: string;
  loader?: "upgradeable" | "legacy" | "unknown";
  dataLen?: number;
  upgradeAuthority?: string | null;
  /** How `upgradeAuthority` is held. Undefined when it could not be resolved. */
  upgradeAuthorityKind?: AuthorityKind;
  /**
   * Why `upgradeAuthorityKind` is undefined, when the reason is a failed read
   * rather than a program that has none.
   *
   * Without this the two are indistinguishable. `loadProgram` returns
   * `{exists: true, executable: true, loader: "upgradeable"}` with no `error`
   * whether the ProgramData read succeeded and found a renounced authority, or
   * timed out against a rate-limited RPC — and `authorityFindings` returns `[]`
   * for both. The caller then reports `ok`, which the report defines as "ran
   * against real input; silence here is evidence". A program whose upgrade
   * authority is a live hot key gets published as clean.
   */
  upgradeAuthorityUnresolved?: string;
  /** Owner of the upgrade-authority account, when it is `program-controlled`. */
  upgradeAuthorityOwner?: string;
  programDataAddress?: string;
  error?: string;
}

let connection: Connection | undefined;

function getConnection(): Connection {
  if (!connection) {
    const url = env.HELIUS_RPC_URL ?? env.SOLANA_RPC_URL;
    connection = new Connection(url, {
      commitment: env.SOLANA_COMMITMENT,
      // web3.js has no timeout option; the deadline goes on its fetch.
      fetch: timedFetch(env.SOLANA_TIMEOUT_MS),
    });
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
    //
    // `executable` gates the decode because three account kinds share this
    // owner — Program (executable), ProgramData and Buffer (neither) — and only
    // Program has the layout read below. On a ProgramData account bytes 4..36
    // are slot + option + the first 23 bytes of the authority, and `new
    // PublicKey` accepts any 32 bytes rather than rejecting them, so the decode
    // could not fail: it emitted a base58 address belonging to no account at
    // all. `analyze-onchain` branches only on `error` and `exists`, both fine
    // here, and JSON.stringify's the record into the analyzer prompt under "On-
    // chain program metadata (tool output)" — an invented address presented as
    // an observed on-chain fact. Pasting a ProgramData address is a normal
    // mistake; every explorer shows one on the page for an upgradeable program.
    if (loader === "upgradeable" && !acct.executable) {
      info.upgradeAuthorityUnresolved =
        "account is owned by the upgradeable loader but is not executable, so it is a ProgramData or Buffer account rather than a program";
    } else if (loader === "upgradeable" && acct.data.length < 36) {
      info.upgradeAuthorityUnresolved = `program account is ${acct.data.length} bytes, too short to point at a ProgramData account`;
    } else if (loader === "upgradeable") {
      try {
        const programDataKey = new PublicKey(acct.data.subarray(4, 36));
        info.programDataAddress = programDataKey.toBase58();
        const programData = await conn.getAccountInfo(programDataKey);
        if (!programData) {
          info.upgradeAuthorityUnresolved =
            "ProgramData account returned no data";
        } else if (programData.data.length < 45) {
          info.upgradeAuthorityUnresolved = `ProgramData account is ${programData.data.length} bytes, too short to hold an authority`;
        } else {
          // Layout: [0..4] enum, [4..12] slot, [12] option, [13..45] authority.
          const hasAuthority = programData.data[12] === 1;
          info.upgradeAuthority = hasAuthority
            ? new PublicKey(programData.data.subarray(13, 45)).toBase58()
            : null;

          if (!hasAuthority) {
            info.upgradeAuthorityKind = "renounced";
          } else {
            // One more read: a keypair authority is System-owned, a PDA is owned
            // by the program that controls it. An authority that holds no
            // lamports has no account at all, which still means a keypair.
            const authority = await conn.getAccountInfo(
              new PublicKey(info.upgradeAuthority!),
            );
            const owner = authority?.owner.toBase58();
            if (!authority || owner === SYSTEM_PROGRAM) {
              info.upgradeAuthorityKind = "single-key";
            } else {
              info.upgradeAuthorityKind = "program-controlled";
              info.upgradeAuthorityOwner = owner;
            }
          }
        }
      } catch (err) {
        // Not debug: this is the difference between "no upgrade authority" and
        // "we never found out", and the caller has to be able to say which.
        info.upgradeAuthorityUnresolved = String(err);
        logger.warn(
          { component: "solana", address, err: String(err) },
          "Could not resolve upgrade authority; on-chain result is incomplete",
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
