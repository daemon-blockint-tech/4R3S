/**
 * The upgradeable loader owns three different account kinds and only one of
 * them is a program, so `loadProgram` is exercised here against a real
 * JSON-RPC server serving real account bytes. The defect this covers is a
 * mis-decode of those bytes; a hand-built ProgramInfo would assert nothing
 * about it.
 *
 * The server is local and the RPC URL is set before the tool module is loaded,
 * because `getConnection` reads it from the frozen env at first use.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { PublicKey } from "@solana/web3.js";
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const SYSTEM = "11111111111111111111111111111111";

const key = (fill: number) => new PublicKey(Buffer.alloc(32, fill));
const PROGRAM = key(11);
const PROGRAM_DATA = key(22);
const AUTHORITY = key(33);

interface Account {
  owner: string;
  executable: boolean;
  data: Buffer;
}

/** `[0..4] enum, [4..36] programdata_address` — the only kind with that layout. */
function programAccount(): Account {
  const data = Buffer.alloc(36);
  data.writeUInt32LE(2, 0);
  PROGRAM_DATA.toBuffer().copy(data, 4);
  return { owner: LOADER, executable: true, data };
}

/** `[0..4] enum, [4..12] slot, [12] option, [13..45] authority` — not a program. */
function programDataAccount(): Account {
  const data = Buffer.alloc(200);
  data.writeUInt32LE(3, 0);
  data.writeBigUInt64LE(123n, 4);
  data[12] = 1;
  AUTHORITY.toBuffer().copy(data, 13);
  return { owner: LOADER, executable: false, data };
}

let server: Server;
let loadProgram: typeof import("./solana.js").loadProgram;

beforeAll(async () => {
  const accounts = new Map<string, Account>([
    [PROGRAM.toBase58(), programAccount()],
    [PROGRAM_DATA.toBase58(), programDataAccount()],
    [
      AUTHORITY.toBase58(),
      { owner: SYSTEM, executable: false, data: Buffer.alloc(0) },
    ],
  ]);

  server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const rpc = JSON.parse(body) as { id: number; params?: unknown[] };
      const address = String(rpc.params?.[0] ?? "");
      const account = accounts.get(address);
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            context: { apiVersion: "2.1.0", slot: 1 },
            value: account
              ? {
                  data: [account.data.toString("base64"), "base64"],
                  executable: account.executable,
                  lamports: 1,
                  owner: account.owner,
                  rentEpoch: 0,
                  space: account.data.length,
                }
              : null,
          },
        }),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  // `getConnection` reads `HELIUS_RPC_URL ?? SOLANA_RPC_URL`, so leaving the
  // former set points this test at a real third-party RPC provider and the
  // synthetic addresses below simply miss. Clear it: the endpoint under test has
  // to be the one this file is serving, whatever the ambient environment holds.
  delete process.env.HELIUS_RPC_URL;
  process.env.SOLANA_RPC_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  ({ loadProgram } = await import("./solana.js"));
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe("loadProgram against the upgradeable loader's account kinds", () => {
  it("resolves the ProgramData account and authority of a real program", async () => {
    const info = await loadProgram(PROGRAM.toBase58());
    expect(info.exists).toBe(true);
    expect(info.executable).toBe(true);
    expect(info.loader).toBe("upgradeable");
    expect(info.programDataAddress).toBe(PROGRAM_DATA.toBase58());
    expect(info.upgradeAuthority).toBe(AUTHORITY.toBase58());
    expect(info.upgradeAuthorityKind).toBe("single-key");
    expect(info.upgradeAuthorityUnresolved).toBeUndefined();
  });

  // Pasting a ProgramData address is an ordinary mistake — every explorer shows
  // one on the page for an upgradeable program. Its bytes 4..36 are slot +
  // option + the first 23 bytes of the authority, and `new PublicKey` accepts
  // any 32 bytes, so the decode could not fail: it produced a base58 address
  // that corresponds to no account, which `analyze-onchain` then hands to the
  // model under "On-chain program metadata (tool output)" as observed fact.
  it("invents no programDataAddress for a ProgramData account", async () => {
    const info = await loadProgram(PROGRAM_DATA.toBase58());
    expect(info.exists).toBe(true);
    expect(info.executable).toBe(false);
    expect(info.programDataAddress).toBeUndefined();
    expect(info.upgradeAuthority).toBeUndefined();
    expect(info.upgradeAuthorityUnresolved).toMatch(/not executable/);
  });
});
