/**
 * Well-known Solana programs that are canonical / battle-tested.
 *
 * When the audit target matches one of these, heuristic findings are
 * automatically tagged `speculative: true` with `confidence: "low"` and
 * severity is downgraded to `info`, since pattern-matching against a
 * black-box core program produces noise rather than signal.
 */
export interface KnownProgram {
  address: string;
  name: string;
  /** Short note on why it's whitelisted. */
  note: string;
}

export const KNOWN_PROGRAMS: KnownProgram[] = [
  {
    address: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    name: "SPL Token Program",
    note: "Core Solana infrastructure, audited by Solana Labs + community.",
  },
  {
    address: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    name: "SPL Token-2022 Program",
    note: "Extension of SPL Token, maintained by Solana Labs.",
  },
  {
    address: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    name: "SPL Associated Token Account Program",
    note: "Core Solana infrastructure.",
  },
  {
    address: "11111111111111111111111111111111",
    name: "System Program",
    note: "Native Solana system program.",
  },
  {
    address: "Stake11111111111111111111111111111111111111",
    name: "Stake Program",
    note: "Native Solana staking program.",
  },
  {
    address: "Vote111111111111111111111111111111111111111",
    name: "Vote Program",
    note: "Native Solana vote program.",
  },
  {
    address: "BPFLoader1111111111111111111111111111111111",
    name: "BPF Loader (legacy)",
    note: "Native program loader.",
  },
  {
    address: "BPFLoaderUpgradeab1e11111111111111111111111",
    name: "BPF Loader (upgradeable)",
    note: "Native upgradeable program loader.",
  },
  {
    address: "ComputeBudget111111111111111111111111111111",
    name: "Compute Budget Program",
    note: "Native compute budget program.",
  },
  {
    address: "AddressLookupTab1e1111111111111111111111111",
    name: "Address Lookup Table Program",
    note: "Native ALT program.",
  },
  {
    address: "Memo1UhkJRfHyvLMhVtfkQKE3M7zXQ3RdfEzDkDqA2Kp",
    name: "Memo Program",
    note: "Native memo program.",
  },
  {
    address: "Ed25519SigVerify111111111111111111111111111",
    name: "Ed25519 Signature Verify Program",
    note: "Native signature verification program.",
  },
];

const KNOWN_SET = new Set(KNOWN_PROGRAMS.map((p) => p.address));

/** Check if a program address is a known canonical program. */
export function isKnownProgram(address: string): boolean {
  return KNOWN_SET.has(address);
}

/** Look up a known program by address. */
export function getKnownProgram(address: string): KnownProgram | undefined {
  return KNOWN_PROGRAMS.find((p) => p.address === address);
}
