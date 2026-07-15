/**
 * Solana vulnerability taxonomy — the structured catalog that drives ARES's
 * analyzers. Each entry is a vulnerability class with detection hints and
 * remediation guidance. The catalog is injected into analyzer prompts as a
 * checklist, and every finding is tagged with a catalog `id` as its `category`.
 */
import type { Severity } from "../graph/state.js";

export interface VulnEntry {
  /** Unique kebab-case identifier used as the finding `category`. */
  id: string;
  /** Human-readable title. */
  title: string;
  /** Broad category grouping (access-control, arithmetic, cpi, ...). */
  category: string;
  /** Default severity if no context-specific adjustment is made. */
  defaultSeverity: Severity;
  /** Optional CWE reference. */
  cwe?: string;
  /** What the vulnerability is and why it matters. */
  description: string;
  /** Concrete signals to look for in code / on-chain data. */
  detectionHints: string;
  /** How to fix it. */
  remediation: string;
  /** References (blog posts, audit reports, docs). */
  references: string[];
}

export const VULN_CATALOG: VulnEntry[] = [
  {
    id: "missing-signer-check",
    title: "Missing Signer Verification",
    category: "access-control",
    defaultSeverity: "high",
    cwe: "CWE-862",
    description:
      "An instruction that modifies privileged state does not verify that the expected account has signed the transaction, allowing any caller to invoke it.",
    detectionHints:
      "Look for instructions that change authority, withdraw funds, or set config without checking `AccountInfo::is_signer` or Anchor `Signer` constraint.",
    remediation:
      "Add `has_one = authority` or `Signer` constraint in Anchor; in raw programs check `account.is_signer` before proceeding.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/signer.html",
      "https://neodyme.io/blog/solana_common_security_pitfalls/",
    ],
  },
  {
    id: "missing-owner-check",
    title: "Missing Account Owner Check",
    category: "access-control",
    defaultSeverity: "high",
    cwe: "CWE-284",
    description:
      "The program does not verify that an account passed in is owned by the expected program or system program, allowing attacker-crafted accounts to be substituted.",
    detectionHints:
      "Check for `account.owner != expected_program_id` guards. In Anchor, ensure `Account<'info, T>` types are used rather than raw `AccountInfo`.",
    remediation:
      "Always validate `account.owner == id()` for PDA-derived accounts, or use Anchor's typed `Account` wrapper which enforces ownership automatically.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/accounts.html",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "account-data-matching",
    title: "Insufficient Account Data Matching",
    category: "access-control",
    defaultSeverity: "medium",
    cwe: "CWE-284",
    description:
      "The program checks account ownership but does not verify the account's data matches the expected discriminator or fields, allowing accounts of the wrong type to be used.",
    detectionHints:
      "Look for raw `AccountInfo` usage where a typed account should be expected, or missing discriminator checks in raw-BPF programs.",
    remediation:
      "Use Anchor `Account<'info, T>` which checks the discriminator, or manually verify the first 8 bytes match the expected account type.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/accounts.html",
    ],
  },
  {
    id: "arbitrary-cpi",
    title: "Arbitrary CPI (Untrusted Program Invocation)",
    category: "cpi",
    defaultSeverity: "critical",
    cwe: "CWE-913",
    description:
      "The program performs a CPI call to an address supplied by the user without verifying it is an expected program, allowing calls to arbitrary malicious programs.",
    detectionHints:
      "Search for `invoke()` or `CpiContext::new()` where the program address comes from an `AccountInfo` rather than a constant or `crate::ID`.",
    remediation:
      "Hardcode the expected program ID or verify `program.key() == EXPECTED_PROGRAM_ID` before any CPI call.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/cpi.html",
      "https://medium.com/@buffalo_joe/solana-security-cpi-attacks-2d42a35c8a6",
    ],
  },
  {
    id: "non-canonical-bump",
    title: "Non-Canonical PDA Bump Seed",
    category: "pda",
    defaultSeverity: "medium",
    cwe: "CWE-347",
    description:
      "The program accepts a PDA with a non-canonical bump seed (not the highest valid bump), which can lead to address collisions or unexpected behavior.",
    detectionHints:
      "Look for `find_program_address` results where the bump is stored from user input instead of using `Pubkey::find_program_address` canonical result.",
    remediation:
      "Always use `Pubkey::find_program_address` to get the canonical bump, or store the bump in the account and verify it on every instruction.",
    references: [
      "https://solanacookbook.com/guides/pda.html",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "pda-seed-collision",
    title: "PDA Seed Collision",
    category: "pda",
    defaultSeverity: "high",
    cwe: "CWE-347",
    description:
      "PDA seeds include user-controlled values without sufficient domain separation, allowing different logical entities to map to the same PDA.",
    detectionHints:
      "Check if PDA seeds use raw user input without a namespace or hard-coded prefix. Look for `seeds = [user.key().as_ref()]` without additional constants.",
    remediation:
      "Add hard-coded namespace seeds (e.g. `b\"vault\"`) and include all distinguishing fields in the seed derivation.",
    references: [
      "https://solanacookbook.com/guides/pda.html",
      "https://neodyme.io/blog/solana_common_security_pitfalls/",
    ],
  },
  {
    id: "account-reinitialization",
    title: "Account Reinitialization",
    category: "initialization",
    defaultSeverity: "high",
    cwe: "CWE-1236",
    description:
      "An initialize instruction does not check whether the account is already initialized, allowing an attacker to re-initialize it and overwrite critical fields like authority.",
    detectionHints:
      "Look for `init` or `initialize` instructions that don't check `account.is_initialized` or an Anchor `constraint` that the account is empty.",
    remediation:
      "Use Anchor's `init` constraint (which sets the discriminator and checks emptiness), or manually verify `account.data_len() == 0` / `!is_initialized` before initializing.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/init.html",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "missing-reload-after-cpi",
    title: "Missing Account Reload After CPI",
    category: "cpi",
    defaultSeverity: "high",
    cwe: "CWE-367",
    description:
      "The program reads account data, performs a CPI that modifies that account, then uses the stale pre-CPI data for authorization or logic decisions.",
    detectionHints:
      "Look for sequences where account fields are read before a CPI call and used after without calling `account.reload()` or re-deserializing.",
    remediation:
      "Always `account.reload()` or re-deserialize account data after any CPI that may modify it, before using it for decisions.",
    references: [
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
      "https://book.anchor-lang.com/anchor_bts/cpi.html",
    ],
  },
  {
    id: "integer-overflow-underflow",
    title: "Integer Overflow / Underflow",
    category: "arithmetic",
    defaultSeverity: "high",
    cwe: "CWE-190",
    description:
      "Arithmetic operations on token amounts, balances, or indices do not use checked math, allowing overflow/underflow to wrap values and drain funds.",
    detectionHints:
      "Search for `+`, `-`, `*` on `u64` / `u128` values without `checked_add`, `checked_sub`, `checked_mul`, or Anchor `#[accessor]` with `SafeArithmetic`.",
    remediation:
      "Use `checked_add`, `checked_sub`, `checked_mul` and handle `None` results, or use Anchor's `SafeMath` pattern.",
    references: [
      "https://doc.rust-lang.org/std/primitive.u64.html#method.checked_add",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "precision-loss",
    title: "Precision Loss in Arithmetic",
    category: "arithmetic",
    defaultSeverity: "medium",
    cwe: "CWE-1339",
    description:
      "Ordering of division and multiplication causes rounding loss that can be exploited to extract value (e.g. in AMM or reward calculations).",
    detectionHints:
      "Look for `a / b * c` patterns where reordering to `a * c / b` would reduce rounding loss, or where division happens before multiplication.",
    remediation:
      "Always multiply before dividing, use scaling factors, and consider rounding in favor of the protocol rather than the user.",
    references: [
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "account-close-revival",
    title: "Closed Account Revival",
    category: "lifecycle",
    defaultSeverity: "critical",
    cwe: "CWE-672",
    description:
      "A closed account can be revived by submitting a transaction that references it before rent reclamation, re-initializing it with attacker-controlled data.",
    detectionHints:
      "Look for close instructions that don't zero out account data or don't check a `is_closed` flag on subsequent instructions. Check for `close` without `zero` in Anchor.",
    remediation:
      "Use Anchor's `close` constraint which zeros data and transfers lamports. Add a `closed_at` or `is_closed` flag checked on re-entry.",
    references: [
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
      "https://book.anchor-lang.com/anchor_bts/close.html",
    ],
  },
  {
    id: "duplicate-mutable-account",
    title: "Duplicate Mutable Account",
    category: "access-control",
    defaultSeverity: "high",
    cwe: "CWE-1188",
    description:
      "The program accepts the same account twice (once read-only, once mutable, or both mutable) in a single instruction, allowing the duplicate to bypass checks.",
    detectionHints:
      "Look for instructions that take multiple `AccountInfo` parameters without checking they are distinct, or without Anchor `#[account(mut)]` deduplication.",
    remediation:
      "Use Anchor's `#[account(mut)]` which deduplicates, or manually assert `account_a.key() != account_b.key()` for accounts that should be distinct.",
    references: [
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
      "https://book.anchor-lang.com/anchor_bts/accounts.html",
    ],
  },
  {
    id: "missing-rent-exemption",
    title: "Missing Rent Exemption Check",
    category: "lifecycle",
    defaultSeverity: "low",
    cwe: "CWE-400",
    description:
      "An account is created or resized without ensuring it is rent-exempt, allowing it to be garbage-collected by the runtime and lose data.",
    detectionHints:
      "Look for `system::create_account` or `account.realloc()` without `Rent::is_exempt` checks.",
    remediation:
      "Always verify `rent.is_exempt(account.lamports(), account.data_len())` after creation or resize, or use Anchor's `init` which enforces this.",
    references: [
      "https://docs.solana.com/developing/programming-model/accounts#rent",
      "https://book.anchor-lang.com/anchor_bts/init.html",
    ],
  },
  {
    id: "sysvar-spoofing",
    title: "Sysvar Spoofing",
    category: "access-control",
    defaultSeverity: "high",
    cwe: "CWE-347",
    description:
      "The program accepts a sysvar (e.g. clock, rent) as a regular `AccountInfo` instead of via `Sysvar` or `Clock`, allowing an attacker to pass a fake account.",
    detectionHints:
      "Look for `Clock`, `Rent`, or `EpochSchedule` being read from `AccountInfo` rather than via `Clock::get()` or Anchor `Sysvar` constraint.",
    remediation:
      "Use `Clock::get()` / `Rent::get()` or Anchor's `Sysvar<'info, Clock>` constraint which fetches sysvars from the runtime, not from user-supplied accounts.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/sysvars.html",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "anchor-constraint-gap",
    title: "Anchor Constraint Gap",
    category: "framework",
    defaultSeverity: "medium",
    cwe: "CWE-284",
    description:
      "Anchor constraints are missing or too permissive (e.g. using `UncheckedAccount` without `#[account(address = ...)]`, or missing `has_one` / `constraint` checks).",
    detectionHints:
      "Search for `UncheckedAccount` in Anchor programs, or `AccountInfo` where a typed account should be used. Check for missing `has_one` on authority fields.",
    remediation:
      "Replace `UncheckedAccount` with typed `Account` or `Program` types, and add explicit `#[account(constraint = ...)]` or `has_one` constraints.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/accounts.html",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "unchecked-cpi-return",
    title: "Unchecked CPI Return Data",
    category: "cpi",
    defaultSeverity: "medium",
    cwe: "CWE-252",
    description:
      "The program invokes a CPI and does not check the return data or result, assuming success when the called program may have returned an error.",
    detectionHints:
      "Look for `invoke()` calls without checking the `ProgramResult`, or `CpiContext` calls without `.map_err()` handling.",
    remediation:
      "Always check the return value of CPI calls and propagate errors with `?` or explicit error handling. Use `get_return_data()` when results are expected.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/cpi.html",
    ],
  },
  {
    id: "authority-mismanagement",
    title: "Authority Mismanagement",
    category: "access-control",
    defaultSeverity: "high",
    cwe: "CWE-269",
    description:
      "Authority can be set to any value (including the system program or zero address), or there is no two-step authority transfer, allowing permanent lockout or takeover.",
    detectionHints:
      "Look for `set_authority` instructions that accept any `Pubkey` without validation, or missing `has_one = authority` on the set-authority instruction itself.",
    remediation:
      "Implement a two-step authority transfer (propose + accept). Validate the new authority is not zero or the system program. Use `has_one` on the set-authority instruction.",
    references: [
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
  {
    id: "oracle-price-manipulation",
    title: "Oracle Price Manipulation",
    category: "oracle",
    defaultSeverity: "high",
    cwe: "CWE-20",
    description:
      "The program reads a price from an on-chain oracle without checking staleness, confidence bands, or using TWAP, allowing flash-loan-style manipulation.",
    detectionHints:
      "Look for direct `price` reads from Switchboard / Pyth accounts without checking `confidence_interval`, `staleness`, or using a TWAP.",
    remediation:
      "Use Pyth/Switchboard SDK helpers that validate staleness and confidence. Consider TWAP for price feeds used in critical decisions.",
    references: [
      "https://docs.pyth.network/documentation/pyth-client-price-feeds/best-practices",
      "https://docs.switchboard.xyz/",
    ],
  },
  {
    id: "insecure-init-order",
    title: "Insecure Initialization Order",
    category: "initialization",
    defaultSeverity: "medium",
    cwe: "CWE-696",
    description:
      "Accounts or configuration are initialized in an order that allows an attacker to front-run and initialize with attacker-controlled values.",
    detectionHints:
      "Look for `init` instructions that don't check the initializer is the expected deployer/authority, or that can be called by anyone.",
    remediation:
      "Restrict `init` instructions with `has_one = authority` or `Signer` constraints on the deployer. Use Anchor's `init` with `payer = authority`.",
    references: [
      "https://book.anchor-lang.com/anchor_bts/init.html",
    ],
  },
  {
    id: "spl-authority-check",
    title: "SPL Token Authority Check Bypass",
    category: "spl",
    defaultSeverity: "high",
    cwe: "CWE-284",
    description:
      "The program interacts with SPL Token accounts without properly verifying the authority/owner of the token account, allowing unauthorized transfers or mints.",
    detectionHints:
      "Look for `spl_token::transfer` or `mint_to` calls where the `authority` is taken from user-supplied `AccountInfo` without verifying it matches the token account owner.",
    remediation:
      "Use Anchor's `TokenAccount` and `Mint` types which verify ownership. In raw programs, check `token_account.owner == expected_authority` before any SPL operation.",
    references: [
      "https://spl.solana.com/token",
      "https://blog.trailofbits.com/2023/04/11/solana-common-pitfalls/",
    ],
  },
];

/** Set of all valid catalog ids for fast lookup. */
export const VULN_IDS: Set<string> = new Set(VULN_CATALOG.map((v) => v.id));

/** Look up a catalog entry by id. */
export function getVuln(id: string): VulnEntry | undefined {
  return VULN_CATALOG.find((v) => v.id === id);
}

/** Returns true if `id` is a valid catalog vulnerability id. */
export function isVulnId(id: string): boolean {
  return VULN_IDS.has(id);
}

/**
 * Format the catalog as a compact numbered checklist for prompt injection.
 * Each line: `N. <id> — <title> (<one-line detection hint>)`.
 */
export function formatChecklistForPrompt(): string {
  return VULN_CATALOG.map(
    (v, i) =>
      `${i + 1}. ${v.id} — ${v.title} (${v.detectionHints.split(". ")[0]})`,
  ).join("\n");
}
