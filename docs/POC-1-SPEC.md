# POC-1 — PoC generator spec (draft)

**Status:** draft, not yet reviewed/ACK'd. Written ahead of ENG-1 so that once
Michael lands "Pull ARES-v3 as `core/`; green build + 54 tests," this becomes a
wiring task instead of a design task. **Nothing here is final** — the id scheme
and field set may need to reconcile with whatever contract ENG-1 actually lands
with (see [Open questions](#open-questions-for-eng-1-reconciliation)).

**Scope:** a deterministic transform — no LLM, no network, no randomness (core
crate rule, `core/README.md`) — from an Anchor IDL instruction fragment to a
safe, redacted **PoC instruction object**. Lives in the planned `core/poc` crate
(does not exist yet; scaffolded by ENG-1).

Grounded against the 11 real fixtures produced for EVAL-3:
`eval/mappings/sealevel-attacks.json` + `eval/fixtures/idl/sealevel-attacks/*.json`.
Every rule below was checked against all 11, not just the worked examples shown.

## Input: Anchor IDL instruction fragment

One instruction from an Anchor IDL (`instructions[]` array element), plus the
IDL's `name` (program name) and a `provenance` triple supplied by the caller
(source path / idl version / commit) since the IDL file itself doesn't carry that.

```json
{
  "name": "logMessage",
  "accounts": [
    { "name": "authority", "isMut": false, "isSigner": false }
  ],
  "args": []
}
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Instruction name, camelCase (Anchor convention). |
| `accounts[].name` | yes | Account name, camelCase. |
| `accounts[].isMut` | yes | Account is written to. |
| `accounts[].isSigner` | yes | Account must sign the transaction. |
| `args[].name` | yes (if any args) | Argument name. |
| `args[].type` | yes (if any args) | Raw Rust/Anchor type (`u64`, `u8`, `publicKey`, ...). |

## Output: PoC instruction object

```json
{
  "id": "string (sha256(program:instruction:argTypes)[:12])",
  "canonical_target": "string (program:instruction)",
  "vector": "string (one-line description of the exploitable path)",
  "parameters": [{ "name": "string", "type": "normalized type" }],
  "preconditions": ["string"],
  "payload_template": "<PAYLOAD_TEMPLATE_REDACTED>",
  "expected_effect": "string (simulated, non-actionable)",
  "detection_signatures": ["string"],
  "provenance": { "source_path": "string", "idl_version": "string", "commit": "string" },
  "tags": ["string"],
  "severity_hint": "info|low|medium|high|critical"
}
```

`severity_hint` uses the existing `Severity` type (`src/knowledge/finding.ts`) —
same vocabulary as `Finding.severity`, not a new scale. `payload_template` is
**always** the literal string `<PAYLOAD_TEMPLATE_REDACTED>` — this object never
carries an executable payload.

## Deterministic mapping rules

1. **`canonical_target`** = `` `${idl.name}:${instruction.name}` ``.
   Caveat: every sealevel-attacks fixture shares the same placeholder
   `declare_id!` pubkey, so the IDL's `name` string (not a program address) is
   the only meaningful differentiator here. A real mainnet target would key on
   the program's deployed address instead — worth resolving before this scheme
   is trusted for anything beyond this synthetic corpus.

2. **`id`** = first 12 hex chars of `sha256(canonical_target + ":" + argTypes.join(","))`.
   Same content-addressing style already used in `eval/fetch_sealevel_attacks.py`'s
   `content_digest` and in `fetch_datasets.py`'s `target_ids` — deterministic,
   stable across reorderings.

3. **`preconditions`** — one entry per account, in IDL order:
   - `isSigner: true` → `"requires signer {name}"`
   - `isMut: true` → `"account {name} writable"`
   - An account can contribute both entries; an account with neither flag
     contributes none.

4. **`parameters`** — each arg's type normalized:

   | Raw type | Normalized |
   |---|---|
   | `u8`,`u16`,`u32`,`u64`,`u128`,`usize`,`i8`…`i128` | `int` |
   | `publicKey` / `Pubkey` | `address` |
   | `bytes`, `Vec<u8>` | `bytes` |
   | `bool` | `bool` |
   | `string` | `string` |
   | anything else | passed through raw, flagged `"normalized": false` |

5. **`detection_signatures`** and **`expected_effect`** — derived from what the
   instruction actually *does* to its accounts (from the source, not from
   name-matching heuristics — name-matching is fragile, e.g. `update_user` in
   fixture 3 only reads and logs, it never writes):
   - Instruction invokes a **CPI to a known transfer-capable program**
     (`spl_token::instruction::transfer`, `token::transfer`, etc.) →
     `detection_signatures: ["<program> CPI log", "balance delta on <account> (simulated)"]`,
     `expected_effect: "simulated balance delta via CPI, no real transfer executed"`.
   - Instruction **writes account lamports directly** (not via CPI) →
     `detection_signatures: ["lamport delta on <account> (simulated)"]`,
     `expected_effect: "simulated lamport transfer/zeroing, no real transfer executed"`.
   - Instruction **writes account data** (serializes new state into an account) →
     `detection_signatures: ["account data mutation on <account> (simulated), state hash before/after"]`,
     `expected_effect: "simulated state overwrite on <account>, no persisted change"`.
   - Instruction only **reads/logs** →
     `detection_signatures: []`, `expected_effect: "no state change (read-only instruction)"`.

6. **`vector`** — one line combining the mapped `VULN_CATALOG` category (from
   `eval/mappings/sealevel-attacks.json` for this corpus) with the specific
   missing/weak check, e.g. `"unauthorized action via missing signer check on {account}"`.

7. **`tags`** = `["solana", "anchor", "<category>"]`.

8. **`severity_hint`** = the `VULN_CATALOG` `defaultSeverity` for the mapped
   category (same source `eval/mappings/sealevel-attacks.json` already uses for
   `ground_truth.csv`).

## Worked examples

Three chosen for diversity: read-only/missing-signer (simplest), CPI+args
(most complex), direct-lamport-mutation (different mutation class).

### `0-signer-authorization` — missing signer check

Input (`eval/fixtures/idl/sealevel-attacks/0-signer-authorization.json`):
```json
{ "name": "logMessage", "accounts": [{ "name": "authority", "isMut": false, "isSigner": false }], "args": [] }
```

Output:
```json
{
  "id": "5e18fa8c7a12",
  "canonical_target": "signer_authorization_insecure:logMessage",
  "vector": "unauthorized action via missing signer check on authority",
  "parameters": [],
  "preconditions": [],
  "payload_template": "<PAYLOAD_TEMPLATE_REDACTED>",
  "expected_effect": "no state change (read-only instruction)",
  "detection_signatures": [],
  "provenance": {
    "source_path": "eval/fixtures/idl/sealevel-attacks/0-signer-authorization.json",
    "idl_version": "0.0.0",
    "commit": "24555d044802db4022112a94d6d70e74291a4b6d"
  },
  "tags": ["solana", "anchor", "missing-signer-check"],
  "severity_hint": "high"
}
```
Note: `preconditions` is empty because `authority` is `isSigner:false` — that
absence *is* the vulnerability (rule 3 has nothing to emit). The finding
itself lives in `vector`, not in a missing precondition; a downstream
fork-validator step (POC-2) is what actually proves an unsigned call succeeds.

### `5-arbitrary-cpi` — unchecked CPI target, with args

Input:
```json
{
  "name": "cpi",
  "accounts": [
    { "name": "source", "isMut": true, "isSigner": false },
    { "name": "destination", "isMut": true, "isSigner": false },
    { "name": "authority", "isMut": false, "isSigner": false },
    { "name": "tokenProgram", "isMut": false, "isSigner": false }
  ],
  "args": [{ "name": "amount", "type": "u64" }]
}
```

Output:
```json
{
  "id": "73d744f8a921",
  "canonical_target": "arbitrary_cpi_insecure:cpi",
  "vector": "unchecked CPI target (tokenProgram) allows invoking an attacker-controlled program",
  "parameters": [{ "name": "amount", "type": "int" }],
  "preconditions": ["account source writable", "account destination writable"],
  "payload_template": "<PAYLOAD_TEMPLATE_REDACTED>",
  "expected_effect": "simulated balance delta via CPI, no real transfer executed",
  "detection_signatures": ["tokenProgram CPI log", "balance delta on source/destination (simulated)"],
  "provenance": {
    "source_path": "eval/fixtures/idl/sealevel-attacks/5-arbitrary-cpi.json",
    "idl_version": "0.0.0",
    "commit": "24555d044802db4022112a94d6d70e74291a4b6d"
  },
  "tags": ["solana", "anchor", "arbitrary-cpi"],
  "severity_hint": "critical"
}
```

### `9-closing-accounts` — direct lamport mutation, account revival risk

Input:
```json
{
  "name": "close",
  "accounts": [
    { "name": "account", "isMut": true, "isSigner": false },
    { "name": "destination", "isMut": true, "isSigner": false }
  ],
  "args": []
}
```

Output:
```json
{
  "id": "7d6c8e742f02",
  "canonical_target": "closing_accounts_insecure:close",
  "vector": "lamport drain without data zeroing/discriminator burn allows account revival",
  "parameters": [],
  "preconditions": ["account account writable", "account destination writable"],
  "payload_template": "<PAYLOAD_TEMPLATE_REDACTED>",
  "expected_effect": "simulated lamport transfer/zeroing, no real transfer executed",
  "detection_signatures": ["lamport delta on account (simulated)", "lamport delta on destination (simulated)"],
  "provenance": {
    "source_path": "eval/fixtures/idl/sealevel-attacks/9-closing-accounts.json",
    "idl_version": "0.0.0",
    "commit": "24555d044802db4022112a94d6d70e74291a4b6d"
  },
  "tags": ["solana", "anchor", "account-close-revival"],
  "severity_hint": "critical"
}
```

## Open questions for ENG-1 reconciliation

These are guesses made to keep this spec concrete; they need Michael's/the
engine owner's confirmation once ENG-1's actual contract exists — flagged so
review is fast, not a surprise:

1. **`canonical_target` keying** — program *name* string (used here) vs.
   deployed program *address* (what a real mainnet audit target would need).
   This corpus can't distinguish them (shared placeholder pubkey across all 11
   fixtures), so this spec picked the only option available, not necessarily
   the right one for production targets.
2. **`id` scheme** — whether ENG-1's canonical-ID mapping (per the original
   ENG-1 acceptance criteria: "~50 sample mappings or deterministic rule") is
   meant to *replace* this content-hash id, or sit alongside it as a separate
   namespace.
3. **Field set completeness** — this spec's 11 fields match the original
   Notion description of POC-1. ENG-1's actual JSON Schema (once it exists)
   may require more fields for the broader non-Solana (HTTP/gRPC) input
   classes mentioned in its acceptance criteria; this spec is Solana/Anchor-only.

## Where this lives once ENG-1 lands

Per `core/README.md`, the real implementation goes in the **`poc` crate**
(planned, one of `mapper`/`cli`/`poc`/`fork-validator`/`trident`) — Rust,
deterministic, no LLM. This markdown spec plus the 11 worked-example fixtures
in `eval/fixtures/idl/sealevel-attacks/` are the reference inputs/outputs to
port against; POC-2 (`fork_validator`) consumes this object's output next.
