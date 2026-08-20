# evidence_registry — on-chain anchoring for ARES evidence bundles

Records the 32-byte commitment from an evidence bundle on Solana, so the
commitment is timestamped by a clock the auditor does not control.

**Status: program source + host-target spec tests. Never compiled to SBF, never
deployed, no cluster anchor exists. Reject-path behaviour is asserted at the
declaration level only.**

That is not hedging. There is no `solana` CLI, no `anchor` CLI and no
`cargo build-sbf` in this repository's CI or on the machine this was written on,
so `anchor/programs/evidence_registry/src/lib.rs` has never been built. What is
mechanically checked is the *specification* it implements. Read "What CI actually
proves" below before treating a green badge as evidence the program works.

## Layout

```
spec/     WORKSPACE A — zero dependencies, the only thing CI builds.
          Seeds, account layout offsets, commitment preimage, discriminator,
          and RFC 6962 proof verification generic over the hasher.
anchor/   WORKSPACE B — never built. The Anchor program: a thin #[program] +
          #[derive(Accounts)] + #[account] wrapper over spec/.
```

Two workspaces, not one, and that is the load-bearing decision. If `spec` were a
member of the anchor workspace, `cargo test -p evidence-registry-spec` would
still have to **resolve** the `anchor-lang` → `solana-program` graph — which needs
the registry index and is exposed to toolchain drift under a floating `stable`.
Split, the CI job resolves a manifest with zero `[dependencies]` and is immune to
Anchor and Solana churn by construction.

Neither lives under `core/`. Three *required* status checks run cargo over that
tree on every Rust PR, and being wrong about one cargo subtlety there would red
every PR in the repository. Placing it under `core/` would also buy no gating:
dependabot's `/core` entry does not descend into a nested independent workspace,
and `cargo deny --manifest-path core/Cargo.toml` does not see a non-member.

## What an anchor proves

The holder of `authority` published this `(root, leaf_count, report_sha256,
target_binding)` tuple in a transaction included at some slot. Anyone with an
archival RPC can confirm the account's contents and its creation slot
independently. Because the PDA seeds bind every one of those fields into the
address, the record cannot be internally inconsistent — and because there is no
`update` and no `close`, it cannot be altered *if* the upgrade authority has been
renounced.

That is **an upper bound on when the root was known.** Nothing more.

## What an anchor does not prove

1. **Not that the audit happened, was competent, or was complete.** The chain sees
   32 bytes. It cannot distinguish a real audit from `sha256(random)`.
2. **Not that findings were not withheld.** The root commits to the leaves that
   were *included*. You can prove a finding **was** in the committed set; you can
   never prove one was not held back before anchoring. Absence from the tree is
   not evidence of absence in the code.
3. **Not that `authority` is ARES.** Key-to-identity binding is entirely
   off-chain and is a single point of failure. Publishing a key in a README is a
   claim, not a proof.
4. **Not that the root concerns the claimed target.** `target_binding` is
   self-asserted, and the report carries no program id at all — `scan.rs:102,104`
   hardcode `repository_url: None` and `program_id: None`. Anyone can anchor any
   root claiming any target for about 0.002 SOL. Only the authority's reputation
   constrains this.
5. **Not a lower bound on time.** The root may have existed for years before
   being anchored.
6. **Not that the findings are reproducible.** The engine version lives in the
   target binding but is self-asserted.
7. **Not durable on its own — the root is useless without the leaves.** If the
   bundle is lost, the anchor is 32 bytes of noise. Anchoring without a durable,
   retrievable bundle store is theatre, and this is the likeliest way the feature
   becomes worthless in practice.
8. **Not a notary.** No legal timestamping claim, at all.

## The one attack the design does mitigate, and how

A dishonest auditor can anchor several variant bundles cheaply and later reveal
whichever suits them. Anchoring cannot prevent that. It can make it *detectable*,
but only because the design is permissionless, immutable and enumerable — so the
verifier procedure has to be:

1. `getProgramAccounts(PROGRAM_ID, { dataSize: 157, filters: [memcmp(8, authority), memcmp(104, target_binding)] })`
2. Assert **exactly one** record. More than one means this authority anchored
   multiple roots for one target — treat as disqualifying until explained.
3. Recompute the commitment from the record body and re-derive the PDA; assert it
   equals the fetched address.
4. Recompute `report_sha256` from the report bytes; assert it matches offset 72.
5. Recompute `root` from the bundle's leaves; assert it matches offset 40 and that
   `leaf_count` matches offset 136.
6. Verify the inclusion proof **against the anchored `leaf_count`**, not a locally
   inferred one.
7. Read the program's upgrade authority and assert it is renounced — *and* that
   renunciation predates the anchoring slot.

Steps 2, 3 and 7 are the ones people skip, and each one silently voids the claim.

## The upgrade-authority kicker

Every immutability claim above is conditional on the program being
non-upgradeable. An upgrade authority can deploy a version with an
arbitrary-write instruction and rewrite or delete any record. So:

- `solana program set-upgrade-authority --final` must happen **before the first
  real anchor**, and `solana program show <ID>` must report `Authority: none`.
- Renouncing later does not retroactively secure earlier anchors, because a
  different binary may have been deployed in the interim. Anchors made while
  upgradeable are worth strictly less, permanently.
- `src/tools/solana.ts:34-38` already classifies exactly this
  (`renounced` / `single-key` / `program-controlled`), and
  `upgrade-authority-risk` is in ARES's own vulnerability catalog. **An
  ARES-authored program that stays upgradeable fails ARES's own detector.** That
  is the argument that should settle it internally.
- Accept the consequence: **final means v1 is forever.** No layout fix, no bug
  fix. That is the strongest possible argument for the minimal instruction set,
  and for a real localnet pass before any mainnet deploy.

## Account model

One account type, one PDA, immutable.

```
seeds = [ b"ares-evidence-v1", authority, commitment ]
commitment = sha256(0x02 || DOMAIN || leaf_count_be || root
                    || report_sha256 || target_binding)
```

The address is a binding commitment to every anchored field: the program
recomputes `commitment` on chain and requires it to equal the seed value, and the
runtime's own PDA check then makes it impossible to land a record whose data
disagrees with its address. That is what makes "inspect the payload before
signing" mean something — the PDA is not an independent input to trust, it is a
function of the bytes just read.

`authority` is in the seeds for two reasons. It kills front-running: a
content-addressed `[PREFIX, root]` scheme lets anyone who sees a root claim that
PDA first for ~0.002 SOL. And it makes the claim mean something — "a root exists
on chain" is worthless; "this key asserted this root" is not.

Seeding on the commitment rather than the root also fixes a real collision: RFC
6962's empty tree has one constant root, and 178 of the 636 reports in the local
corpus produce no leaves at all. Under `[PREFIX, authority, root]` the *second* clean
audit could never be anchored.

| offset | field | type | len |
|---|---|---|---|
| 0 | discriminator | `[u8;8]` | 8 |
| 8 | `authority` | `Pubkey` | 32 |
| 40 | `root` | `[u8;32]` | 32 |
| 72 | `report_sha256` | `[u8;32]` | 32 |
| 104 | `target_binding` | `[u8;32]` | 32 |
| 136 | `leaf_count` | `u32` | 4 |
| 140 | `slot` | `u64` | 8 |
| 148 | `unix_timestamp` | `i64` | 8 |
| 156 | `bump` | `u8` | 1 |

`ACCOUNT_LEN = 157`. Field order is part of the contract — the verifier
procedure's `memcmp` offsets depend on it.

Deliberate omissions: no `reserved` padding (the account is immutable, so
reserved bytes could never be filled — they would be rent paid forever for a
false signal of extensibility); no `update`, `close` or `set_authority` (an
anchor that can change is not an anchor, and a `close` makes it deniable, so the
rent is permanently spent — the right trade, stated rather than hidden); no
`schema_version` (the root is useless without the bundle, and the bundle already
states its own `schema` and `leaf_encoding`, so duplicating it on chain would
cost rent forever to record something the reader necessarily already has — the
domain tag is the version gate).

`Clock::get()` is the syscall, never a sysvar account: passing `Clock` as an
account is `sysvar-spoofing` in ARES's own catalog. Nothing the submitter says
about time is stored — no timestamp argument, no slot argument. The clock is the
only input the submitter does not control, and that is the entire mechanical
value of an anchor.

**Residual hazard:** standard Anchor `init` fails if the PDA is pre-funded, so
whoever learns a commitment before submission can permanently deny that one
address. Because the commitment covers the report digest, the address is
unpredictable until the bundle is published. **Operational rule: anchor before
publishing the bundle.**

## What CI actually proves

Four layers, each with a different failure mode. Together they are real
mechanical evidence about the **specification** — they are not evidence the
program works.

1. **Zero-dependency Rust, host-tested** (`spec/tests/golden_vectors.rs`, 22
   tests). Constants, offsets, preimages, and RFC 6962 proof verification. The
   adversarial cases are where the value is: a proof valid at n=5 must fail at
   n=6 where the path shape differs; `[a,b,c]` and `[a,b,c,c]` must not collide
   (CVE-2012-2459); a leaf and an internal node over the same bytes must hash
   differently.
2. **`syn` conformance against the un-compilable program**
   (`spec/tests/program_source_conformance.rs`, 15 tests). `include_str!`s the
   Anchor source and parses it as data — the same pattern
   `core/crates/ares-core/src/lib.rs` uses for its generated catalog and
   `core/crates/ares-cli/src/poc.rs:707-722` uses to prove a property of Rust it
   cannot compile. Asserts the `RecordV1` field list and order match the layout
   table, `space = 8 + 149`, the seed expression element for element, that `bump`
   takes no argument, that `init_if_needed` appears nowhere, that no `update` or
   `close` exists, and that every documented `require!` is present.
3. **Lockfile subset** (`spec/tests/lockfile_subset.rs`). Asserts every resolved
   dependency already appears in `core/Cargo.lock`. `cargo-deny` in `ci.yml` is
   pinned to `manifest-path: core/Cargo.toml` and `cargo-audit` runs only in
   `core/`, so nothing here is otherwise gated; a strict subset cannot introduce a
   crate those two have not already cleared. Corollary: **no dependabot entry for
   these manifests** — a bump here would break the invariant until core bumped
   too, producing permanently-red PRs.
4. **An independent PDA oracle** (`scripts/evidence-pda-vectors.test.ts`). Checks
   the hand-rolled ed25519 on-curve arithmetic in `anchor_payload.py` against
   `PublicKey.findProgramAddressSync` from `@solana/web3.js` — an implementation
   nobody here wrote — and re-implements RFC 6962 a third time in a third
   language against the same shared vectors.

### What none of it covers

- **That the program compiles to SBF.** It has never been compiled at all.
- **That Anchor's macros expand to the assumed layout.** The account
  discriminator preimage `sha256("account:RecordV1")[..8]` is an
  Anchor-version-dependent assumption; `anchor-lang` is pinned to `=0.31.1` and a
  `syn` parse cannot verify a macro expansion.
- **Every reject path — the security-relevant half.** The host tests verify the
  constraints are *declared*. They cannot verify the runtime *enforces* them.
  "We asserted the constraint is declared" is a bounded, honest claim. "The
  program rejects overwrites" is not provable until `anchor test` runs.
- Rent, compute budget, transaction size, `Clock` behaviour, and the
  `getProgramAccounts` offsets against a real node.
- **The `anchor/` workspace has no committed `Cargo.lock` and is outside every
  gate.** Expect it to fail `core/deny.toml` as written: the Solana tree
  historically pulls `ring` (not SPDX-clean at `confidence-threshold = 0.9`) and
  can pull git dependencies, which `unknown-git = "deny"` rejects outright. That
  fight belongs to the BPF task with its own `deny.toml`. **Do not pre-emptively
  widen `core/deny.toml`.**

## Submitting an anchor

`services/evidence/anchor_payload.py` emits an **unsigned** request. It never
signs, never opens a keypair file, never contacts an RPC endpoint and never
submits a transaction.

```bash
python anchor_payload.py <bundle>.evidence.json \
  --authority <YOUR BASE58 PUBLIC KEY> \
  --program-id <DEPLOYED PROGRAM ID> \
  --cluster mainnet-beta
```

`--cluster` is required, with no default. Devnet is periodically **reset**, so a
devnet anchor is destroyed while looking identical to a real one — a silent
devnet default would manufacture worthless anchors that read as evidence. A
silent mainnet default would spend real SOL irreversibly.

It emits an **instruction, not a transaction**: a serialised transaction needs a
recent blockhash that expires in 60–90 seconds, and a payload meant to be read
carefully by a human cannot carry a live blockhash.

### Verify before signing

1. `sha256` of `instruction.discriminator_preimage` — first 8 bytes must equal
   `instruction.discriminator_hex`.
2. `sha256` of `commitment.preimage_hex` must equal `commitment.hex`, and the six
   `preimage_segments` must equal the values in `anchored`.
3. `solana find-program-derived-address <PROGRAM_ID> string:ares-evidence-v1 pubkey:<AUTHORITY> hex:<COMMITMENT>`
   must equal `pda.address` and `pda.bump`. (The exact subcommand spelling was
   not verified here — no `solana` CLI was available.)
4. `anchored.merkle_root` must equal `recomputed.merkle_root`, which this tool
   re-derived from the bundle's leaves rather than copying from its root field.
5. `solana program show <PROGRAM_ID>` — confirm it exists, is executable, and its
   authority is what you expect.
6. `accounts[1].pubkey` must be your own wallet's `solana address`.

Step 3 buys a lot: because the program recomputes the commitment on chain and the
runtime enforces the seeds, **a payload whose data disagrees with its address
cannot land.**

### The practical gap

**There is no `solana` CLI subcommand that submits an arbitrary instruction.**
Offline signing and durable nonces exist, but none of them accept a raw
instruction. The realistic paths:

- **Production: a Squads-style multisig.** Import the base64 instruction, review,
  threshold-sign, execute. This is the right answer anyway — it gives a published,
  stable authority identity and removes the single hot key. A vault PDA satisfies
  `Signer` via `invoke_signed`.
- **Development: a short `@solana/web3.js` snippet** the operator runs on their
  own machine with their own keypair. This repository commits no signing code.
- **Truly offline: a durable nonce account.** Deferred.

## Deferred work

Everything requiring `solana` / `anchor` / `cargo build-sbf`:

```bash
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
cargo install --git https://github.com/coral-xyz/anchor avm --locked --force
avm install 0.31.1 && avm use 0.31.1

# OPERATOR ONLY -- a private key. Never committed, never generated by CI or an agent.
solana-keygen new -o anchor/target/deploy/evidence_registry-keypair.json
solana address -k anchor/target/deploy/evidence_registry-keypair.json
# paste into declare_id! and Anchor.toml; the conformance test's
# `the_program_id_is_still_the_documented_placeholder` then needs updating

cd anchor
anchor build
anchor test                 # localnet; the reject-path suite lands here

# the gates the anchor/ lockfile currently escapes
cargo deny --manifest-path anchor/Cargo.toml check licenses bans sources
cargo audit --file anchor/Cargo.lock

# deploy and renounce, in this order, before the first real anchor
solana program deploy --url mainnet-beta target/deploy/evidence_registry.so
solana program set-upgrade-authority --final <PROGRAM_ID>
solana program show <PROGRAM_ID>       # must print "Authority: none"
```

Reject-path tests only `anchor test` can write: re-anchoring the same commitment
fails; an unsigned authority fails; a caller-supplied non-canonical bump fails; a
mismatched commitment fails; zero root / digest / binding fails; the pre-funded
PDA behaviour is characterised; `Clock` values land in the record; the
`getProgramAccounts` offsets really filter.

Also deferred: manual `allocate`+`assign` init hardening; the durable-nonce
offline ceremony; a `rust-toolchain.toml` in `anchor/` for SBF reproducibility
(**do not** add one now — it would force a rustup download on every dev machine
for a build nobody runs).

## Tests

```bash
cd spec && cargo fmt --all -- --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked
```

40 tests: 22 golden vectors, 15 source conformance, 3 lockfile subset.
