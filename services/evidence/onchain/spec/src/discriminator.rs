//! Anchor instruction discriminator for `anchor_evidence`.
//!
//! Anchor derives it as `sha256("global:" + snake_case(name))[..8]`. The same
//! algorithm is already implemented and golden-verified elsewhere in this
//! repository, at `core/crates/ares-cli/src/idl.rs:84-96`.
//!
//! Hardcoded here as a constant with a test that recomputes it -- the same
//! golden-constant pattern `idl.rs` uses. That keeps this crate dependency-free
//! while still proving the constant is right.

/// Preimage Anchor hashes to derive the instruction discriminator.
pub const INSTRUCTION_PREIMAGE: &str = "global:anchor_evidence";

/// First 8 bytes of `sha256(INSTRUCTION_PREIMAGE)`.
///
/// Recomputed and asserted in `tests/golden_vectors.rs`, so this literal cannot
/// silently be wrong.
pub const INSTRUCTION_DISCRIMINATOR: [u8; 8] = [0x77, 0x74, 0xd4, 0x21, 0x36, 0x8a, 0xc2, 0xa5];

/// Preimage Anchor hashes to derive the *account* discriminator.
///
/// # This is an assumption, not a verified fact
///
/// The `sha256("account:" + StructName)[..8]` scheme is Anchor-version
/// dependent, and no `syn` parse can verify a macro expansion. It is recorded
/// here so a future task with the toolchain installed can check it, and
/// `anchor-lang` must stay pinned to an exact version until then.
pub const ACCOUNT_PREIMAGE: &str = "account:RecordV1";
