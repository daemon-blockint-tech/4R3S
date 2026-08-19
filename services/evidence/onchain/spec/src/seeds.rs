//! PDA seeds for an evidence record.
//!
//! `[SEED_PREFIX, authority, commitment]` -- 16 + 32 + 32 bytes, well inside the
//! 16-seed / 32-byte-each limits.
//!
//! # Why the commitment is a seed
//!
//! The address becomes a binding commitment to every anchored field. The program
//! recomputes the commitment on chain from the instruction arguments and requires
//! it to equal the seed value; the runtime's own PDA check then makes it
//! impossible to land a record whose data disagrees with its address.
//!
//! That is what makes "the operator inspects the payload before signing" mean
//! something. The PDA is not an independent input they have to trust separately
//! -- it is a function of the bytes they just read.
//!
//! # Why the authority is a seed
//!
//! Two reasons, and the second is the one that matters.
//!
//! Front-running: a purely content-addressed `[PREFIX, root]` scheme is
//! grief-able. Anyone who sees a root can initialise that PDA first for about
//! 0.002 SOL, permanently denying the address and leaving the chain showing that
//! root anchored under attacker-chosen data.
//!
//! Meaning: "a root exists on chain" is worthless. "This published key asserted
//! this root" is the only version of the claim with any content at all.
//!
//! # Why not seed on the root alone
//!
//! RFC 6962's empty tree has one constant root, and a clean audit is a
//! legitimate -- arguably the more valuable -- thing to anchor. Under
//! `[PREFIX, authority, root]` the *second* clean audit could never be anchored,
//! because the address would already be taken. Seeding on the commitment fixes
//! this, since the commitment folds in the report digest and is therefore unique
//! per run.

/// First PDA seed. Bumping the version here is the only migration path a
/// non-upgradeable program has, alongside a new account discriminator.
pub const SEED_PREFIX: &[u8; 16] = b"ares-evidence-v1";

/// Number of seeds, excluding the bump.
pub const SEED_COUNT: usize = 3;
