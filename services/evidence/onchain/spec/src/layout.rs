//! Byte layout of the `RecordV1` account.
//!
//! Borsh applies no alignment padding, so offsets are simply declaration order.
//! `tests/program_source_conformance.rs` parses the Anchor program's source and
//! asserts its field list matches this table exactly, which is what keeps the two
//! from drifting while neither can be compiled here.
//!
//! # Field order is part of the contract
//!
//! `authority` at 8, `root` at 40 and `target_binding` at 104 are chosen so a
//! verifier can filter with `getProgramAccounts` using `dataSize` plus two
//! `memcmp`s. That procedure is how a reader detects an authority that anchored
//! several different roots for one target, so these offsets are load-bearing
//! rather than incidental.
//!
//! # No reserved padding
//!
//! Reserved bytes exist so a later version can fill them. This account is
//! immutable, so they never could be -- they would be rent paid forever for a
//! false signal of extensibility. Versioning is a new struct name (hence a new
//! account discriminator) plus a new `SEED_PREFIX`, which is the only migration
//! path available to a program whose upgrade authority has been renounced.

/// Anchor's account discriminator occupies the first 8 bytes.
pub const DISCRIMINATOR_LEN: usize = 8;

/// One field in the account layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Field name, matching the Rust struct field in the program.
    pub name: &'static str,
    /// Offset from the start of the account data, discriminator included.
    pub offset: usize,
    /// Length in bytes.
    pub len: usize,
    /// The Rust type as written in the program, for the conformance check.
    pub ty: &'static str,
}

/// The complete layout, in declaration order.
///
/// `slot` and `unix_timestamp` both come from `Clock::get()`. Nothing the
/// submitter says about time is stored: there is no timestamp argument and no
/// slot argument. The clock is the only input the submitter does not control,
/// and that is the entire mechanical value of an anchor.
pub const FIELDS: &[Field] = &[
    Field {
        name: "authority",
        offset: 8,
        len: 32,
        ty: "Pubkey",
    },
    Field {
        name: "root",
        offset: 40,
        len: 32,
        ty: "[u8; 32]",
    },
    Field {
        name: "report_sha256",
        offset: 72,
        len: 32,
        ty: "[u8; 32]",
    },
    Field {
        name: "target_binding",
        offset: 104,
        len: 32,
        ty: "[u8; 32]",
    },
    Field {
        name: "leaf_count",
        offset: 136,
        len: 4,
        ty: "u32",
    },
    Field {
        name: "slot",
        offset: 140,
        len: 8,
        ty: "u64",
    },
    Field {
        name: "unix_timestamp",
        offset: 148,
        len: 8,
        ty: "i64",
    },
    Field {
        name: "bump",
        offset: 156,
        len: 1,
        ty: "u8",
    },
];

/// Serialised length of the struct fields, excluding the discriminator. This is
/// what `#[account]`'s `space = 8 + ...` adds to.
pub const FIELDS_LEN: usize = 149;

/// Total account size: discriminator plus fields -- the `space` an `init` must
/// request from the System program.
pub const ACCOUNT_LEN: usize = DISCRIMINATOR_LEN + FIELDS_LEN;

/// Offsets a `getProgramAccounts` verifier filters on.
pub mod filter_offset {
    /// Offset of `authority`, for a per-authority memcmp filter.
    pub const AUTHORITY: usize = 8;
    /// Offset of `root`.
    pub const ROOT: usize = 40;
    /// Offset of `target_binding`, for a per-target memcmp filter.
    pub const TARGET_BINDING: usize = 104;
}
