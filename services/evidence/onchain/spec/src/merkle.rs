//! RFC 6962 Merkle constants and proof verification, generic over the hasher.
//!
//! Generic over `H` so this module stays dependency-free: the program supplies
//! the `sol_sha256` syscall, the host tests supply `sha2`. One implementation,
//! two hashers, no way for them to disagree about the construction.
//!
//! These constants must match `services/evidence/merkle.py` exactly, and both
//! are pinned by `services/evidence/vectors/merkle_vectors.json`.

/// Domain tag. Exactly 16 bytes, so it needs no length prefix of its own.
///
/// Bumping this is how a v2 leaf encoding is version-gated: it changes every
/// hash in the scheme, so a v1 proof can never be replayed against a v2 root.
pub const DOMAIN: &[u8; 16] = b"ares.evidence.v1";

/// Prefix for a leaf hash.
pub const LEAF_PREFIX: u8 = 0x00;
/// Prefix for an internal node hash.
pub const NODE_PREFIX: u8 = 0x01;
/// Prefix for the anchored commitment.
pub const COMMITMENT_PREFIX: u8 = 0x02;
/// Prefix for the target binding.
pub const TARGET_BINDING_PREFIX: u8 = 0x03;

/// Length of a SHA-256 digest.
pub const HASH_SIZE: usize = 32;

/// Which side a proof sibling sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is the left child; the accumulator is the right.
    Left,
    /// Sibling is the right child; the accumulator is the left.
    Right,
}

/// `MTH({})` -- SHA-256 of the empty string.
///
/// Carries neither the leaf nor the node prefix, so an empty tree's root cannot
/// be confused with either. A clean audit is a legitimate thing to anchor, and
/// 178 of the 636 reports in the local corpus produce no leaves at all, so this
/// is the common case rather than an edge case.
pub const EMPTY_ROOT: [u8; HASH_SIZE] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Preimage of a leaf hash: `0x00 || DOMAIN || payload`.
pub fn leaf_preimage(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + DOMAIN.len() + payload.len());
    out.push(LEAF_PREFIX);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(payload);
    out
}

/// Preimage of an internal node hash: `0x01 || DOMAIN || left || right`.
///
/// The prefixes are what give second-preimage resistance. Without them,
/// `H(L||R)` for a node is drawn from the same distribution as `H(x)` for a leaf
/// `x = L||R`, so an internal node could be presented as a leaf and used to
/// prove inclusion of data that was never a leaf -- a fabricated finding backed
/// by a real anchored root.
pub fn node_preimage(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; 81] {
    let mut out = [0u8; 81];
    out[0] = NODE_PREFIX;
    out[1..17].copy_from_slice(DOMAIN);
    out[17..49].copy_from_slice(left);
    out[49..81].copy_from_slice(right);
    out
}

/// RFC 6962's `k`: the largest power of two strictly less than `n`.
///
/// Returns `None` for `n < 2`, where `k` is undefined.
pub fn largest_pow2_below(n: u32) -> Option<u32> {
    if n < 2 {
        return None;
    }
    Some(1u32 << (u32::BITS - 1 - (n - 1).leading_zeros()))
}

/// The sibling sides on the audit path for `index`, derived from the shape alone.
///
/// Exists so no verifier has to trust the positions a prover supplied. A
/// position array is an attacker-controlled degree of freedom, and RFC 6962's
/// unbalanced shape makes index-to-side derivation the error-prone part -- which
/// is exactly the part that must not be delegated to the prover.
///
/// Returns `None` if `index` is out of range for `leaf_count`.
pub fn derive_sides(index: u32, leaf_count: u32) -> Option<Vec<Side>> {
    if index >= leaf_count {
        return None;
    }
    let mut sides = Vec::new();
    let mut n = leaf_count;
    let mut m = index;
    // Descend, recording the side at each split, then reverse: the audit path is
    // ordered deepest-sibling-first.
    while n > 1 {
        let k = largest_pow2_below(n)?;
        if m < k {
            sides.push(Side::Right);
            n = k;
        } else {
            sides.push(Side::Left);
            m -= k;
            n -= k;
        }
    }
    sides.reverse();
    Some(sides)
}

/// Verify an inclusion proof, re-deriving the sibling sides rather than trusting
/// the ones supplied.
///
/// `hasher` is the SHA-256 implementation: the syscall on chain, `sha2` in tests.
///
/// # What `leaf_count` does and does not buy
///
/// It rejects a proof whose sibling sides disagree with the shape implied by
/// `(index, leaf_count)` -- real, since for index 4 the path is `[Left]` at n=5
/// but `[Right, Left]` at n=6. It does **not** make every wrong count
/// detectable: for index 0 the path is `[Right; 3]` at both n=5 and n=6. That is
/// inherent to any bare inclusion check, because the root recomputes from
/// whatever siblings were supplied.
///
/// What closes it is [`commitment::preimage`](crate::commitment::preimage)
/// binding `leaf_count` together with the root, so a verifier compares the pair
/// against the anchored value instead of trusting either alone.
pub fn verify_inclusion<H>(
    leaf_payload: &[u8],
    index: u32,
    leaf_count: u32,
    proof: &[([u8; HASH_SIZE], Side)],
    expected_root: &[u8; HASH_SIZE],
    hasher: H,
) -> bool
where
    H: Fn(&[u8]) -> [u8; HASH_SIZE],
{
    let Some(expected_sides) = derive_sides(index, leaf_count) else {
        return false;
    };
    if proof.len() != expected_sides.len() {
        return false;
    }
    if proof.iter().map(|(_, s)| *s).ne(expected_sides) {
        return false;
    }

    let mut acc = hasher(&leaf_preimage(leaf_payload));
    for (sibling, side) in proof {
        acc = match side {
            Side::Left => hasher(&node_preimage(sibling, &acc)),
            Side::Right => hasher(&node_preimage(&acc, sibling)),
        };
    }
    &acc == expected_root
}
