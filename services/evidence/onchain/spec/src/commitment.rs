//! The 32 bytes an anchor records, and its preimage.
//!
//! Byte-identical to what `services/evidence/merkle.py::commitment` produces, so
//! the value the bundler prints is the value the program stores. The two are
//! pinned against each other by `tests/golden_vectors.rs` and
//! `services/evidence/test_merkle.py`.

use crate::merkle::{COMMITMENT_PREFIX, DOMAIN, HASH_SIZE, TARGET_BINDING_PREFIX};

/// Byte length of the commitment preimage: 1 + 16 + 4 + 32 + 32 + 32.
pub const PREIMAGE_LEN: usize = 117;

/// Build the commitment preimage.
///
/// `0x02 || DOMAIN || leaf_count_be || root || report_sha256 || target_binding`
///
/// Returns bytes rather than a digest so this crate stays dependency-free: the
/// program hashes it with the `sol_sha256` syscall, the host tests with `sha2`.
/// One preimage definition, two hashers, no way for them to disagree.
///
/// # Field rationale
///
/// - `leaf_count` -- without the tree size an inclusion proof is shape-malleable.
///   This is where the classic duplicate-last-leaf forgeries live.
/// - `report_sha256` -- makes the commitment unique even for an empty tree, whose
///   bare root is the same 32 bytes for every target on earth. Also binds the
///   volatile report header transitively, so an edited timestamp is detectable
///   even though it is hashed into no leaf.
/// - `target_binding` -- makes an anchor non-replayable onto a different program,
///   commit or report kind.
pub fn preimage(
    leaf_count: u32,
    root: &[u8; HASH_SIZE],
    report_sha256: &[u8; HASH_SIZE],
    target_binding: &[u8; HASH_SIZE],
) -> [u8; PREIMAGE_LEN] {
    let mut out = [0u8; PREIMAGE_LEN];
    out[0] = COMMITMENT_PREFIX;
    out[1..17].copy_from_slice(DOMAIN);
    out[17..21].copy_from_slice(&leaf_count.to_be_bytes());
    out[21..53].copy_from_slice(root);
    out[53..85].copy_from_slice(report_sha256);
    out[85..117].copy_from_slice(target_binding);
    out
}

/// Length-prefix one field: `u32` big-endian length, then the bytes.
///
/// Without this, `("ab", "c")` and `("a", "bc")` would produce the same preimage.
/// `target_name` comes from the audited repository, so part of the input is
/// attacker-shaped and boundary-shifting is a live lever rather than a
/// theoretical one.
fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// Build the target-binding preimage.
///
/// `0x03 || DOMAIN || lp(name) || lp(commit) || lp(version) || lp(program_id) || lp(kind)`
///
/// `report_kind` is included so a `confirmed` bundle cannot be presented as a
/// `scan` bundle or the reverse.
pub fn target_binding_preimage(
    target_name: &str,
    commit_hash: &str,
    ares_version: &str,
    operator_program_id: &str,
    report_kind: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(TARGET_BINDING_PREFIX);
    out.extend_from_slice(DOMAIN);
    push_lp(&mut out, target_name.as_bytes());
    push_lp(&mut out, commit_hash.as_bytes());
    push_lp(&mut out, ares_version.as_bytes());
    push_lp(&mut out, operator_program_id.as_bytes());
    push_lp(&mut out, report_kind.as_bytes());
    out
}
