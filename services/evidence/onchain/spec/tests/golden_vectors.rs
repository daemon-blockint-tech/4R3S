//! The Rust half of the cross-language contract.
//!
//! Asserts against `services/evidence/vectors/merkle_vectors.json` -- the same
//! file `services/evidence/test_merkle.py` and `scripts/evidence-pda-vectors.test.ts`
//! assert against. Nothing may be added to the `core/` cargo workspace, so a
//! shared vector file is the only mechanism available for proving three
//! independent implementations agree.
//!
//! These tests hash with `sha2`; the program hashes with the `sol_sha256`
//! syscall. The preimage functions in `evidence_registry_spec` are shared, so
//! there is one definition of what gets hashed and two implementations of the
//! hashing itself.

use evidence_registry_spec::merkle::{self, Side, HASH_SIZE};
use evidence_registry_spec::{commitment, discriminator, layout, seeds};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn vectors() -> serde_json::Value {
    // ../../../vectors/ from services/evidence/onchain/spec/
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/merkle_vectors.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read the shared vectors at {path}: {e}"));
    serde_json::from_str(&raw).expect("vectors are not valid JSON")
}

/// Lowercase hex, so this crate needs no `hex` dependency and the lockfile stays
/// a subset of core's.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Independent oracle: RFC 6962 section 2.1, transcribed recursively.
fn ref_root(leaves: &[Vec<u8>]) -> [u8; HASH_SIZE] {
    match leaves.len() {
        0 => merkle::EMPTY_ROOT,
        1 => sha256(&merkle::leaf_preimage(&leaves[0])),
        n => {
            let k = merkle::largest_pow2_below(n as u32).unwrap() as usize;
            let left = ref_root(&leaves[..k]);
            let right = ref_root(&leaves[k..]);
            sha256(&merkle::node_preimage(&left, &right))
        }
    }
}

fn payloads(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

/// RFC 6962 PATH(m, D[n]), with the sibling side recorded.
fn ref_path(leaves: &[Vec<u8>], m: usize) -> Vec<([u8; HASH_SIZE], Side)> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let k = merkle::largest_pow2_below(leaves.len() as u32).unwrap() as usize;
    if m < k {
        let mut path = ref_path(&leaves[..k], m);
        path.push((ref_root(&leaves[k..]), Side::Right));
        path
    } else {
        let mut path = ref_path(&leaves[k..], m - k);
        path.push((ref_root(&leaves[..k]), Side::Left));
        path
    }
}

#[test]
fn the_domain_tag_is_exactly_sixteen_bytes() {
    // It carries no length prefix of its own, so a change in width would make
    // the preimage ambiguous.
    assert_eq!(merkle::DOMAIN.len(), 16);
    assert_eq!(merkle::DOMAIN, b"ares.evidence.v1");
}

#[test]
fn the_empty_root_constant_is_sha256_of_the_empty_string() {
    assert_eq!(merkle::EMPTY_ROOT, sha256(b""));
    assert_eq!(
        hex(&merkle::EMPTY_ROOT),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn the_prefixes_are_distinct_and_pinned() {
    assert_eq!(merkle::LEAF_PREFIX, 0x00);
    assert_eq!(merkle::NODE_PREFIX, 0x01);
    assert_eq!(merkle::COMMITMENT_PREFIX, 0x02);
    assert_eq!(merkle::TARGET_BINDING_PREFIX, 0x03);
}

#[test]
fn a_leaf_and_a_node_over_the_same_bytes_hash_differently() {
    // The RFC 6962 second-preimage property: without distinct prefixes, an
    // internal node could be presented as a leaf.
    let left = [7u8; 32];
    let right = [9u8; 32];
    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&left);
    concatenated.extend_from_slice(&right);

    let as_leaf = sha256(&merkle::leaf_preimage(&concatenated));
    let as_node = sha256(&merkle::node_preimage(&left, &right));
    assert_ne!(as_leaf, as_node);
}

#[test]
fn largest_pow2_below_matches_the_rfc_definition() {
    assert_eq!(merkle::largest_pow2_below(0), None);
    assert_eq!(merkle::largest_pow2_below(1), None);
    assert_eq!(merkle::largest_pow2_below(2), Some(1));
    assert_eq!(merkle::largest_pow2_below(3), Some(2));
    // Strictly less than n, so n=4 gives 2 rather than 4.
    assert_eq!(merkle::largest_pow2_below(4), Some(2));
    assert_eq!(merkle::largest_pow2_below(5), Some(4));
    assert_eq!(merkle::largest_pow2_below(8), Some(4));
    assert_eq!(merkle::largest_pow2_below(9), Some(8));
}

#[test]
fn roots_match_the_shared_python_vectors() {
    let v = vectors();
    let by_count = &v["roots_by_leaf_count"];
    for n in 0..=8usize {
        let expected = by_count[n.to_string()].as_str().expect("missing vector");
        let got = hex(&ref_root(&payloads(n)));
        assert_eq!(got, expected, "root disagrees at n={n}");
    }
}

#[test]
fn leaf_hashes_match_the_shared_python_vectors() {
    let v = vectors();
    for (payload, expected) in v["leaf_hashes"].as_object().unwrap() {
        let got = hex(&sha256(&merkle::leaf_preimage(payload.as_bytes())));
        assert_eq!(&got, expected.as_str().unwrap(), "leaf hash for {payload}");
    }
}

#[test]
fn the_malleability_vector_confirms_rfc6962_not_bitcoin() {
    // Under Bitcoin's duplicate-last rule these two roots are EQUAL, which would
    // mean one root attesting to two different finding sets (CVE-2012-2459).
    let v = vectors();
    let three = payloads(3);
    let mut four = payloads(3);
    four.push(payloads(3)[2].clone());

    let abc = hex(&ref_root(&three));
    let abcc = hex(&ref_root(&four));
    assert_ne!(abc, abcc);
    assert_eq!(abc, v["malleability_check"]["abc_root"].as_str().unwrap());
    assert_eq!(abcc, v["malleability_check"]["abcc_root"].as_str().unwrap());
}

#[test]
fn inclusion_proofs_match_the_shared_python_vectors() {
    let v = vectors();
    let leaves = payloads(5);
    let root = ref_root(&leaves);

    for entry in v["inclusion_proofs_n5"].as_array().unwrap() {
        let index = entry["index"].as_u64().unwrap() as usize;
        let path = ref_path(&leaves, index);
        let published = entry["proof"].as_array().unwrap();
        assert_eq!(path.len(), published.len(), "proof length at index {index}");

        for (step, want) in path.iter().zip(published) {
            let side = match step.1 {
                Side::Left => "left",
                Side::Right => "right",
            };
            assert_eq!(side, want["position"].as_str().unwrap());
            assert_eq!(hex(&step.0), want["hash"].as_str().unwrap());
        }

        assert!(merkle::verify_inclusion(
            &leaves[index],
            index as u32,
            5,
            &path,
            &root,
            sha256
        ));
    }
}

#[test]
fn every_leaf_verifies_for_every_tree_size_up_to_forty() {
    for n in 1..=40usize {
        let leaves = payloads(n);
        let root = ref_root(&leaves);
        for m in 0..n {
            let path = ref_path(&leaves, m);
            assert!(
                merkle::verify_inclusion(&leaves[m], m as u32, n as u32, &path, &root, sha256),
                "n={n} m={m}"
            );
            let cap = if n <= 1 {
                0
            } else {
                (n as u32 - 1).ilog2() as usize + 1
            };
            assert!(path.len() <= cap, "proof too long at n={n} m={m}");
        }
    }
}

#[test]
fn a_proof_with_flipped_sides_does_not_verify() {
    let leaves = payloads(5);
    let root = ref_root(&leaves);
    let flipped: Vec<_> = ref_path(&leaves, 0)
        .into_iter()
        .map(|(h, s)| {
            (
                h,
                match s {
                    Side::Left => Side::Right,
                    Side::Right => Side::Left,
                },
            )
        })
        .collect();
    assert!(!merkle::verify_inclusion(
        &leaves[0], 0, 5, &flipped, &root, sha256
    ));
}

#[test]
fn a_truncated_proof_does_not_verify() {
    let leaves = payloads(8);
    let root = ref_root(&leaves);
    let mut path = ref_path(&leaves, 0);
    path.pop();
    assert!(!merkle::verify_inclusion(
        &leaves[0], 0, 8, &path, &root, sha256
    ));
}

#[test]
fn a_wrong_leaf_count_is_rejected_where_the_path_shape_differs() {
    // The half of the leaf_count binding that re-deriving sides does buy.
    let leaves = payloads(5);
    let root = ref_root(&leaves);
    let path = ref_path(&leaves, 4);
    assert_eq!(merkle::derive_sides(4, 5), Some(vec![Side::Left]));
    assert_eq!(
        merkle::derive_sides(4, 6),
        Some(vec![Side::Right, Side::Left])
    );
    assert!(!merkle::verify_inclusion(
        &leaves[4], 4, 6, &path, &root, sha256
    ));
}

#[test]
fn a_wrong_leaf_count_is_not_caught_where_the_path_shape_coincides() {
    // The half it does NOT buy, documented rather than assumed. For index 0 the
    // path is [Right; 3] at both n=5 and n=6, so the count is not detectable from
    // the proof alone. What closes it is the commitment binding leaf_count
    // together with the root -- see the next test.
    let leaves = payloads(5);
    let root = ref_root(&leaves);
    let path = ref_path(&leaves, 0);
    assert_eq!(merkle::derive_sides(0, 5), merkle::derive_sides(0, 6));
    assert!(merkle::verify_inclusion(
        &leaves[0], 0, 6, &path, &root, sha256
    ));
}

#[test]
fn the_commitment_binds_the_leaf_count_together_with_the_root() {
    let root = ref_root(&payloads(5));
    let digest = sha256(b"report");
    let binding = sha256(b"binding");
    let five = sha256(&commitment::preimage(5, &root, &digest, &binding));
    let six = sha256(&commitment::preimage(6, &root, &digest, &binding));
    assert_ne!(five, six);
}

#[test]
fn derive_sides_rejects_an_out_of_range_index() {
    assert_eq!(merkle::derive_sides(5, 5), None);
    assert_eq!(merkle::derive_sides(0, 1), Some(vec![]));
}

#[test]
fn the_commitment_preimage_layout_is_pinned() {
    let root = [1u8; 32];
    let digest = [2u8; 32];
    let binding = [3u8; 32];
    let preimage = commitment::preimage(7, &root, &digest, &binding);

    assert_eq!(preimage.len(), commitment::PREIMAGE_LEN);
    assert_eq!(preimage[0], merkle::COMMITMENT_PREFIX);
    assert_eq!(&preimage[1..17], merkle::DOMAIN.as_slice());
    assert_eq!(&preimage[17..21], &7u32.to_be_bytes());
    assert_eq!(&preimage[21..53], &root);
    assert_eq!(&preimage[53..85], &digest);
    assert_eq!(&preimage[85..117], &binding);
}

#[test]
fn the_target_binding_preimage_is_length_prefixed() {
    // ("ab", "c") and ("a", "bc") must not collide.
    let a = commitment::target_binding_preimage("ab", "c", "v", "", "scan");
    let b = commitment::target_binding_preimage("a", "bc", "v", "", "scan");
    assert_ne!(a, b);

    // scan and confirmed must not collide either.
    let scan = commitment::target_binding_preimage("t", "c", "v", "", "scan");
    let confirmed = commitment::target_binding_preimage("t", "c", "v", "", "confirmed");
    assert_ne!(scan, confirmed);
}

#[test]
fn the_instruction_discriminator_matches_a_live_recomputation() {
    // The same golden-constant pattern core/crates/ares-cli/src/idl.rs:84-96 uses:
    // the constant is hardcoded so the crate needs no hasher, and a test proves it.
    let digest = sha256(discriminator::INSTRUCTION_PREIMAGE.as_bytes());
    assert_eq!(&digest[..8], &discriminator::INSTRUCTION_DISCRIMINATOR);
}

#[test]
fn the_account_layout_table_is_internally_consistent() {
    let mut expected_offset = layout::DISCRIMINATOR_LEN;
    for field in layout::FIELDS {
        assert_eq!(
            field.offset, expected_offset,
            "field {} is not contiguous -- borsh applies no padding",
            field.name
        );
        expected_offset += field.len;
    }
    assert_eq!(expected_offset, layout::ACCOUNT_LEN);
    assert_eq!(
        layout::FIELDS_LEN,
        layout::ACCOUNT_LEN - layout::DISCRIMINATOR_LEN
    );
    assert_eq!(layout::ACCOUNT_LEN, 157);
}

#[test]
fn the_getprogramaccounts_filter_offsets_match_the_layout() {
    // A verifier's filters depend on these, so they are part of the contract.
    let find = |name: &str| {
        layout::FIELDS
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .offset
    };
    assert_eq!(layout::filter_offset::AUTHORITY, find("authority"));
    assert_eq!(layout::filter_offset::ROOT, find("root"));
    assert_eq!(
        layout::filter_offset::TARGET_BINDING,
        find("target_binding")
    );
}

#[test]
fn the_seed_prefix_is_pinned() {
    assert_eq!(seeds::SEED_PREFIX, b"ares-evidence-v1");
    assert_eq!(seeds::SEED_PREFIX.len(), 16);
    assert_eq!(seeds::SEED_COUNT, 3);
}
