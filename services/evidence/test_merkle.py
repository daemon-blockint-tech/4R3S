"""Tree properties: domain separation, malleability, and two independent oracles.

The two silent failure modes this file exists to catch:

1. **A tree that looks right and is malleable.** Switching to the Bitcoin
   odd-node rule changes nothing observable about a bundle -- roots still
   compute, proofs still verify -- while making two different finding sets share
   one root. Only a test that constructs the collision can see it.
2. **Both implementations drifting together.** A recursive reference transcribed
   from the RFC catches a bug in the production builder, but not a shared
   misreading of the spec. That is what the pinned hex vectors are for; they
   were computed once and are also what the Rust spec crate and the TypeScript
   oracle assert against.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

import merkle
from canonical import EvidenceError

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "merkle_vectors.json").read_text(encoding="utf-8")
)
PAYLOADS = [p.encode("utf-8") for p in VECTORS["leaf_payloads"]]


def _ref_root(leaves: list[bytes]) -> bytes:
    """Independent oracle #1: RFC 6962 section 2.1, transcribed literally.

    Recursive where the production builder is iterative-with-a-stack, so a bug
    in one is very unlikely to be mirrored in the other. Deliberately naive --
    it recomputes subtree roots rather than sharing them, which is fine for a
    test and keeps the transcription obviously faithful to the spec.
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return merkle.leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return merkle.node_hash(_ref_root(leaves[:k]), _ref_root(leaves[k:]))


def _leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode("utf-8") for i in range(n)]


class TestDomainSeparation:
    def test_leaf_and_node_hashes_of_the_same_bytes_differ(self):
        payload = b"\x00" * 64
        assert merkle.leaf_hash(payload) != hashlib.sha256(
            merkle.NODE_PREFIX + merkle.DOMAIN + payload
        ).digest()

    def test_an_internal_node_hash_is_not_accepted_as_a_leaf(self):
        """The RFC 6962 second-preimage property.

        Without the 0x00/0x01 prefixes, H(L||R) for an internal node is drawn
        from the same distribution as H(x) for a leaf x = L||R, so an attacker
        could present an internal node AS a leaf and prove inclusion of data
        that was never a leaf. Concretely: take an anchored 8-finding root and
        produce a valid-looking proof for a fabricated finding.
        """
        leaves = _leaves(4)
        root, proofs = merkle.build(leaves)
        left_internal = merkle.node_hash(merkle.leaf_hash(leaves[0]), merkle.leaf_hash(leaves[1]))

        # The internal node's own bytes, offered as if they were a leaf payload.
        forged_payload = merkle.leaf_hash(leaves[0]) + merkle.leaf_hash(leaves[1])
        assert merkle.leaf_hash(forged_payload) != left_internal

        right_internal = merkle.node_hash(merkle.leaf_hash(leaves[2]), merkle.leaf_hash(leaves[3]))
        assert not merkle.verify_inclusion(
            forged_payload, 0, 2, [("right", right_internal)], root
        )

    def test_changing_the_domain_tag_changes_every_root(self, monkeypatch):
        before = merkle.root(_leaves(5))
        monkeypatch.setattr(merkle, "DOMAIN", b"ares.evidence.v2")
        assert merkle.root(_leaves(5)) != before

    def test_swapping_the_leaf_and_node_prefixes_changes_the_root(self, monkeypatch):
        """Proves the prefixes are load-bearing, not decorative."""
        before = merkle.root(_leaves(5))
        monkeypatch.setattr(merkle, "LEAF_PREFIX", b"\x01")
        monkeypatch.setattr(merkle, "NODE_PREFIX", b"\x00")
        assert merkle.root(_leaves(5)) != before

    def test_the_domain_is_exactly_16_bytes(self):
        """It carries no length prefix, so a change in width would be ambiguous."""
        assert len(merkle.DOMAIN) == 16


class TestOddNodeMalleability:
    def test_appending_a_duplicate_of_the_last_leaf_changes_the_root(self):
        """CVE-2012-2459, spelled as an assertion.

        Under Bitcoin's duplicate-last rule these two roots are EQUAL: [a,b,c]
        and [a,b,c,c] collide, so one root attests to two different leaf
        multisets. For an evidence anchor that means the root attests to a
        finding set that was never produced.
        """
        three = PAYLOADS[:3]
        four_with_dup = PAYLOADS[:3] + [PAYLOADS[2]]
        assert merkle.root(three) != merkle.root(four_with_dup)
        assert merkle.root(three).hex() == VECTORS["malleability_check"]["abc_root"]
        assert merkle.root(four_with_dup).hex() == VECTORS["malleability_check"]["abcc_root"]

    def test_no_two_distinct_leaf_counts_share_a_root(self):
        roots = {}
        for n in range(0, 18):
            r = merkle.root(_leaves(n)).hex()
            assert r not in roots, f"n={n} collides with n={roots[r]}"
            roots[r] = n


class TestKnownAnswerVectors:
    def test_empty_root_is_sha256_of_the_empty_string(self):
        """RFC 6962's MTH({}), and a value a third party recognises on sight."""
        assert (
            merkle.EMPTY_ROOT.hex()
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert merkle.root([]) == merkle.EMPTY_ROOT
        assert merkle.EMPTY_ROOT.hex() == VECTORS["empty_root"]

    def test_empty_root_carries_neither_prefix(self):
        """So an empty tree cannot be confused with a leaf or an internal node."""
        assert merkle.EMPTY_ROOT != merkle.leaf_hash(b"")
        assert merkle.EMPTY_ROOT != hashlib.sha256(merkle.NODE_PREFIX + merkle.DOMAIN).digest()

    @pytest.mark.parametrize("n", range(0, 34))
    def test_production_builder_matches_the_transcribed_rfc_reference(self, n):
        assert merkle.root(_leaves(n)) == _ref_root(_leaves(n))

    @pytest.mark.parametrize("n", range(0, 9))
    def test_roots_match_the_pinned_hex_vectors(self, n):
        """Independent oracle #2 -- catches both implementations drifting together.

        These are also the cross-language contract: the Rust spec crate and the
        TypeScript oracle assert against this same file. Nothing may be added to
        the core/ cargo workspace, so a shared vector file is the only mechanism
        available for proving the three implementations agree.
        """
        assert merkle.root(PAYLOADS[:n]).hex() == VECTORS["roots_by_leaf_count"][str(n)]

    def test_leaf_hashes_match_the_pinned_hex_vectors(self):
        for payload, expected in VECTORS["leaf_hashes"].items():
            assert merkle.leaf_hash(payload.encode("utf-8")).hex() == expected

    @pytest.mark.parametrize("n", range(1, 65))
    def test_proof_length_is_at_most_ceil_log2_n(self, n):
        _, proofs = merkle.build(_leaves(n))
        cap = max(0, (n - 1).bit_length())
        for proof in proofs:
            assert len(proof) <= cap


class TestInclusionProofs:
    @pytest.mark.parametrize("n", range(1, 41))
    def test_every_leaf_proof_verifies_for_every_tree_size(self, n):
        leaves = _leaves(n)
        root, proofs = merkle.build(leaves)
        assert root == merkle.root(leaves)
        for m in range(n):
            assert merkle.verify_inclusion(leaves[m], m, n, proofs[m], root)

    def test_pinned_n5_proofs_match_the_vectors(self):
        root, proofs = merkle.build(PAYLOADS[:5])
        for entry in VECTORS["inclusion_proofs_n5"]:
            i = entry["index"]
            got = [{"position": s, "hash": h.hex()} for s, h in proofs[i]]
            assert got == [{"position": d["position"], "hash": d["hash"]} for d in entry["proof"]]

    def test_a_proof_with_swapped_sibling_positions_does_not_verify(self):
        leaves = _leaves(5)
        root, proofs = merkle.build(leaves)
        flipped = [("left" if s == "right" else "right", h) for s, h in proofs[0]]
        assert not merkle.verify_inclusion(leaves[0], 0, 5, flipped, root)

    def test_a_proof_presented_at_the_wrong_index_does_not_verify(self):
        leaves = _leaves(5)
        root, proofs = merkle.build(leaves)
        assert not merkle.verify_inclusion(leaves[0], 1, 5, proofs[0], root)

    def test_a_truncated_or_extended_proof_does_not_verify(self):
        leaves = _leaves(8)
        root, proofs = merkle.build(leaves)
        assert not merkle.verify_inclusion(leaves[0], 0, 8, proofs[0][:-1], root)
        assert not merkle.verify_inclusion(
            leaves[0], 0, 8, proofs[0] + [("right", b"\x00" * 32)], root
        )

    def test_a_wrong_leaf_count_is_rejected_where_the_path_shape_differs(self):
        """The half of the leaf_count binding that re-deriving positions does buy."""
        leaves = _leaves(5)
        root, proofs = merkle.build(leaves)
        assert merkle.derive_positions(4, 5) == ["left"]
        assert merkle.derive_positions(4, 6) == ["right", "left"]
        assert not merkle.verify_inclusion(leaves[4], 4, 6, proofs[4], root)

    def test_a_wrong_leaf_count_is_NOT_caught_where_the_path_shape_coincides(self):
        """The half it does not buy -- documented rather than quietly assumed.

        For index 0 the audit path is ["right","right","right"] at both n=5 and
        n=6, so a proof built at n=5 still verifies if the prover claims n=6.
        That is inherent to any bare inclusion check. What actually closes it is
        commitment() binding leaf_count together with the root, so a verifier
        compares the pair against the anchored value -- see the next test. A
        caller that verifies a proof without checking leaf_count has skipped the
        step that matters.
        """
        leaves = _leaves(5)
        root, proofs = merkle.build(leaves)
        assert merkle.derive_positions(0, 5) == merkle.derive_positions(0, 6) == ["right"] * 3
        assert merkle.verify_inclusion(leaves[0], 0, 6, proofs[0], root)

    def test_the_commitment_is_what_actually_binds_the_leaf_count(self):
        root = merkle.root(_leaves(5))
        binding = merkle.target_binding(
            target_name="t",
            commit_hash="abc",
            ares_version="0.1.0",
            operator_program_id=None,
            report_kind="scan",
        )
        digest = hashlib.sha256(b"report").digest()
        five = merkle.commitment(leaf_count=5, merkle_root=root, report_sha256=digest, binding=binding)
        six = merkle.commitment(leaf_count=6, merkle_root=root, report_sha256=digest, binding=binding)
        assert five != six

    def test_merkle_does_not_police_duplicate_preimages(self):
        """Documents the layer boundary.

        A pure Merkle tree legitimately may contain duplicate leaves. The
        decision that an ARES evidence bundle may not is a policy call, and it
        lives in bundle.py so that this module stays a general tree.
        """
        duplicated = [b"same", b"same"]
        assert merkle.root(duplicated) == merkle.node_hash(
            merkle.leaf_hash(b"same"), merkle.leaf_hash(b"same")
        )


class TestArgumentChecking:
    def test_largest_pow2_below_matches_the_definition(self):
        assert merkle.largest_pow2_below(2) == 1
        assert merkle.largest_pow2_below(3) == 2
        assert merkle.largest_pow2_below(4) == 2  # strictly less than n
        assert merkle.largest_pow2_below(5) == 4
        assert merkle.largest_pow2_below(8) == 4
        assert merkle.largest_pow2_below(9) == 8

    def test_k_is_undefined_below_two(self):
        with pytest.raises(EvidenceError):
            merkle.largest_pow2_below(1)

    def test_node_hash_rejects_a_non_digest(self):
        with pytest.raises(EvidenceError):
            merkle.node_hash(b"short", b"\x00" * 32)

    def test_derive_positions_rejects_an_out_of_range_index(self):
        with pytest.raises(EvidenceError):
            merkle.derive_positions(5, 5)

    def test_commitment_rejects_a_non_digest(self):
        with pytest.raises(EvidenceError):
            merkle.commitment(
                leaf_count=1, merkle_root=b"short", report_sha256=b"\x00" * 32, binding=b"\x00" * 32
            )

    def test_target_binding_distinguishes_scan_from_confirmed(self):
        """Otherwise a confirmed bundle could be presented as a scan bundle."""
        common = dict(
            target_name="t", commit_hash="abc", ares_version="0.1.0", operator_program_id=None
        )
        assert merkle.target_binding(report_kind="scan", **common) != merkle.target_binding(
            report_kind="confirmed", **common
        )

    def test_target_binding_fields_cannot_be_shifted_into_each_other(self):
        """Length-prefixing means ("ab","c") and ("a","bc") cannot collide."""
        a = merkle.target_binding(
            target_name="ab", commit_hash="c", ares_version="v", operator_program_id=None,
            report_kind="scan",
        )
        b = merkle.target_binding(
            target_name="a", commit_hash="bc", ares_version="v", operator_program_id=None,
            report_kind="scan",
        )
        assert a != b

    def test_absent_and_empty_operator_program_id_are_distinguishable_from_a_value(self):
        common = dict(target_name="t", commit_hash="c", ares_version="v", report_kind="scan")
        none = merkle.target_binding(operator_program_id=None, **common)
        real = merkle.target_binding(operator_program_id="SomeProgramId", **common)
        assert none != real
