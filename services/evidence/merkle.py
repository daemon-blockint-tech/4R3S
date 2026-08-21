"""RFC 6962 Merkle tree over SHA-256, with domain-separated leaves and nodes.

Pure bytes in, pure bytes out. This module knows nothing about ARES types: it
takes a list of leaf preimages and returns hashes, so it can be tested in
isolation and reused by anything. It deliberately does **not** police duplicate
preimages -- a Merkle tree legitimately may contain them, and the decision that
an ARES evidence bundle may not is a policy call that lives in bundle.py.

Why RFC 6962 and not the Bitcoin construction
---------------------------------------------
Bitcoin hashes a lone right-hand child as H(x||x). That makes the 3-leaf tree
[a,b,c] and the 4-leaf tree [a,b,c,c] produce the *identical* root
(CVE-2012-2459): two different leaf multisets, one root. For an evidence anchor
that means the root attests to a finding set that was never produced.

Our leaves happen to be unique, so a duplicate check would paper over it. But
patching a malleable tree with a uniqueness invariant is the fragile design --
it breaks the moment someone relaxes the invariant. RFC 6962 splits at the
largest power of two below n and never duplicates, so the malleability is
structurally impossible rather than checked-against, the shape is canonical for
each n, and the published second-preimage reduction is stated for exactly this
construction with exactly these prefixes.

Why the prefixes
----------------
Without them, H(L||R) for an internal node is drawn from the same distribution
as H(x) for a leaf x = L||R. An attacker could present an internal node as a
leaf and produce a proof that verifies for data that was never a leaf -- an
n-leaf tree reinterpreted as a tree of fewer, larger ones. Concretely here:
take an anchored 8-finding root and produce a valid-looking inclusion proof for
a *fabricated* finding, backed by an on-chain root.

The 16-byte domain tag is a second, cheaper layer. It stops any other SHA-256
Merkle tree in the ecosystem (an SPL merkle-distributor root, a concurrent
merkle-tree node) from ever being replayed as an ARES evidence node, and it
version-gates a future v2 of the encoding.

The values here are pinned by services/evidence/vectors/merkle_vectors.json,
which is also what the Rust spec crate and the TypeScript oracle assert against
-- that shared file is the only thing proving the three implementations agree.
"""

from __future__ import annotations

import hashlib

from canonical import EvidenceError, lp

#: Exactly 16 bytes, so it needs no length prefix of its own to be unambiguous.
DOMAIN = b"ares.evidence.v1"

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
COMMITMENT_PREFIX = b"\x02"
TARGET_BINDING_PREFIX = b"\x03"

assert len(DOMAIN) == 16, "DOMAIN is length-prefix-free only because it is fixed at 16 bytes"

#: RFC 6962's MTH({}) -- the hash of the empty string, carrying neither the leaf
#: nor the node prefix, so an empty tree's root cannot be confused with either.
#: Recognisable on sight (e3b0c442...), which is a real benefit when a third
#: party is eyeballing an anchored value.
EMPTY_ROOT = hashlib.sha256(b"").digest()

HASH_SIZE = 32


def leaf_hash(preimage: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + DOMAIN + preimage).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise EvidenceError("node_hash takes two 32-byte digests")
    return hashlib.sha256(NODE_PREFIX + DOMAIN + left + right).digest()


def largest_pow2_below(n: int) -> int:
    """RFC 6962's k: the largest power of two strictly less than n."""
    if n < 2:
        raise EvidenceError(f"k is only defined for n >= 2, got {n}")
    return 1 << (n - 1).bit_length() - 1


def _build(preimages: list[bytes], base: int, proofs: dict[int, list]) -> bytes:
    """Compute the root and, in the same pass, every leaf's audit path.

    Siblings are appended as the recursion unwinds, so each proof comes out
    bottom-up (deepest sibling first) -- the order RFC 6962's PATH() produces
    and the order verify_inclusion consumes.
    """
    n = len(preimages)
    if n == 1:
        return leaf_hash(preimages[0])
    k = largest_pow2_below(n)
    left = _build(preimages[:k], base, proofs)
    right = _build(preimages[k:], base + k, proofs)
    for i in range(base, base + k):
        proofs[i].append(("right", right))
    for i in range(base + k, base + n):
        proofs[i].append(("left", left))
    return node_hash(left, right)


def root(preimages: list[bytes]) -> bytes:
    """MTH(D[n])."""
    if not preimages:
        return EMPTY_ROOT
    return _build(list(preimages), 0, {i: [] for i in range(len(preimages))})


def build(preimages: list[bytes]) -> tuple[bytes, list[list[tuple[str, bytes]]]]:
    """Return (root, per-leaf audit paths) in one pass."""
    if not preimages:
        return EMPTY_ROOT, []
    proofs: dict[int, list] = {i: [] for i in range(len(preimages))}
    r = _build(list(preimages), 0, proofs)
    return r, [proofs[i] for i in range(len(preimages))]


def derive_positions(index: int, leaf_count: int) -> list[str]:
    """Which side each sibling sits on, derived from the tree shape alone.

    This exists so no verifier ever has to trust the positions a prover supplied.
    A position array is an attacker-controlled degree of freedom, and RFC 6962's
    unbalanced shape makes index-to-position derivation the error-prone part --
    which is exactly the part that must not be delegated to the prover. Both
    this module's verifier and the on-chain program re-derive and compare.
    """
    if not 0 <= index < leaf_count:
        raise EvidenceError(f"leaf index {index} out of range for {leaf_count} leaves")
    positions: list[str] = []

    def rec(n: int, m: int) -> None:
        if n == 1:
            return
        k = largest_pow2_below(n)
        if m < k:
            rec(k, m)
            positions.append("right")
        else:
            rec(n - k, m - k)
            positions.append("left")

    rec(leaf_count, index)
    return positions


def verify_inclusion(
    preimage: bytes,
    index: int,
    leaf_count: int,
    proof: list[tuple[str, bytes]],
    expected_root: bytes,
) -> bool:
    """Verify one leaf against a root, re-deriving the sibling sides.

    What re-deriving positions does and does not buy, stated precisely, because
    the tempting overclaim is wrong:

    It rejects a proof whose sibling *sides* disagree with the shape implied by
    `(index, leaf_count)`. That is a real constraint -- for index 4 the audit
    path is ["left"] at n=5 but ["right", "left"] at n=6, so a substituted count
    is caught.

    It does **not** make every wrong `leaf_count` detectable. For index 0 the
    path is ["right", "right", "right"] at both n=5 and n=6, so a proof built at
    n=5 still verifies if the prover claims n=6. That is inherent to any bare
    inclusion check: given the sibling digests, the root recomputes regardless of
    what size is asserted alongside them.

    The protection that actually closes this is not here. It is that
    `commitment()` binds `leaf_count` *together with* the root, so a verifier
    compares the pair against what was anchored on chain rather than trusting
    either alone -- and that RFC 6962 gives the same leaves a different root at a
    different n, so a prover cannot pick the count freely. A caller that verifies
    a proof without also checking `leaf_count` against the anchored value has
    skipped the step that matters.
    """
    expected_positions = derive_positions(index, leaf_count)
    if [side for side, _ in proof] != expected_positions:
        return False
    acc = leaf_hash(preimage)
    for side, sibling in proof:
        if len(sibling) != HASH_SIZE:
            return False
        acc = node_hash(sibling, acc) if side == "left" else node_hash(acc, sibling)
    return acc == expected_root


def target_binding(
    *,
    target_name: str,
    commit_hash: str | None,
    ares_version: str,
    operator_program_id: str | None,
    report_kind: str,
) -> bytes:
    """Bind an anchor to a specific target, so it cannot be replayed elsewhere.

    `ares_version` is technically redundant with the report digest that the
    commitment also covers, but that digest is opaque; the commitment preimage is
    published in the bundle, so this is the one place a reader can see which
    engine made the claim without holding the report.

    `report_kind` prevents a `confirmed` bundle being presented as a `scan`
    bundle, or the reverse.
    """
    return hashlib.sha256(
        TARGET_BINDING_PREFIX
        + DOMAIN
        + lp(target_name.encode("utf-8"))
        + lp((commit_hash or "").encode("utf-8"))
        + lp(ares_version.encode("utf-8"))
        + lp((operator_program_id or "").encode("utf-8"))
        + lp(report_kind.encode("utf-8"))
    ).digest()


def commitment(
    *,
    leaf_count: int,
    merkle_root: bytes,
    report_sha256: bytes,
    binding: bytes,
) -> bytes:
    """The 32 bytes an anchor actually records.

    Why a commitment and not the bare root: RFC 6962's empty tree has one
    constant root for every target on earth, and 178 of the 636 reports in the
    local corpus produce no leaves at all. Anchoring the bare empty root would
    publish "nothing found" in a form anyone could replay against any program.
    Folding in the report digest and the target binding keeps even the empty case
    unique per (target, commit, artifact bytes).

    (194 reports have `findings == []`; the smaller 178 is the number with no
    leaves, because suppressed findings are leaves too. The distinction matters
    here and is easy to conflate.)

    `leaf_count` is included so that no residual shape ambiguity can change what
    was committed, independently of the tree construction.
    """
    for name, value in (("merkle_root", merkle_root), ("report_sha256", report_sha256), ("binding", binding)):
        if len(value) != HASH_SIZE:
            raise EvidenceError(f"{name} must be 32 bytes, got {len(value)}")
    if not 0 <= leaf_count <= 2**32 - 1:
        raise EvidenceError(f"leaf_count out of u32 range: {leaf_count}")
    return hashlib.sha256(
        COMMITMENT_PREFIX
        + DOMAIN
        + leaf_count.to_bytes(4, "big")
        + merkle_root
        + report_sha256
        + binding
    ).digest()
