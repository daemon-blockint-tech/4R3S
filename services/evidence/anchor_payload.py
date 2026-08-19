"""Build a reviewable, UNSIGNED anchoring request from an evidence bundle.

This module never signs anything, never opens a keypair file, never contacts an
RPC endpoint and never submits a transaction. It emits a JSON document that a
human can read field by field and then submit with their own wallet.

That is a deliberate reframing, and it is worth being straight about what it
costs. The deliverable is not "a tool that anchors" but "a tool that produces an
anchoring request you can check before you sign it". The honest consequence:
**no end-to-end path is ever exercised by this repository.** Nothing here has
ever put a byte on a Solana cluster.

There is also no `solana` CLI subcommand that submits an arbitrary instruction.
Offline signing and durable nonces exist, but none of them take a raw
instruction, so the realistic submission paths are a multisig UI that accepts a
base64 instruction, or a short web3.js snippet the operator runs themselves. See
onchain/README.md.

# An instruction, not a transaction

A serialised transaction needs a recent blockhash, which expires in about 60-90
seconds. A payload meant to be read carefully by a human cannot carry a live
blockhash, so the blockhash and the fee payer are supplied at signing time.

# Two integer encodings, deliberately different

`leaf_count` appears twice with two byte orders, and conflating them is the
easiest way to produce a payload the program rejects:

  - in the **commitment preimage** it is big-endian, because that preimage is
    this project's own format and matches services/evidence/merkle.py
  - in the **Borsh instruction data** it is little-endian, because that is what
    Borsh specifies

Both are pinned by tests.

Deterministic and offline: no LLM, no network, no randomness. See "Hermetic by
default" in ../../SECURITY.md.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

import merkle
from canonical import EvidenceError, leaf_preimage

PAYLOAD_VERSION = "ares.evidence.anchor-payload/1"

#: Program id in the committed source. The payload builder refuses to emit
#: anything for it: a payload naming a program that was never deployed would look
#: exactly like a real one.
PLACEHOLDER_PROGRAM_ID = "Evid1111111111111111111111111111111111111111"

#: sha256("global:anchor_evidence")[..8]. Pinned in the Rust spec crate too, at
#: onchain/spec/src/discriminator.rs, and recomputed in tests on both sides.
INSTRUCTION_PREIMAGE = "global:anchor_evidence"

#: Rent for a 157-byte account at current parameters, as a labelled ESTIMATE. The
#: program never hardcodes this -- `init` CPIs into System with `Rent::get()`, so
#: the real figure is correct automatically and survives a parameter change. This
#: is here only so an operator can plan how much SOL to hold.
ESTIMATED_RENT_LAMPORTS = (128 + 157) * 3480 * 2
ESTIMATED_FEE_LAMPORTS = 5000

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ---------------------------------------------------------------------------
# base58, stdlib only
# ---------------------------------------------------------------------------


def b58encode(raw: bytes) -> str:
    """Bitcoin/Solana base58. Leading zero bytes become leading '1's."""
    n = int.from_bytes(raw, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_BASE58_ALPHABET[rem])
    for byte in raw:
        if byte != 0:
            break
        out.append(_BASE58_ALPHABET[0])
    return out[::-1].decode("ascii")


def b58decode(text: str) -> bytes:
    """Inverse of :func:`b58encode`. Raises on any character outside the alphabet."""
    n = 0
    for char in text:
        index = _BASE58_ALPHABET.find(char.encode("ascii"))
        if index < 0:
            raise EvidenceError(f"not base58: {char!r} in {text!r}")
        n = n * 58 + index
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading + body


# ---------------------------------------------------------------------------
# PDA derivation
#
# Solana's find_program_address hashes the seeds with a candidate bump and
# rejects any result that is a valid ed25519 curve point -- that is what makes a
# PDA an address no private key can sign for. The on-curve test is therefore
# load-bearing, not decoration: skip it and this would happily return an address
# that someone could hold a key to.
#
# scripts/evidence-pda-vectors.test.ts checks this implementation against
# @solana/web3.js's PublicKey.findProgramAddressSync -- an implementation nobody
# in this repository wrote. That cross-check is why a hand-rolled curve routine
# is acceptable here.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
#: sqrt(-1) mod p, used to recover the other square root candidate.
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

_MAX_SEED_LEN = 32
_MAX_SEEDS = 16
_PDA_MARKER = b"ProgramDerivedAddress"


def is_on_curve(point: bytes) -> bool:
    """Whether 32 bytes decompress to a valid ed25519 curve point.

    Recovers x from the compressed y per RFC 8032 section 5.1.3: solve
    x^2 = (y^2 - 1) / (d*y^2 + 1), then check the candidate square root actually
    squares back. A y outside the field, or a zero denominator, is not on the
    curve.
    """
    if len(point) != 32:
        return False
    y = int.from_bytes(point, "little") & ((1 << 255) - 1)
    if y >= _P:
        return False

    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    if v == 0:
        return False

    x2 = (u * pow(v, _P - 2, _P)) % _P
    if x2 == 0:
        # x = 0 is on the curve only when the sign bit is clear.
        return point[31] & 0x80 == 0

    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _SQRT_M1) % _P
    return (x * x - x2) % _P == 0


def find_program_address(seeds: list[bytes], program_id: bytes) -> tuple[bytes, int]:
    """Solana's canonical PDA: the highest bump whose hash is off-curve."""
    if len(seeds) > _MAX_SEEDS:
        raise EvidenceError(f"at most {_MAX_SEEDS} seeds, got {len(seeds)}")
    for seed in seeds:
        if len(seed) > _MAX_SEED_LEN:
            raise EvidenceError(f"seed of {len(seed)} bytes exceeds {_MAX_SEED_LEN}")
    if len(program_id) != 32:
        raise EvidenceError("program id must be 32 bytes")

    for bump in range(255, -1, -1):
        digest = hashlib.sha256(
            b"".join(seeds) + bytes([bump]) + program_id + _PDA_MARKER
        ).digest()
        if not is_on_curve(digest):
            return digest, bump
    raise EvidenceError("no off-curve bump found; this is effectively impossible")


# ---------------------------------------------------------------------------
# Authority validation
# ---------------------------------------------------------------------------

_SEED_PHRASE_RE = re.compile(r"^(?:\s*[a-z]+){11,}\s*$")


def parse_authority_pubkey(value: str) -> bytes:
    """Accept a 32-byte base58 public key and nothing else.

    Every rejection below is a shape that could carry a *private* key. This tool
    must never be handed one, so the guard is a refusal rather than a best-effort
    parse: there is no code path here that opens a file or reads a secret.
    """
    text = value.strip()
    if not text:
        raise EvidenceError("--authority is empty")
    if any(sep in text for sep in ("/", "\\", "~")) or text.lower().endswith(".json"):
        raise EvidenceError(
            f"--authority looks like a file path ({text!r}). Pass the base58 "
            f"PUBLIC key, e.g. the output of `solana address`. This tool never "
            f"reads a keypair file."
        )
    if text.startswith("[") or "," in text:
        raise EvidenceError(
            "--authority looks like a JSON byte array, which is how a SECRET key "
            "is stored. Pass the base58 public key instead."
        )
    if _SEED_PHRASE_RE.match(text):
        raise EvidenceError(
            "--authority looks like a seed phrase. Never pass a seed phrase to "
            "any tool. Pass the base58 public key."
        )

    raw = b58decode(text)
    if len(raw) == 64:
        raise EvidenceError(
            "--authority decoded to 64 bytes, which is a SECRET key, not a public "
            "key. Pass the 32-byte public key."
        )
    if len(raw) != 32:
        raise EvidenceError(f"--authority decoded to {len(raw)} bytes; expected 32")
    return raw


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


def _instruction_data(
    leaf_count: int,
    root: bytes,
    report_sha256: bytes,
    target_binding: bytes,
    commitment: bytes,
) -> tuple[bytes, list[dict]]:
    """Borsh-encode the instruction, and describe it field by field.

    The field table is not decoration: nobody should have to trust a 140-byte
    blob, and the operator's verification procedure walks these offsets.
    """
    discriminator = hashlib.sha256(INSTRUCTION_PREIMAGE.encode("ascii")).digest()[:8]
    # Borsh integers are LITTLE-endian. The commitment preimage uses big-endian
    # for the same value; see the module docstring.
    leaf_count_le = leaf_count.to_bytes(4, "little")

    parts = [
        ("discriminator", "[u8; 8]", discriminator),
        ("leaf_count", "u32 (borsh, little-endian)", leaf_count_le),
        ("root", "[u8; 32]", root),
        ("report_sha256", "[u8; 32]", report_sha256),
        ("target_binding", "[u8; 32]", target_binding),
        ("commitment_arg", "[u8; 32]", commitment),
    ]

    data = b""
    table = []
    for name, ty, chunk in parts:
        table.append(
            {
                "name": name,
                "type": ty,
                "offset": len(data),
                "len": len(chunk),
                "hex": chunk.hex(),
            }
        )
        data += chunk
    return data, table


def build_payload(
    bundle_path: str | Path,
    *,
    authority: str,
    program_id: str,
    cluster: str,
) -> dict:
    """Assemble the unsigned anchoring request for one bundle."""
    if program_id == PLACEHOLDER_PROGRAM_ID:
        raise EvidenceError(
            f"{program_id} is the placeholder id in the committed program source. "
            f"The program has never been deployed, so there is nothing to anchor "
            f"to. Refusing to emit a payload that would look like a real one."
        )

    authority_raw = parse_authority_pubkey(authority)
    program_raw = b58decode(program_id)
    if len(program_raw) != 32:
        raise EvidenceError(f"--program-id decoded to {len(program_raw)} bytes; expected 32")

    doc = json.loads(Path(bundle_path).read_text(encoding="utf-8"))

    # Recompute the root from the published leaves rather than copying the
    # bundle's own `tree.merkle_root`. This is the difference between reporting
    # what the bundler said and verifying it.
    preimages = [leaf_preimage(leaf["fields"]) for leaf in doc["leaves"]]
    recomputed_root = merkle.root(preimages)
    claimed_root = doc["tree"]["merkle_root"]
    root_matches = recomputed_root.hex() == claimed_root
    if not root_matches:
        raise EvidenceError(
            f"the bundle's leaves rebuild to {recomputed_root.hex()} but it records "
            f"{claimed_root}. Refusing to build an anchoring payload for a bundle "
            f"that does not verify -- run verify.py to see which check fails."
        )

    leaf_count = doc["tree"]["leaf_count"]
    report_sha256 = bytes.fromhex(doc["source"]["report_sha256"])
    target_binding = bytes.fromhex(doc["anchor"]["target_binding"])

    commitment = merkle.commitment(
        leaf_count=leaf_count,
        merkle_root=recomputed_root,
        report_sha256=report_sha256,
        binding=target_binding,
    )
    if commitment.hex() != doc["anchor"]["commitment"]:
        raise EvidenceError(
            f"the recomputed commitment {commitment.hex()} does not match the "
            f"bundle's {doc['anchor']['commitment']}"
        )

    seed_prefix = b"ares-evidence-v1"
    pda, bump = find_program_address(
        [seed_prefix, authority_raw, commitment], program_raw
    )

    data, field_table = _instruction_data(
        leaf_count, recomputed_root, report_sha256, target_binding, commitment
    )

    commitment_preimage = (
        merkle.COMMITMENT_PREFIX
        + merkle.DOMAIN
        + leaf_count.to_bytes(4, "big")
        + recomputed_root
        + report_sha256
        + target_binding
    )

    payload = {
        "payload_version": PAYLOAD_VERSION,
        "generated_by": "services/evidence/anchor_payload.py",
        "program_id": program_id,
        "cluster": cluster,
        "instruction": {
            "name": "anchor_evidence",
            "discriminator_preimage": INSTRUCTION_PREIMAGE,
            "discriminator_hex": data[:8].hex(),
            "data_len": len(data),
            "data_hex": data.hex(),
            "data_base64": base64.b64encode(data).decode("ascii"),
            "fields": field_table,
            "note": (
                "Borsh integers are little-endian. The same leaf_count is "
                "big-endian inside the commitment preimage below, which is this "
                "project's own format -- do not conflate the two."
            ),
        },
        "accounts": [
            {
                "index": 0,
                "name": "record",
                "pubkey": b58encode(pda),
                "is_signer": False,
                "is_writable": True,
                "role": "the PDA being created; its address binds every anchored field",
            },
            {
                "index": 1,
                "name": "authority",
                "pubkey": b58encode(authority_raw),
                "is_signer": True,
                "is_writable": True,
                "role": "signs the claim and pays rent; must be your own wallet",
            },
            {
                "index": 2,
                "name": "system_program",
                "pubkey": "11111111111111111111111111111111",
                "is_signer": False,
                "is_writable": False,
                "role": "creates the account",
            },
        ],
        "pda": {
            "address": b58encode(pda),
            "bump": bump,
            "seeds": [
                {"label": "SEED_PREFIX", "utf8": seed_prefix.decode(), "hex": seed_prefix.hex()},
                {"label": "authority", "base58": b58encode(authority_raw), "hex": authority_raw.hex()},
                {"label": "commitment", "hex": commitment.hex()},
            ],
            "derivation": (
                "sha256(seeds || bump || program_id || 'ProgramDerivedAddress'), "
                "highest bump whose result is off-curve"
            ),
            "verify_with": (
                f"solana find-program-derived-address {program_id} "
                f"string:{seed_prefix.decode()} pubkey:{b58encode(authority_raw)} "
                f"hex:{commitment.hex()}"
            ),
        },
        "commitment": {
            "hex": commitment.hex(),
            "preimage_hex": commitment_preimage.hex(),
            "preimage_segments": [
                {"name": "commitment_prefix", "hex": "02"},
                {"name": "domain", "utf8": merkle.DOMAIN.decode(), "hex": merkle.DOMAIN.hex()},
                {"name": "leaf_count (u32 BIG-endian)", "hex": leaf_count.to_bytes(4, "big").hex()},
                {"name": "merkle_root", "hex": recomputed_root.hex()},
                {"name": "report_sha256", "hex": report_sha256.hex()},
                {"name": "target_binding", "hex": target_binding.hex()},
            ],
        },
        "anchored": {
            "merkle_root": recomputed_root.hex(),
            "leaf_count": leaf_count,
            "report_sha256": doc["source"]["report_sha256"],
            "target_binding": doc["anchor"]["target_binding"],
            "target_name": doc["target"]["name"],
            "report_kind": doc["source"]["report_kind"],
        },
        "recomputed": {
            "merkle_root": recomputed_root.hex(),
            "matches_bundle_root": root_matches,
            "note": (
                "Recomputed from the bundle's published leaf fields by this tool, "
                "not copied from the bundle's own root field."
            ),
        },
        "estimates": {
            "rent_lamports": ESTIMATED_RENT_LAMPORTS,
            "fee_lamports": ESTIMATED_FEE_LAMPORTS,
            "note": (
                "Estimates only. The program never hardcodes rent -- `init` CPIs "
                "into System with Rent::get() -- so the real figure is correct "
                "automatically. Rent is spent permanently: the record is "
                "immutable and there is no close instruction, because evidence "
                "you can delete is not evidence."
            ),
        },
        "not_included": [
            "signature",
            "recent blockhash",
            "keypair",
            "rpc endpoint",
        ],
        "evidentiary_value": (
            "none -- devnet is periodically reset, so an anchor there is destroyed "
            "while looking identical to a real one"
            if cluster == "devnet"
            else "an upper bound on when the root was known, and nothing more"
        ),
    }
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anchor_payload.py",
        description=(
            "Emit an UNSIGNED, reviewable anchoring request for an evidence "
            "bundle. Never signs, never submits, never reads a keypair."
        ),
    )
    parser.add_argument("bundle", help="path to a *.evidence.json bundle")
    parser.add_argument(
        "--authority",
        required=True,
        help="your base58 PUBLIC key (e.g. `solana address`). Never a keypair path.",
    )
    parser.add_argument(
        "--program-id",
        required=True,
        help="base58 program id of a DEPLOYED evidence_registry. No default: "
        "there is no deployed program to point at.",
    )
    parser.add_argument(
        "--cluster",
        required=True,
        choices=["devnet", "mainnet-beta"],
        help="required explicitly. A silent devnet default would manufacture "
        "worthless anchors that read as real; a silent mainnet default would "
        "spend real SOL.",
    )
    parser.add_argument("--out", default=None, help="write here instead of stdout")
    args = parser.parse_args(argv)

    try:
        payload = build_payload(
            args.bundle,
            authority=args.authority,
            program_id=args.program_id,
            cluster=args.cluster,
        )
    except (EvidenceError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if args.cluster == "devnet":
        print(
            "note: devnet is periodically reset. An anchor there has NO "
            "evidentiary value, and looks identical to one that does.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
