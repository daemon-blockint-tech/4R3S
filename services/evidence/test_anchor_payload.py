"""The unsigned payload: base58, PDA derivation, and the refusals.

Two groups matter most here.

The **refusals** are the safety surface. This tool must never be handed a private
key, so every shape that could carry one is rejected rather than parsed
best-effort -- and there is no code path in the module that opens a file or reads
a secret at all.

The **PDA derivation** is hand-rolled ed25519 arithmetic, which is exactly the
kind of code that is subtly wrong and still passes its author's own tests. The
vectors here are also asserted by `scripts/evidence-pda-vectors.test.ts` against
`@solana/web3.js`, an implementation nobody in this repository wrote. That
cross-check is what makes the hand-rolled routine acceptable; these tests alone
would not be enough.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

import anchor_payload as ap
from canonical import EvidenceError

HERE = pathlib.Path(__file__).parent
VECTORS = HERE / "vectors"
BUNDLE = VECTORS / "ares-report-suppressed-only.evidence.json"
PDA_VECTORS = json.loads((VECTORS / "pda_vectors.json").read_text(encoding="utf-8"))

# Deterministic stand-ins. Neither corresponds to a real deployed program or a
# real wallet, and no private key exists for either.
TEST_PROGRAM = ap.b58encode(hashlib.sha256(b"test-program").digest())
TEST_AUTHORITY = ap.b58encode(hashlib.sha256(b"test-authority").digest())


class TestBase58:
    def test_roundtrips_arbitrary_32_byte_values(self):
        for seed in (b"a", b"b", b"zzz", bytes(range(32))):
            raw = hashlib.sha256(seed).digest()
            assert ap.b58decode(ap.b58encode(raw)) == raw

    def test_leading_zero_bytes_become_leading_ones(self):
        """The System program id is 32 zero bytes, and must render as 32 '1's."""
        assert ap.b58encode(b"\x00" * 32) == "1" * 32
        assert ap.b58decode("1" * 32) == b"\x00" * 32

    def test_the_system_program_id_matches_the_payload_constant(self):
        doc = _payload()
        system = next(a for a in doc["accounts"] if a["name"] == "system_program")
        assert system["pubkey"] == ap.b58encode(b"\x00" * 32)

    def test_an_invalid_character_raises(self):
        # 0, O, I and l are deliberately absent from the base58 alphabet.
        for bad in ("0", "O", "I", "l"):
            with pytest.raises(EvidenceError, match="not base58"):
                ap.b58decode(f"abc{bad}def")

    def test_encoding_is_not_base64(self):
        assert "+" not in ap.b58encode(bytes(range(32)))
        assert "/" not in ap.b58encode(bytes(range(32)))


class TestOnCurve:
    def test_the_ed25519_basepoint_is_on_the_curve(self):
        """An independent known-answer check on the curve arithmetic.

        The RFC 8032 basepoint's compressed encoding is a published constant, so
        this does not depend on anything else in this repository being right.
        """
        basepoint = bytes.fromhex(
            "5866666666666666666666666666666666666666666666666666666666666666"
        )
        assert ap.is_on_curve(basepoint)

    def test_the_identity_element_is_on_the_curve(self):
        identity = b"\x01" + b"\x00" * 31
        assert ap.is_on_curve(identity)

    def test_a_y_outside_the_field_is_rejected(self):
        # y = p is not a field element.
        y = ap._P
        assert not ap.is_on_curve(y.to_bytes(32, "little"))

    def test_wrong_length_input_is_rejected(self):
        assert not ap.is_on_curve(b"\x00" * 31)
        assert not ap.is_on_curve(b"\x00" * 33)

    def test_some_hashes_are_on_the_curve_and_some_are_not(self):
        """The check must actually discriminate.

        A routine that always returned False would make find_program_address
        always return bump 255 and still pass a naive test. This asserts both
        outcomes occur over a sample.
        """
        results = {ap.is_on_curve(hashlib.sha256(bytes([i])).digest()) for i in range(64)}
        assert results == {True, False}


class TestPdaDerivation:
    @pytest.mark.parametrize(
        "case", PDA_VECTORS["cases"], ids=[c["label"] for c in PDA_VECTORS["cases"]]
    )
    def test_matches_the_shared_vectors(self, case):
        seeds = [
            PDA_VECTORS["seed_prefix_utf8"].encode(),
            ap.b58decode(case["authority_base58"]),
            bytes.fromhex(case["commitment_hex"]),
        ]
        pda, bump = ap.find_program_address(seeds, ap.b58decode(case["program_id_base58"]))
        assert ap.b58encode(pda) == case["expected_pda_base58"]
        assert bump == case["expected_bump"]

    def test_at_least_one_vector_exercises_the_on_curve_rejection(self):
        """A bump below 255 means a candidate was rejected for being on-curve.

        Without such a case the whole vector set would pass even if the on-curve
        test always returned False.
        """
        assert min(c["expected_bump"] for c in PDA_VECTORS["cases"]) < 255

    def test_the_derived_address_is_never_itself_on_the_curve(self):
        """That property is the entire point of a PDA: no key can sign for it."""
        for case in PDA_VECTORS["cases"]:
            assert not ap.is_on_curve(ap.b58decode(case["expected_pda_base58"]))

    def test_too_many_seeds_raises(self):
        with pytest.raises(EvidenceError, match="at most 16 seeds"):
            ap.find_program_address([b"x"] * 17, b"\x00" * 32)

    def test_an_oversized_seed_raises(self):
        with pytest.raises(EvidenceError, match="exceeds 32"):
            ap.find_program_address([b"x" * 33], b"\x00" * 32)

    def test_a_short_program_id_raises(self):
        with pytest.raises(EvidenceError, match="32 bytes"):
            ap.find_program_address([b"x"], b"\x00" * 31)

    def test_changing_any_seed_changes_the_address(self):
        program = ap.b58decode(TEST_PROGRAM)
        base = [b"ares-evidence-v1", b"\x01" * 32, b"\x02" * 32]
        first, _ = ap.find_program_address(base, program)
        for i in range(3):
            mutated = list(base)
            mutated[i] = bytes([b ^ 0xFF for b in mutated[i]])
            other, _ = ap.find_program_address(mutated, program)
            assert other != first, f"seed {i} does not affect the address"


class TestAuthorityRefusals:
    """Every rejected shape is one that could carry a PRIVATE key."""

    @pytest.mark.parametrize(
        "value",
        [
            "~/.config/solana/id.json",
            "/home/me/id.json",
            r"C:\Users\me\id.json",
            "./keypair.json",
        ],
    )
    def test_a_filesystem_path_is_refused(self, value):
        with pytest.raises(EvidenceError, match="file path"):
            ap.parse_authority_pubkey(value)

    def test_a_json_byte_array_is_refused(self):
        with pytest.raises(EvidenceError, match="JSON byte array"):
            ap.parse_authority_pubkey("[12,34,56,78]")

    def test_a_seed_phrase_is_refused(self):
        phrase = " ".join(["abandon"] * 12)
        with pytest.raises(EvidenceError, match="seed phrase"):
            ap.parse_authority_pubkey(phrase)

    def test_a_64_byte_secret_key_is_refused(self):
        secret = ap.b58encode(hashlib.sha512(b"not-a-pubkey").digest())
        with pytest.raises(EvidenceError, match="SECRET key"):
            ap.parse_authority_pubkey(secret)

    def test_an_empty_value_is_refused(self):
        with pytest.raises(EvidenceError, match="empty"):
            ap.parse_authority_pubkey("   ")

    def test_a_wrong_length_key_is_refused(self):
        with pytest.raises(EvidenceError, match="expected 32"):
            ap.parse_authority_pubkey(ap.b58encode(b"\x01" * 31))

    def test_a_valid_pubkey_is_accepted_and_whitespace_trimmed(self):
        expected = hashlib.sha256(b"test-authority").digest()
        assert ap.parse_authority_pubkey(f"  {TEST_AUTHORITY}  ") == expected

    def test_the_module_never_opens_a_file_for_the_authority(self):
        """A structural check, not a behavioural one.

        The refusals above are the first line; this asserts the second -- there is
        no `open`/`read_text`/`read_bytes` anywhere near authority handling that a
        future edit could reach by accident.
        """
        source = (HERE / "anchor_payload.py").read_text(encoding="utf-8")
        marker = "def parse_authority_pubkey"
        body = source[source.index(marker) :]
        body = body[: body.index("\n# ---")] if "\n# ---" in body else body
        for forbidden in ("open(", "read_text", "read_bytes", "os.environ"):
            assert forbidden not in body, f"{forbidden} appears in authority handling"


def _payload(**overrides):
    kwargs = {
        "authority": TEST_AUTHORITY,
        "program_id": TEST_PROGRAM,
        "cluster": "mainnet-beta",
    }
    kwargs.update(overrides)
    return ap.build_payload(BUNDLE, **kwargs)


class TestPayloadContents:
    def test_the_placeholder_program_id_is_refused(self):
        """A payload naming a never-deployed program would look exactly like a real one."""
        with pytest.raises(EvidenceError, match="placeholder"):
            _payload(program_id=ap.PLACEHOLDER_PROGRAM_ID)

    def test_the_commitment_matches_the_committed_bundle(self):
        doc = json.loads(BUNDLE.read_text(encoding="utf-8"))
        assert _payload()["commitment"]["hex"] == doc["anchor"]["commitment"]

    def test_the_root_is_recomputed_not_copied(self):
        """The difference between reporting what the bundler said and verifying it."""
        payload = _payload()
        assert payload["recomputed"]["matches_bundle_root"] is True
        assert payload["recomputed"]["merkle_root"] == payload["anchored"]["merkle_root"]

    def test_a_bundle_whose_leaves_do_not_rebuild_its_root_is_refused(self, tmp_path):
        doc = json.loads(BUNDLE.read_text(encoding="utf-8"))
        doc["tree"]["merkle_root"] = "ab" * 32
        tampered = tmp_path / "x.evidence.json"
        tampered.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(EvidenceError, match="does not verify"):
            ap.build_payload(
                tampered, authority=TEST_AUTHORITY, program_id=TEST_PROGRAM, cluster="devnet"
            )

    def test_the_instruction_data_length_is_140_bytes(self):
        # 8 discriminator + 4 leaf_count + 4 * 32 digests.
        payload = _payload()
        assert payload["instruction"]["data_len"] == 140
        assert len(bytes.fromhex(payload["instruction"]["data_hex"])) == 140

    def test_the_discriminator_is_recomputable_by_hand(self):
        """An operator checks this with one sha256, so it must be exactly derivable."""
        payload = _payload()
        preimage = payload["instruction"]["discriminator_preimage"]
        assert preimage == "global:anchor_evidence"
        expected = hashlib.sha256(preimage.encode()).digest()[:8]
        assert payload["instruction"]["discriminator_hex"] == expected.hex()

    def test_the_field_table_reassembles_the_instruction_data(self):
        payload = _payload()
        rebuilt = b"".join(bytes.fromhex(f["hex"]) for f in payload["instruction"]["fields"])
        assert rebuilt == bytes.fromhex(payload["instruction"]["data_hex"])
        offsets = [f["offset"] for f in payload["instruction"]["fields"]]
        assert offsets == sorted(offsets)

    def test_leaf_count_is_little_endian_in_borsh_and_big_endian_in_the_commitment(self):
        """The one footgun worth a dedicated test.

        The same number appears twice with two byte orders. Conflating them
        produces a payload the program rejects, and the failure would look like a
        mysterious CommitmentMismatch rather than an encoding bug.
        """
        payload = _payload()
        leaf_count = payload["anchored"]["leaf_count"]

        borsh_field = next(
            f for f in payload["instruction"]["fields"] if f["name"] == "leaf_count"
        )
        assert borsh_field["hex"] == leaf_count.to_bytes(4, "little").hex()
        assert "little-endian" in borsh_field["type"]

        segment = next(
            s for s in payload["commitment"]["preimage_segments"] if "leaf_count" in s["name"]
        )
        assert segment["hex"] == leaf_count.to_bytes(4, "big").hex()
        assert "BIG-endian" in segment["name"]

    def test_the_commitment_preimage_segments_reassemble_the_preimage(self):
        payload = _payload()
        rebuilt = b"".join(
            bytes.fromhex(s["hex"]) for s in payload["commitment"]["preimage_segments"]
        )
        assert rebuilt.hex() == payload["commitment"]["preimage_hex"]
        assert hashlib.sha256(rebuilt).hexdigest() == payload["commitment"]["hex"]

    def test_the_accounts_are_ordered_and_flagged_correctly(self):
        accounts = _payload()["accounts"]
        assert [a["name"] for a in accounts] == ["record", "authority", "system_program"]
        assert [a["is_signer"] for a in accounts] == [False, True, False]
        assert [a["is_writable"] for a in accounts] == [True, True, False]

    def test_the_pda_in_the_accounts_list_matches_the_pda_block(self):
        payload = _payload()
        record = next(a for a in payload["accounts"] if a["name"] == "record")
        assert record["pubkey"] == payload["pda"]["address"]

    def test_the_pda_seeds_are_published_for_manual_verification(self):
        seeds = _payload()["pda"]["seeds"]
        assert [s["label"] for s in seeds] == ["SEED_PREFIX", "authority", "commitment"]
        assert seeds[0]["utf8"] == "ares-evidence-v1"

    def test_no_signature_blockhash_or_keypair_is_included(self):
        payload = _payload()
        assert set(payload["not_included"]) == {
            "signature",
            "recent blockhash",
            "keypair",
            "rpc endpoint",
        }
        serialized = json.dumps(payload).lower()
        for forbidden in ("blockhash", "privatekey", "secretkey", "mnemonic"):
            assert forbidden not in serialized.replace("recent blockhash", "")

    def test_devnet_is_labelled_as_carrying_no_evidentiary_value(self):
        """Devnet is periodically reset, so an anchor there is destroyed while
        looking identical to a real one."""
        assert "none" in _payload(cluster="devnet")["evidentiary_value"]
        assert "reset" in _payload(cluster="devnet")["evidentiary_value"]

    def test_mainnet_states_only_the_upper_bound_claim(self):
        value = _payload(cluster="mainnet-beta")["evidentiary_value"]
        assert "upper bound" in value

    def test_rent_and_fee_are_labelled_estimates(self):
        estimates = _payload()["estimates"]
        assert estimates["rent_lamports"] > 0
        assert "Estimates only" in estimates["note"]
        assert "Rent::get()" in estimates["note"]


class TestCli:
    def test_the_cli_requires_a_cluster(self, capsys):
        """Neither default is safe: devnet manufactures worthless anchors, mainnet
        spends real SOL."""
        with pytest.raises(SystemExit):
            ap.main([str(BUNDLE), "--authority", TEST_AUTHORITY, "--program-id", TEST_PROGRAM])

    def test_the_cli_writes_a_payload(self, tmp_path, capsys):
        out = tmp_path / "payload.json"
        code = ap.main(
            [
                str(BUNDLE),
                "--authority",
                TEST_AUTHORITY,
                "--program-id",
                TEST_PROGRAM,
                "--cluster",
                "mainnet-beta",
                "--out",
                str(out),
            ]
        )
        assert code == 0
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["payload_version"] == ap.PAYLOAD_VERSION

    def test_the_cli_reports_one_on_a_refusal(self, capsys):
        code = ap.main(
            [
                str(BUNDLE),
                "--authority",
                "~/.config/solana/id.json",
                "--program-id",
                TEST_PROGRAM,
                "--cluster",
                "devnet",
            ]
        )
        assert code == 1
        assert "file path" in capsys.readouterr().err

    def test_the_cli_warns_on_devnet(self, tmp_path, capsys):
        ap.main(
            [
                str(BUNDLE),
                "--authority",
                TEST_AUTHORITY,
                "--program-id",
                TEST_PROGRAM,
                "--cluster",
                "devnet",
                "--out",
                str(tmp_path / "p.json"),
            ]
        )
        assert "NO evidentiary value" in capsys.readouterr().err
