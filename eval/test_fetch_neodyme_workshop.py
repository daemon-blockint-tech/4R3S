import json
from pathlib import Path

import pytest

from fetch_neodyme_workshop import (
    FIXTURE_IDL_DIR,
    build_ground_truth,
    load_idl,
    target_id_for,
    to_camel,
    validate_idl,
    write_corpus,
    write_idls,
)

MAPPING = json.loads((Path(__file__).parent / "mappings" / "neodyme-workshop.json").read_text())
CATALOG_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def test_target_id_is_stable_and_namespaced():
    assert target_id_for("level1") == "neodyme-workshop:level1"


def test_every_program_has_a_fixture_idl_that_validates():
    for entry in MAPPING["programs"].values():
        validate_idl(load_idl(entry), entry)  # raises on drift


def test_validate_idl_rejects_wrong_program_name():
    entry = MAPPING["programs"]["level1"]
    with pytest.raises(ValueError, match="!= mapping program_name"):
        validate_idl({"name": "wrong", "instructions": [{"name": "withdraw"}]}, entry)


def test_validate_idl_rejects_missing_instruction():
    entry = MAPPING["programs"]["level1"]
    with pytest.raises(ValueError, match="lacks instruction"):
        validate_idl({"name": entry["program_name"], "instructions": [{"name": "deposit"}]}, entry)


def test_ground_truth_has_one_row_per_level_with_valid_category_and_severity():
    digests = {p: "deadbeefcafe" for p in MAPPING["programs"]}
    truth = build_ground_truth(MAPPING, digests)
    assert len(truth) == len(MAPPING["programs"]) == 4
    assert set(truth.columns) == {"target_id", "category", "severity", "location", "source_ref"}
    assert set(truth["severity"]).issubset(CATALOG_SEVERITIES)
    assert truth["target_id"].is_unique
    assert set(truth["category"]) == {
        "missing-signer-check",
        "integer-overflow-underflow",
        "type-cosplay",
        "arbitrary-cpi",
    }


def test_level1_declares_signer_but_bug_is_missing_enforcement():
    # The IDL reflects the DECLARED interface: level1's withdraw builder marks
    # authority as a signer. The vulnerability (missing enforcement) is carried
    # by the mapping category + location, not by the IDL shape.
    idl = load_idl(MAPPING["programs"]["level1"])
    withdraw = next(i for i in idl["instructions"] if i["name"] == "withdraw")
    authority = next(a for a in withdraw["accounts"] if a["name"] == "authority")
    assert authority["isSigner"] is True
    assert MAPPING["programs"]["level1"]["category"] == "missing-signer-check"
    assert MAPPING["programs"]["level1"]["location"] == "level1.withdraw.authority"


def test_level3_initialize_carries_typed_args_including_f64_and_pubkey():
    idl = load_idl(MAPPING["programs"]["level3"])
    init = next(i for i in idl["instructions"] if i["name"] == "initialize")
    args = {a["name"]: a["type"] for a in init["args"]}
    assert args == {"seed": "u8", "fee": "f64", "feeRecipient": "publicKey"}


def test_level4_withdraw_exposes_the_unverified_token_program_account():
    idl = load_idl(MAPPING["programs"]["level4"])
    withdraw = next(i for i in idl["instructions"] if i["name"] == "withdraw")
    names = [a["name"] for a in withdraw["accounts"]]
    assert "splTokenProgram" in names
    assert MAPPING["programs"]["level4"]["location"] == "level4.withdraw.splTokenProgram"


def test_full_instruction_set_is_captured_per_program():
    # Not just the vulnerable instruction — the whole advertised interface.
    counts = {p: len(load_idl(e)["instructions"]) for p, e in MAPPING["programs"].items()}
    assert counts == {"level1": 3, "level2": 3, "level3": 4, "level4": 3}


def test_write_corpus_and_idls_use_matching_target_names(tmp_path):
    sources = {"level1": "// ==== level1/src/lib.rs ====\n// rust source"}
    assert write_corpus(sources, tmp_path) == 1
    assert (tmp_path / "corpus" / "neodyme-workshop_level1.rs").exists()
    assert write_idls(MAPPING, tmp_path) == 4
    assert (tmp_path / "idl" / "neodyme-workshop_level1.json").exists()


def test_fixture_dir_has_exactly_the_mapped_idls():
    on_disk = {p.name for p in FIXTURE_IDL_DIR.glob("*.json")}
    referenced = {entry["idl"] for entry in MAPPING["programs"].values()}
    assert on_disk == referenced


def test_to_camel():
    assert to_camel("create_pool") == "createPool"
    assert to_camel("withdraw") == "withdraw"
