import json
from pathlib import Path

import pytest

from fetch_sealevel_attacks import (
    FIXTURE_IDL_DIR,
    build_ground_truth,
    load_idl,
    target_id_for,
    to_camel,
    validate_idl,
    write_corpus,
    write_idls,
)

MAPPING = json.loads((Path(__file__).parent / "mappings" / "sealevel-attacks.json").read_text())
CATALOG_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def test_to_camel_matches_anchor_convention():
    assert to_camel("log_message") == "logMessage"
    assert to_camel("set_value") == "setValue"
    assert to_camel("check_sysvar_address") == "checkSysvarAddress"
    assert to_camel("cpi") == "cpi"


def test_target_id_is_stable_and_namespaced():
    assert target_id_for("0-signer-authorization") == "sealevel-attacks:0-signer-authorization"


def test_every_program_has_a_fixture_idl_that_validates():
    for entry in MAPPING["programs"].values():
        idl = load_idl(entry)
        validate_idl(idl, entry)  # raises on drift


def test_validate_idl_rejects_wrong_program_name():
    entry = MAPPING["programs"]["0-signer-authorization"]
    with pytest.raises(ValueError, match="!= mapping program_name"):
        validate_idl({"name": "wrong", "instructions": [{"name": "logMessage"}]}, entry)


def test_validate_idl_rejects_missing_instruction():
    entry = MAPPING["programs"]["0-signer-authorization"]
    with pytest.raises(ValueError, match="lacks instruction"):
        validate_idl({"name": entry["program_name"], "instructions": []}, entry)


def test_ground_truth_has_one_row_per_program_with_valid_category_and_severity():
    digests = {p: "deadbeefcafe" for p in MAPPING["programs"]}
    truth = build_ground_truth(MAPPING, digests)
    assert len(truth) == len(MAPPING["programs"]) == 11
    assert set(truth.columns) == {"target_id", "category", "severity", "location", "source_ref"}
    assert set(truth["severity"]).issubset(CATALOG_SEVERITIES)
    assert truth["target_id"].is_unique
    assert truth["source_ref"].str.contains("sha256:").all()


def test_signer_flags_are_faithful_to_the_vulnerable_source():
    # 0-signer-authorization's whole point: authority is NOT required to sign.
    idl = load_idl(MAPPING["programs"]["0-signer-authorization"])
    authority = idl["instructions"][0]["accounts"][0]
    assert authority["name"] == "authority"
    assert authority["isSigner"] is False
    # 1-account-data-matching DOES type authority as Signer.
    idl = load_idl(MAPPING["programs"]["1-account-data-matching"])
    authority = next(a for a in idl["instructions"][0]["accounts"] if a["name"] == "authority")
    assert authority["isSigner"] is True


def test_mut_flags_mark_written_accounts():
    # 9-closing-accounts mutates both account (zeroed) and destination (credited).
    idl = load_idl(MAPPING["programs"]["9-closing-accounts"])
    assert all(a["isMut"] for a in idl["instructions"][0]["accounts"])
    # 4-initialization writes `user` but only reads `authority`.
    idl = load_idl(MAPPING["programs"]["4-initialization"])
    flags = {a["name"]: a["isMut"] for a in idl["instructions"][0]["accounts"]}
    assert flags == {"user": True, "authority": False}


def test_args_carry_typed_parameters():
    idl = load_idl(MAPPING["programs"]["7-bump-seed-canonicalization"])
    args = {a["name"]: a["type"] for a in idl["instructions"][0]["args"]}
    assert args == {"key": "u64", "newValue": "u64", "bump": "u8"}


def test_write_corpus_and_idls_use_matching_target_names(tmp_path):
    sources = {"0-signer-authorization": "// rust source"}
    assert write_corpus(sources, tmp_path) == 1
    assert (tmp_path / "corpus" / "sealevel-attacks_0-signer-authorization.rs").exists()
    assert write_idls(MAPPING, tmp_path) == 11
    assert (tmp_path / "idl" / "sealevel-attacks_0-signer-authorization.json").exists()


def test_fixture_dir_has_exactly_the_mapped_idls():
    on_disk = {p.name for p in FIXTURE_IDL_DIR.glob("*.json")}
    referenced = {entry["idl"] for entry in MAPPING["programs"].values()}
    assert on_disk == referenced
