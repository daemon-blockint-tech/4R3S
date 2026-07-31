import json
import re
from pathlib import Path

import pytest

from build_incident_repros import (
    FIXTURE_IDL_DIR,
    FIXTURE_RS_DIR,
    build_ground_truth,
    load_idl,
    read_source,
    target_id_for,
    to_camel,
    validate_idl,
    write_corpus,
    write_idls,
)

MAPPING = json.loads((Path(__file__).parent / "mappings" / "incident-repros.json").read_text())
CATALOG_SEVERITIES = {"info", "low", "medium", "high", "critical"}
GIT_SHA_LIKE = re.compile(r"\b[0-9a-f]{7,40}\b")


def test_target_id_is_stable_and_namespaced():
    assert target_id_for("wormhole-2022") == "incident-repros:wormhole-2022"


def test_every_program_has_a_fixture_idl_that_validates():
    for entry in MAPPING["programs"].values():
        validate_idl(load_idl(entry), entry)  # raises on drift


def test_validate_idl_rejects_wrong_program_name():
    entry = MAPPING["programs"]["wormhole-2022"]
    with pytest.raises(ValueError, match="!= mapping program_name"):
        validate_idl({"name": "wrong", "instructions": [{"name": "verifySignatures"}]}, entry)


def test_validate_idl_rejects_missing_instruction():
    entry = MAPPING["programs"]["cashio-2022"]
    with pytest.raises(ValueError, match="lacks instruction"):
        validate_idl({"name": entry["program_name"], "instructions": []}, entry)


def test_ground_truth_has_one_row_per_incident_with_valid_category_and_severity():
    digests = {p: "deadbeefcafe" for p in MAPPING["programs"]}
    truth = build_ground_truth(MAPPING, digests)
    assert len(truth) == len(MAPPING["programs"]) == 3
    assert set(truth.columns) == {"target_id", "category", "severity", "location", "source_ref"}
    assert set(truth["severity"]).issubset(CATALOG_SEVERITIES)
    assert truth["target_id"].is_unique
    assert set(truth["category"]) == {
        "sysvar-spoofing",
        "account-data-matching",
        "oracle-price-manipulation",
    }


def test_source_ref_carries_no_fabricated_commit_hash():
    # Regression guard: nothing was fetched here, so source_ref must not look
    # like a real git commit -- that would misrepresent the provenance as more
    # legitimate (extracted from a pinned upstream revision) than it is.
    digests = {p: "deadbeefcafe" for p in MAPPING["programs"]}
    truth = build_ground_truth(MAPPING, digests)
    for ref in truth["source_ref"]:
        assert ref.startswith("incident:"), ref
        assert "git://" not in ref
        assert "github.com" not in ref


def test_mapping_declares_no_upstream_revision():
    assert MAPPING["source_kind"] == "authored"
    assert MAPPING["revision"] is None
    assert MAPPING["repo_url"] is None


def code_lines_only(code: str) -> str:
    """Strip full-line `//` comments so content assertions check real code, not
    the disclaimer/explanation comments describing what's deliberately missing."""
    return "\n".join(
        line for line in code.splitlines() if not line.strip().startswith("//")
    )


def test_wormhole_snippet_never_checks_the_real_secp256k1_program():
    # The whole point of the reproduction: no checked sysvar accessor, no
    # comparison against the real secp256k1 program id, in the actual code
    # (comments are allowed to *describe* the missing check).
    code = code_lines_only(read_source(MAPPING["programs"]["wormhole-2022"]))
    assert "load_instruction_at_checked" not in code
    assert "secp256k1_program::ID" not in code
    assert "== secp256k1" not in code


def test_cashio_snippet_never_links_bank_to_crate_token():
    code = code_lines_only(read_source(MAPPING["programs"]["cashio-2022"]))
    assert "crate_token_key ==" not in code
    assert "bank_data.crate_token_key" not in code


def test_mango_snippet_price_read_has_no_staleness_or_confidence_check():
    code = code_lines_only(read_source(MAPPING["programs"]["mango-2022"]))
    for token in ("confidence", "staleness", "twap", "TWAP"):
        assert token not in code


def test_write_corpus_and_idls_use_matching_target_names(tmp_path):
    sources = {"wormhole-2022": "// stylized snippet"}
    assert write_corpus(sources, tmp_path) == 1
    assert (tmp_path / "corpus" / "incident-repros_wormhole-2022.rs").exists()
    assert write_idls(MAPPING, tmp_path) == 3
    assert (tmp_path / "idl" / "incident-repros_wormhole-2022.json").exists()


def test_fixture_dirs_have_exactly_the_mapped_files():
    on_disk_idl = {p.name for p in FIXTURE_IDL_DIR.glob("*.json")}
    referenced_idl = {entry["idl"] for entry in MAPPING["programs"].values()}
    assert on_disk_idl == referenced_idl

    on_disk_rs = {p.name for p in FIXTURE_RS_DIR.glob("*.rs")}
    referenced_rs = {entry["rs"] for entry in MAPPING["programs"].values()}
    assert on_disk_rs == referenced_rs


def test_to_camel():
    assert to_camel("verify_signatures") == "verifySignatures"
    assert to_camel("borrow_against_collateral") == "borrowAgainstCollateral"
