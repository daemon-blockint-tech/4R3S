import json
from pathlib import Path

import pandas as pd
import pytest

from fetch_datasets import (
    build_ground_truth,
    conflicting_targets,
    label_rows,
    split_records,
    target_ids,
    write_corpus,
)

MAPPING = json.loads((Path(__file__).parent / "mappings" / "solana-vuln-rust.json").read_text())

VULN_ROW = (
    "<s> [INST] Can you check if the following smart contract written in Rust contains a vulnerability? "
    "```let x = a - b;```. [/INST] Yes, it contains a vulnerability. It is classified as Integer Flow "
    "and is related to the code:`a - b`. In SWC it is mapped with: SWC-101. </s>"
    "<s> [INST] Can you suggest how to mitigate this vulnerability? [/INST] Use checked_sub. </s>"
)
CLEAN_ROW = (
    "<s> [INST] Can you check if the following smart contract written in Rust contains a vulnerability? "
    "```pub struct Message { pub nick: String }```. [/INST] No, it does not contain any vulnerabilities. </s>"
)


def prepared(rows):
    records = split_records(pd.Series(rows))
    records["target_id"] = target_ids(records, MAPPING["dataset"], MAPPING["split"])
    return label_rows(records, MAPPING)


def test_verdict_turn_is_parsed_not_the_remediation_turn():
    records = split_records(pd.Series([VULN_ROW]))
    assert records.loc[0, "code"] == "let x = a - b;"
    assert records.loc[0, "verdict"].startswith("Yes, it contains a vulnerability")
    assert "checked_sub" not in records.loc[0, "verdict"]


def test_label_is_mapped_to_catalog_category_with_location_and_swc():
    labeled = prepared([VULN_ROW])
    row = labeled.iloc[0]
    assert row["dataset_label"] == "Integer Flow"
    assert row["category"] == "integer-overflow-underflow"
    assert row["severity"] == "high"
    assert row["location"] == "a - b"
    assert row["swc"] == "SWC-101"
    assert not row["is_clean"]


def test_clean_rows_carry_no_category_and_no_ground_truth():
    labeled = prepared([CLEAN_ROW])
    assert labeled.iloc[0]["is_clean"]
    assert pd.isna(labeled.iloc[0]["category"])
    assert build_ground_truth(labeled, MAPPING["dataset"], MAPPING["revision"]).empty


def test_target_id_is_content_addressed():
    labeled = prepared([VULN_ROW, VULN_ROW])
    assert labeled["target_id"].nunique() == 1
    assert labeled.iloc[0]["target_id"].startswith("solana-vuln-rust:train:")


def test_duplicate_rows_collapse_into_one_ground_truth_row():
    truth = build_ground_truth(prepared([VULN_ROW, VULN_ROW]), MAPPING["dataset"], MAPPING["revision"])
    assert len(truth) == 1
    assert truth.iloc[0]["source_ref"].startswith("hf://FraChiacc99/solana-vuln-rust@")
    assert truth.iloc[0]["source_ref"].endswith("SWC-101")


def test_snippet_labeled_both_ways_is_reported_and_scored_as_vulnerable():
    same_code_clean = VULN_ROW.replace(
        "Yes, it contains a vulnerability. It is classified as Integer Flow "
        "and is related to the code:`a - b`. In SWC it is mapped with: SWC-101.",
        "No, it does not contain any vulnerabilities.",
    )
    labeled = prepared([VULN_ROW, same_code_clean])
    assert len(conflicting_targets(labeled)) == 1
    truth = build_ground_truth(labeled, MAPPING["dataset"], MAPPING["revision"])
    assert list(truth["category"]) == ["integer-overflow-underflow"]


def test_unknown_dataset_label_is_rejected():
    row = VULN_ROW.replace("classified as Integer Flow", "classified as Reentrancy")
    with pytest.raises(ValueError, match="absent from"):
        prepared([row])


def test_unparseable_verdict_is_rejected():
    row = VULN_ROW.replace("It is classified as Integer Flow and is related to the code:`a - b`.", "Maybe?")
    with pytest.raises(ValueError, match="neither a clean verdict nor a parseable"):
        prepared([row])


def test_missing_code_block_is_rejected():
    with pytest.raises(ValueError, match="no ``` code block"):
        split_records(pd.Series(["[INST] no code here [/INST] No, it does not contain any vulnerabilities."]))


def test_corpus_files_are_written_per_target(tmp_path):
    labeled = prepared([VULN_ROW, CLEAN_ROW])
    assert write_corpus(labeled, tmp_path) == 2
    corpus = tmp_path / "corpus"
    rs_files = sorted(p.name for p in corpus.iterdir() if p.suffix == ".rs")
    assert all(name.startswith("solana-vuln-rust_train_") and name.endswith(".rs") for name in rs_files)
    assert "let x = a - b;" in (corpus / rs_files[0]).read_text() or "let x = a - b;" in (
        corpus / rs_files[1]
    ).read_text()
    # index.json restores each file stem to its ground-truth target_id (the ':'
    # the filename had to drop). The eval runner scores against these ids, so a
    # missing or mismatched index silently zeroes every prediction.
    index = json.loads((corpus / "index.json").read_text())
    assert sorted(stem + ".rs" for stem in index) == rs_files
    assert all(index[name[:-3]].replace(":", "_") == name[:-3] for name in rs_files)
