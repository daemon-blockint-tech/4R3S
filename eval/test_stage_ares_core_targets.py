import json

import pandas as pd
import pytest

from stage_ares_core_targets import safe_name_for, stage_targets


def test_safe_name_for_matches_corpus_filename_convention():
    # Must match the transform used by all three EVAL-3 fetch/build scripts:
    # target_id_for(...).replace(":", "_") -- verified directly against
    # fetch_sealevel_attacks.py, fetch_neodyme_workshop.py, build_incident_repros.py.
    assert safe_name_for("sealevel-attacks:0-signer-authorization") == "sealevel-attacks_0-signer-authorization"


def test_stage_targets_creates_one_src_dir_per_target(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "sealevel-attacks_0-signer-authorization.rs").write_text("// vuln a")
    (corpus_dir / "neodyme-workshop_level1.rs").write_text("// vuln b")

    ground_truth = pd.DataFrame(
        {
            "target_id": [
                "sealevel-attacks:0-signer-authorization",
                "neodyme-workshop:level1",
            ]
        }
    )
    staging_root = tmp_path / "staging"
    manifest = stage_targets(ground_truth, corpus_dir, staging_root)

    assert manifest == {
        "sealevel-attacks_0-signer-authorization": "sealevel-attacks:0-signer-authorization",
        "neodyme-workshop_level1": "neodyme-workshop:level1",
    }
    lib_a = staging_root / "sealevel-attacks_0-signer-authorization" / "src" / "lib.rs"
    lib_b = staging_root / "neodyme-workshop_level1" / "src" / "lib.rs"
    assert lib_a.read_text() == "// vuln a"
    assert lib_b.read_text() == "// vuln b"
    # Each target gets its OWN src/ dir -- never shared -- so ares-cli scan's
    # report-per-directory identity stays one report per target_id.
    assert lib_a.parent != lib_b.parent


def test_stage_targets_raises_loudly_on_missing_corpus_file(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    ground_truth = pd.DataFrame({"target_id": ["incident-repros:wormhole-2022"]})

    with pytest.raises(FileNotFoundError, match="corpus file missing"):
        stage_targets(ground_truth, corpus_dir, tmp_path / "staging")


def test_stage_targets_deduplicates_repeated_target_ids(tmp_path):
    # ground_truth.csv can have multiple rows per target_id (one per
    # vulnerability); staging must not try to copy the same file twice or
    # error on it.
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "sealevel-attacks_1-account-data-matching.rs").write_text("// vuln")

    ground_truth = pd.DataFrame(
        {
            "target_id": [
                "sealevel-attacks:1-account-data-matching",
                "sealevel-attacks:1-account-data-matching",
            ]
        }
    )
    manifest = stage_targets(ground_truth, corpus_dir, tmp_path / "staging")
    assert len(manifest) == 1


def test_manifest_is_written_to_disk(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "sealevel-attacks_0-signer-authorization.rs").write_text("// vuln")
    ground_truth = pd.DataFrame({"target_id": ["sealevel-attacks:0-signer-authorization"]})

    import stage_ares_core_targets as mod

    staging_root = tmp_path / "staging"
    mod.main(
        [
            "--ground-truth",
            str(_write_ground_truth_csv(tmp_path, ground_truth)),
            "--corpus-dir",
            str(corpus_dir),
            "--staging-root",
            str(staging_root),
        ]
    )
    manifest_path = staging_root / "staging_manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text())
    assert manifest == {"sealevel-attacks_0-signer-authorization": "sealevel-attacks:0-signer-authorization"}


def _write_ground_truth_csv(tmp_path, df: pd.DataFrame):
    path = tmp_path / "ground_truth.csv"
    df.to_csv(path, index=False)
    return path
