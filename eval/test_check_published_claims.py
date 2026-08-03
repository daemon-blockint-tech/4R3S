"""Exercise every exit path of the published-claims gate, across both products.

`gate_selftest.py` proves the scorer accepts and rejects at the right F1, but
nothing covered `check_published_claims.py`, so its branches were asserted
rather than demonstrated. Each test here pins one.

Branch map (return value in parentheses):
  README absent                               (0) — ares-sec is a skeleton
  README states no numeric metric             (0) — "not measured" is honest
  claim + no predictions file                 (1) — no run produced it
  claim + predictions but no score.json       (1) — cannot verify
  claim disagrees with the scored run         (1) — stale or invented
  claim agrees with the scored run            (0) — re-derivable
  claim in a product with no harness          (1) — unverifiable by construction
"""
import json

import pytest

import check_published_claims as gate

ROOT_README = "README.md"
AUDITOR_README = "apps/auditor-api/README.md"
SEC_README = "apps/ares-sec/README.md"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A scratch monorepo so tests never read the real one."""
    for app in ("ares-sec", "auditor-api", "auditor-web"):
        (tmp_path / "apps" / app).mkdir(parents=True)
    predictions = tmp_path / "ares-latest.csv"
    score = tmp_path / "score.json"
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "PREDICTIONS", predictions)
    monkeypatch.setattr(gate, "SCORE", score)
    return tmp_path, predictions, score


def write(root, relative_path, text):
    (root / relative_path).write_text(text)


def scored(path, **metrics):
    path.write_text(json.dumps({"overall": metrics}))


def test_absent_readmes_pass(repo):
    assert gate.main() == 0


def test_readme_without_a_numeric_metric_passes(repo):
    root, _, _ = repo
    write(root, ROOT_README, "# ARES\n\n| F1 | not measured |\n")
    assert gate.main() == 0


def test_claim_without_predictions_fails(repo):
    root, _, _ = repo
    write(root, ROOT_README, "| F1 | 0.94 | verified |\n")
    assert gate.main() == 1


def test_claim_without_a_score_file_fails(repo):
    root, predictions, _ = repo
    write(root, ROOT_README, "| F1 | 0.94 | verified |\n")
    predictions.write_text("target_id,category\n")
    assert gate.main() == 1


def test_claim_that_disagrees_with_the_run_fails(repo):
    root, predictions, score = repo
    write(root, ROOT_README, "| F1 | 0.94 | verified |\n")
    predictions.write_text("target_id,category\n")
    scored(score, f1=0.0603)
    assert gate.main() == 1


def test_claim_that_matches_the_run_passes(repo):
    root, predictions, score = repo
    write(root, ROOT_README, "| F1 | 0.0603 | measured |\n")
    predictions.write_text("target_id,category\n")
    scored(score, f1=0.0603)
    assert gate.main() == 0


def test_tolerance_admits_rounding_but_not_drift(repo):
    # TOLERANCE is 0.005: a rounded figure is the same claim, a moved one is not.
    root, predictions, score = repo
    predictions.write_text("target_id,category\n")
    scored(score, f1=0.0603)

    write(root, ROOT_README, "| F1 | 0.06 | measured |\n")
    assert gate.main() == 0

    write(root, ROOT_README, "| F1 | 0.07 | measured |\n")
    assert gate.main() == 1


def test_every_claimed_metric_is_checked_not_just_the_first(repo):
    # A README that gets F1 right and recall wrong is still publishing a number
    # nobody measured.
    root, predictions, score = repo
    write(root, ROOT_README, "| Precision | 0.13 |\n| Recall | 0.99 |\n| F1 | 0.06 |\n")
    predictions.write_text("target_id,category\n")
    scored(score, precision=0.1277, recall=0.0395, f1=0.0603)
    assert gate.main() == 1


def test_a_product_readme_is_guarded_too(repo):
    # The defect this covers: before both products were guarded, a figure here
    # shipped unchecked because only the root README was read.
    root, predictions, score = repo
    write(root, AUDITOR_README, "| F1 | 0.94 | verified |\n")
    predictions.write_text("target_id,category\n")
    scored(score, f1=0.0603)
    assert gate.main() == 1


def test_ares_sec_cannot_publish_a_figure_while_it_has_no_harness(repo):
    # Not a disagreement — there is no run that could produce this at all, and
    # the message has to say so rather than compare it to the Auditor's score.
    root, predictions, score = repo
    write(root, SEC_README, "| F1 | 0.94 | verified |\n")
    predictions.write_text("target_id,category\n")
    scored(score, f1=0.94)  # even an exact match must not launder the claim
    assert gate.main() == 1


def test_all_offending_readmes_are_reported_not_just_the_first(repo, capsys):
    root, predictions, score = repo
    write(root, ROOT_README, "| F1 | 0.94 |\n")
    write(root, AUDITOR_README, "| F1 | 0.88 |\n")
    predictions.write_text("target_id,category\n")
    scored(score, f1=0.0603)

    assert gate.main() == 1
    err = capsys.readouterr().err
    assert ROOT_README in err
    assert AUDITOR_README in err


def test_parser_reads_all_three_metrics_case_insensitively():
    found = gate.published_metrics("| precision | 0.1 |\n| RECALL | 0.2 |\n| F1 | 0.3 |")
    assert found == {"precision": 0.1, "recall": 0.2, "f1": 0.3}
