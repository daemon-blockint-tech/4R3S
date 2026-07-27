import pandas as pd
import pytest

from gate_selftest import degraded, main, perfect

TRUTH = pd.DataFrame(
    {
        "target_id": ["p1", "p1", "p2", "p3"],
        "category": ["arbitrary-cpi", "type-cosplay", "precision-loss", "missing-owner-check"],
        "severity": ["critical", "high", "medium", "high"],
    }
)


@pytest.fixture
def truth_csv(tmp_path):
    path = tmp_path / "ground_truth.csv"
    TRUTH.to_csv(path, index=False)
    return path


def test_perfect_predictions_carry_only_the_match_key():
    assert list(perfect(TRUTH).columns) == ["target_id", "category"]
    assert len(perfect(TRUTH)) == len(TRUTH)


def test_degraded_predictions_drop_labels_deterministically():
    first = degraded(TRUTH, keep=0.5, seed=7)
    assert len(first) == 2
    assert first.equals(degraded(TRUTH, keep=0.5, seed=7))


def test_selftest_passes_when_the_gate_behaves(truth_csv, tmp_path):
    assert main(["--truth", str(truth_csv), "--tmp-dir", str(tmp_path / "out")]) == 0


def test_selftest_fails_when_the_gate_cannot_reject(truth_csv, tmp_path, capsys):
    # A target of 0 accepts everything, so the degraded and empty cases stop
    # failing and the self-test must notice.
    code = main(["--truth", str(truth_csv), "--target-f1", "0.0", "--tmp-dir", str(tmp_path / "out")])
    assert code == 1
    assert "GATE SELF-TEST FAILED" in capsys.readouterr().err


def test_empty_ground_truth_is_rejected(tmp_path, capsys):
    path = tmp_path / "empty.csv"
    path.write_text("target_id,category\n")
    assert main(["--truth", str(path), "--tmp-dir", str(tmp_path / "out")]) == 1
    assert "ground truth is empty" in capsys.readouterr().err
