"""The load-bearing suite: real committed artifacts, not synthetic fixtures.

This is the file that would catch a change nobody meant to make. Every other
test builds its own inputs, so every other test moves when the code moves. These
run against two real `ares scan` reports and their committed bundles, with the
roots and commitments pinned as hex literals -- so a code change that alters a
root cannot pass by quietly regenerating the fixture.

Same role as services/cve/test_snapshot_integrity.py, and the same reason it
exists: it moves an encoding change from anchor time, where nobody sees it, to
CI, where a human does.

Note what this suite can and cannot cover. eval/data/ is entirely gitignored, so
the 636-report corpus these two artifacts came from is not available in CI. The
sweep at the bottom skips there, and says so in its skip reason.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil

import pytest

import bundle
import merkle
import verify
from canonical import leaf_preimage
from report import load_report

HERE = pathlib.Path(__file__).parent
VECTORS = HERE / "vectors"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
REPO_ROOT = HERE.parents[1]

REPORTS = ("ares-report-suppressed-only", "ares-report-sixteen-findings")


class TestManifestIntegrity:
    """Recomputed digests, deliberately duplicating what other code checks.

    services/cve/test_snapshot_integrity.py:28-36 does the same thing for the
    advisory snapshot, for the same stated reason: CI should see it on every
    push, not only when something happens to load the file.
    """

    @pytest.mark.parametrize("name", sorted(MANIFEST["files"]))
    def test_every_vector_matches_its_recorded_digest(self, name):
        raw = (VECTORS / name).read_bytes()
        recorded = MANIFEST["files"][name]
        assert hashlib.sha256(raw).hexdigest() == recorded["sha256"], name
        assert len(raw) == recorded["bytes"], name
        assert raw.endswith(b"\n") == recorded["ends_with_newline"], name

    def test_the_manifest_lists_every_file_in_the_directory(self):
        on_disk = {p.name for p in VECTORS.iterdir() if p.name != "manifest.json"}
        assert on_disk == set(MANIFEST["files"])

    def test_the_reports_still_end_without_a_newline(self):
        """serde_json's to_string_pretty leaves none, and the digest covers the
        exact bytes -- an editor adding one would change the artifact."""
        for name in REPORTS:
            assert not (VECTORS / f"{name}.json").read_bytes().endswith(b"\n")

    def test_the_manifest_records_the_not_checked_by_ci_caveat(self):
        """The corpus these came from is gitignored; the manifest must say so."""
        joined = " ".join(MANIFEST["notes"])
        assert "not_checked_by_ci" in joined
        assert "eval/data/" in joined


class TestCommittedBundlesAreReproducible:
    @pytest.mark.parametrize("name", REPORTS)
    def test_bundling_a_committed_vector_reproduces_the_committed_bundle_byte_for_byte(
        self, name, tmp_path
    ):
        """The strongest single assertion in the suite.

        Covers the leaf encoding, the tree, the proofs, the commitment, the
        header, key ordering and the trailing newline in one comparison.
        """
        staged = tmp_path / f"{name}.json"
        shutil.copyfile(VECTORS / f"{name}.json", staged)
        rebuilt = bundle.serialize_bundle(bundle.build_bundle(load_report(staged)))
        committed = (VECTORS / f"{name}.evidence.json").read_bytes()
        assert rebuilt == committed, (
            f"{name}: regenerating the bundle no longer reproduces the committed "
            f"bytes. If this change is intended, it is a new leaf encoding "
            f"version -- bump canonical.LEAF_ENCODING and refresh the manifest "
            f"deliberately, do not just overwrite the fixture."
        )

    @pytest.mark.parametrize("name", REPORTS)
    def test_the_pinned_root_and_commitment_hex_match(self, name):
        """Pinned separately from the bundle bytes, so a regenerated fixture that
        silently changed a root still fails here."""
        pinned = MANIFEST["pinned_values"][name]
        doc = json.loads((VECTORS / f"{name}.evidence.json").read_text(encoding="utf-8"))
        assert doc["tree"]["merkle_root"] == pinned["merkle_root"]
        assert doc["anchor"]["commitment"] == pinned["commitment"]
        assert doc["tree"]["leaf_count"] == pinned["leaf_count"]

    def test_the_pinned_empty_root_is_the_rfc6962_constant(self):
        assert MANIFEST["pinned_values"]["empty_root"] == merkle.EMPTY_ROOT.hex()

    @pytest.mark.parametrize("name", REPORTS)
    def test_every_leaf_in_a_committed_bundle_has_a_verifying_proof(self, name):
        doc = json.loads((VECTORS / f"{name}.evidence.json").read_text(encoding="utf-8"))
        root = bytes.fromhex(doc["tree"]["merkle_root"])
        count = doc["tree"]["leaf_count"]
        for leaf in doc["leaves"]:
            proof = [(s["position"], bytes.fromhex(s["hash"])) for s in leaf["proof"]]
            assert merkle.verify_inclusion(
                leaf_preimage(leaf["fields"]), leaf["index"], count, proof, root
            ), f"{name} leaf {leaf['index']}"

    @pytest.mark.parametrize("name", REPORTS)
    def test_a_committed_bundle_verifies_end_to_end(self, name):
        outcome = verify.verify(VECTORS / f"{name}.evidence.json", VECTORS / f"{name}.json")
        assert outcome.code == verify.OK, outcome.message


class TestOneFieldEditsProduceSpecificOutcomes:
    """Walks the decision table against a real artifact.

    Each case is a single field edit, and each must produce its own outcome. If
    two of these ever collapsed onto one code, the verifier would have stopped
    being able to say *what* went wrong.
    """

    @pytest.fixture
    def staged(self, tmp_path):
        name = "ares-report-sixteen-findings"
        report_path = tmp_path / f"{name}.json"
        shutil.copyfile(VECTORS / f"{name}.json", report_path)
        bundle_path = bundle.write_bundle(report_path, force=True)
        return report_path, bundle_path

    def _edit(self, path, fn):
        data = json.loads(path.read_text(encoding="utf-8"))
        fn(data)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def test_editing_generated_at_gives_edited_outside_leaves(self, staged):
        report_path, bundle_path = staged
        self._edit(report_path, lambda d: d["metadata"].__setitem__("generated_at", "2099-01-01T00:00:00Z"))
        assert verify.verify(bundle_path, report_path).code == verify.REPORT_EDITED_OUTSIDE_LEAVES

    def test_editing_a_summary_count_gives_edited_outside_leaves(self, staged):
        report_path, bundle_path = staged
        self._edit(report_path, lambda d: d["summary"].__setitem__("tests_failed", 7))
        assert verify.verify(bundle_path, report_path).code == verify.REPORT_EDITED_OUTSIDE_LEAVES

    def test_editing_a_severity_gives_report_tampered(self, staged):
        report_path, bundle_path = staged
        self._edit(report_path, lambda d: d["findings"][0].__setitem__("severity", "Informational"))
        assert verify.verify(bundle_path, report_path).code == verify.REPORT_TAMPERED

    def test_demoting_a_finding_gives_report_tampered(self, staged):
        report_path, bundle_path = staged

        def demote(d):
            moved = d["findings"].pop(0)
            d["suppressed_findings"].append(
                {"finding": moved, "reason": "quietly dropped", "suppressed_by": "llm_judge"}
            )

        self._edit(report_path, demote)
        assert verify.verify(bundle_path, report_path).code == verify.REPORT_TAMPERED

    def test_swapping_in_the_other_vector_gives_different_report(self, staged):
        report_path, bundle_path = staged
        shutil.copyfile(VECTORS / "ares-report-suppressed-only.json", report_path)
        assert verify.verify(bundle_path, report_path).code == verify.DIFFERENT_REPORT

    def test_editing_the_bundle_root_gives_root_mismatch(self, staged):
        _, bundle_path = staged
        doc = json.loads(bundle_path.read_text(encoding="utf-8"))
        doc["tree"]["merkle_root"] = "ab" * 32
        bundle_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert verify.verify(bundle_path).code == verify.ROOT_MISMATCH


class TestTheLocalCorpus:
    """A sweep over every report from the run the vectors came from.

    This NEVER runs in CI. eval/data/ is entirely gitignored -- `git ls-files
    eval/data/` returns zero files -- so the directory exists only on a machine
    that has done a local eval run. The skip reason says so explicitly, because a
    silently-skipped sweep is how a green CI gets mistaken for coverage it does
    not have.
    """

    CORPUS = REPO_ROOT / "eval" / "data" / "reports-astscan"

    @pytest.mark.skipif(
        not (REPO_ROOT / "eval" / "data" / "reports-astscan").is_dir(),
        reason=(
            "eval/data/ is gitignored, so this sweep never runs in CI -- it only "
            "runs on a machine with a local eval run present. CI coverage is the "
            "two committed vectors."
        ),
    )
    def test_every_local_report_bundles_and_verifies(self, tmp_path):
        reports = sorted(self.CORPUS.glob("ares-report-*.json"))
        assert reports, "corpus directory exists but holds no reports"

        failures = []
        for i, source in enumerate(reports):
            staged = tmp_path / f"{i:04d}-{source.name}"
            shutil.copyfile(source, staged)
            try:
                bundle_path = bundle.write_bundle(staged, force=True)
                outcome = verify.verify(bundle_path, staged)
                if outcome.code != verify.OK:
                    failures.append(f"{source.name}: {outcome.name} -- {outcome.message[:120]}")
            except Exception as exc:  # noqa: BLE001 -- collect, do not stop the sweep
                failures.append(f"{source.name}: {type(exc).__name__}: {exc}")

        assert not failures, (
            f"{len(failures)} of {len(reports)} local reports did not round-trip:\n"
            + "\n".join(failures[:20])
        )
