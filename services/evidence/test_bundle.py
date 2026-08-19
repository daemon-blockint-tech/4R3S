"""Bundle assembly: what the root sees, what it deliberately does not, and the
guarantee that the report is never touched.

The pair of tests that carry the design are
`test_editing_generated_at_leaves_the_root_unchanged_but_changes_report_sha256`
and `test_moving_a_finding_into_suppressed_findings_changes_the_root`. Between
them they pin both halves of the two-commitment decision: the root is stable
across the volatile header, and it is sensitive to every claim.
"""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest

import bundle
import merkle
from canonical import EvidenceError, leaf_preimage
from report import load_report

HERE = pathlib.Path(__file__).parent
VECTORS = HERE / "vectors"
SMALL = VECTORS / "ares-report-suppressed-only.json"
LARGE = VECTORS / "ares-report-sixteen-findings.json"


def _staged(tmp_path: pathlib.Path, source: pathlib.Path = LARGE, name: str | None = None) -> pathlib.Path:
    """Copy a fixture into a scratch dir so bundling writes beside a disposable copy."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / (name or source.name)
    shutil.copyfile(source, target)
    return target


def _mutate(path: pathlib.Path, fn) -> pathlib.Path:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _root_of(path: pathlib.Path) -> str:
    return bundle.build_bundle(load_report(path))["tree"]["merkle_root"]


class TestSiblingFileDiscipline:
    def test_the_bundle_lands_beside_the_report_with_the_expected_name(self, tmp_path):
        report_path = _staged(tmp_path)
        written = bundle.write_bundle(report_path)
        assert written == tmp_path / "ares-report-sixteen-findings.evidence.json"

    def test_a_confirmed_report_yields_a_confirmed_evidence_filename(self, tmp_path):
        """Chaining falls out of using the stem, as confirm.rs:387-394 does."""
        report_path = _staged(tmp_path, SMALL, "ares-report-vault.confirmed.json")
        written = bundle.write_bundle(report_path)
        assert written.name == "ares-report-vault.confirmed.evidence.json"

    def test_the_report_is_byte_identical_after_bundling(self, tmp_path):
        """GOLDEN RULE 4: the scan artifact stays byte-for-byte intact."""
        report_path = _staged(tmp_path)
        before = report_path.read_bytes()
        bundle.write_bundle(report_path)
        assert report_path.read_bytes() == before

    def test_out_pointing_at_the_report_is_refused(self, tmp_path):
        """The obvious way to destroy the artifact you are attesting."""
        report_path = _staged(tmp_path)
        with pytest.raises(EvidenceError, match="report itself"):
            bundle.write_bundle(report_path, out=report_path)

    def test_an_existing_bundle_is_not_overwritten_without_force(self, tmp_path):
        report_path = _staged(tmp_path)
        bundle.write_bundle(report_path)
        with pytest.raises(EvidenceError, match="already exists"):
            bundle.write_bundle(report_path)
        bundle.write_bundle(report_path, force=True)

    def test_the_bundle_file_ends_with_a_newline(self, tmp_path):
        """The refresh_snapshot.py convention, which applies to a file we author."""
        report_path = _staged(tmp_path)
        written = bundle.write_bundle(report_path)
        assert written.read_bytes().endswith(b"\n")

    def test_the_bundle_file_has_sorted_keys(self, tmp_path):
        report_path = _staged(tmp_path)
        written = bundle.write_bundle(report_path)
        text = written.read_text(encoding="utf-8")
        assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


class TestWhatTheRootIsSensitiveTo:
    def test_editing_generated_at_leaves_the_root_unchanged_but_changes_report_sha256(self, tmp_path):
        """Both halves of the two-commitment design, in one assertion.

        This is the property that makes a re-run reproducible at all: scan.rs:501
        stamps Utc::now(), so without excluding it the root would differ on every
        single run.
        """
        a = _staged(tmp_path / "a", LARGE)
        b = _staged(tmp_path / "b", LARGE)
        _mutate(b, lambda d: d["metadata"].__setitem__("generated_at", "2099-01-01T00:00:00Z"))

        doc_a = bundle.build_bundle(load_report(a))
        doc_b = bundle.build_bundle(load_report(b))
        assert doc_a["tree"]["merkle_root"] == doc_b["tree"]["merkle_root"]
        assert doc_a["source"]["report_sha256"] != doc_b["source"]["report_sha256"]

    def test_editing_scan_duration_leaves_the_root_unchanged(self, tmp_path):
        a = _staged(tmp_path / "a", LARGE)
        b = _staged(tmp_path / "b", LARGE)
        _mutate(b, lambda d: d["metadata"].__setitem__("scan_duration_secs", 987))
        assert _root_of(a) == _root_of(b)

    def test_reordering_the_findings_array_leaves_the_root_unchanged(self, tmp_path):
        """Nothing in scan.rs sorts findings, so that order is incidental."""
        a = _staged(tmp_path / "a", LARGE)
        b = _staged(tmp_path / "b", LARGE)
        _mutate(b, lambda d: d["findings"].reverse())
        assert _root_of(a) == _root_of(b)

    def test_changing_the_output_directory_leaves_the_root_unchanged(self, tmp_path):
        """proof_of_concept is a function of --output, not of the finding."""
        a = _staged(tmp_path / "a", SMALL)
        b = _staged(tmp_path / "b", SMALL)

        def repoint(d):
            f = d["suppressed_findings"][0]["finding"]
            f["proof_of_concept"] = "some-other-output\\poc\\ares_ast_1_test.rs"

        _mutate(b, repoint)
        assert _root_of(a) == _root_of(b)

    def test_moving_a_finding_into_suppressed_findings_changes_the_root(self, tmp_path):
        """The `kind` leaf field's entire purpose.

        Without it, a real finding demoted to suppressed would produce an
        identical leaf and the root could not see the demotion.
        """
        a = _staged(tmp_path / "a", LARGE)
        b = _staged(tmp_path / "b", LARGE)

        def demote(d):
            moved = d["findings"].pop(0)
            d["suppressed_findings"].append(
                {"finding": moved, "reason": "demoted", "suppressed_by": "triager"}
            )

        _mutate(b, demote)
        assert _root_of(a) != _root_of(b)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("severity", "Low"),
            ("category", "arbitrary-cpi"),
            ("title", "a different title"),
            ("description", "a different description"),
            ("recommendation", "different advice"),
            ("confidence", 0.99),
            ("validation", "confirmed"),
        ],
    )
    def test_editing_any_published_claim_changes_the_root(self, tmp_path, field, value):
        a = _staged(tmp_path / "a", LARGE)
        b = _staged(tmp_path / "b", LARGE)

        original = json.loads(a.read_text(encoding="utf-8"))["findings"][0].get(field)
        # Guard against a no-op mutation quietly passing: the first finding is a
        # type-cosplay one, so an earlier version of this test set `category` to
        # the value it already had and asserted nothing.
        assert str(original) != str(value), f"{field} is already {value!r} in the fixture"

        _mutate(b, lambda d: d["findings"][0].__setitem__(field, value))
        assert _root_of(a) != _root_of(b)

    def test_editing_a_suppression_reason_changes_the_root(self, tmp_path):
        """Otherwise "Confidence below threshold" could become anything else."""
        a = _staged(tmp_path / "a", SMALL)
        b = _staged(tmp_path / "b", SMALL)
        _mutate(b, lambda d: d["suppressed_findings"][0].__setitem__("reason", "Duplicate"))
        assert _root_of(a) != _root_of(b)

    def test_editing_which_judge_suppressed_a_finding_changes_the_root(self, tmp_path):
        """local_judge and llm_judge are materially different evidence."""
        a = _staged(tmp_path / "a", SMALL)
        b = _staged(tmp_path / "b", SMALL)
        _mutate(b, lambda d: d["suppressed_findings"][0].__setitem__("suppressed_by", "llm_judge"))
        assert _root_of(a) != _root_of(b)

    def test_scan_and_confirmed_bundles_of_the_same_findings_differ_in_commitment(self, tmp_path):
        scan = _staged(tmp_path / "a", LARGE, "ares-report-x.json")
        confirmed = _staged(tmp_path / "b", LARGE, "ares-report-x.confirmed.json")
        doc_scan = bundle.build_bundle(load_report(scan))
        doc_conf = bundle.build_bundle(load_report(confirmed))
        # Same claims, so the same root -- but the anchor must not be reusable.
        assert doc_scan["tree"]["merkle_root"] == doc_conf["tree"]["merkle_root"]
        assert doc_scan["anchor"]["commitment"] != doc_conf["anchor"]["commitment"]


class TestLeafOrderingAndDuplicates:
    def test_leaves_are_in_canonical_preimage_order(self, tmp_path):
        doc = bundle.build_bundle(load_report(LARGE))
        preimages = [leaf_preimage(leaf["fields"]) for leaf in doc["leaves"]]
        assert preimages == sorted(preimages)

    def test_findings_sort_before_suppressed_findings(self, tmp_path):
        """Falls out of byte order: lp("finding") starts 0x07, lp("suppressed") 0x0a."""
        report_path = _staged(tmp_path, SMALL)

        def add_finding(d):
            f = json.loads(json.dumps(d["suppressed_findings"][0]["finding"]))
            f["id"] = "ARES-AST-2"
            d["findings"].append(f)
            d["summary"]["total_findings"] = 1
            d["summary"]["medium_count"] = 1
            d["summary"]["poc_generated"] = 1

        _mutate(report_path, add_finding)
        doc = bundle.build_bundle(load_report(report_path))
        kinds = [leaf["kind"] for leaf in doc["leaves"]]
        assert kinds == ["finding", "suppressed"]

    def test_duplicate_finding_ids_raise(self, tmp_path):
        """An inclusion proof for a duplicated id cannot say which finding it attests."""
        report_path = _staged(tmp_path, LARGE)

        def duplicate_id(d):
            d["findings"][1]["id"] = d["findings"][0]["id"]

        _mutate(report_path, duplicate_id)
        with pytest.raises(EvidenceError, match="duplicate finding id"):
            bundle.build_bundle(load_report(report_path))

    def test_two_findings_identical_except_id_produce_two_distinct_leaves(self, tmp_path):
        """Pins the 36-of-636 case that decided `id` belongs in the leaf.

        Excluding the positional id is tempting -- it is a fragile identifier --
        but those reports would then produce duplicate leaves, which is a multiset
        ambiguity and the precondition for the shape tricks RFC 6962 prevents.
        """
        report_path = _staged(tmp_path, LARGE)

        def clone_first(d):
            twin = json.loads(json.dumps(d["findings"][0]))
            twin["id"] = "ARES-AST-999"
            d["findings"].append(twin)

        _mutate(report_path, clone_first)
        doc = bundle.build_bundle(load_report(report_path))
        hashes = [leaf["leaf_hash"] for leaf in doc["leaves"]]
        assert len(hashes) == len(set(hashes))
        assert doc["tree"]["leaf_count"] == 17


class TestTheEmptyCase:
    def _empty(self, tmp_path: pathlib.Path, name: str, target_name: str) -> pathlib.Path:
        data = json.loads(LARGE.read_text(encoding="utf-8"))
        data["findings"] = []
        data["suppressed_findings"] = []
        data["target"]["name"] = target_name
        for key in data["summary"]:
            data["summary"][key] = 0
        p = tmp_path / name
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return p

    def test_an_empty_report_bundles_to_the_rfc6962_empty_root(self, tmp_path):
        doc = bundle.build_bundle(load_report(self._empty(tmp_path, "ares-report-a.json", "a")))
        assert doc["tree"]["leaf_count"] == 0
        assert doc["tree"]["merkle_root"] == merkle.EMPTY_ROOT.hex()
        assert doc["leaves"] == []

    def test_two_different_targets_with_zero_findings_share_a_root_but_not_a_commitment(self, tmp_path):
        """Why the commitment exists at all.

        178 of the 636 reports in the local corpus produce no leaves at all, and the
        bare empty root is the same 32 bytes for every target on earth --
        anchoring it would publish "nothing found" in a form anyone could replay
        against any program.
        """
        a = bundle.build_bundle(load_report(self._empty(tmp_path, "ares-report-a.json", "alpha")))
        b = bundle.build_bundle(load_report(self._empty(tmp_path, "ares-report-b.json", "beta")))
        assert a["tree"]["merkle_root"] == b["tree"]["merkle_root"] == merkle.EMPTY_ROOT.hex()
        assert a["anchor"]["commitment"] != b["anchor"]["commitment"]


class TestHeaderContents:
    def test_the_raw_source_path_is_not_published_only_its_digest(self):
        """The machine path is bound without being republished."""
        rep = load_report(SMALL)
        doc = bundle.build_bundle(rep)
        raw_path = rep.data["target"]["source_path"]
        assert raw_path not in json.dumps(doc)
        assert doc["target"]["source_path_normalized"] == raw_path.rstrip("/")
        assert len(doc["target"]["source_path_raw_sha256"]) == 64

    def test_the_program_id_lands_in_operator_assertions_not_in_target(self):
        """The report carries no program_id, so anything here is a human's claim."""
        doc = bundle.build_bundle(load_report(SMALL), operator_program_id="SomeProgram111")
        assert doc["operator_assertions"]["solana_program_id"] == "SomeProgram111"
        assert doc["target"]["program_id_in_report"] is None

    def test_an_operator_program_id_changes_the_commitment(self):
        without = bundle.build_bundle(load_report(SMALL))
        with_id = bundle.build_bundle(load_report(SMALL), operator_program_id="SomeProgram111")
        assert without["anchor"]["commitment"] != with_id["anchor"]["commitment"]
        # But not the root: it is not a claim the engine made about a finding.
        assert without["tree"]["merkle_root"] == with_id["tree"]["merkle_root"]

    def test_the_volatile_block_records_the_excluded_fields(self):
        rep = load_report(SMALL)
        doc = bundle.build_bundle(rep)
        assert doc["volatile"]["generated_at"] == rep.data["metadata"]["generated_at"]
        assert "no leaf" in doc["volatile"]["note"]

    def test_the_bundle_publishes_fields_but_never_the_preimage(self):
        """A stored preimage could hash correctly while the readable fields lied."""
        doc = bundle.build_bundle(load_report(SMALL))
        serialized = json.dumps(doc)
        assert "preimage" not in serialized
        assert "fields" in doc["leaves"][0]

    def test_the_summary_is_recounted_from_the_leaves(self):
        doc = bundle.build_bundle(load_report(SMALL))
        assert doc["summary_from_leaves"]["false_positives_suppressed"] == 1
        assert doc["summary_from_leaves"]["total_findings"] == 0
        assert doc["summary_agrees"] is True

    def test_a_doctored_summary_is_reported_as_disagreeing(self, tmp_path):
        """Recounting turns an unattested field into a checkable one."""
        report_path = _staged(tmp_path, SMALL)
        _mutate(report_path, lambda d: d["summary"].__setitem__("total_findings", 99))
        doc = bundle.build_bundle(load_report(report_path))
        assert doc["summary_agrees"] is False
        assert doc["summary_from_leaves"]["total_findings"] == 0

    def test_only_recomputable_summary_fields_are_recounted(self):
        """tests_passed and the lamport estimates cannot be re-derived per finding,
        so claiming to have recounted them would be a trust-me number."""
        doc = bundle.build_bundle(load_report(SMALL))
        assert "tests_passed" not in doc["summary_from_leaves"]
        assert "total_economic_impact_lamports" not in doc["summary_from_leaves"]
        assert "tests_passed" in doc["summary_in_report"]


class TestCli:
    def test_the_cli_writes_a_bundle_and_reports_zero(self, tmp_path, capsys):
        report_path = _staged(tmp_path)
        assert bundle.main([str(report_path)]) == 0
        out = capsys.readouterr().out
        assert "merkle_root" in out and "commitment" in out

    def test_the_cli_reports_one_on_a_refusal(self, tmp_path, capsys):
        report_path = _staged(tmp_path)
        bundle.main([str(report_path)])
        assert bundle.main([str(report_path)]) == 1
        assert "already exists" in capsys.readouterr().err
