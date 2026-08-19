"""Every outcome the verifier can reach, and the fact that they stay distinct.

Exit codes are pinned deliberately. A caller scripting around this tool needs to
tell "the timestamp moved" from "a severity was rewritten", and collapsing two
distinguishable failures onto one code would throw away the diagnosis the
two-stage design exists to produce.

The pair worth reading together is `test_editing_leaf_hash_alone_fails_at_the_leaf`
and `test_editing_fields_and_leaf_hash_together_still_fails_at_the_root`: between
them there is no single-field edit to a bundle that verifies.
"""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest

import bundle
import canonical
import merkle
import verify

HERE = pathlib.Path(__file__).parent
VECTORS = HERE / "vectors"
SMALL = VECTORS / "ares-report-suppressed-only.json"
LARGE = VECTORS / "ares-report-sixteen-findings.json"


@pytest.fixture
def staged(tmp_path):
    """Give each test a disposable report + freshly built bundle beside it."""

    def _make(source: pathlib.Path = LARGE, name: str | None = None):
        report_path = tmp_path / (name or source.name)
        shutil.copyfile(source, report_path)
        bundle_path = bundle.write_bundle(report_path, force=True)
        return report_path, bundle_path

    return _make


def _edit_report(path: pathlib.Path, fn):
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _edit_bundle(path: pathlib.Path, fn):
    doc = json.loads(path.read_text(encoding="utf-8"))
    fn(doc)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class TestTheHappyPath:
    @pytest.mark.parametrize("source", [SMALL, LARGE], ids=["suppressed-only", "sixteen"])
    def test_a_freshly_built_bundle_verifies(self, staged, source):
        report_path, bundle_path = staged(source)
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.OK
        assert outcome.name == "OK"

    def test_the_report_is_found_beside_the_bundle_without_being_named(self, staged):
        _, bundle_path = staged()
        assert verify.verify(bundle_path).code == verify.OK

    def test_the_committed_golden_bundles_verify(self):
        for report_name in ("ares-report-suppressed-only", "ares-report-sixteen-findings"):
            outcome = verify.verify(
                VECTORS / f"{report_name}.evidence.json", VECTORS / f"{report_name}.json"
            )
            assert outcome.code == verify.OK, f"{report_name}: {outcome.message}"


class TestStageAFailures:
    def test_a_wrong_schema_is_malformed(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d.__setitem__("schema", "something/else"))
        assert verify.verify(bundle_path).code == verify.BUNDLE_MALFORMED

    def test_invalid_json_is_malformed(self, tmp_path):
        p = tmp_path / "x.evidence.json"
        p.write_text("{not json", encoding="utf-8")
        assert verify.verify(p).code == verify.BUNDLE_MALFORMED

    def test_a_missing_bundle_is_a_usage_error(self, tmp_path):
        assert verify.verify(tmp_path / "absent.evidence.json").code == verify.USAGE

    def test_a_leaf_count_disagreeing_with_the_leaf_array_is_malformed(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["tree"].__setitem__("leaf_count", 99))
        assert verify.verify(bundle_path).code == verify.BUNDLE_MALFORMED

    def test_a_bundle_declaring_blake3_is_refused_not_rehashed(self, staged):
        """Otherwise this tool would "verify" a document whose own header says it
        means something different."""
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["algorithm"].__setitem__("hash", "blake3"))
        outcome = verify.verify(bundle_path)
        assert outcome.code == verify.ALGORITHM_UNSUPPORTED
        assert "hash" in outcome.message

    def test_a_bundle_declaring_the_bitcoin_tree_is_refused(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["algorithm"].__setitem__("tree", "bitcoin"))
        assert verify.verify(bundle_path).code == verify.ALGORITHM_UNSUPPORTED

    def test_a_changed_domain_tag_is_refused(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["algorithm"].__setitem__("domain", "other.domain.v1"))
        assert verify.verify(bundle_path).code == verify.ALGORITHM_UNSUPPORTED

    def test_editing_leaf_hash_alone_fails_at_the_leaf(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["leaves"][0].__setitem__("leaf_hash", "00" * 32))
        assert verify.verify(bundle_path).code == verify.LEAF_HASH_MISMATCH

    def test_editing_a_published_field_alone_fails_at_the_leaf(self, staged):
        """The readable fields and the digest must agree, so a bundle cannot lie
        to a human who reads it."""
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["leaves"][0]["fields"].__setitem__("severity", "Low"))
        assert verify.verify(bundle_path).code == verify.LEAF_HASH_MISMATCH

    def test_editing_fields_and_leaf_hash_together_still_fails_at_the_root(self, staged):
        """No single-field edit passes: fix the leaf and the root breaks."""
        _, bundle_path = staged()

        def forge(d):
            d["leaves"][0]["fields"]["severity"] = "Low"
            preimage = canonical.leaf_preimage(d["leaves"][0]["fields"])
            d["leaves"][0]["leaf_hash"] = merkle.leaf_hash(preimage).hex()

        _edit_bundle(bundle_path, forge)
        assert verify.verify(bundle_path).code == verify.ROOT_MISMATCH

    def test_editing_the_recorded_root_fails(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["tree"].__setitem__("merkle_root", "11" * 32))
        assert verify.verify(bundle_path).code == verify.ROOT_MISMATCH

    def test_permuting_the_leaves_fails_at_the_order_check(self, staged):
        """Every leaf hash still matches individually; only the order is wrong."""
        _, bundle_path = staged()

        def permute(d):
            d["leaves"][0], d["leaves"][1] = d["leaves"][1], d["leaves"][0]
            d["leaves"][0]["index"], d["leaves"][1]["index"] = 0, 1

        _edit_bundle(bundle_path, permute)
        assert verify.verify(bundle_path).code == verify.LEAF_ORDER_INVALID

    def test_a_tampered_proof_position_fails(self, staged):
        """Positions are re-derived from (index, leaf_count), never trusted."""
        _, bundle_path = staged()

        def flip(d):
            step = d["leaves"][0]["proof"][0]
            step["position"] = "left" if step["position"] == "right" else "right"

        _edit_bundle(bundle_path, flip)
        assert verify.verify(bundle_path).code == verify.PROOF_INVALID

    def test_a_tampered_proof_hash_fails(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["leaves"][0]["proof"][0].__setitem__("hash", "22" * 32))
        assert verify.verify(bundle_path).code == verify.PROOF_INVALID

    def test_a_tampered_commitment_fails(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["anchor"].__setitem__("commitment", "11" * 32))
        assert verify.verify(bundle_path).code == verify.COMMITMENT_MISMATCH

    def test_a_tampered_target_binding_fails(self, staged):
        _, bundle_path = staged()
        _edit_bundle(bundle_path, lambda d: d["anchor"].__setitem__("target_binding", "33" * 32))
        assert verify.verify(bundle_path).code == verify.COMMITMENT_MISMATCH

    def test_claiming_a_different_operator_program_id_breaks_the_commitment(self, staged):
        """So an anchor cannot be re-labelled onto another program after the fact."""
        _, bundle_path = staged()
        _edit_bundle(
            bundle_path,
            lambda d: d["operator_assertions"].__setitem__("solana_program_id", "Other111"),
        )
        assert verify.verify(bundle_path).code == verify.COMMITMENT_MISMATCH

    def test_a_machine_path_smuggled_into_a_leaf_field_is_refused(self, staged):
        _, bundle_path = staged()

        def poison(d):
            d["leaves"][0]["fields"]["file"] = r"D:\Github repo\x\src\lib.rs"
            preimage_fields = d["leaves"][0]["fields"]
            d["leaves"][0]["leaf_hash"] = merkle.leaf_hash(
                canonical.leaf_preimage(preimage_fields)
            ).hex()

        _edit_bundle(bundle_path, poison)
        assert verify.verify(bundle_path).code == verify.NON_DETERMINISTIC_INPUT


class TestStageBDecisionTable:
    def test_editing_generated_at_is_edited_outside_leaves(self, staged):
        """The most likely real tamper, and the one a root alone cannot see."""
        report_path, bundle_path = staged()
        _edit_report(
            report_path, lambda d: d["metadata"].__setitem__("generated_at", "2099-01-01T00:00:00Z")
        )
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.REPORT_EDITED_OUTSIDE_LEAVES
        assert "generated_at" in outcome.message

    def test_editing_a_summary_count_is_edited_outside_leaves(self, staged):
        report_path, bundle_path = staged()
        _edit_report(report_path, lambda d: d["summary"].__setitem__("tests_passed", 42))
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.REPORT_EDITED_OUTSIDE_LEAVES
        assert "summary field" in outcome.message

    def test_reformatting_the_report_is_edited_outside_leaves(self, staged):
        """Whitespace and key order change the bytes but no claim."""
        report_path, bundle_path = staged()
        data = json.loads(report_path.read_text(encoding="utf-8"))
        report_path.write_text(json.dumps(data, indent=4, sort_keys=True), encoding="utf-8")
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.REPORT_EDITED_OUTSIDE_LEAVES
        assert "formatting" in outcome.message

    def test_editing_a_severity_is_report_tampered(self, staged):
        report_path, bundle_path = staged()
        _edit_report(report_path, lambda d: d["findings"][0].__setitem__("severity", "Low"))
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.REPORT_TAMPERED
        assert "ARES-HYP-1" in outcome.message

    def test_demoting_a_finding_is_report_tampered(self, staged):
        report_path, bundle_path = staged()

        def demote(d):
            moved = d["findings"].pop(0)
            d["suppressed_findings"].append(
                {"finding": moved, "reason": "demoted", "suppressed_by": "triager"}
            )

        _edit_report(report_path, demote)
        assert verify.verify(bundle_path, report_path).code == verify.REPORT_TAMPERED

    def test_removing_a_finding_is_report_tampered_and_names_it(self, staged):
        report_path, bundle_path = staged()
        removed_id = json.loads(report_path.read_text(encoding="utf-8"))["findings"][0]["id"]
        _edit_report(report_path, lambda d: d["findings"].pop(0))
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.REPORT_TAMPERED
        assert removed_id in outcome.message

    def test_swapping_in_a_different_report_is_different_report(self, staged):
        report_path, bundle_path = staged()
        shutil.copyfile(SMALL, report_path)
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.DIFFERENT_REPORT

    def test_a_confirmed_report_cannot_be_passed_off_as_a_scan(self, staged, tmp_path):
        """report_kind is inside the target binding for exactly this reason."""
        report_path, bundle_path = staged()
        confirmed = tmp_path / "ares-report-sixteen-findings.confirmed.json"
        shutil.copyfile(report_path, confirmed)
        outcome = verify.verify(bundle_path, confirmed)
        assert outcome.code == verify.DIFFERENT_REPORT

    def test_a_missing_report_is_reported_distinctly(self, staged):
        report_path, bundle_path = staged()
        report_path.unlink()
        outcome = verify.verify(bundle_path)
        assert outcome.code == verify.REPORT_MISSING

    def test_a_report_that_no_longer_validates_is_surfaced(self, staged):
        report_path, bundle_path = staged()
        _edit_report(report_path, lambda d: d["findings"][0].__setitem__("exploitability", 0.5))
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.REPORT_TAMPERED
        assert "closed schema" in outcome.message


class TestAdvisories:
    def _empty(self, tmp_path):
        data = json.loads(LARGE.read_text(encoding="utf-8"))
        data["findings"] = []
        data["suppressed_findings"] = []
        for key in data["summary"]:
            data["summary"][key] = 0
        p = tmp_path / "ares-report-empty.json"
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return p

    def test_an_empty_report_verifies_but_says_it_proves_no_scan_ran(self, tmp_path):
        """194 of 636 local reports are empty, and `ares scan /nonexistent` also
        exits 0 with a well-formed empty report. The outcome must not read as a
        clean bill of health."""
        report_path = self._empty(tmp_path)
        bundle_path = bundle.write_bundle(report_path, force=True)
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.OK
        assert outcome.name == "OK_EMPTY"
        assert any("ZERO findings" in a for a in outcome.advisories)
        assert any("not evidence of an audit" in a for a in outcome.advisories)

    def test_a_disagreeing_summary_is_an_advisory_not_a_failure(self, tmp_path):
        """The report's summary is not part of any leaf, so a mismatch is a
        warning about the artifact rather than proof of tampering."""
        report_path = tmp_path / "ares-report-x.json"
        data = json.loads(SMALL.read_text(encoding="utf-8"))
        data["summary"]["total_findings"] = 99
        report_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        bundle_path = bundle.write_bundle(report_path, force=True)
        outcome = verify.verify(bundle_path, report_path)
        assert outcome.code == verify.OK
        assert any("summary" in a for a in outcome.advisories)


class TestExitCodes:
    def test_every_outcome_code_is_distinct(self):
        codes = [
            verify.OK,
            verify.USAGE,
            verify.BUNDLE_MALFORMED,
            verify.REPORT_MISSING,
            verify.LEAF_HASH_MISMATCH,
            verify.ROOT_MISMATCH,
            verify.LEAF_ORDER_INVALID,
            verify.PROOF_INVALID,
            verify.COMMITMENT_MISMATCH,
            verify.REPORT_EDITED_OUTSIDE_LEAVES,
            verify.REPORT_TAMPERED,
            verify.DIFFERENT_REPORT,
            verify.BUNDLER_SKEW,
            verify.NON_DETERMINISTIC_INPUT,
            verify.ALGORITHM_UNSUPPORTED,
        ]
        assert len(codes) == len(set(codes)) == 15

    def test_the_codes_are_pinned_to_their_documented_values(self):
        """A caller scripting around this tool needs them stable."""
        assert (verify.OK, verify.USAGE, verify.BUNDLE_MALFORMED) == (0, 1, 2)
        assert (verify.REPORT_MISSING, verify.LEAF_HASH_MISMATCH) == (3, 4)
        assert (verify.ROOT_MISMATCH, verify.LEAF_ORDER_INVALID, verify.PROOF_INVALID) == (5, 6, 7)
        assert verify.COMMITMENT_MISMATCH == 8
        assert verify.REPORT_EDITED_OUTSIDE_LEAVES == 9
        assert (verify.REPORT_TAMPERED, verify.DIFFERENT_REPORT, verify.BUNDLER_SKEW) == (10, 11, 12)
        assert (verify.NON_DETERMINISTIC_INPUT, verify.ALGORITHM_UNSUPPORTED) == (13, 14)

    def test_the_cli_returns_the_outcome_code(self, staged, capsys):
        report_path, bundle_path = staged()
        assert verify.main([str(bundle_path), "--report", str(report_path)]) == 0
        assert "OK" in capsys.readouterr().out

    def test_the_cli_prints_failures_to_stderr(self, staged, capsys):
        report_path, bundle_path = staged()
        _edit_report(report_path, lambda d: d["findings"][0].__setitem__("severity", "Low"))
        code = verify.main([str(bundle_path), "--report", str(report_path)])
        assert code == verify.REPORT_TAMPERED
        assert "REPORT_TAMPERED" in capsys.readouterr().err
