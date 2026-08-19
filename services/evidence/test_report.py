"""The closed schema, and the parser hardening that makes a digest meaningful.

The load-bearing test in this file is
`test_the_category_set_matches_the_committed_mapping`: it pins this module's
transcription of `VulnerabilityCategory` against
`eval/mappings/ares-core-categories.json`, which already carries its own
Rust-side cross-check. So a category added in Rust cannot quietly become an
unknown token here, and the two vocabularies cannot drift apart silently.

Everything else in this file is about the same principle from a different angle:
a report this bundler does not fully understand must not be attested, because a
field it fails to recognise would be published in the bundle and excluded from
every digest.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

import report
from canonical import EvidenceError
from report import ReportError, load_report

HERE = pathlib.Path(__file__).parent
REPO_ROOT = HERE.parents[1]
VECTORS = HERE / "vectors"
SMALL = VECTORS / "ares-report-suppressed-only.json"
LARGE = VECTORS / "ares-report-sixteen-findings.json"


def _load_raw(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(tmp_path: pathlib.Path, data: dict, name: str = "ares-report-x.json") -> pathlib.Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


class TestTheCommittedVectorsLoad:
    @pytest.mark.parametrize("path", [SMALL, LARGE], ids=["suppressed-only", "sixteen-findings"])
    def test_a_real_artifact_validates(self, path):
        rep = load_report(path)
        assert rep.kind == "scan"
        assert len(rep.sha256) == 64

    def test_neither_vector_ends_with_a_newline(self):
        """serde_json's to_string_pretty then fs::write leaves none.

        The digest is taken over the bytes exactly as they sit on disk, so this
        is a property the fixtures must keep -- an editor that "helpfully" adds a
        final newline would change the artifact.
        """
        for path in (SMALL, LARGE):
            assert not path.read_bytes().endswith(b"\n"), path.name

    def test_the_report_digest_is_over_raw_bytes_with_nothing_added(self):
        import hashlib

        rep = load_report(SMALL)
        assert rep.sha256 == hashlib.sha256(SMALL.read_bytes()).hexdigest()
        # And explicitly NOT over a re-serialisation.
        reserialized = json.dumps(rep.data, indent=2, sort_keys=True).encode()
        assert rep.sha256 != hashlib.sha256(reserialized).hexdigest()


class TestEnumVocabularies:
    def test_the_category_set_matches_the_committed_mapping(self):
        """Cross-checks this transcription against a file with its own Rust test.

        eval/mappings/ares-core-categories.json is keyed by the 21 kebab-case
        wire spellings of VulnerabilityCategory and is already cross-checked
        against the Rust enum. Asserting equality here means a category added in
        Rust breaks this test rather than silently becoming an unknown token.
        """
        mapping = json.loads(
            (REPO_ROOT / "eval" / "mappings" / "ares-core-categories.json").read_text(
                encoding="utf-8"
            )
        )
        assert set(mapping["categories"]) == report._CATEGORIES

    def test_there_are_exactly_21_categories(self):
        assert len(report._CATEGORIES) == 21

    def test_severity_is_pascal_case_and_category_is_kebab_case(self):
        """The asymmetry is real; a parser assuming one convention for both fails.

        See docs/ORC-2-CORE-CALL-CONTRACT.md:129-133.
        """
        assert "Critical" in report._SEVERITIES
        assert "critical" not in report._SEVERITIES
        assert "type-cosplay" in report._CATEGORIES
        assert "TypeCosplay" not in report._CATEGORIES

    def test_validation_outcomes_are_kebab_case(self):
        assert report._VALIDATIONS == {"confirmed", "refuted", "inconclusive"}

    def test_all_four_suppressors_are_known(self):
        """There are four write sites, not the two ares-core's comment claims.

        `ares-core/src/lib.rs:234` says `// "local_judge" or "llm_judge"`. That
        comment is stale: `triager` (scan.rs:439) and `semantic_validator`
        (validator.rs:72,:92) also reach the artifact. `semantic_validator` was
        found only because the closed schema rejected four real reports in the
        local corpus -- had the set been permissive, an unvalidated string would
        have been hashed into leaves.
        """
        assert report._SUPPRESSORS == {
            "local_judge",
            "llm_judge",
            "triager",
            "semantic_validator",
        }


class TestTheSchemaIsClosed:
    def test_an_unknown_top_level_key_raises(self, tmp_path):
        data = _load_raw(SMALL)
        data["extra_block"] = {}
        with pytest.raises(ReportError, match="unknown key"):
            load_report(_write(tmp_path, data))

    def test_an_unknown_finding_key_raises(self, tmp_path):
        """The refactor guard.

        Adding Finding.exploitability in Rust must fail here, not be silently
        omitted from every leaf -- otherwise every root already anchored becomes
        a commitment to a claim that no longer describes the report.
        """
        data = _load_raw(LARGE)
        data["findings"][0]["exploitability"] = 0.5
        with pytest.raises(ReportError, match="unknown key"):
            load_report(_write(tmp_path, data))

    def test_an_unknown_location_key_raises(self, tmp_path):
        data = _load_raw(LARGE)
        data["findings"][0]["location"]["module"] = "x"
        with pytest.raises(ReportError, match="unknown key"):
            load_report(_write(tmp_path, data))

    def test_a_missing_required_finding_key_raises(self, tmp_path):
        data = _load_raw(LARGE)
        del data["findings"][0]["recommendation"]
        with pytest.raises(ReportError, match="missing required key"):
            load_report(_write(tmp_path, data))

    def test_a_missing_validation_key_is_accepted(self, tmp_path):
        """#[serde(default)] means a pre-POC-2 report legitimately omits it."""
        data = _load_raw(LARGE)
        del data["findings"][0]["validation"]
        rep = load_report(_write(tmp_path, data))
        assert "validation" not in rep.data["findings"][0]

    def test_an_unknown_severity_token_raises(self, tmp_path):
        data = _load_raw(LARGE)
        data["findings"][0]["severity"] = "Catastrophic"
        with pytest.raises(ReportError, match="unknown value"):
            load_report(_write(tmp_path, data))

    def test_a_lowercase_severity_raises(self, tmp_path):
        data = _load_raw(LARGE)
        data["findings"][0]["severity"] = "critical"
        with pytest.raises(ReportError, match="unknown value"):
            load_report(_write(tmp_path, data))

    def test_an_unknown_category_token_raises(self, tmp_path):
        data = _load_raw(LARGE)
        data["findings"][0]["category"] = "brand-new-class"
        with pytest.raises(ReportError, match="unknown value"):
            load_report(_write(tmp_path, data))

    def test_an_unknown_suppressed_by_value_raises(self, tmp_path):
        data = _load_raw(SMALL)
        data["suppressed_findings"][0]["suppressed_by"] = "vibes"
        with pytest.raises(ReportError, match="unknown value"):
            load_report(_write(tmp_path, data))

    def test_all_three_known_suppressors_are_accepted(self, tmp_path):
        for suppressor in sorted(report._SUPPRESSORS):
            data = _load_raw(SMALL)
            data["suppressed_findings"][0]["suppressed_by"] = suppressor
            load_report(_write(tmp_path, data, f"ares-report-{suppressor}.json"))


class TestParserHardening:
    def test_duplicate_json_keys_are_rejected(self, tmp_path):
        """A real tamper vector, not a theoretical one.

        json.loads('{"a":1,"a":2}') silently returns {'a': 2} -- last one wins --
        while a JavaScript viewer may show the first. A report could therefore
        read one way to a human and hash another way here.
        """
        assert json.loads('{"a":1,"a":2}') == {"a": 2}  # the default behaviour
        p = tmp_path / "ares-report-dup.json"
        p.write_text('{"target":{},"target":{},"findings":[]}', encoding="utf-8")
        with pytest.raises(ReportError, match="duplicate JSON key"):
            load_report(p)

    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
    def test_non_json_constants_are_rejected(self, tmp_path, constant):
        """serde_json cannot emit these, so their presence means a hand edit."""
        assert str(json.loads("NaN")) == "nan"  # the default behaviour
        data = _load_raw(LARGE)
        raw, count = re.subn(
            r'"confidence": [0-9.]+', f'"confidence": {constant}', json.dumps(data, indent=2), count=1
        )
        assert count == 1, "fixture no longer has a confidence value to replace"
        p = tmp_path / "ares-report-nan.json"
        p.write_text(raw, encoding="utf-8")
        with pytest.raises(ReportError):
            load_report(p)

    def test_a_float_confidence_stays_a_string_token(self, tmp_path):
        rep = load_report(SMALL)
        confidence = rep.data["suppressed_findings"][0]["finding"]["confidence"]
        assert isinstance(confidence, str)
        assert confidence == "0.55"

    def test_integers_stay_string_tokens(self):
        rep = load_report(SMALL)
        assert isinstance(rep.data["summary"]["total_findings"], str)
        assert isinstance(rep.data["metadata"]["scan_duration_secs"], str)

    def test_invalid_utf8_raises(self, tmp_path):
        p = tmp_path / "ares-report-bad.json"
        p.write_bytes(b'{"target": "\xff\xfe"}')
        with pytest.raises(ReportError, match="not valid UTF-8"):
            load_report(p)

    def test_invalid_json_raises(self, tmp_path):
        p = tmp_path / "ares-report-bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(ReportError, match="not valid JSON"):
            load_report(p)

    def test_a_missing_file_raises(self, tmp_path):
        with pytest.raises(ReportError, match="cannot read report"):
            load_report(tmp_path / "nope.json")

    def test_a_u64_summary_value_is_accepted(self, tmp_path):
        """total_economic_impact_lamports is u64, wider than a line number."""
        data = _load_raw(SMALL)
        data["summary"]["total_economic_impact_lamports"] = 2**63
        rep = load_report(_write(tmp_path, data))
        assert rep.data["summary"]["total_economic_impact_lamports"] == str(2**63)

    def test_a_beyond_u64_summary_value_raises(self, tmp_path):
        data = _load_raw(SMALL)
        raw = json.dumps(data, indent=2).replace(
            '"total_economic_impact_lamports": 0',
            f'"total_economic_impact_lamports": {2**64}',
        )
        p = tmp_path / "ares-report-big.json"
        p.write_text(raw, encoding="utf-8")
        with pytest.raises(ReportError, match="exceeds u64"):
            load_report(p)

    def test_a_line_number_beyond_u32_raises(self, tmp_path):
        """Raises EvidenceError, not ReportError, and that layering is deliberate.

        The u32 check lives in canonical.py, which cannot import report.py
        without a cycle. ReportError subclasses EvidenceError, so a caller
        catching EvidenceError gets both -- which is what bundle.py and verify.py
        do.
        """
        data = _load_raw(LARGE)
        raw = json.dumps(data, indent=2).replace(
            '"line_start": null', '"line_start": 4294967296', 1
        )
        p = tmp_path / "ares-report-line.json"
        p.write_text(raw, encoding="utf-8")
        with pytest.raises(EvidenceError, match="exceeds u32"):
            load_report(p)

    def test_report_error_is_an_evidence_error(self):
        """So one `except EvidenceError` covers every refusal in this service."""
        assert issubclass(ReportError, EvidenceError)


class TestReportKind:
    def test_a_plain_stem_is_a_scan(self, tmp_path):
        assert report.report_kind_for(pathlib.Path("ares-report-vault.json")) == "scan"

    def test_a_confirmed_stem_is_detected(self):
        """The name `confirm.rs:387-394` produces."""
        assert (
            report.report_kind_for(pathlib.Path("ares-report-vault.confirmed.json")) == "confirmed"
        )

    def test_kind_reaches_the_loaded_report(self, tmp_path):
        data = _load_raw(SMALL)
        p = _write(tmp_path, data, "ares-report-x.confirmed.json")
        assert load_report(p).kind == "confirmed"
