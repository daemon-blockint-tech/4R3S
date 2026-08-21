"""Leaf encoding: path normalisation, number tokens, and field framing.

The three silent failure modes here, in the order they would actually bite:

1. **A machine path reaches a digest.** The same audit re-run on another box
   then anchors a different root, and nothing says so. `Finding.title` is the
   non-obvious carrier: `scan.rs:237` formats a file path into what is otherwise
   free text, so normalising only the path-typed fields is not enough.
2. **A float gets spelled.** Every confidence value in the local corpus
   round-trips cleanly through `repr(float(t))`, so a float-based encoder is
   green today and wrong on the first value that does not.
3. **A field boundary shifts.** Without length prefixes, moving a character
   between two adjacent fields leaves the preimage unchanged -- and `title`
   embeds paths from the scanned repository, so part of it is attacker-shaped.
"""

from __future__ import annotations

import json

import pytest

import canonical
from canonical import EvidenceError, normalize_path


def _finding(**overrides) -> dict:
    base = {
        "id": "ARES-AST-1",
        "title": "anchor-constraint-gap: src/lib.rs",
        "description": "a description",
        "severity": "Medium",
        "category": "ownership-check",
        "location": {
            "file": "src/lib.rs",
            "line_start": None,
            "line_end": None,
            "column_start": None,
            "column_end": None,
            "function": None,
            "commit": None,
        },
        "proof_of_concept": None,
        "recommendation": "a recommendation",
        "references": [],
        "confidence": "0.55",
        "validation": None,
    }
    base.update(overrides)
    return base


class TestPathNormalization:
    def test_backslashes_become_forward_slashes(self):
        assert normalize_path(r"src\lib.rs").value == "src/lib.rs"

    def test_mixed_separators_in_one_path_normalize_identically(self):
        """The real shape in the committed fixtures: forward slashes, then a backslash."""
        mixed = "eval/data/staging/x/src\\lib.rs"
        assert normalize_path(mixed).value == "eval/data/staging/x/src/lib.rs"

    def test_windows_drive_prefix_is_stripped(self):
        assert normalize_path(r"D:\Github repo\ARES\4R3S\src\lib.rs").value == (
            "Github repo/ARES/4R3S/src/lib.rs"
        )

    def test_posix_absolute_prefix_is_stripped(self):
        assert normalize_path("/home/runner/work/x/src/lib.rs").value == (
            "home/runner/work/x/src/lib.rs"
        )

    def test_unc_prefix_is_stripped(self):
        assert normalize_path(r"\\server\share\src\lib.rs").value == "src/lib.rs"

    def test_runs_of_separators_collapse(self):
        assert normalize_path("src//deep///lib.rs").value == "src/deep/lib.rs"

    def test_trailing_separator_on_source_path_does_not_change_the_result(self):
        """Every report in the local corpus has a trailing slash on source_path."""
        with_slash = normalize_path("eval/data/staging/x/")
        without = normalize_path("eval/data/staging/x")
        assert with_slash == without

    def test_file_equal_to_source_path_becomes_dot(self):
        """Never the empty string: after framing, "" is indistinguishable from absent."""
        result = normalize_path("eval/data/staging/x/", "eval/data/staging/x/")
        assert result.value == "."
        assert result.scope == "relative"

    def test_a_file_under_the_target_is_relativized(self):
        result = normalize_path("eval/data/staging/x/src/lib.rs", "eval/data/staging/x/")
        assert result.value == "src/lib.rs"
        assert result.scope == "relative"

    def test_a_path_outside_the_target_is_flagged_not_silently_rerooted(self):
        result = normalize_path("somewhere/else/lib.rs", "eval/data/staging/x")
        assert result.scope == "outside_target"
        assert result.value == "somewhere/else/lib.rs"

    def test_dotdot_is_resolved_lexically(self):
        assert normalize_path("src/inner/../lib.rs").value == "src/lib.rs"
        assert normalize_path("src/./lib.rs").value == "src/lib.rs"

    def test_dotdot_that_escapes_the_root_forces_outside_target(self):
        result = normalize_path("../../etc/passwd", "target")
        assert result.scope == "outside_target"

    def test_normalization_never_touches_the_filesystem(self, tmp_path, monkeypatch):
        """Path.resolve() would inject the cwd and follow machine-specific symlinks."""

        def explode(*args, **kwargs):
            raise AssertionError("canonical.py must not touch the filesystem")

        monkeypatch.setattr("os.getcwd", explode)
        monkeypatch.setattr("os.path.realpath", explode)
        assert normalize_path(r"D:\x\src\lib.rs").value == "x/src/lib.rs"

    def test_normalization_is_idempotent(self):
        once = normalize_path(r"D:\Github repo\x\src\lib.rs").value
        assert normalize_path(once).value == once

    def test_nfc_normalizes_a_decomposed_unicode_filename(self):
        """macOS writes NFD, Windows and Linux NFC. Same file, one leaf."""
        nfd = "src/cafe\u0301.rs"  # e + combining acute
        nfc = "src/caf\u00e9.rs"  # precomposed
        assert nfd != nfc
        assert normalize_path(nfd).value == normalize_path(nfc).value

    def test_case_is_not_folded(self):
        """On Windows these are one file; on Linux two. Folding would collide them."""
        assert normalize_path("SRC/lib.rs").value != normalize_path("src/lib.rs").value


class TestTitleRewrite:
    def test_a_title_ending_in_the_raw_location_file_is_rewritten(self):
        raw = "eval/data/staging/x/src\\lib.rs"
        title = f"anchor-constraint-gap: {raw}"
        assert canonical.rewrite_title(title, raw, "src/lib.rs") == (
            "anchor-constraint-gap: src/lib.rs"
        )

    def test_a_title_not_containing_the_location_file_is_left_byte_identical(self):
        title = "`LegacyAccounts` carries no type discriminator"
        assert canonical.rewrite_title(title, "src/lib.rs", "src/lib.rs") is title

    def test_only_the_exact_suffix_is_replaced(self):
        """Inverts scan.rs's format!, rather than pattern-matching on path-ish text.

        A heuristic rewrite of free-text evidence would be a worse defect than
        the leak it fixed: it would silently alter the wording of a published
        claim.
        """
        raw = "src/lib.rs"
        title = "src/lib.rs mentioned mid-sentence, ending in src/lib.rs"
        assert canonical.rewrite_title(title, raw, "L.rs") == (
            "src/lib.rs mentioned mid-sentence, ending in L.rs"
        )

    def test_an_empty_raw_path_leaves_the_title_alone(self):
        assert canonical.rewrite_title("a title", "", "x") == "a title"


class TestNoMachinePathSurvivesIntoADigest:
    @pytest.mark.parametrize(
        "bad",
        [
            r"D:\Github repo\x\src\lib.rs",
            "C:/Users/x/src/lib.rs",
            r"src\lib.rs",
            "/home/runner/src/lib.rs",
        ],
    )
    def test_a_machine_path_in_a_hashed_field_raises(self, bad):
        with pytest.raises(EvidenceError, match="machine-specific path"):
            canonical.assert_no_machine_path("title", bad)

    def test_a_normalized_relative_path_passes(self):
        canonical.assert_no_machine_path("file", "src/lib.rs")
        canonical.assert_no_machine_path("file", ".")

    def test_projecting_a_finding_whose_title_keeps_a_backslash_raises(self):
        """The durable guard: fires when a NEW field starts carrying a path.

        The title here does not end with location.file, so the suffix rewrite
        cannot help it -- which is exactly the case a future scan.rs change would
        create.
        """
        finding = _finding(title=r"note about C:\Windows\system32 in prose")
        with pytest.raises(EvidenceError, match="machine-specific path"):
            canonical.project_finding(finding, kind="finding", target_root="src")


class TestNumericTokens:
    def test_confidence_is_the_raw_json_token_not_a_python_float(self):
        """Fails on any repr()-based encoder; passes on every value in the corpus.

        serde_json formats f64 via ryu; CPython's repr spells exponents
        differently. `1e-7` becomes `1e-07`, so a float round-trip would change
        the preimage -- and therefore the root -- for a value the engine can
        legitimately emit, since apply_refuted computes (c*0.3).min(0.2).
        """
        parsed = json.loads('{"confidence": 1e-7}', parse_float=str)
        assert parsed["confidence"] == "1e-7"
        assert repr(float("1e-7")) == "1e-07"  # the bug this avoids
        assert canonical.validate_number_token("confidence", parsed["confidence"]) == "1e-7"

    def test_large_exponent_is_not_respelled(self):
        parsed = json.loads('{"x": 1e16}', parse_float=str)
        assert parsed["x"] == "1e16"
        assert repr(float("1e16")) == "1e+16"

    def test_every_confidence_token_in_the_corpus_is_accepted(self):
        for token in ["0.55", "0.7", "0.72", "0.75", "0.78", "0.8", "0.85"]:
            assert canonical.validate_number_token("confidence", token) == token

    @pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity", "nan", "inf"])
    def test_non_finite_tokens_are_rejected(self, bad):
        with pytest.raises(EvidenceError):
            canonical.validate_number_token("confidence", bad)

    @pytest.mark.parametrize("bad", ["01", "+1", ".5", "1.", "0x10", "1_0", ""])
    def test_malformed_number_tokens_are_rejected(self, bad):
        with pytest.raises(EvidenceError):
            canonical.validate_number_token("confidence", bad)

    def test_minus_zero_is_not_folded_to_zero(self):
        assert canonical.validate_number_token("c", "-0.0") == "-0.0"
        assert canonical.validate_number_token("c", "-0.0") != "0.0"

    @pytest.mark.parametrize("bad", ["01", "1.0", "+1", "-1", "4294967296", ""])
    def test_line_number_tokens_reject_leading_zeros_floats_and_u32_overflow(self, bad):
        with pytest.raises(EvidenceError):
            canonical.validate_uint_token("line_start", bad)

    def test_u32_boundary_is_accepted(self):
        assert canonical.validate_uint_token("line_start", "4294967295") == "4294967295"
        assert canonical.validate_uint_token("line_start", "0") == "0"


class TestFieldFraming:
    def test_moving_a_character_between_two_fields_changes_the_preimage(self):
        """Plain concatenation would make these identical."""
        a = canonical.req("ab") + canonical.req("c")
        b = canonical.req("a") + canonical.req("bc")
        assert a != b

    def test_none_and_empty_string_produce_different_preimages(self):
        """function, commit and a suppression reason are all Option<String>."""
        assert canonical.opt(None) != canonical.opt("")

    def test_a_field_containing_length_prefix_bytes_cannot_forge_a_boundary(self):
        sneaky = "\x00\x00\x00\x04beef"
        assert canonical.req(sneaky) != canonical.req("") + canonical.req("beef")

    def test_an_oversized_field_is_refused(self):
        with pytest.raises(EvidenceError, match="exceeds"):
            canonical.lp(b"x" * (canonical.MAX_FIELD_BYTES + 1))

    def test_a_list_is_framed_with_its_count(self):
        assert canonical.seq([]) != canonical.seq([""])
        assert canonical.seq(["a", "b"]) != canonical.seq(["ab"])


class TestLeafProjection:
    def test_mutating_each_leaf_field_in_turn_changes_the_leaf_hash(self):
        """Parametrized over the whole field list, so a field silently dropped
        from the encoder fails loudly rather than becoming unattested."""
        base = canonical.project_finding(_finding(), kind="finding", target_root="src")
        baseline = canonical.leaf_preimage(base)

        mutations = {
            "kind": "suppressed",
            "id": "ARES-AST-2",
            "title": "different title",
            "description": "different description",
            "severity": "Critical",
            "category": "type-cosplay",
            "path_scope": "outside_target",
            "file": "other.rs",
            "line_start": "1",
            "line_end": "2",
            "column_start": "3",
            "column_end": "4",
            "function": "handler",
            "commit": "deadbeef",
            "recommendation": "different recommendation",
            "poc_present": "present",
            "confidence": "0.9",
            "validation": "confirmed",
            "suppression_reason": "because",
            "suppressed_by": "triager",
            "references": ["https://example.invalid"],
        }
        # Every field except the constant encoding tag must be covered.
        covered = set(mutations) | {"encoding"}
        assert covered == {name for name, _ in canonical.LEAF_FIELDS}

        for field, new_value in mutations.items():
            mutated = dict(base)
            mutated[field] = new_value
            assert canonical.leaf_preimage(mutated) != baseline, field

    def test_the_encoding_tag_is_the_first_field(self):
        assert canonical.LEAF_FIELDS[0] == ("encoding", "req")
        base = canonical.project_finding(_finding(), kind="finding", target_root="src")
        assert canonical.leaf_preimage(base).startswith(canonical.req(canonical.LEAF_ENCODING))

    def test_kind_is_in_the_leaf_so_a_demotion_is_visible(self):
        """Without `kind`, moving a real finding into suppressed_findings would
        leave the leaf unchanged and the root could not see the demotion."""
        as_finding = canonical.project_finding(_finding(), kind="finding", target_root="src")
        as_suppressed = canonical.project_finding(
            _finding(), kind="suppressed", target_root="src",
            suppression_reason="r", suppressed_by="triager",
        )
        assert canonical.leaf_preimage(as_finding) != canonical.leaf_preimage(as_suppressed)

    def test_absent_validation_key_projects_identically_to_explicit_null(self):
        """`validation` carries #[serde(default)], so a pre-POC-2 report omits it.

        Both mean "no confirmation pass ran". If they encoded differently, two
        reports asserting identical facts would anchor differently because of a
        serde default.
        """
        with_null = _finding(validation=None)
        without = _finding()
        del without["validation"]
        a = canonical.project_finding(with_null, kind="finding", target_root="src")
        b = canonical.project_finding(without, kind="finding", target_root="src")
        assert canonical.leaf_preimage(a) == canonical.leaf_preimage(b)
        assert a["validation"] == "none"

    def test_the_poc_path_is_excluded_but_its_presence_is_not(self):
        """Where a harness lives is a function of --output; that it exists is a claim."""
        absent = canonical.project_finding(
            _finding(proof_of_concept=None), kind="finding", target_root="src"
        )
        one = canonical.project_finding(
            _finding(proof_of_concept="out-a\\poc\\x_test.rs"), kind="finding", target_root="src"
        )
        two = canonical.project_finding(
            _finding(proof_of_concept="out-b\\poc\\x_test.rs"), kind="finding", target_root="src"
        )
        assert absent["poc_present"] == "absent"
        assert one["poc_present"] == "present"
        # Two different output directories must not change the root.
        assert canonical.leaf_preimage(one) == canonical.leaf_preimage(two)
        assert canonical.leaf_preimage(one) != canonical.leaf_preimage(absent)

    def test_an_unknown_kind_is_refused(self):
        with pytest.raises(EvidenceError):
            canonical.project_finding(_finding(), kind="maybe", target_root="src")

    def test_a_projection_with_an_extra_field_is_refused(self):
        """An extra field would be published in the bundle but excluded from the
        digest -- readable, and unattested."""
        base = canonical.project_finding(_finding(), kind="finding", target_root="src")
        base["exploitability"] = "0.5"
        with pytest.raises(EvidenceError, match="outside LEAF_FIELDS"):
            canonical.leaf_preimage(base)

    def test_a_projection_missing_a_field_is_refused(self):
        base = canonical.project_finding(_finding(), kind="finding", target_root="src")
        del base["severity"]
        with pytest.raises(EvidenceError, match="missing leaf fields"):
            canonical.leaf_preimage(base)
