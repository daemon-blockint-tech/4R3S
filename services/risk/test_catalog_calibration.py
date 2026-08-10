from __future__ import annotations

import json

import pytest

from catalog_calibration import (
    CATALOG_PATH,
    CATEGORY_RISK_TEMPLATES,
    CatalogCalibrationError,
    calibrate,
)


class TestCalibratesAgainstTheRealCommittedCatalog:
    """Runs against the actual committed vuln-catalog.generated.json, not a
    fixture -- the point is to know today's real divergence between the
    static defaultSeverity values and the OWASP-methodology templates, and
    to fail loudly if a future catalog edit changes that count silently."""

    def test_every_entry_is_covered_by_a_template(self):
        report = calibrate()
        assert report.total == len(json.loads(CATALOG_PATH.read_text(encoding="utf-8")))

    def test_current_mismatch_count_is_16_of_34(self):
        # Not a target to hit -- a snapshot of today's real divergence. If
        # this changes, it's because the catalog or a template rationale
        # changed; update the count deliberately, don't just bump it to
        # make the test pass.
        report = calibrate()
        assert report.total == 34
        assert len(report.matches) == 18
        assert len(report.mismatches) == 16

    def test_the_impact_axis_currently_does_no_discriminating_work(self):
        """Pins a real limitation rather than leaving it as an unexamined
        assumption: because loss_of_confidentiality (2) and
        loss_of_accountability (7) are pinned across every template as
        properties of the Solana execution environment, the technical-impact
        average is compressed into [4.25, 5.75] and EVERY entry lands in the
        MEDIUM impact band. Severity is therefore effectively ranked by
        likelihood alone.

        This test exists so that stops being invisible. If a future template
        change makes the impact axis meaningful, this test fails and should
        be deleted -- that would be an improvement, not a regression."""
        report = calibrate()
        impact_levels = {e.impact_level for e in (*report.matches, *report.mismatches)}
        assert impact_levels == {"medium"}, (
            f"impact axis now discriminates ({impact_levels}) -- if that is "
            f"intended, delete this test and update README.md's 'The impact "
            f"axis does not discriminate' section."
        )

    def test_pda_sits_close_to_a_band_boundary(self):
        """The pda template scores likelihood 5.875, only 0.125 below the
        MEDIUM/HIGH threshold of 6.0 -- the single most fragile template.
        At intrusion_detection=9 ('Not logged') it would score exactly 6.000
        and flip to HIGH; 8 ('Logged without review') is used instead because
        every Solana transaction is logged on-chain by construction. Pinned
        because a reader deserves to know this category's result turns on one
        factor choice."""
        report = calibrate()
        pda = next(e for e in (*report.matches, *report.mismatches) if e.category == "pda")
        assert pda.likelihood_level == "medium"

        from risk_score import RiskVector, score_risk

        template = CATEGORY_RISK_TEMPLATES["pda"]
        assert score_risk(
            RiskVector(
                likelihood=template["likelihood"],
                technical_impact=template["technical_impact"],
            )
        ).likelihood_score == 5.875

        not_logged = dict(template["likelihood"], intrusion_detection=9)
        flipped = score_risk(
            RiskVector(likelihood=not_logged, technical_impact=template["technical_impact"])
        )
        assert flipped.likelihood_score == 6.0
        assert flipped.likelihood_level == "high"

    def test_known_high_confidence_mismatches_are_present(self):
        # Spot-checks the two starkest divergences (a computed band two
        # steps away from the catalog default), so a bug that flips the
        # matrix lookup silently wouldn't just change the total count but
        # would also lose these specific, easy-to-eyeball entries.
        report = calibrate()
        by_id = {m.id: m for m in report.mismatches}

        assert by_id["account-close-revival"].catalog_default_severity == "critical"
        assert by_id["account-close-revival"].computed_severity == "medium"

        assert by_id["arbitrary-cpi"].catalog_default_severity == "critical"
        assert by_id["arbitrary-cpi"].computed_severity == "high"

    def test_matches_and_mismatches_partition_all_entries(self):
        report = calibrate()
        assert len(report.matches) + len(report.mismatches) == report.total
        matched_ids = {m.id for m in report.matches}
        mismatched_ids = {m.id for m in report.mismatches}
        assert matched_ids.isdisjoint(mismatched_ids)


class TestRejectsAnUncoveredCategory:
    def test_unknown_category_raises_rather_than_skipping(self, tmp_path):
        fixture = tmp_path / "catalog.json"
        fixture.write_text(
            json.dumps(
                [{"id": "made-up-entry", "category": "not-a-real-category", "defaultSeverity": "low"}]
            ),
            encoding="utf-8",
        )
        with pytest.raises(CatalogCalibrationError):
            calibrate(path=fixture)


class TestRejectsAMalformedCatalogFile:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(CatalogCalibrationError):
            calibrate(path=tmp_path / "does-not-exist.json")

    def test_non_json_file_raises(self, tmp_path):
        fixture = tmp_path / "catalog.json"
        fixture.write_text("not json", encoding="utf-8")
        with pytest.raises(CatalogCalibrationError):
            calibrate(path=fixture)

    def test_non_array_json_raises(self, tmp_path):
        fixture = tmp_path / "catalog.json"
        fixture.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
        with pytest.raises(CatalogCalibrationError):
            calibrate(path=fixture)

    def test_empty_array_raises_rather_than_reporting_a_vacuous_clean_run(self, tmp_path):
        # 0 entries would otherwise calibrate to 0 matches / 0 mismatches --
        # indistinguishable from "the catalog agrees with every template".
        fixture = tmp_path / "catalog.json"
        fixture.write_text("[]", encoding="utf-8")
        with pytest.raises(CatalogCalibrationError, match="empty"):
            calibrate(path=fixture)

    @pytest.mark.parametrize(
        "entry,missing",
        [
            ({"id": "x", "category": "cpi"}, "defaultSeverity"),
            ({"id": "x", "defaultSeverity": "low"}, "category"),
            ({"category": "cpi", "defaultSeverity": "low"}, "id"),
        ],
    )
    def test_entry_missing_a_required_field_raises_our_error_not_a_bare_keyerror(
        self, tmp_path, entry, missing
    ):
        # These reached the API as an unhandled 500 before the shape check
        # existed, not the documented 503.
        fixture = tmp_path / "catalog.json"
        fixture.write_text(json.dumps([entry]), encoding="utf-8")
        with pytest.raises(CatalogCalibrationError, match=missing):
            calibrate(path=fixture)

    def test_non_object_entry_raises_our_error_not_a_bare_typeerror(self, tmp_path):
        fixture = tmp_path / "catalog.json"
        fixture.write_text(json.dumps(["just a string"]), encoding="utf-8")
        with pytest.raises(CatalogCalibrationError):
            calibrate(path=fixture)


class TestEveryTemplateProducesAValidScore:
    """Every template must itself be a complete, valid RiskVector -- a
    typo'd factor name or an off-table score in a template should fail
    here, not surface later as a confusing calibrate() error."""

    @pytest.mark.parametrize("category", sorted(CATEGORY_RISK_TEMPLATES))
    def test_template_scores_without_raising(self, category):
        from risk_score import RiskVector, score_risk

        template = CATEGORY_RISK_TEMPLATES[category]
        scored = score_risk(
            RiskVector(
                likelihood=template["likelihood"],
                technical_impact=template["technical_impact"],
            )
        )
        assert scored.severity in ("info", "low", "medium", "high", "critical")
