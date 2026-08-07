"""Integrity checks against the committed snapshot itself, not synthetic
fixtures. This is the load-bearing suite in this package: it moves range-
parser gaps and data corruption to CI/snapshot-build time, where a human
sees them, instead of to scan time, where an unparseable range or a stale
digest would be indistinguishable from a clean result. See version_req.py's
module docstring and match.py's ORC2-F7 reference for why that distinction
matters here.
"""
from __future__ import annotations

import hashlib

import pytest

from advisories import ADVISORIES_PATH, MANIFEST_PATH, AdvisoryDB
from version_req import UnsupportedVersionReq, VersionReq

pytestmark = pytest.mark.skipif(
    not ADVISORIES_PATH.exists() or not MANIFEST_PATH.exists(),
    reason="services/cve/snapshot/ is not populated in this checkout -- run refresh_snapshot.py",
)


def _load() -> AdvisoryDB:
    return AdvisoryDB.load()


class TestDigestMatchesTheCommittedFile:
    def test_manifest_digest_matches_actual_file_bytes(self):
        # Duplicates AdvisoryDB.load()'s own check, deliberately: that check
        # protects a running service; this test makes the same fact visible
        # in CI on every push, per ci.yml's no-paths-filter convention, so a
        # hand-edit to either file is caught before merge, not at first boot.
        actual = hashlib.sha256(ADVISORIES_PATH.read_bytes()).hexdigest()
        db = _load()
        assert db.manifest["advisories_sha256"] == actual

    def test_manifest_advisory_count_matches_the_array_length(self):
        db = _load()
        assert db.manifest["advisory_count"] == len(db.advisories)


class TestEveryVersionRangeInTheSnapshotIsParseable:
    """The property version_req.py exists to guarantee: an advisory's
    `patched`/`unaffected` ranges must never silently fail to match. Proving
    that here, once, against the whole real corpus, means match.py's
    per-dependency exception handling for UnsupportedVersionReq is a safety
    net for a case this test has already ruled out for the committed data."""

    def test_all_patched_and_unaffected_ranges_parse(self):
        db = _load()
        failures: list[str] = []
        for adv in db.advisories:
            for range_str in (*adv.patched, *adv.unaffected):
                try:
                    VersionReq.parse(range_str)
                except UnsupportedVersionReq as exc:
                    failures.append(f"{adv.id} ({adv.package}): {range_str!r} -- {exc}")
        assert not failures, (
            f"{len(failures)} version range(s) in the committed snapshot cannot be "
            "parsed by version_req.py -- these advisories would silently fail to "
            "match at scan time:\n" + "\n".join(failures[:20])
        )


class TestSchemaShapeHoldsForEveryRecord:
    def test_every_advisory_has_a_nonempty_id_package_and_title(self):
        db = _load()
        for adv in db.advisories:
            assert adv.id, "an advisory is missing its id"
            assert adv.package, f"{adv.id} is missing package"
            assert adv.title, f"{adv.id} is missing title"

    def test_ids_are_unique(self):
        db = _load()
        ids = [a.id for a in db.advisories]
        assert len(ids) == len(set(ids))

    def test_by_crate_index_covers_every_advisory_exactly_once(self):
        db = _load()
        indexed_count = sum(len(v) for v in db.by_crate.values())
        assert indexed_count == len(db.advisories)


class TestKnownRealAdvisoriesSurvivedTheRoundTrip:
    """Anchors this snapshot to three specific advisories confirmed by hand
    against the upstream .md source during development (see
    docs/<ID>-ASSUMPTIONS.md) -- catches a normalization bug that corrupts
    or drops a real record without changing the file's overall shape."""

    def test_anchor_lang_cvss31_advisory(self):
        db = _load()
        matches = [a for a in db.for_crate("anchor-lang") if a.id == "RUSTSEC-2026-0144"]
        assert len(matches) == 1
        assert matches[0].cvss == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
        assert "CVE-2026-45137" in matches[0].aliases

    def test_anchor_lang_cvss4_advisory_is_present_but_unscored_by_severity_py(self):
        db = _load()
        matches = [a for a in db.for_crate("anchor-lang") if a.id == "RUSTSEC-2026-0146"]
        assert len(matches) == 1
        assert matches[0].cvss is not None and matches[0].cvss.startswith("CVSS:4.0/")

    def test_borsh_advisory_with_no_cvss_and_a_caret_range(self):
        db = _load()
        matches = [a for a in db.for_crate("borsh") if a.id == "RUSTSEC-2023-0033"]
        assert len(matches) == 1
        assert matches[0].cvss is None
        assert "^0.10.4" in matches[0].patched
