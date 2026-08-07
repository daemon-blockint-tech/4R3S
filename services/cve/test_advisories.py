from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from advisories import AdvisoryDB, SnapshotError

MINIMAL_ADVISORY = {
    "id": "RUSTSEC-2026-0144",
    "package": "anchor-lang",
    "title": "`Program<System>` accepts arbitrary executable programs",
    "description": "Affected versions did not properly validate...",
    "date": "2026-05-07",
    "withdrawn": None,
    "url": "https://github.com/otter-sec/anchor/security/advisories/GHSA-c6rc-8jpp-2fgc",
    "references": ["https://github.com/solana-foundation/anchor/releases/tag/v1.0.2"],
    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
    "aliases": ["CVE-2026-45137", "GHSA-c6rc-8jpp-2fgc"],
    "informational": None,
    "license": "CC-BY-4.0",
    "categories": [],
    "keywords": ["solana", "anchor"],
    "patched": [">= 1.0.2"],
    "unaffected": ["< 1.0.0"],
}


def _write_snapshot(tmp_path: Path, advisories: list[dict]) -> tuple[Path, Path]:
    advisories_path = tmp_path / "advisories.json"
    manifest_path = tmp_path / "manifest.json"
    body = json.dumps(advisories, indent=2).encode("utf-8")
    advisories_path.write_bytes(body)
    manifest_path.write_text(
        json.dumps({"advisories_sha256": hashlib.sha256(body).hexdigest()}),
        encoding="utf-8",
    )
    return advisories_path, manifest_path


class TestLoadingAValidSnapshot:
    def test_loads_and_indexes_by_crate(self, tmp_path):
        adv_path, man_path = _write_snapshot(tmp_path, [MINIMAL_ADVISORY])
        db = AdvisoryDB.load(adv_path, man_path)
        assert len(db.advisories) == 1
        assert [a.id for a in db.for_crate("anchor-lang")] == ["RUSTSEC-2026-0144"]
        assert db.for_crate("no-such-crate") == ()

    def test_missing_optional_fields_default_sensibly(self, tmp_path):
        sparse = {
            "id": "RUSTSEC-0000-0000",
            "package": "x",
            "title": "t",
            "description": "d",
            "date": "2020-01-01",
            "url": "https://example.com",
            "patched": [],
            "unaffected": [],
        }
        adv_path, man_path = _write_snapshot(tmp_path, [sparse])
        db = AdvisoryDB.load(adv_path, man_path)
        a = db.advisories[0]
        assert a.withdrawn is None
        assert a.aliases == ()
        assert a.informational is None
        assert a.license is None


class TestIntegrityChecksFailLoudly:
    """A corrupt or hand-edited snapshot must refuse to load, not degrade
    silently -- consistent with the strictness in version_req.py."""

    def test_missing_advisories_file_raises(self, tmp_path):
        with pytest.raises(SnapshotError):
            AdvisoryDB.load(tmp_path / "nope.json", tmp_path / "manifest.json")

    def test_missing_manifest_raises(self, tmp_path):
        adv_path = tmp_path / "advisories.json"
        adv_path.write_text("[]", encoding="utf-8")
        with pytest.raises(SnapshotError):
            AdvisoryDB.load(adv_path, tmp_path / "manifest.json")

    def test_digest_mismatch_raises(self, tmp_path):
        adv_path, man_path = _write_snapshot(tmp_path, [MINIMAL_ADVISORY])
        # Simulate a hand-edit after the manifest was generated.
        adv_path.write_text(adv_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with pytest.raises(SnapshotError):
            AdvisoryDB.load(adv_path, man_path)

    def test_malformed_json_raises(self, tmp_path):
        adv_path = tmp_path / "advisories.json"
        adv_path.write_text("{not json", encoding="utf-8")
        man_path = tmp_path / "manifest.json"
        man_path.write_text("{}", encoding="utf-8")
        with pytest.raises(SnapshotError):
            AdvisoryDB.load(adv_path, man_path)

    def test_advisories_not_a_list_raises(self, tmp_path):
        adv_path = tmp_path / "advisories.json"
        body = b'{"not": "a list"}'
        adv_path.write_bytes(body)
        man_path = tmp_path / "manifest.json"
        man_path.write_text(
            json.dumps({"advisories_sha256": hashlib.sha256(body).hexdigest()}),
            encoding="utf-8",
        )
        with pytest.raises(SnapshotError):
            AdvisoryDB.load(adv_path, man_path)
