"""Load the vendored RustSec advisory snapshot (see refresh_snapshot.py and
snapshot/manifest.json for provenance) and index it by crate name.

This module only reads the two committed JSON files under snapshot/. It never
touches the network -- the snapshot is refreshed offline, manually, by a
human running refresh_snapshot.py, never as part of handling a request. See
services/cve/README.md and the "hermetic by default" posture in SECURITY.md.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshot"
ADVISORIES_PATH = SNAPSHOT_DIR / "advisories.json"
MANIFEST_PATH = SNAPSHOT_DIR / "manifest.json"


class SnapshotError(ValueError):
    """Raised when the committed snapshot files are missing or malformed.
    This is a deployment/build problem, not a per-request condition -- the
    caller should surface it as a 5xx, not map it onto a per-scan outcome."""


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    title: str
    description: str
    date: str
    withdrawn: str | None
    url: str | None  # some real advisories omit this despite the upstream template implying it's required
    references: tuple[str, ...]
    cvss: str | None
    aliases: tuple[str, ...]
    informational: str | None  # e.g. "unmaintained" | "unsound" | "notice" | None
    license: str | None  # per-advisory override; None means the DB's default (see manifest)
    categories: tuple[str, ...]
    keywords: tuple[str, ...]
    patched: tuple[str, ...]
    unaffected: tuple[str, ...]

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Advisory":
        return Advisory(
            id=d["id"],
            package=d["package"],
            title=d["title"],
            description=d["description"],
            date=d["date"],
            withdrawn=d.get("withdrawn"),
            url=d.get("url"),
            references=tuple(d.get("references", [])),
            cvss=d.get("cvss"),
            aliases=tuple(d.get("aliases", [])),
            informational=d.get("informational"),
            license=d.get("license"),
            categories=tuple(d.get("categories", [])),
            keywords=tuple(d.get("keywords", [])),
            patched=tuple(d.get("patched", [])),
            unaffected=tuple(d.get("unaffected", [])),
        )


@dataclass(frozen=True)
class AdvisoryDB:
    advisories: tuple[Advisory, ...]
    by_crate: dict[str, tuple[Advisory, ...]]
    manifest: dict[str, Any]

    @staticmethod
    def load(
        advisories_path: Path = ADVISORIES_PATH,
        manifest_path: Path = MANIFEST_PATH,
    ) -> "AdvisoryDB":
        if not advisories_path.exists():
            raise SnapshotError(
                f"{advisories_path} does not exist -- run refresh_snapshot.py "
                "before using this service, or check the checkout is complete."
            )
        if not manifest_path.exists():
            raise SnapshotError(f"{manifest_path} does not exist")

        advisories_bytes = advisories_path.read_bytes()
        try:
            raw = json.loads(advisories_bytes)
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"{advisories_path} is not valid JSON: {exc}") from exc
        try:
            manifest = json.loads(manifest_path.read_bytes())
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"{manifest_path} is not valid JSON: {exc}") from exc

        recorded_digest = manifest.get("advisories_sha256")
        actual_digest = hashlib.sha256(advisories_bytes).hexdigest()
        if recorded_digest and recorded_digest != actual_digest:
            # This is the load-bearing integrity check described in the plan:
            # the manifest records the digest of advisories.json AT GENERATION
            # TIME; a mismatch here means the committed file was hand-edited,
            # corrupted, or regenerated without updating the manifest -- any
            # of which means the data cannot be trusted, so this must not be
            # a warning. See test_snapshot_integrity.py for the same check run
            # as a CI-visible test rather than a runtime surprise.
            raise SnapshotError(
                f"advisories.json digest mismatch: manifest says {recorded_digest}, "
                f"actual is {actual_digest}. The snapshot is corrupt or stale -- "
                "re-run refresh_snapshot.py."
            )

        if not isinstance(raw, list):
            raise SnapshotError(f"{advisories_path} must contain a JSON array")

        advisories = tuple(Advisory.from_dict(d) for d in raw)
        by_crate: dict[str, list[Advisory]] = {}
        for adv in advisories:
            by_crate.setdefault(adv.package, []).append(adv)
        return AdvisoryDB(
            advisories=advisories,
            by_crate={k: tuple(v) for k, v in by_crate.items()},
            manifest=manifest,
        )

    def for_crate(self, name: str) -> tuple[Advisory, ...]:
        return self.by_crate.get(name, ())
