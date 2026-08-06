#!/usr/bin/env python3
"""Rebuild services/cve/snapshot/{advisories.json,manifest.json} from the
RustSec advisory-db (https://github.com/rustsec/advisory-db).

MANUAL AND NETWORKED. This script is never imported or invoked by the CVE
service itself, by apps/auditor-api, or by any test in services/cve/ -- it is
run by a human, on demand, to produce the two committed JSON files that the
service actually reads at runtime. See services/cve/README.md for the
refresh procedure and SECURITY.md's "hermetic by default" posture, which
this script's manual-only nature is what keeps intact.

Each RustSec advisory is a Markdown file (`crates/<crate>/RUSTSEC-*.md`) with
a fenced ```toml front-matter block followed by a prose description. This is
confirmed against the real upstream repo, not assumed from its docs -- see
docs/<ID>-ASSUMPTIONS.md for the exploration this was based on.

Usage:
    python refresh_snapshot.py --source-dir <path-to-existing-clone>
    python refresh_snapshot.py --clone-to <scratch-dir> [--revision <sha>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

UPSTREAM_URL = "https://github.com/rustsec/advisory-db.git"
SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshot"

# The DB's own LICENSE.txt: everything is CC0-1.0 (public domain) EXCEPT
# advisories carrying an explicit `license` field in their front matter, which
# marks content imported from the GitHub Security Advisory database and is
# CC-BY-4.0 (attribution required). Confirmed by reading crates/anchor-lang/
# RUSTSEC-2026-0144.md, which carries `license = "CC-BY-4.0"` explicitly.
# core/deny.toml's crate-license allow-list does NOT apply here -- it only
# inspects Cargo crate metadata, never committed data files (confirmed: no
# gate in this repo inspects data-file licenses at all). This default is
# recorded by hand in the manifest, not machine-checked, and must be
# re-confirmed by whoever next runs this script if upstream's terms change.
DEFAULT_LICENSE = "CC0-1.0"
GHSA_EXCEPTION_LICENSE = "CC-BY-4.0"

_TOML_BLOCK = re.compile(r"```toml\n(.*?)\n```\n?(.*)", re.DOTALL)


class AdvisoryParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedAdvisory:
    id: str
    package: str
    title: str
    description: str
    date: str
    withdrawn: str | None
    url: str | None
    references: list[str]
    cvss: str | None
    aliases: list[str]
    informational: str | None
    license: str | None
    categories: list[str]
    keywords: list[str]
    patched: list[str]
    unaffected: list[str]


def parse_advisory_file(path: Path) -> ParsedAdvisory:
    text = path.read_text(encoding="utf-8")
    m = _TOML_BLOCK.match(text)
    if not m:
        raise AdvisoryParseError(f"{path}: no fenced ```toml block found at file start")
    toml_text, body = m.group(1), m.group(2).strip()

    try:
        doc = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as exc:
        raise AdvisoryParseError(f"{path}: malformed TOML front matter: {exc}") from exc

    adv = doc.get("advisory")
    versions = doc.get("versions", {})
    if not isinstance(adv, dict):
        raise AdvisoryParseError(f"{path}: missing [advisory] table")

    # `url` is shown WITHOUT a comment marker in EXAMPLE_ADVISORY.md, implying
    # it is mandatory -- but real advisories in the corpus omit it (confirmed:
    # crates/aovec/RUSTSEC-2020-0099.md, crates/fake-static/RUSTSEC-2020-0013.md,
    # 136 files total in the revision this was written against). The template
    # is misleading; the real data is authoritative, so only id/package/date
    # are enforced here.
    for required in ("id", "package", "date"):
        if required not in adv:
            raise AdvisoryParseError(f"{path}: [advisory] missing required key {required!r}")

    # First markdown heading is the title; the rest is the description body.
    title = ""
    description_lines: list[str] = []
    for line in body.splitlines():
        if not title and line.startswith("# "):
            title = line[2:].strip()
            continue
        description_lines.append(line)
    description = "\n".join(description_lines).strip()
    if not title:
        raise AdvisoryParseError(f"{path}: no '# Title' heading found in the description body")

    return ParsedAdvisory(
        id=adv["id"],
        package=adv["package"],
        title=title,
        description=description,
        date=str(adv["date"]),
        withdrawn=(str(adv["withdrawn"]) if "withdrawn" in adv else None),
        url=adv.get("url"),
        references=list(adv.get("references", [])),
        cvss=adv.get("cvss"),
        aliases=list(adv.get("aliases", [])),
        informational=adv.get("informational"),
        license=adv.get("license"),
        categories=list(adv.get("categories", [])),
        keywords=list(adv.get("keywords", [])),
        patched=list(versions.get("patched", [])),
        unaffected=list(versions.get("unaffected", [])),
    )


def _clone(dest: Path, revision: str | None) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise SystemExit(f"refusing to clone into existing path: {dest}")
    if revision:
        subprocess.run(["git", "clone", UPSTREAM_URL, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "checkout", revision], check=True)
    else:
        subprocess.run(["git", "clone", "--depth", "1", UPSTREAM_URL, str(dest)], check=True)
    result = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _revision_date(source_dir: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_dir), "log", "-1", "--format=%cI"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _revision_sha(source_dir: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_dir), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def build_snapshot(source_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    crates_dir = source_dir / "crates"
    if not crates_dir.is_dir():
        raise SystemExit(f"{crates_dir} does not exist -- is {source_dir} a real advisory-db clone?")

    files = sorted(crates_dir.glob("*/RUSTSEC-*.md"))
    if not files:
        raise SystemExit(f"no RUSTSEC-*.md files found under {crates_dir}")

    parsed: list[ParsedAdvisory] = []
    errors: list[str] = []
    for f in files:
        try:
            parsed.append(parse_advisory_file(f))
        except AdvisoryParseError as exc:
            errors.append(str(exc))
    if errors:
        # Fail the whole refresh rather than silently vendoring a partial
        # snapshot -- a missing advisory here is invisible at scan time in
        # exactly the way ORC2-F7 was invisible: nothing downstream can tell
        # a skipped file apart from a crate that genuinely has no advisory.
        raise SystemExit(
            f"{len(errors)} advisory file(s) failed to parse, refusing to write a partial "
            f"snapshot:\n" + "\n".join(errors[:20]) + ("\n..." if len(errors) > 20 else "")
        )

    parsed.sort(key=lambda a: a.id)
    ghsa_derived = sum(1 for a in parsed if a.license == GHSA_EXCEPTION_LICENSE)
    withdrawn = sum(1 for a in parsed if a.withdrawn is not None)
    informational = sum(1 for a in parsed if a.informational is not None)
    with_cve_alias = sum(1 for a in parsed if any(x.startswith("CVE-") for x in a.aliases))

    records = [asdict(a) for a in parsed]
    advisories_bytes = json.dumps(records, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    revision = _revision_sha(source_dir)
    manifest = {
        "source": UPSTREAM_URL,
        "revision": revision,
        "revision_date": _revision_date(source_dir),
        "generated_by": "services/cve/refresh_snapshot.py",
        "advisory_count": len(parsed),
        "advisories_sha256": hashlib.sha256(advisories_bytes).hexdigest(),
        "license": {
            "default": DEFAULT_LICENSE,
            "exception": (
                f"{ghsa_derived} of {len(parsed)} advisories carry an explicit "
                f"license = \"{GHSA_EXCEPTION_LICENSE}\" front-matter field, marking "
                "content imported from the GitHub Security Advisory database. Per "
                "advisory-db's LICENSE.txt, that subset requires attribution to "
                "the GitHub Security Advisory Database; the rest is CC0-1.0 "
                "(public domain)."
            ),
            "verified_by_hand": True,
            "not_checked_by_ci": (
                "core/deny.toml and scripts/check-licenses.mjs inspect only "
                "npm/cargo dependency metadata, never committed data files -- "
                "this license was confirmed by reading LICENSE.txt directly, "
                "not by any repo gate."
            ),
        },
        "notes": [
            "Vendored as one normalized advisories.json, not as the original "
            "per-file .md sources, so the digest above covers the FULL "
            "advisory set as a single unit rather than per-file, unlike the "
            "eval/ convention of per-source-row sha256 digests. See "
            "services/cve/README.md for why (there is no per-file original "
            "kept in this repo to re-digest against).",
            f"{withdrawn} advisories are formally withdrawn by RustSec; the "
            "matcher (match.py) excludes them from results but counts the "
            "exclusion rather than deleting them from this snapshot.",
            f"{informational} advisories are informational only (unmaintained/"
            "unsound/notice) rather than a specific version range vulnerability "
            "-- these still produce matches, tagged with their informational kind.",
            f"{with_cve_alias} of {len(parsed)} advisories carry a CVE-* alias; "
            "the remainder have only a RUSTSEC-* id and/or a GHSA-* alias. "
            "RustSec advisories are the primary key everywhere in this "
            "service -- CVE is surfaced when present, never synthesized.",
            "Refreshing this snapshot changes match results for every future "
            "scan against the same lockfile. There is no mechanism in this "
            "service (or in eval/) that reproduces a PAST scan's result after "
            "a refresh -- only the manifest's revision field tells a reader "
            "which snapshot a stored result came from.",
        ],
    }
    return records, manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--source-dir", type=Path, help="path to an existing advisory-db clone")
    group.add_argument("--clone-to", type=Path, help="clone advisory-db fresh into this path")
    p.add_argument("--revision", help="pin the clone to this commit SHA (only with --clone-to)")
    p.add_argument("--out-dir", type=Path, default=SNAPSHOT_DIR)
    args = p.parse_args(argv)

    if args.source_dir:
        source_dir = args.source_dir
    else:
        _clone(args.clone_to, args.revision)
        source_dir = args.clone_to

    records, manifest = build_snapshot(source_dir)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "advisories.json").write_bytes(
        json.dumps(records, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    (args.out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(records)} advisories at revision {manifest['revision']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
