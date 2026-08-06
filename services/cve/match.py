"""Match a target's dependencies against the loaded advisory DB.

Deliberately NOT called "scan" -- that name is already the CLI verb `core/`
uses for the deterministic Rust engine (docs/ORC-2-CORE-CALL-CONTRACT.md).
Keeping this vocabulary distinct avoids a reader mistaking dependency
matching for a second implementation of that contract.
"""
from __future__ import annotations

from dataclasses import dataclass

from advisories import Advisory, AdvisoryDB
from lockfile import Dependency
from version_req import UnsupportedVersionReq, matches_any


@dataclass(frozen=True)
class Match:
    crate: str
    version: str
    advisory_id: str
    title: str
    url: str | None
    aliases: tuple[str, ...]
    cvss: str | None
    informational: str | None
    patched: tuple[str, ...]


@dataclass(frozen=True)
class MatchResult:
    matches: tuple[Match, ...]
    dependencies_scanned: int
    dependencies_skipped_local: int
    withdrawn_advisories_excluded: int
    notes: tuple[str, ...]


def _is_resolved(version: str, adv: Advisory) -> bool:
    """True if `version` is covered by either the advisory's `patched` or
    `unaffected` ranges -- i.e. NOT vulnerable. RustSec semantics: a version
    is presumed affected unless one of these arrays says otherwise, so an
    advisory with both arrays empty (real example: RUSTSEC-2021-0120,
    abomonation, patched=[]) matches every version of the crate."""
    return matches_any(version, list(adv.patched)) or matches_any(version, list(adv.unaffected))


def match_dependencies(dependencies: list[Dependency], db: AdvisoryDB) -> MatchResult:
    matches: list[Match] = []
    notes: list[str] = []
    scanned = 0
    skipped_local = 0
    withdrawn_excluded = 0

    for dep in dependencies:
        if dep.is_local:
            # A workspace-local crate is the target's own code, not a
            # third-party dependency -- there is no upstream advisory to
            # look up. See lockfile.py's module docstring.
            skipped_local += 1
            continue
        scanned += 1

        for adv in db.for_crate(dep.name):
            if adv.withdrawn is not None:
                # A withdrawn advisory was formally retracted by RustSec
                # (e.g. found not to be a real vulnerability, or the range
                # was wrong). Surfacing it as an active match would be a
                # false positive baked in by us, on top of one RustSec
                # already corrected. It stays in the snapshot (see
                # advisories.py) so the count here is visible rather than
                # the advisory silently vanishing without a trace.
                withdrawn_excluded += 1
                continue
            try:
                resolved = _is_resolved(dep.version, adv)
            except UnsupportedVersionReq as exc:
                # This should be unreachable for any advisory that passed
                # test_snapshot_integrity.py against this exact snapshot, and
                # unreachable for `dep.version` because Cargo itself enforces
                # semver in a committed lockfile. If it happens anyway, this
                # must not resolve to a silent non-match (see version_req's
                # module docstring / ORC2-F7) -- it is surfaced per-dependency
                # so one bad range doesn't abort the whole scan, but loudly,
                # in a field the caller is expected to check.
                notes.append(
                    f"could not evaluate {adv.id} against {dep.name} {dep.version}: {exc}"
                )
                continue
            if resolved:
                continue
            matches.append(
                Match(
                    crate=dep.name,
                    version=dep.version,
                    advisory_id=adv.id,
                    title=adv.title,
                    url=adv.url,
                    aliases=adv.aliases,
                    cvss=adv.cvss,
                    informational=adv.informational,
                    patched=adv.patched,
                )
            )

    return MatchResult(
        matches=tuple(matches),
        dependencies_scanned=scanned,
        dependencies_skipped_local=skipped_local,
        withdrawn_advisories_excluded=withdrawn_excluded,
        notes=tuple(notes),
    )
