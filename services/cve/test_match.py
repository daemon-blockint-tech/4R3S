from __future__ import annotations

from advisories import Advisory, AdvisoryDB
from lockfile import Dependency
from match import match_dependencies

ANCHOR_ADVISORY = Advisory(
    id="RUSTSEC-2026-0144",
    package="anchor-lang",
    title="`Program<System>` accepts arbitrary executable programs",
    description="...",
    date="2026-05-07",
    withdrawn=None,
    url="https://example.com/RUSTSEC-2026-0144",
    references=(),
    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
    aliases=("CVE-2026-45137", "GHSA-c6rc-8jpp-2fgc"),
    informational=None,
    license="CC-BY-4.0",
    categories=(),
    keywords=(),
    patched=(">= 1.0.2",),
    unaffected=("< 1.0.0",),
)

BORSH_ADVISORY_NO_PATCHED_RANGE_COVERAGE = Advisory(
    id="RUSTSEC-2021-0120",
    package="abomonation",
    title="unsound transmute",
    description="...",
    date="2021-10-17",
    withdrawn=None,
    url="https://example.com/RUSTSEC-2021-0120",
    references=(),
    cvss=None,
    aliases=("CVE-2021-45708",),
    informational="unsound",
    license=None,
    categories=(),
    keywords=(),
    patched=(),  # no version is patched -- every version is affected
    unaffected=(),
)

WITHDRAWN_ADVISORY = Advisory(
    id="RUSTSEC-2021-0147",
    package="daemonize",
    title="unmaintained",
    description="...",
    date="2021-09-01",
    withdrawn="2023-02-19",
    url="https://example.com/RUSTSEC-2021-0147",
    references=(),
    cvss=None,
    aliases=(),
    informational="unmaintained",
    license=None,
    categories=(),
    keywords=(),
    patched=(),
    unaffected=(),
)


def _db(*advisories: Advisory) -> AdvisoryDB:
    by_crate: dict[str, tuple[Advisory, ...]] = {}
    for a in advisories:
        by_crate[a.package] = by_crate.get(a.package, ()) + (a,)
    return AdvisoryDB(advisories=tuple(advisories), by_crate=by_crate, manifest={})


class TestBasicMatching:
    def test_vulnerable_version_produces_a_match(self):
        deps = [Dependency(name="anchor-lang", version="1.0.0", is_local=False)]
        result = match_dependencies(deps, _db(ANCHOR_ADVISORY))
        assert len(result.matches) == 1
        m = result.matches[0]
        assert m.advisory_id == "RUSTSEC-2026-0144"
        assert m.aliases == ("CVE-2026-45137", "GHSA-c6rc-8jpp-2fgc")

    def test_patched_version_produces_no_match(self):
        deps = [Dependency(name="anchor-lang", version="1.0.2", is_local=False)]
        result = match_dependencies(deps, _db(ANCHOR_ADVISORY))
        assert result.matches == ()
        assert result.dependencies_scanned == 1

    def test_unaffected_version_produces_no_match(self):
        deps = [Dependency(name="anchor-lang", version="0.9.0", is_local=False)]
        result = match_dependencies(deps, _db(ANCHOR_ADVISORY))
        assert result.matches == ()

    def test_crate_with_no_advisories_produces_no_match(self):
        deps = [Dependency(name="serde", version="1.0.0", is_local=False)]
        result = match_dependencies(deps, _db(ANCHOR_ADVISORY))
        assert result.matches == ()
        assert result.dependencies_scanned == 1


class TestEmptyRangesMeanEveryVersionIsAffected:
    def test_no_patched_or_unaffected_ranges_matches_any_version(self):
        deps = [Dependency(name="abomonation", version="99.0.0", is_local=False)]
        result = match_dependencies(deps, _db(BORSH_ADVISORY_NO_PATCHED_RANGE_COVERAGE))
        assert len(result.matches) == 1
        assert result.matches[0].informational == "unsound"


class TestLocalCratesAreSkippedNotAdvisoryCandidates:
    def test_local_workspace_crate_is_never_matched(self):
        deps = [Dependency(name="anchor-lang", version="1.0.0", is_local=True)]
        result = match_dependencies(deps, _db(ANCHOR_ADVISORY))
        assert result.matches == ()
        assert result.dependencies_skipped_local == 1
        assert result.dependencies_scanned == 0


class TestWithdrawnAdvisoriesAreExcludedButCounted:
    def test_withdrawn_advisory_does_not_produce_a_match(self):
        deps = [Dependency(name="daemonize", version="1.0.0", is_local=False)]
        result = match_dependencies(deps, _db(WITHDRAWN_ADVISORY))
        assert result.matches == ()
        # Not silently dropped -- the exclusion is a visible, counted field.
        assert result.withdrawn_advisories_excluded == 1


class TestMultipleDependenciesAndAdvisoriesTogether:
    def test_mixed_scan_reports_correct_totals(self):
        deps = [
            Dependency(name="anchor-lang", version="1.0.0", is_local=False),  # vulnerable
            Dependency(name="anchor-lang", version="1.0.2", is_local=False),  # patched
            Dependency(name="ares-core", version="0.1.0", is_local=True),  # local, skipped
            Dependency(name="serde", version="1.0.0", is_local=False),  # clean, no advisories
        ]
        result = match_dependencies(deps, _db(ANCHOR_ADVISORY))
        assert len(result.matches) == 1
        assert result.matches[0].version == "1.0.0"
        assert result.dependencies_scanned == 3
        assert result.dependencies_skipped_local == 1
