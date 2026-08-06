"""Parse a `Cargo.lock` into the (crate, version) pairs the advisory matcher
needs. `Cargo.lock` is itself valid TOML (confirmed against the real lockfile
committed at core/Cargo.lock), so this uses the stdlib `tomllib` -- no new
runtime dependency, see services/cve/requirements.txt.

Two things this file has to get right, both confirmed against core/Cargo.lock
rather than assumed:

1. Workspace-local crates have no `source` field (they aren't fetched from
   crates.io or a registry) and must NOT be treated as dependencies to
   advisory-match -- there is no upstream advisory database entry for a crate
   that is the target's own code.
2. The SAME crate name legitimately appears more than once at different
   versions (a real duplicate in that lockfile: `hashbrown` at 4 distinct
   versions, pulled in by different dependents). Returning a dict keyed by
   name would silently drop all but one version and under-report advisories
   against the dropped ones.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass


class MalformedLockfile(ValueError):
    """Raised when the input is not a Cargo.lock this parser can read.
    Callers (the endpoint) must map this to outcome=\"failed\", never to an
    empty/ok result -- an empty result must mean "parsed, zero deps", not
    "could not parse"."""


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    is_local: bool  # True when the [[package]] entry has no `source` field


def parse_lockfile(text: str) -> list[Dependency]:
    """Parse Cargo.lock TEXT into a list of Dependency, one per [[package]]
    table, preserving duplicates (see module docstring point 2).

    Raises MalformedLockfile if `text` is not parseable TOML, or is TOML but
    has no top-level `package` array at all (a Cargo.lock with zero packages
    is a legitimate empty lockfile -- see parse_lockfile's caller for how
    that is distinguished at the outcome level, this function returns `[]`
    for it rather than raising)."""
    if not text or not text.strip():
        raise MalformedLockfile("empty input")
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise MalformedLockfile(f"not valid TOML: {exc}") from exc

    if "package" not in doc:
        # Some early Cargo.lock v1 files use a different top-level shape
        # entirely (a bare list of tables with no `version` key at all was
        # never standard, but a lockfile from an unsupported/future format
        # could plausibly omit `package`). Rather than guess, and rather
        # than silently returning "zero dependencies" for a document that
        # might not even be a lockfile, this is a hard failure.
        raise MalformedLockfile("no top-level 'package' array -- is this a Cargo.lock?")

    packages = doc["package"]
    if not isinstance(packages, list):
        raise MalformedLockfile("'package' is present but is not an array of tables")

    deps: list[Dependency] = []
    for i, pkg in enumerate(packages):
        if not isinstance(pkg, dict) or "name" not in pkg or "version" not in pkg:
            raise MalformedLockfile(
                f"[[package]] entry at index {i} is missing 'name' or 'version'"
            )
        deps.append(
            Dependency(
                name=pkg["name"],
                version=pkg["version"],
                is_local="source" not in pkg,
            )
        )
    return deps
