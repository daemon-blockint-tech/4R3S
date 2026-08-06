"""Cargo-style version requirement matching, ported narrowly for advisory ranges.

Why this exists rather than pulling in a `semver`/`packaging`-style dependency:
RustSec's `patched` / `unaffected` fields use Cargo's own requirement grammar
(https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html), which
is caret-by-default and NOT the same grammar as Python's PEP 440 or npm's
node-semver range syntax. A general-purpose semver library would silently
mis-parse `>= 1.2.3, < 2.0.0` (a real RustSec pattern) or apply the wrong
default-operator rule to a bare `1.2.3`. Implementing the narrow grammar we
actually see keeps the matcher auditable in one file instead of trusting a
third-party parser's Cargo-compatibility claims.

This module has ONE job and is deliberately strict about failing on anything
it does not recognize. A version requirement string that silently fails to
match looks identical to a clean scan result — the same failure shape as
ORC2-F7 (docs/CORE-CONTRACT-FINDINGS.md), where a dropped result was
indistinguishable from "nothing found." Raising `UnsupportedVersionReq` moves
that failure to snapshot-build time (see test_snapshot_integrity.py), where a
human sees it, rather than to scan time, where it is invisible.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


class UnsupportedVersionReq(ValueError):
    """Raised when a version or requirement string doesn't fit the grammar
    this module implements. Callers must not catch this and treat it as
    "no match" — see module docstring."""


_NUMERIC = re.compile(r"^\d+$")


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()

    @staticmethod
    def parse(text: str) -> "Version":
        text = text.strip()
        core, _, pre_part = text.partition("-")
        # Cargo/semver build metadata (+build) is not ordering-significant;
        # drop it rather than mis-parsing it as part of pre-release.
        core = core.split("+", 1)[0]
        parts = core.split(".")
        if len(parts) != 3 or not all(_NUMERIC.match(p) for p in parts):
            raise UnsupportedVersionReq(f"not a MAJOR.MINOR.PATCH version: {text!r}")
        major, minor, patch = (int(p) for p in parts)
        pre = tuple(pre_part.split(".")) if pre_part else ()
        return Version(major, minor, patch, pre)

    def _pre_key(self) -> tuple:
        # Absence of a pre-release sorts ABOVE any pre-release of the same
        # MAJOR.MINOR.PATCH (1.0.0 > 1.0.0-alpha), matching semver precedence.
        if not self.pre:
            return (1,)
        # Numeric identifiers compare numerically, alphanumeric compare as
        # strings; mixing the two within one identifier is not handled by
        # semver either, so we don't special-case it further.
        key = tuple((0, int(p)) if _NUMERIC.match(p) else (1, p) for p in self.pre)
        return (0,) + key

    def sort_key(self) -> tuple:
        return (self.major, self.minor, self.patch, self._pre_key())

    def __str__(self) -> str:  # pragma: no cover - debugging aid only
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{'.'.join(self.pre)}" if self.pre else base


def _cmp(a: Version, b: Version) -> int:
    ak, bk = a.sort_key(), b.sort_key()
    return -1 if ak < bk else (1 if ak > bk else 0)


@dataclass(frozen=True)
class _Comparator:
    op: str  # one of: "=", ">", ">=", "<", "<=", "^", "~", "*"
    version: Version | None  # None only for "*"

    def matches(self, v: Version) -> bool:
        if self.op == "*":
            return True
        assert self.version is not None
        c = _cmp(v, self.version)
        if self.op == "=":
            return c == 0
        if self.op == ">":
            return c > 0
        if self.op == ">=":
            return c >= 0
        if self.op == "<":
            return c < 0
        if self.op == "<=":
            return c <= 0
        if self.op == "^":
            return self._caret_matches(v)
        if self.op == "~":
            return self._tilde_matches(v)
        raise UnsupportedVersionReq(f"unknown comparator operator: {self.op!r}")  # pragma: no cover

    def _caret_matches(self, v: Version) -> bool:
        base = self.version
        assert base is not None
        if _cmp(v, base) < 0:
            return False
        # Caret compatibility: bump is allowed in the leftmost nonzero of
        # major/minor/patch as written; a zero leading component narrows the
        # allowed range (Cargo's "0.x is basically exact" rule).
        if base.major != 0:
            return v.major == base.major
        if base.minor != 0:
            return v.major == 0 and v.minor == base.minor
        return v.major == 0 and v.minor == 0 and v.patch == base.patch

    def _tilde_matches(self, v: Version) -> bool:
        base = self.version
        assert base is not None
        if _cmp(v, base) < 0:
            return False
        return v.major == base.major and v.minor == base.minor


_COMPARATOR_RE = re.compile(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$")


def _parse_comparator(raw: str) -> _Comparator:
    raw = raw.strip()
    if raw == "*":
        return _Comparator("*", None)
    m = _COMPARATOR_RE.match(raw)
    if not m:
        raise UnsupportedVersionReq(f"unrecognized comparator: {raw!r}")  # pragma: no cover
    op, ver_text = m.group(1), m.group(2)
    ver_text = ver_text.strip()

    # Partial versions ("0", "0.3", "111.9") default their missing
    # components to 0 -- this is independent of which operator is present.
    # Confirmed against real advisories, not just the (fully-specified-only)
    # EXAMPLE_ADVISORY.md template: RUSTSEC-2020-0015 (openssl-src) has
    # `patched = [">= 111.9"]`, RUSTSEC-2019-0004 (libp2p-core) has
    # `unaffected = ["< 0.3"]` -- both explicit operators on a two-component
    # version. A first version of this parser padded partial versions only
    # in the operator-absent branch, which raised UnsupportedVersionReq on
    # every one of these -- i.e. would have silently dropped 40 real ranges
    # from matching (caught by test_snapshot_integrity.py against the real
    # corpus, not by a hand-written fixture).
    n_parts = ver_text.split(".")
    if len(n_parts) < 3 and all(_NUMERIC.match(p) for p in n_parts if p):
        ver_text = ".".join(n_parts + ["0"] * (3 - len(n_parts)))
        was_partial = True
    else:
        was_partial = False

    # Cargo's default-operator rule: a version with NO leading operator
    # (bare "1.2.3", or a partial one) behaves like `^` (caret), never `=`.
    # "1.2.3" alone means ^1.2.3, matching up to (but excluding) 2.0.0.
    if op is None:
        op = "^"
    elif op == "~" and was_partial and len(n_parts) == 1:
        # `~1` (major only, no minor) is specified by Cargo to behave like
        # `^1` (i.e. allow minor/patch bumps), NOT like the ordinary tilde
        # rule (pin the minor) applied to the padded "1.0.0" -- those two
        # give different ranges (`<2.0.0` vs `<1.1.0`). This exact shape did
        # not occur in the corpus this was built against; raising here means
        # a future snapshot refresh that introduces one fails loudly in
        # test_snapshot_integrity.py rather than silently matching the
        # narrower, wrong range.
        raise UnsupportedVersionReq(
            f"~MAJOR (tilde with no minor component) is not implemented: {raw!r}"
        )

    version = Version.parse(ver_text)
    return _Comparator(op, version)


@dataclass(frozen=True)
class VersionReq:
    """One or more comma-separated comparators, ALL of which must match
    (Cargo semantics — comma is conjunction, never disjunction)."""

    comparators: tuple[_Comparator, ...]
    raw: str

    def matches(self, version_text: str) -> bool:
        v = Version.parse(version_text)
        return all(c.matches(v) for c in self.comparators)

    @staticmethod
    def parse(raw: str) -> "VersionReq":
        if not raw or not raw.strip():
            raise UnsupportedVersionReq("empty version requirement")
        pieces = [p.strip() for p in raw.split(",")]
        if any(not p for p in pieces):
            raise UnsupportedVersionReq(f"malformed comma-separated requirement: {raw!r}")
        return VersionReq(tuple(_parse_comparator(p) for p in pieces), raw)


def matches_any(version_text: str, requirements: list[str]) -> bool:
    """True if `version_text` satisfies at least one requirement string in
    `requirements` (the OR-across-entries semantics RustSec's `patched` and
    `unaffected` arrays use — each array element is independently sufficient).
    Raises UnsupportedVersionReq if any entry can't be parsed; callers must
    not swallow that into a false "no match" (see module docstring)."""
    parsed = [VersionReq.parse(r) for r in requirements]
    return any(r.matches(version_text) for r in parsed)
