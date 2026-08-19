"""Canonical leaf encoding for an ARES audit finding.

Turns one finding from an `ares scan` report into the exact bytes that get
hashed into a Merkle leaf. Everything here is about making that byte string
depend on *the claim* and on nothing else — not on which machine ran the scan,
not on which directory it ran from, not on which CPython built the bundle.

Deterministic and hermetic: no LLM, no network, no randomness, and in
particular **no filesystem access**. `Path.resolve()` is deliberately never
called: it would inject the host's current directory and follow symlinks that
differ per machine, which is exactly the class of bug this module exists to
prevent. All path handling is purely lexical.

The report is not byte-reproducible across runs -- `metadata.generated_at` is
`Utc::now()` (core/crates/ares-cli/src/commands/scan.rs:501), paths are
absolute and machine-specific, and `Finding.title` embeds one of those paths
(`scan.rs:237`). So a leaf commits to a normalized projection of a finding,
never to the raw JSON. What the raw bytes are for is a separate digest; see
`bundle.py`.

See "Hermetic by default" in ../../SECURITY.md.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

#: Version tag, first field of every leaf preimage. A v2 field order can then
#: never produce the same bytes as a v1 one, so two encodings cannot collide
#: even if a later version happens to reuse the same field values.
LEAF_ENCODING = "ares.evidence.leaf/1"

#: Refuse any single field larger than this. A leaf is a commitment to a claim,
#: not a transport for a payload, and an unbounded field is an easy way to make
#: bundling pathologically slow on a hostile report.
MAX_FIELD_BYTES = 1024 * 1024

#: Windows drive prefix (`C:/`, `D:\`), matched at the start of a string.
_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")

#: UNC share prefix (`//server/share/`), after separators are normalized.
_UNC_RE = re.compile(r"^//[^/]+/[^/]+/")

#: What must never survive into a hashed field. A machine path in a leaf means
#: the same audit, re-run on another box, anchors a different root -- silently.
#: Checked as a refusal rather than a cleanup: a value we did not expect to be
#: a path should stop the bundle, not get quietly rewritten.
_MACHINE_PATH_RE = re.compile(r"^[A-Za-z]:[/\\]|\\|^/")


class EvidenceError(Exception):
    """A bundle cannot be built, or cannot be trusted if it were.

    Mirrors `SnapshotError` in services/cve/advisories.py: these conditions are
    raised, never logged and continued past. A bundle built around a problem is
    worse than no bundle, because it looks like evidence.
    """


@dataclass(frozen=True)
class NormalizedPath:
    """A path stripped of everything machine-specific.

    `scope` is carried alongside because normalization throws away the absolute
    prefix, and without it "a file inside the audited program" and "a file
    somewhere else on the auditor's disk" would encode identically.
    """

    #: Forward-slashed, NFC, root-stripped, relative to the target where possible.
    value: str
    #: "relative" (under the audited target) or "outside_target".
    scope: str


def _strip_root(path: str) -> tuple[str, bool]:
    """Remove a filesystem root, returning the remainder and whether one was found."""
    m = _DRIVE_RE.match(path)
    if m:
        return path[m.end() :], True
    m = _UNC_RE.match(path)
    if m:
        return path[m.end() :], True
    if path.startswith("/"):
        return path.lstrip("/"), True
    return path, False


def _lexical_segments(path: str) -> tuple[list[str], bool]:
    """Split on `/`, dropping `.` and resolving `..` without touching the disk.

    Returns the segments plus whether any `..` escaped the top, which is what
    forces `outside_target` -- a path that climbs above its own root is not
    describable relative to that root.
    """
    out: list[str] = []
    escaped = False
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            else:
                # Nothing left to pop: this climbs above the root. Keep it
                # literal so the value stays faithful, and remember why.
                out.append("..")
                escaped = True
            continue
        out.append(seg)
    return out, escaped


def normalize_path(raw: str, target_root: str | None = None) -> NormalizedPath:
    """Make a path from a report machine-independent, purely lexically.

    Order matters. Separators are unified first because real artifacts contain
    *mixed* separators inside a single string (an `eval/data/...` prefix joined
    to a `src\\lib.rs` suffix), so a drive- or root-check before that step would
    miss half of them.

    Deliberately does **not** casefold. On Windows `SRC/lib.rs` and `src/lib.rs`
    are one file; on Linux they are two. Folding would make genuinely distinct
    files collide, which is a worse failure than the inconsistency it fixes.
    """
    s = raw.replace("\\", "/")
    # Collapse runs of separators, but preserve a leading `//` long enough for
    # the UNC check below to see it.
    lead = "//" if s.startswith("//") else ""
    s = lead + re.sub(r"/+", "/", s.lstrip("/") if lead else s)

    s, _had_root = _strip_root(s)
    segments, escaped = _lexical_segments(s)

    # macOS writes NFD filenames, Windows and Linux NFC. Without this the same
    # file scanned on two machines produces two different leaves.
    normalized = unicodedata.normalize("NFC", "/".join(segments))

    if target_root is None:
        return NormalizedPath(normalized or ".", "outside_target" if escaped else "relative")

    root = normalize_path(target_root, None).value
    if escaped:
        return NormalizedPath(normalized or ".", "outside_target")
    if normalized == root:
        # The finding is about the target itself, not a file inside it. Emit a
        # literal "." rather than "" so the field is never empty -- an empty
        # string is indistinguishable from a missing one after framing.
        return NormalizedPath(".", "relative")
    if root and normalized.startswith(root + "/"):
        return NormalizedPath(normalized[len(root) + 1 :], "relative")
    if not root:
        return NormalizedPath(normalized or ".", "relative")
    return NormalizedPath(normalized or ".", "outside_target")


def rewrite_title(title: str, raw_location_file: str, normalized_file: str) -> str:
    """Replace a machine path that `scan.rs` formatted into a finding title.

    `scan.rs:237` builds AST titles as `format!("{}: {}", category, file.display())`,
    so 352 of the 1296 findings in the local corpus carry an absolute path in a
    field that is otherwise free text.

    This inverts that exact construction -- suffix match on the raw value, then
    substitution -- rather than pattern-matching on things that look like paths.
    A heuristic rewrite of free-text evidence would be a worse defect than the
    leak it fixed: it would silently alter the wording of a published claim.
    Titles that do not end with the raw path are returned byte-identical.
    """
    if raw_location_file and title.endswith(raw_location_file):
        return title[: -len(raw_location_file)] + normalized_file
    return title


def assert_no_machine_path(field: str, value: str) -> None:
    """Refuse to hash a value that still looks like a machine path.

    This guard matters more than any single normalization rule. When a future
    `Finding` field starts embedding paths -- as `title` already does -- this
    fires on the first bundle instead of quietly poisoning every root anchored
    from then on.
    """
    if _MACHINE_PATH_RE.search(value):
        raise EvidenceError(
            f"field {field!r} still contains a machine-specific path after "
            f"normalization: {value!r}. Refusing to build a bundle whose root "
            f"would depend on which machine ran the scan. If a new Finding "
            f"field carries a path, add it to the normalization in canonical.py."
        )


# ---------------------------------------------------------------------------
# Byte framing
#
# Length-prefixed, so no two different field tuples can ever produce the same
# preimage. Plain concatenation would make ("ab", "c") and ("a", "bc")
# identical -- and `title` is partly attacker-controlled, since it embeds file
# paths from the scanned repository. That makes boundary-shifting a live lever,
# not a theoretical one.
#
# `json.dumps(..., sort_keys=True)` is deliberately NOT used here, even though
# services/cve/refresh_snapshot.py:201 establishes it elsewhere in this repo.
# The digest that decides a Merkle root must not depend on CPython's json
# formatting, because CI pins 3.12 and development runs 3.14 -- the same class
# of cross-interpreter drift that commit dc5c97f fixed for PYTHONHASHSEED.
# Explicit framing has no such dependency. The cve convention is kept where it
# belongs: the bundle file's own checksum.
# ---------------------------------------------------------------------------


def lp(payload: bytes) -> bytes:
    """Length-prefix one field: u32 big-endian length, then the bytes."""
    if len(payload) > MAX_FIELD_BYTES:
        raise EvidenceError(
            f"field of {len(payload)} bytes exceeds the {MAX_FIELD_BYTES}-byte limit"
        )
    return len(payload).to_bytes(4, "big") + payload


def req(value: str) -> bytes:
    """Frame a field that is always present."""
    return lp(value.encode("utf-8"))


def opt(value: str | None) -> bytes:
    """Frame an optional field, with the presence flag *inside* the framed slot.

    Encoding `None` as an empty string would make `function: None` and
    `function: Some("")` produce identical bytes. `function`, `commit` and a
    suppression `reason` are all `Option<String>` in Rust that could legitimately
    hold an empty string, so the presence byte is the whole fix.
    """
    if value is None:
        return lp(b"\x00")
    return lp(b"\x01" + value.encode("utf-8"))


def seq(values: list[str]) -> bytes:
    """Frame a list: u32 count, then each entry length-prefixed."""
    out = len(values).to_bytes(4, "big")
    for v in values:
        out += lp(v.encode("utf-8"))
    return out


# ---------------------------------------------------------------------------
# Numeric tokens
#
# Numbers reach a leaf as the literal characters from the report file, never as
# a Python float. `json.loads(raw, parse_float=str)` is what makes that possible
# (see report.py) and this is where the tokens are checked.
#
# Why not just use float(): serde_json formats f64 via ryu, and CPython's repr
# spells exponents differently -- `1e-7` round-trips through repr() as `1e-07`,
# `1e16` as `1e+16`. Every confidence value in the local corpus happens to
# round-trip cleanly, so a repr()-based implementation is green today and
# latently broken. Carrying the token verbatim makes the question moot instead
# of answering it.
# ---------------------------------------------------------------------------

#: JSON's own number grammar. Deliberately stricter than Python's float(): it
#: rejects `01`, `+1`, `.5`, `1.`, `nan` and `inf`, all of which float() accepts
#: and none of which serde_json can emit.
_JSON_NUMBER_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")

#: Non-negative integer, no leading zeros. Line and column numbers are u32 in
#: `CodeLocation`, so anything wider did not come from the engine.
_UINT_TOKEN_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")

_U32_MAX = 2**32 - 1


def validate_number_token(field: str, token: str) -> str:
    """Check a JSON number literal and return it unchanged.

    Returns the token rather than a number on purpose: the caller wants the
    original characters, and handing back a parsed value would reintroduce
    exactly the spelling problem this avoids.
    """
    if not isinstance(token, str) or not _JSON_NUMBER_RE.match(token):
        raise EvidenceError(
            f"field {field!r} is not a JSON number literal: {token!r}. "
            f"A non-finite or oddly-spelled number cannot have come from "
            f"serde_json, so the report was edited by something else."
        )
    return token


def validate_uint_token(field: str, token: str) -> str:
    """Check a u32-ranged integer literal and return it unchanged."""
    if not isinstance(token, str) or not _UINT_TOKEN_RE.match(token):
        raise EvidenceError(f"field {field!r} is not a plain integer literal: {token!r}")
    if int(token) > _U32_MAX:
        raise EvidenceError(f"field {field!r} exceeds u32: {token!r}")
    return token


# ---------------------------------------------------------------------------
# The leaf projection
# ---------------------------------------------------------------------------

#: Field order for the preimage. Fixed, and the numbering is load-bearing --
#: reordering these silently changes every root ever produced, so a change here
#: is a new LEAF_ENCODING version, not an edit.
#:
#: `kind` is the highest-value field in the whole design: without it, moving a
#: real finding into `suppressed_findings` leaves the leaf unchanged and the
#: root cannot see the demotion.
LEAF_FIELDS: tuple[tuple[str, str], ...] = (
    ("encoding", "req"),
    ("kind", "req"),
    ("id", "req"),
    ("title", "req"),
    ("description", "req"),
    ("severity", "req"),
    ("category", "req"),
    ("path_scope", "req"),
    ("file", "req"),
    ("line_start", "opt"),
    ("line_end", "opt"),
    ("column_start", "opt"),
    ("column_end", "opt"),
    ("function", "opt"),
    ("commit", "opt"),
    ("recommendation", "req"),
    ("poc_present", "req"),
    ("confidence", "req"),
    ("validation", "req"),
    ("suppression_reason", "opt"),
    ("suppressed_by", "opt"),
    ("references", "seq"),
)

#: Fields whose value is a path or may contain one, and so must pass the
#: machine-path refusal before being framed.
_PATH_BEARING = ("file", "title")


def project_finding(
    finding: dict,
    *,
    kind: str,
    target_root: str | None,
    suppression_reason: str | None = None,
    suppressed_by: str | None = None,
) -> dict:
    """Build the hashed projection of one finding.

    `finding` must already have passed report.py's closed-schema validation, so
    every enum token here is known and every number is a verified literal.

    Returns a plain dict in LEAF_FIELDS order. It is what the bundle publishes
    as the leaf's `fields` block -- the bundle never stores the preimage, so a
    verifier has to re-encode what a human can read.
    """
    if kind not in ("finding", "suppressed"):
        raise EvidenceError(f"leaf kind must be 'finding' or 'suppressed', got {kind!r}")

    location = finding.get("location") or {}
    raw_file = location.get("file") or ""
    norm = normalize_path(raw_file, target_root)

    title = rewrite_title(finding["title"], raw_file, norm.value)

    fields: dict = {
        "encoding": LEAF_ENCODING,
        "kind": kind,
        "id": finding["id"],
        "title": title,
        "description": finding["description"],
        "severity": finding["severity"],
        "category": finding["category"],
        "path_scope": norm.scope,
        "file": norm.value,
        "line_start": location.get("line_start"),
        "line_end": location.get("line_end"),
        "column_start": location.get("column_start"),
        "column_end": location.get("column_end"),
        "function": location.get("function"),
        "commit": location.get("commit"),
        "recommendation": finding["recommendation"],
        # Whether a harness was generated is a claim about the audit. Where it
        # happens to live on disk is a function of the --output flag, so the
        # path itself is excluded; see the exclusions table in the plan.
        "poc_present": "absent" if finding.get("proof_of_concept") is None else "present",
        "confidence": finding["confidence"],
        # `validation` carries #[serde(default)], so a pre-POC-2 report omits
        # the key while a current one writes null. Both mean "no confirmation
        # pass ran" and carry no information, so both encode as "none" -- if
        # they differed, two reports asserting identical facts would anchor
        # differently because of a serde default.
        "validation": finding.get("validation") or "none",
        "suppression_reason": suppression_reason,
        "suppressed_by": suppressed_by,
        "references": list(finding.get("references") or []),
    }

    for name in _PATH_BEARING:
        assert_no_machine_path(name, fields[name])

    return fields


def leaf_preimage(fields: dict) -> bytes:
    """Serialize a projection to the exact bytes that get hashed."""
    missing = [name for name, _ in LEAF_FIELDS if name not in fields]
    if missing:
        raise EvidenceError(f"projection is missing leaf fields: {missing}")
    extra = sorted(set(fields) - {name for name, _ in LEAF_FIELDS})
    if extra:
        # A field present in the projection but absent from LEAF_FIELDS would be
        # published in the bundle yet excluded from the digest -- readable, and
        # unattested. Refuse rather than silently drop it.
        raise EvidenceError(f"projection carries fields outside LEAF_FIELDS: {extra}")

    out = b""
    for name, framing in LEAF_FIELDS:
        value = fields[name]
        if framing == "req":
            if not isinstance(value, str):
                raise EvidenceError(f"leaf field {name!r} must be a string, got {value!r}")
            out += req(value)
        elif framing == "opt":
            if value is not None and not isinstance(value, str):
                raise EvidenceError(f"leaf field {name!r} must be a string or None")
            out += opt(value)
        else:
            if not isinstance(value, list):
                raise EvidenceError(f"leaf field {name!r} must be a list")
            out += seq(value)
    return out
