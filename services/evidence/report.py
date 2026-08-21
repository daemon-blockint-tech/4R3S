"""Strict loader for an `ares scan` report artifact.

Reads the JSON the Rust engine writes (core/crates/ares-cli/src/commands/scan.rs:526-530)
and refuses anything it does not fully recognise. The strictness is the point,
not a nicety, and it has two jobs.

**Numbers never become floats.** `json.loads` is called with `parse_float=str`
and `parse_int=str`, so every number reaches the leaf encoder as the literal
characters from the file. serde_json formats f64 via ryu and CPython's repr
spells exponents differently (`1e-7` round-trips as `1e-07`), so a
float-based implementation would produce a different root on a value that
happens not to round-trip. Every confidence in the local corpus does round-trip,
which is exactly why that bug would ship green.

**The schema is closed.** Any unknown key, and any unknown enum token, is an
error. Consider adding `Finding.exploitability: f64` in Rust: a permissive
loader would silently omit it from every leaf, and every root ever anchored
would become a commitment to a claim that no longer describes the report --
invisibly, retroactively, and unfixably. A closed schema turns that into a red
test on the PR that adds the field.

Deterministic and offline: no LLM, no network, no randomness. See "Hermetic by
default" in ../../SECURITY.md.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from canonical import EvidenceError, validate_number_token, validate_uint_token

# --- the closed schema, transcribed from core/crates/ares-core/src/lib.rs ---

#: AuditReport, lib.rs:250-257
_TOP_KEYS = frozenset({"target", "findings", "suppressed_findings", "metadata", "summary"})

#: ProgramTarget, lib.rs:260-268
_TARGET_KEYS = frozenset(
    {"name", "repository_url", "commit_hash", "program_id", "source_path", "idl_path"}
)

#: ReportMetadata, lib.rs:271-286. `confirmed_at` carries #[serde(default)] and
#: is Option<DateTime<Utc>>, the same pattern Finding.validation uses -- a report
#: written before `ares confirm` started setting it omits the key entirely, and
#: every scan report (confirmed or not) now carries it as `null` or a string. It
#: is optional here for that reason and no other; see _METADATA_REQUIRED.
_METADATA_KEYS = frozenset(
    {
        "generated_at",
        "confirmed_at",
        "ares_version",
        "scan_duration_secs",
        "agent_pipeline",
        "tools_used",
    }
)
_METADATA_REQUIRED = _METADATA_KEYS - {"confirmed_at"}

#: ReportSummary, lib.rs:281-297 -- twelve fields, not the five that `confirm`
#: recomputes. See the `summary_agrees` note in bundle.py.
_SUMMARY_KEYS = frozenset(
    {
        "total_findings",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "informational_count",
        "false_positives_suppressed",
        "poc_generated",
        "tests_passed",
        "tests_failed",
        "total_economic_impact_lamports",
        "max_single_exploit_lamports",
    }
)

#: Finding, lib.rs:183-201. `validation` carries #[serde(default)], so a report
#: written before POC-2 omits the key entirely -- it is optional here for that
#: reason and no other.
_FINDING_REQUIRED = frozenset(
    {
        "id",
        "title",
        "description",
        "severity",
        "category",
        "location",
        "proof_of_concept",
        "recommendation",
        "references",
        "confidence",
    }
)
_FINDING_KEYS = _FINDING_REQUIRED | {"validation"}

#: CodeLocation, lib.rs:238-247
_LOCATION_KEYS = frozenset(
    {"file", "line_start", "line_end", "column_start", "column_end", "function", "commit"}
)

#: SuppressedFinding, lib.rs:230-235
_SUPPRESSED_KEYS = frozenset({"finding", "reason", "suppressed_by"})

#: Severity, lib.rs:161-168. PascalCase on the wire -- this enum carries no
#: `rename_all`, unlike VulnerabilityCategory. The asymmetry is real; see
#: docs/ORC-2-CORE-CALL-CONTRACT.md:129-133.
_SEVERITIES = frozenset({"Critical", "High", "Medium", "Low", "Informational"})

#: VulnerabilityCategory, lib.rs:49-73, serialised kebab-case. All 21 variants.
#: test_report.py asserts this set equals the keys of the committed
#: eval/mappings/ares-core-categories.json, which already has its own Rust-side
#: cross-check -- so a category added in Rust cannot pass unnoticed here.
_CATEGORIES = frozenset(
    {
        "account-data-matching",
        "account-reloading",
        "arbitrary-cpi",
        "arithmetic-overflow",
        "close-account",
        "duplicate-mutable-accounts",
        "fuzzing-crash",
        "generic",
        "initialization-frontrunning",
        "invariant-violation",
        "missing-revalidation",
        "missing-signer",
        "ownership-check",
        "pda-privileges",
        "re-initialization",
        "reentrancy-risk",
        "revival-attack",
        "signer-authorization",
        "state-transition-gap",
        "type-cosplay",
        "unchecked-cast",
    }
)

#: ValidationOutcome, lib.rs:206-216, kebab-case.
_VALIDATIONS = frozenset({"confirmed", "refuted", "inconclusive"})

#: SuppressedFinding.suppressed_by is a bare String in Rust, so the only way to
#: know the real vocabulary is to read every write site. All four:
#:
#:   local_judge         core/crates/ares-mapper/src/local_judge.rs:102
#:   llm_judge           core/crates/ares-cli/src/commands/scan.rs:419
#:   triager             core/crates/ares-cli/src/commands/scan.rs:439
#:   semantic_validator  core/crates/ares-cli/src/validator.rs:72, :92
#:
#: `ares-core/src/lib.rs:234` documents this field as `// "local_judge" or
#: "llm_judge"` -- that comment is stale and misses half the vocabulary. This set
#: was built from the write sites, and `semantic_validator` was found only
#: because the closed schema rejected four real reports in the local corpus. That
#: is the check paying for itself: a silently-accepted unknown suppressor would
#: have been hashed into leaves as an unvalidated string.
_SUPPRESSORS = frozenset({"local_judge", "llm_judge", "triager", "semantic_validator"})

#: Location fields that are u32 line/column numbers.
_LOCATION_UINTS = ("line_start", "line_end", "column_start", "column_end")


class ReportError(EvidenceError):
    """The artifact is not a report this bundler is willing to attest."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """Object hook that refuses duplicate JSON keys.

    `json.loads('{"a":1,"a":2}')` silently returns `{'a': 2}` -- last one wins.
    A JavaScript viewer may show the first. That difference is a tamper vector:
    a report could read one way to a human and hash another way here.
    """
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise ReportError(
                f"duplicate JSON key {key!r}. Different parsers disagree about "
                f"which value wins, so this file cannot be attested."
            )
        seen[key] = value
    return seen


def _reject_constant(name: str) -> object:
    """Refuse NaN / Infinity.

    `json.loads('NaN')` returns a float nan by default. serde_json cannot emit
    any of these, so their presence means the file was written by something
    other than the engine.
    """
    raise ReportError(
        f"report contains the non-JSON constant {name!r}; serde_json cannot "
        f"emit it, so this file was not written by the engine"
    )


def _check_keys(where: str, obj: object, allowed: frozenset, required: frozenset | None = None) -> dict:
    if not isinstance(obj, dict):
        raise ReportError(f"{where} must be a JSON object, got {type(obj).__name__}")
    extra = sorted(set(obj) - allowed)
    if extra:
        raise ReportError(
            f"{where} carries unknown key(s) {extra}. The schema is closed on "
            f"purpose: an unrecognised field would be published in the bundle "
            f"but excluded from every digest. Update report.py and "
            f"canonical.LEAF_FIELDS together, as a new leaf encoding version."
        )
    missing = sorted((required or allowed) - set(obj))
    if missing:
        raise ReportError(f"{where} is missing required key(s) {missing}")
    return obj


def _check_str(where: str, value: object) -> str:
    if not isinstance(value, str):
        raise ReportError(f"{where} must be a string, got {type(value).__name__}")
    return value


def _check_opt_str(where: str, value: object) -> str | None:
    if value is None:
        return None
    return _check_str(where, value)


def _check_token(where: str, value: object, allowed: frozenset) -> str:
    s = _check_str(where, value)
    if s not in allowed:
        raise ReportError(
            f"{where} has unknown value {s!r}; known values are {sorted(allowed)}. "
            f"An unrecognised token is surfaced rather than coerced to a default."
        )
    return s


#: `total_economic_impact_lamports` and `max_single_exploit_lamports` are u64 in
#: Rust, so the u32 bound that suits a line number is wrong for the summary.
#: Kept as a separate helper rather than loosening validate_uint_token, because a
#: u64-wide line number really would be a defect worth catching.
_U64_MAX = 2**64 - 1


def _validate_u64_token(field: str, token: object) -> str:
    if not isinstance(token, str) or not token.isdigit() or (len(token) > 1 and token[0] == "0"):
        raise ReportError(f"field {field!r} is not a plain integer literal: {token!r}")
    if int(token) > _U64_MAX:
        raise ReportError(f"field {field!r} exceeds u64: {token!r}")
    return token


def _validate_location(where: str, raw: object) -> dict:
    loc = _check_keys(where, raw, _LOCATION_KEYS)
    _check_str(f"{where}.file", loc["file"])
    for field in _LOCATION_UINTS:
        if loc[field] is not None:
            validate_uint_token(f"{where}.{field}", loc[field])
    _check_opt_str(f"{where}.function", loc["function"])
    _check_opt_str(f"{where}.commit", loc["commit"])
    return loc


def _validate_finding(where: str, raw: object) -> dict:
    f = _check_keys(where, raw, _FINDING_KEYS, required=_FINDING_REQUIRED)
    _check_str(f"{where}.id", f["id"])
    _check_str(f"{where}.title", f["title"])
    _check_str(f"{where}.description", f["description"])
    _check_token(f"{where}.severity", f["severity"], _SEVERITIES)
    _check_token(f"{where}.category", f["category"], _CATEGORIES)
    _validate_location(f"{where}.location", f["location"])
    _check_opt_str(f"{where}.proof_of_concept", f["proof_of_concept"])
    _check_str(f"{where}.recommendation", f["recommendation"])
    if not isinstance(f["references"], list):
        raise ReportError(f"{where}.references must be a list")
    for i, ref in enumerate(f["references"]):
        _check_str(f"{where}.references[{i}]", ref)
    validate_number_token(f"{where}.confidence", f["confidence"])
    if f.get("validation") is not None:
        _check_token(f"{where}.validation", f["validation"], _VALIDATIONS)
    return f


@dataclass(frozen=True)
class Report:
    """A validated report, plus the raw bytes it came from.

    `raw` and `sha256` are kept because the Merkle root deliberately excludes
    the volatile header, so a second digest over the exact bytes is what lets a
    verifier tell "someone edited the timestamp" apart from "someone edited a
    severity". Neither commitment can do both jobs.
    """

    path: Path
    raw: bytes
    sha256: str
    #: "scan" or "confirmed", from the filename stem.
    kind: str
    data: dict

    @property
    def ends_with_newline(self) -> bool:
        return self.raw.endswith(b"\n")


def report_kind_for(path: Path) -> str:
    """`scan` or `confirmed`, from the stem `confirm.rs:387-394` produces."""
    return "confirmed" if path.stem.endswith(".confirmed") else "scan"


def load_report(path: str | Path) -> Report:
    """Read, digest and strictly validate one report artifact."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ReportError(f"cannot read report {p}: {exc}") from exc

    # The digest is over the bytes exactly as they sit on disk -- no re-encoding
    # and no added newline. All reports in the local corpus end WITHOUT a newline
    # (to_string_pretty then fs::write). This is where the sorted-keys-plus-\n
    # convention from services/cve/refresh_snapshot.py:201 deliberately does not
    # apply: there the canonical form *is* the file, here the file already exists
    # and its bytes are the artifact.
    digest = hashlib.sha256(raw).hexdigest()

    try:
        data = json.loads(
            raw.decode("utf-8"),
            parse_float=str,
            parse_int=str,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise ReportError(f"report {p} is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReportError(f"report {p} is not valid JSON: {exc}") from exc

    _check_keys("report", data, _TOP_KEYS)

    target = _check_keys("report.target", data["target"], _TARGET_KEYS)
    _check_str("report.target.name", target["name"])
    for field in ("repository_url", "commit_hash", "program_id", "idl_path"):
        _check_opt_str(f"report.target.{field}", target[field])
    _check_str("report.target.source_path", target["source_path"])

    metadata = _check_keys(
        "report.metadata", data["metadata"], _METADATA_KEYS, required=_METADATA_REQUIRED
    )
    _check_str("report.metadata.generated_at", metadata["generated_at"])
    # Absent (a report written before this field existed), JSON null (a scan
    # that has never been confirmed), and a timestamp string (a confirmed
    # report) are the three legitimate shapes -- .get() treats the first two
    # identically, matching Option<DateTime<Utc>>'s own None.
    _check_opt_str("report.metadata.confirmed_at", metadata.get("confirmed_at"))
    _check_str("report.metadata.ares_version", metadata["ares_version"])
    validate_uint_token("report.metadata.scan_duration_secs", metadata["scan_duration_secs"])
    for field in ("agent_pipeline", "tools_used"):
        if not isinstance(metadata[field], list):
            raise ReportError(f"report.metadata.{field} must be a list")
        for i, item in enumerate(metadata[field]):
            _check_str(f"report.metadata.{field}[{i}]", item)

    summary = _check_keys("report.summary", data["summary"], _SUMMARY_KEYS)
    for field in sorted(_SUMMARY_KEYS):
        _validate_u64_token(f"report.summary.{field}", summary[field])

    if not isinstance(data["findings"], list):
        raise ReportError("report.findings must be a list")
    for i, raw_finding in enumerate(data["findings"]):
        _validate_finding(f"report.findings[{i}]", raw_finding)

    if not isinstance(data["suppressed_findings"], list):
        raise ReportError("report.suppressed_findings must be a list")
    for i, raw_sup in enumerate(data["suppressed_findings"]):
        s = _check_keys(f"report.suppressed_findings[{i}]", raw_sup, _SUPPRESSED_KEYS)
        _validate_finding(f"report.suppressed_findings[{i}].finding", s["finding"])
        _check_str(f"report.suppressed_findings[{i}].reason", s["reason"])
        _check_token(
            f"report.suppressed_findings[{i}].suppressed_by", s["suppressed_by"], _SUPPRESSORS
        )

    return Report(path=p, raw=raw, sha256=digest, kind=report_kind_for(p), data=data)
