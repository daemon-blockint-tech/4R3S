"""Verify an evidence bundle, and say precisely what is wrong when it isn't.

Two stages, and the stage at which verification fails *is* the diagnosis.

  Stage A  self-consistency, from the bundle alone. Anyone handed only a bundle
           can run this: re-encode every leaf from its published fields, rebuild
           the tree, re-derive the proof positions, recompute the commitment.
  Stage B  binding to the report. Digest the raw bytes, then independently
           re-derive the whole leaf set from the report and compare.

The reason both a Merkle root and a raw-bytes digest exist is visible in the
decision table: a report edited somewhere no leaf covers (`generated_at`, the
summary, key order, whitespace) fails the digest while every leaf still matches.
That is the most likely real tamper, and a root alone cannot see it.

  digest  leaves  target   outcome
  ------  ------  ------   -------
    ok      ok      ok     OK / OK_EMPTY
    ok     bad      -      BUNDLER_SKEW                   encoder drift, not tamper
   bad      ok      ok     REPORT_EDITED_OUTSIDE_LEAVES
   bad     bad      ok     REPORT_TAMPERED
   bad     bad     bad     DIFFERENT_REPORT

Deterministic and offline: no LLM, no network, no randomness. See "Hermetic by
default" in ../../SECURITY.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import merkle
from bundle import BUNDLE_SCHEMA, _project_all, _recount_summary
from canonical import (
    LEAF_ENCODING,
    EvidenceError,
    assert_no_machine_path,
    leaf_preimage,
)
from report import ReportError, load_report

# Exit codes. Pinned by test_verify.py: a caller scripting around this tool
# needs them to be stable, and collapsing two distinguishable failures onto one
# code would throw away the diagnosis the two-stage design exists to produce.
OK = 0
USAGE = 1
BUNDLE_MALFORMED = 2
REPORT_MISSING = 3
LEAF_HASH_MISMATCH = 4
ROOT_MISMATCH = 5
LEAF_ORDER_INVALID = 6
PROOF_INVALID = 7
COMMITMENT_MISMATCH = 8
REPORT_EDITED_OUTSIDE_LEAVES = 9
REPORT_TAMPERED = 10
DIFFERENT_REPORT = 11
BUNDLER_SKEW = 12
NON_DETERMINISTIC_INPUT = 13
ALGORITHM_UNSUPPORTED = 14


@dataclass(frozen=True)
class Outcome:
    code: int
    name: str
    message: str
    #: Non-fatal notes that do not change the exit code.
    advisories: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.code == OK


def _expected_algorithm() -> dict:
    return {
        "hash": "sha256",
        "tree": "rfc6962",
        "domain": merkle.DOMAIN.decode(),
        "leaf_prefix": merkle.LEAF_PREFIX.hex(),
        "node_prefix": merkle.NODE_PREFIX.hex(),
        "commitment_prefix": merkle.COMMITMENT_PREFIX.hex(),
        "target_binding_prefix": merkle.TARGET_BINDING_PREFIX.hex(),
        "leaf_encoding": LEAF_ENCODING,
    }


def _stage_a(doc: dict) -> Outcome | None:
    """Self-consistency. Returns None when the bundle checks out."""
    if doc.get("schema") != BUNDLE_SCHEMA:
        return Outcome(
            BUNDLE_MALFORMED,
            "BUNDLE_MALFORMED",
            f"expected schema {BUNDLE_SCHEMA!r}, got {doc.get('schema')!r}",
        )

    for block in ("algorithm", "source", "target", "engine", "tree", "anchor", "leaves"):
        if block not in doc:
            return Outcome(BUNDLE_MALFORMED, "BUNDLE_MALFORMED", f"missing {block!r} block")

    # A bundle that declares a different construction is refused rather than
    # re-hashed under our own rules -- otherwise this tool would happily
    # "verify" a document whose own header says it means something else.
    expected = _expected_algorithm()
    if doc["algorithm"] != expected:
        differing = sorted(
            k for k in set(expected) | set(doc["algorithm"])
            if doc["algorithm"].get(k) != expected.get(k)
        )
        return Outcome(
            ALGORITHM_UNSUPPORTED,
            "ALGORITHM_UNSUPPORTED",
            f"bundle declares an algorithm this verifier does not implement; "
            f"differing field(s): {differing}",
        )

    leaves = doc["leaves"]
    if not isinstance(leaves, list):
        return Outcome(BUNDLE_MALFORMED, "BUNDLE_MALFORMED", "leaves must be a list")

    leaf_count = doc["tree"].get("leaf_count")
    if leaf_count != len(leaves):
        return Outcome(
            BUNDLE_MALFORMED,
            "BUNDLE_MALFORMED",
            f"tree.leaf_count is {leaf_count} but {len(leaves)} leaves are present",
        )

    preimages: list[bytes] = []
    for i, leaf in enumerate(leaves):
        if leaf.get("index") != i:
            return Outcome(
                BUNDLE_MALFORMED, "BUNDLE_MALFORMED", f"leaves[{i}].index is {leaf.get('index')}"
            )
        fields = leaf.get("fields")
        if not isinstance(fields, dict):
            return Outcome(BUNDLE_MALFORMED, "BUNDLE_MALFORMED", f"leaves[{i}].fields missing")

        try:
            # Re-encode from the PUBLISHED fields. The bundle deliberately does
            # not store the preimage, so what a human reads here is exactly what
            # gets hashed.
            preimage = leaf_preimage(fields)
            for name in ("file", "title"):
                assert_no_machine_path(name, fields[name])
        except EvidenceError as exc:
            return Outcome(
                NON_DETERMINISTIC_INPUT,
                "NON_DETERMINISTIC_INPUT",
                f"leaves[{i}] cannot be canonically encoded: {exc}",
            )

        recomputed = merkle.leaf_hash(preimage).hex()
        if recomputed != leaf.get("leaf_hash"):
            return Outcome(
                LEAF_HASH_MISMATCH,
                "LEAF_HASH_MISMATCH",
                f"leaves[{i}] ({fields.get('id')}): published fields hash to "
                f"{recomputed} but the bundle records {leaf.get('leaf_hash')}. "
                f"The readable fields and the digest disagree.",
            )
        preimages.append(preimage)

    # Canonical order. Catches a bundle whose leaves were permuted after it was
    # built -- the hashes would all still match individually.
    if preimages != sorted(preimages):
        return Outcome(
            LEAF_ORDER_INVALID,
            "LEAF_ORDER_INVALID",
            "leaves are not in canonical (preimage byte) order",
        )

    root, proofs = merkle.build(preimages)
    if root.hex() != doc["tree"].get("merkle_root"):
        return Outcome(
            ROOT_MISMATCH,
            "ROOT_MISMATCH",
            f"leaves rebuild to root {root.hex()} but the bundle records "
            f"{doc['tree'].get('merkle_root')}",
        )

    for i, (leaf, proof) in enumerate(zip(leaves, proofs)):
        published = [(step.get("position"), step.get("hash")) for step in leaf.get("proof", [])]
        expected_proof = [(side, h.hex()) for side, h in proof]
        if published != expected_proof:
            return Outcome(
                PROOF_INVALID,
                "PROOF_INVALID",
                f"leaves[{i}] proof does not match the path derived from "
                f"(index={i}, leaf_count={len(leaves)}). Positions are re-derived "
                f"rather than trusted, so a supplied position array cannot forge one.",
            )
        if not merkle.verify_inclusion(preimages[i], i, len(leaves), proof, root):
            return Outcome(PROOF_INVALID, "PROOF_INVALID", f"leaves[{i}] proof does not verify")

    binding = merkle.target_binding(
        target_name=doc["target"]["name"],
        commit_hash=doc["target"]["commit_hash"],
        ares_version=doc["engine"]["ares_version"],
        operator_program_id=doc.get("operator_assertions", {}).get("solana_program_id"),
        report_kind=doc["source"]["report_kind"],
    )
    if binding.hex() != doc["anchor"].get("target_binding"):
        return Outcome(
            COMMITMENT_MISMATCH,
            "COMMITMENT_MISMATCH",
            f"target_binding recomputes to {binding.hex()} but the bundle records "
            f"{doc['anchor'].get('target_binding')}",
        )

    commitment = merkle.commitment(
        leaf_count=len(leaves),
        merkle_root=root,
        report_sha256=bytes.fromhex(doc["source"]["report_sha256"]),
        binding=binding,
    )
    if commitment.hex() != doc["anchor"].get("commitment"):
        return Outcome(
            COMMITMENT_MISMATCH,
            "COMMITMENT_MISMATCH",
            f"commitment recomputes to {commitment.hex()} but the bundle records "
            f"{doc['anchor'].get('commitment')}. The value anchored on chain does "
            f"not correspond to this bundle.",
        )
    return None


def verify(bundle_file: str | Path, report_file: str | Path | None = None) -> Outcome:
    """Run both stages and return the outcome."""
    bundle_p = Path(bundle_file)
    try:
        raw = bundle_p.read_bytes()
    except OSError as exc:
        return Outcome(USAGE, "USAGE", f"cannot read bundle {bundle_p}: {exc}")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return Outcome(BUNDLE_MALFORMED, "BUNDLE_MALFORMED", f"bundle is not valid JSON: {exc}")
    if not isinstance(doc, dict):
        return Outcome(BUNDLE_MALFORMED, "BUNDLE_MALFORMED", "bundle is not a JSON object")

    failure = _stage_a(doc)
    if failure is not None:
        return failure

    advisories: list[str] = []
    if doc["tree"]["leaf_count"] == 0:
        advisories.append(
            "This bundle attests that the report contained ZERO findings. It does "
            "not attest that a scan meaningfully executed: `ares scan` on a "
            "nonexistent path exits 0 and writes a well-formed empty report "
            "(docs/ORC-2-CORE-CALL-CONTRACT.md:150-181). An anchored empty root "
            "is not evidence of an audit."
        )
    if doc.get("summary_agrees") is False:
        advisories.append(
            "The report's own summary disagrees with a recount from the leaves; "
            "see summary_from_leaves. `confirm` recomputes only five of the twelve "
            "summary fields, so a confirmed report is partially stale by construction."
        )

    # --- Stage B ---
    resolved = Path(report_file) if report_file else bundle_p.parent / doc["source"]["report_filename"]
    if not resolved.exists():
        return Outcome(
            REPORT_MISSING,
            "REPORT_MISSING",
            f"stage A passed, but the report {resolved} is not present, so the "
            f"bundle could not be bound to an artifact",
            tuple(advisories),
        )

    digest_ok = hashlib.sha256(resolved.read_bytes()).hexdigest() == doc["source"]["report_sha256"]

    try:
        rep = load_report(resolved)
    except ReportError as exc:
        return Outcome(
            REPORT_TAMPERED if not digest_ok else BUNDLER_SKEW,
            "REPORT_TAMPERED" if not digest_ok else "BUNDLER_SKEW",
            f"the report no longer validates against the closed schema: {exc}",
            tuple(advisories),
        )

    target_ok = (
        rep.data["target"]["name"] == doc["target"]["name"]
        and rep.data["target"]["commit_hash"] == doc["target"]["commit_hash"]
        and rep.kind == doc["source"]["report_kind"]
    )

    try:
        rederived = sorted(
            merkle.leaf_hash(leaf_preimage(p)).hex() for p in _project_all(rep)
        )
    except EvidenceError as exc:
        return Outcome(
            NON_DETERMINISTIC_INPUT,
            "NON_DETERMINISTIC_INPUT",
            f"the report cannot be canonically re-projected: {exc}",
            tuple(advisories),
        )
    published = sorted(leaf["leaf_hash"] for leaf in doc["leaves"])
    leaves_ok = rederived == published

    if digest_ok and leaves_ok and target_ok:
        recount = _recount_summary(_project_all(rep))
        if recount != doc["summary_from_leaves"]:
            return Outcome(
                BUNDLER_SKEW,
                "BUNDLER_SKEW",
                "leaves match but the recounted summary does not; the bundle was "
                "produced by a different version of this bundler",
                tuple(advisories),
            )
        name = "OK_EMPTY" if doc["tree"]["leaf_count"] == 0 else "OK"
        return Outcome(OK, name, "verified", tuple(advisories))

    if digest_ok and not leaves_ok:
        return Outcome(
            BUNDLER_SKEW,
            "BUNDLER_SKEW",
            "the report bytes are byte-identical to what was bundled, so a leaf "
            "difference cannot be tampering -- it means this verifier encodes "
            "leaves differently from the bundler that produced the file. Encoder "
            "drift, not a compromised artifact.",
            tuple(advisories),
        )

    if not target_ok:
        return Outcome(
            DIFFERENT_REPORT,
            "DIFFERENT_REPORT",
            f"this bundle was built from a different artifact: bundle names "
            f"{doc['target']['name']!r} @ {doc['target']['commit_hash']!r} "
            f"({doc['source']['report_kind']}), report is {rep.data['target']['name']!r} @ "
            f"{rep.data['target']['commit_hash']!r} ({rep.kind})",
            tuple(advisories),
        )

    if leaves_ok:
        return Outcome(
            REPORT_EDITED_OUTSIDE_LEAVES,
            "REPORT_EDITED_OUTSIDE_LEAVES",
            "every finding still matches, but the report's bytes changed. The "
            "edit is somewhere no leaf covers: generated_at, scan_duration_secs, "
            "the summary, source_path, key order or whitespace. "
            + _header_diff(rep, doc),
            tuple(advisories),
        )

    changed = sorted(set(published) ^ set(rederived))
    return Outcome(
        REPORT_TAMPERED,
        "REPORT_TAMPERED",
        f"same target and commit, but finding content changed after bundling: "
        f"{len(changed)} leaf hash(es) differ. "
        + _tampered_detail(rep, doc),
        tuple(advisories),
    )


def _header_diff(rep, doc: dict) -> str:
    """Name which header fields differ, for the edited-outside-leaves case."""
    differences = []
    if rep.data["metadata"]["generated_at"] != doc["volatile"]["generated_at"]:
        differences.append(
            f"generated_at {doc['volatile']['generated_at']!r} -> "
            f"{rep.data['metadata']['generated_at']!r}"
        )
    if str(rep.data["metadata"]["scan_duration_secs"]) != str(doc["volatile"]["scan_duration_secs"]):
        differences.append(
            f"scan_duration_secs {doc['volatile']['scan_duration_secs']!r} -> "
            f"{rep.data['metadata']['scan_duration_secs']!r}"
        )

    changed_summary = sorted(
        k for k, v in doc["summary_in_report"].items()
        if str(rep.data["summary"].get(k)) != str(v)
    )
    if changed_summary:
        differences.append(f"summary field(s) {changed_summary}")
    if not differences:
        return "No header field this bundle records differs, so the change is in formatting."
    return "Differing: " + "; ".join(differences) + "."


def _tampered_detail(rep, doc: dict) -> str:
    """Name the findings whose content changed, by id."""
    published_by_id = {leaf["finding_id"]: leaf["leaf_hash"] for leaf in doc["leaves"]}
    now = {}
    for projection in _project_all(rep):
        now[projection["id"]] = merkle.leaf_hash(leaf_preimage(projection)).hex()

    changed = sorted(i for i in set(published_by_id) & set(now) if published_by_id[i] != now[i])
    added = sorted(set(now) - set(published_by_id))
    removed = sorted(set(published_by_id) - set(now))

    parts = []
    if changed:
        parts.append(f"modified: {changed}")
    if added:
        parts.append(f"added: {added}")
    if removed:
        parts.append(f"removed: {removed}")
    return ("Findings " + "; ".join(parts) + ".") if parts else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description="Verify an ARES evidence bundle against its report.",
    )
    parser.add_argument("bundle", help="path to a *.evidence.json bundle")
    parser.add_argument(
        "--report",
        default=None,
        help="path to the report; defaults to source.report_filename beside the bundle",
    )
    args = parser.parse_args(argv)

    outcome = verify(args.bundle, args.report)
    stream = sys.stdout if outcome.ok else sys.stderr
    print(f"{outcome.name}: {outcome.message}", file=stream)
    for advisory in outcome.advisories:
        print(f"  note: {advisory}", file=stream)
    return outcome.code


if __name__ == "__main__":
    raise SystemExit(main())
