"""Build an evidence bundle: a Merkle commitment over one report's findings.

Writes a sibling file next to the report and never touches the report itself --
the same discipline `ares confirm` follows for `.confirmed.json`
(core/crates/ares-cli/src/commands/confirm.rs:387-394), and what CLAUDE.md's
GOLDEN RULE 4 already commits to for the deterministic scan artifact.

Two commitments, because one digest cannot do both jobs:

  merkle_root    covers the per-finding claims, path-normalized, with the
                 volatile header excluded. Rerun-stable: the same engine on the
                 same input gives the same root, on any OS, from any directory.
  report_sha256  covers the raw bytes exactly as they sit on disk. Catches any
                 edit at all, including ones no leaf covers.

Having both is what lets a verifier distinguish "someone edited the timestamp"
from "someone edited a severity". See verify.py's decision table.

Deterministic and offline: no LLM, no network, no randomness, no keys, and no
transaction. This module produces the 32 bytes an operator may choose to anchor;
it never submits anything. Submitting needs a keypair and an RPC endpoint, both
of which would put a signing surface and a network dependency inside a service
whose only value is being reproducible offline. See "Hermetic by default" in
../../SECURITY.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import merkle
from canonical import EvidenceError, LEAF_ENCODING, leaf_preimage, normalize_path, project_finding
from report import Report, load_report

BUNDLE_SCHEMA = "ares.evidence.bundle/1"

#: Severity token -> the summary counter it feeds, for the recount.
_SEVERITY_COUNTERS = {
    "Critical": "critical_count",
    "High": "high_count",
    "Medium": "medium_count",
    "Low": "low_count",
    "Informational": "informational_count",
}

#: Which summary fields can be re-derived from the leaves at all. The others
#: (tests_passed/tests_failed and the two lamport estimates) describe work the
#: report does not record per-finding, so recomputing them is impossible and
#: claiming otherwise would be worse than leaving them alone.
_RECOMPUTABLE = (
    "total_findings",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "informational_count",
    "false_positives_suppressed",
    "poc_generated",
)


def bundle_path_for(report_path: Path) -> Path:
    """`<stem>.evidence.json`, beside the report.

    Chaining falls out of using the stem: `ares-report-x.json` becomes
    `ares-report-x.evidence.json`, and `ares-report-x.confirmed.json` becomes
    `ares-report-x.confirmed.evidence.json`.
    """
    return report_path.parent / f"{report_path.stem}.evidence.json"


def _project_all(rep: Report) -> list[dict]:
    """Project every finding and suppressed finding into leaf field dicts."""
    target_root = rep.data["target"]["source_path"]
    projections: list[dict] = []
    for finding in rep.data["findings"]:
        projections.append(project_finding(finding, kind="finding", target_root=target_root))
    for entry in rep.data["suppressed_findings"]:
        projections.append(
            project_finding(
                entry["finding"],
                kind="suppressed",
                target_root=target_root,
                suppression_reason=entry["reason"],
                suppressed_by=entry["suppressed_by"],
            )
        )
    return projections


def _order_and_check(projections: list[dict]) -> list[tuple[dict, bytes]]:
    """Sort leaves canonically and refuse the two ambiguity cases.

    Sorting is by preimage bytes. Because `encoding` is a constant first field
    and `kind` is the second, byte order is automatically kind-major, with
    `finding` before `suppressed` -- one sort key, no separate tie-break to keep
    in step with the field list.

    Report array order is deliberately not used. Nothing in `scan.rs` sorts
    `findings`, so that order is incidental, and a root sensitive to a
    meaningless permutation is a root that changes for no reason. This is the
    discipline services/family/cluster.py:230-241 spells out: relying on
    incidental ordering makes output depend on how a caller happened to order
    its input.
    """
    pairs = [(p, leaf_preimage(p)) for p in projections]

    # Duplicate ids: an inclusion proof for a duplicated id cannot say WHICH
    # finding it attests, and the PoC filename is derived from the id
    # (scan.rs:363), so two findings would share one harness. Structurally
    # impossible today -- the id counter is global and monotonic -- which makes
    # the check free to keep.
    seen_ids: dict[str, int] = {}
    for p, _ in pairs:
        key = f"{p['kind']}:{p['id']}"
        seen_ids[key] = seen_ids.get(key, 0) + 1
    dupe_ids = sorted(k for k, n in seen_ids.items() if n > 1)
    if dupe_ids:
        raise EvidenceError(
            f"report contains duplicate finding id(s) {dupe_ids}. An inclusion "
            f"proof for a duplicated id is ambiguous, so this report cannot be "
            f"attested."
        )

    # Duplicate preimages: two leaves with identical bytes make the tree a
    # multiset with no way to tell the copies apart in a proof, and duplicate
    # leaves are the precondition for the shape tricks RFC 6962 exists to
    # prevent. This is reachable in principle -- two AST findings in one file
    # with the same category and a null line share a hardcoded recommendation
    # and title shape -- and is only excluded because `id` is in the leaf.
    counts: dict[bytes, int] = {}
    for _, pre in pairs:
        counts[pre] = counts.get(pre, 0) + 1
    if any(n > 1 for n in counts.values()):
        raise EvidenceError(
            "two findings produced identical leaf bytes. That would make an "
            "inclusion proof ambiguous. This should be unreachable while "
            "`id` is part of the leaf encoding -- if it happened, the leaf "
            "field set in canonical.LEAF_FIELDS has lost a distinguishing field."
        )

    pairs.sort(key=lambda item: item[1])
    return pairs


def _recount_summary(projections: list[dict]) -> dict:
    """Re-derive the summary counters the leaves can actually support.

    Recomputing converts an unattested field into a checkable one. `confirm`
    recomputes only the five severity counters (confirm.rs:319-339), so a
    `.confirmed.json` summary is partially stale by construction -- this is how
    a reader finds that out instead of trusting it.
    """
    out = {name: 0 for name in _RECOMPUTABLE}
    for p in projections:
        if p["kind"] == "suppressed":
            out["false_positives_suppressed"] += 1
            continue
        out["total_findings"] += 1
        counter = _SEVERITY_COUNTERS[p["severity"]]
        out[counter] += 1
        if p["poc_present"] == "present":
            out["poc_generated"] += 1
    return out


def build_bundle(rep: Report, *, operator_program_id: str | None = None, cluster: str | None = None) -> dict:
    """Assemble the bundle document for one loaded report."""
    projections = _project_all(rep)
    ordered = _order_and_check(projections)
    preimages = [pre for _, pre in ordered]

    root, proofs = merkle.build(preimages)
    leaf_count = len(preimages)

    target = rep.data["target"]
    metadata = rep.data["metadata"]
    source_norm = normalize_path(target["source_path"], None)

    binding = merkle.target_binding(
        target_name=target["name"],
        commit_hash=target["commit_hash"],
        ares_version=metadata["ares_version"],
        operator_program_id=operator_program_id,
        report_kind=rep.kind,
    )
    commitment = merkle.commitment(
        leaf_count=leaf_count,
        merkle_root=root,
        report_sha256=bytes.fromhex(rep.sha256),
        binding=binding,
    )

    recount = _recount_summary(projections)
    reported = rep.data["summary"]
    # The report's counters arrive as integer *tokens* (parse_int=str), so
    # compare as ints rather than as strings -- "0" and "00" would already have
    # been rejected by the loader, but the comparison should be about value.
    agrees = all(int(reported[name]) == recount[name] for name in _RECOMPUTABLE)

    leaves = []
    for index, ((fields, preimage), proof) in enumerate(zip(ordered, proofs)):
        leaves.append(
            {
                "index": index,
                "kind": fields["kind"],
                "finding_id": fields["id"],
                "leaf_hash": merkle.leaf_hash(preimage).hex(),
                # `fields` is published; the preimage is NOT. Storing the
                # preimage would let a tampered bundle carry one that hashes
                # correctly while these readable fields say something else, and
                # a verifier that checked only the preimage would be fooled by
                # what a human reads. Forcing re-encoding means what a human
                # reads is exactly what the digest covers.
                "fields": fields,
                "proof": [{"position": side, "hash": h.hex()} for side, h in proof],
            }
        )

    return {
        "schema": BUNDLE_SCHEMA,
        "algorithm": {
            "hash": "sha256",
            "tree": "rfc6962",
            "domain": merkle.DOMAIN.decode(),
            "leaf_prefix": merkle.LEAF_PREFIX.hex(),
            "node_prefix": merkle.NODE_PREFIX.hex(),
            "commitment_prefix": merkle.COMMITMENT_PREFIX.hex(),
            "target_binding_prefix": merkle.TARGET_BINDING_PREFIX.hex(),
            "leaf_encoding": LEAF_ENCODING,
        },
        "source": {
            "report_filename": rep.path.name,
            "report_kind": rep.kind,
            "report_sha256": rep.sha256,
            "report_bytes": len(rep.raw),
            # Recorded so no re-serialization can fake a digest match by
            # differing only in a trailing newline.
            "report_ends_with_newline": rep.ends_with_newline,
        },
        "target": {
            "name": target["name"],
            "commit_hash": target["commit_hash"],
            "repository_url": target["repository_url"],
            # Always null in practice: scan.rs:102,104 hardcode both. Recorded
            # as-is so a reader sees the absence rather than inferring it.
            "program_id_in_report": target["program_id"],
            "source_path_normalized": source_norm.value,
            # Binds the machine-specific path without republishing it.
            "source_path_raw_sha256": hashlib.sha256(
                target["source_path"].encode("utf-8")
            ).hexdigest(),
        },
        "engine": {
            "ares_version": metadata["ares_version"],
            "agent_pipeline": list(metadata["agent_pipeline"]),
            "tools_used": list(metadata["tools_used"]),
        },
        "volatile": {
            "generated_at": metadata["generated_at"],
            "scan_duration_secs": metadata["scan_duration_secs"],
            "note": (
                "Wall-clock values from the scan. Hashed into no leaf, so the "
                "merkle_root is stable across re-runs. Covered only by "
                "report_sha256. `confirm` does not refresh generated_at, so on a "
                "confirmed report this is still the SCAN time -- nothing records "
                "when the confirmation pass ran."
            ),
        },
        "operator_assertions": {
            # Not engine-derived. The report carries no program_id at all, so
            # anything here is a human's claim about which deployed program the
            # audited source corresponds to. Named so nobody mistakes it for
            # evidence.
            "solana_program_id": operator_program_id,
            "cluster": cluster,
            "note": (
                "Operator-supplied, not derived from the report. The engine "
                "records no program_id (scan.rs:104), so there is no "
                "verified-build link between the audited source and any "
                "deployed bytecode."
            ),
        },
        "tree": {"leaf_count": leaf_count, "merkle_root": root.hex()},
        "anchor": {
            "commitment": commitment.hex(),
            "target_binding": binding.hex(),
            "commitment_field_order": [
                "commitment_prefix",
                "domain",
                "leaf_count_u32be",
                "merkle_root",
                "report_sha256",
                "target_binding",
            ],
            "target_binding_field_order": [
                "target_binding_prefix",
                "domain",
                "target_name",
                "commit_hash",
                "ares_version",
                "operator_program_id",
                "report_kind",
            ],
        },
        "summary_in_report": dict(reported),
        "summary_from_leaves": recount,
        "summary_agrees": agrees,
        "leaves": leaves,
    }


def serialize_bundle(doc: dict) -> bytes:
    """Canonical bytes for the bundle file itself.

    Sorted keys, two-space indent, trailing newline -- the convention
    services/cve/refresh_snapshot.py:275-278 established. It applies here,
    unlike for the report digest, because this is a JSON file we author.
    """
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_bundle(
    report_path: str | Path,
    *,
    out: str | Path | None = None,
    force: bool = False,
    operator_program_id: str | None = None,
    cluster: str | None = None,
) -> Path:
    """Bundle one report and write the sibling file. Returns the path written."""
    rep = load_report(report_path)
    destination = Path(out) if out else bundle_path_for(rep.path)

    if destination.resolve() == rep.path.resolve():
        raise EvidenceError(
            f"--out points at the report itself ({destination}). Refusing: that "
            f"would destroy the artifact being attested."
        )
    if destination.exists() and not force:
        raise EvidenceError(f"{destination} already exists; pass --force to replace it")

    doc = build_bundle(rep, operator_program_id=operator_program_id, cluster=cluster)
    destination.write_bytes(serialize_bundle(doc))

    # The report must be untouched. Re-read and compare rather than trusting
    # that we never opened it for writing.
    if rep.path.read_bytes() != rep.raw:
        raise EvidenceError(
            f"the report {rep.path} changed while bundling. This must never "
            f"happen; the scan artifact is required to stay byte-for-byte intact."
        )
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bundle.py",
        description="Build a Merkle evidence bundle for an ares scan report.",
    )
    parser.add_argument("report", help="path to ares-report-*.json (or a .confirmed.json)")
    parser.add_argument("--out", default=None, help="bundle path (default: <stem>.evidence.json)")
    parser.add_argument("--force", action="store_true", help="replace an existing bundle")
    parser.add_argument(
        "--program-id",
        default=None,
        help="operator's claim about the deployed Solana program id. Recorded "
        "under operator_assertions, NOT as evidence -- the report carries none.",
    )
    parser.add_argument(
        "--cluster",
        default=None,
        choices=["devnet", "mainnet-beta"],
        help="operator's intended anchoring cluster, recorded for the reader",
    )
    args = parser.parse_args(argv)

    try:
        written = write_bundle(
            args.report,
            out=args.out,
            force=args.force,
            operator_program_id=args.program_id,
            cluster=args.cluster,
        )
    except EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    doc = json.loads(written.read_text(encoding="utf-8"))
    print(f"wrote {written}")
    print(f"  leaf_count  {doc['tree']['leaf_count']}")
    print(f"  merkle_root {doc['tree']['merkle_root']}")
    print(f"  commitment  {doc['anchor']['commitment']}")
    if not doc["summary_agrees"]:
        print(
            "  warning: the report's summary disagrees with a recount from the "
            "leaves; see summary_from_leaves",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
