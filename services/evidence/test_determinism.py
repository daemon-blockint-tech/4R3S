"""The property the whole service exists for: same claims, same root.

These tests spawn real subprocesses. An in-process test cannot catch the failure
mode they target, which is why commit dc5c97f had to add the same shape to
services/family: CPython randomises `str` hashing per process
(`PYTHONHASHSEED`), and in that service the winnowing minimum shifted with the
seed, so the same pair of programs scored anywhere from 0.32 to 0.53 across five
runs -- straddling the decision threshold.

Why the same risk exists here, specifically: `str` *comparison* is not seeded, so
sorting preimages is safe. But **set and dict iteration order is**. A future
refactor that collected leaves through a `set` instead of `sorted()` would be
invisible to every in-process test and would shift the root between runs. That is
the same bug wearing different clothes.

The Windows-vs-POSIX test is the single most valuable one in the file: it pins
the property that all of canonical.py's path handling exists to provide, and it
fails on any implementation that normalises only the path-typed fields and
forgets that `scan.rs:237` formats a path into `Finding.title`.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import bundle
import canonical
from report import load_report

HERE = pathlib.Path(__file__).parent
VECTORS = HERE / "vectors"
SMALL = VECTORS / "ares-report-suppressed-only.json"
LARGE = VECTORS / "ares-report-sixteen-findings.json"

#: Printed by a fresh interpreter, so nothing from this process leaks in.
_ROOT_SCRIPT = """
import json
from report import load_report
from bundle import build_bundle
doc = build_bundle(load_report({path!r}))
print(doc["tree"]["merkle_root"])
"""


def _root_in_subprocess(report_path: pathlib.Path, env: dict | None = None) -> str:
    result = subprocess.run(
        [sys.executable, "-c", _ROOT_SCRIPT.format(path=str(report_path))],
        cwd=HERE,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    return result.stdout.strip()


class TestCrossProcessStability:
    @pytest.mark.parametrize("source", [SMALL, LARGE], ids=["suppressed-only", "sixteen"])
    def test_root_is_identical_across_five_fresh_processes(self, source):
        """Five real interpreters, five independently-seeded hash tables.

        If leaf ordering ever came from a set or a dict rather than sorted(),
        this is the only test that would notice.
        """
        roots = {_root_in_subprocess(source) for _ in range(5)}
        assert len(roots) == 1, (
            f"merkle_root varied across process runs: {roots} -- something in the "
            f"leaf pipeline is no longer PYTHONHASHSEED-independent"
        )

    def test_root_is_identical_under_five_explicit_hash_seeds(self):
        """Stronger and faster than hoping the OS happens to vary the seed."""
        import os

        roots = set()
        for seed in ("0", "1", "2", "42", "random"):
            env = dict(os.environ)
            env["PYTHONHASHSEED"] = seed
            roots.add(_root_in_subprocess(LARGE, env=env))
        assert len(roots) == 1, f"merkle_root varied with PYTHONHASHSEED: {roots}"

    def test_the_subprocess_root_matches_the_in_process_root(self):
        """Guards against the harness itself being the thing that differs."""
        in_process = bundle.build_bundle(load_report(LARGE))["tree"]["merkle_root"]
        assert _root_in_subprocess(LARGE) == in_process

    def test_bundling_twice_produces_byte_identical_files(self, tmp_path):
        import shutil

        report_path = tmp_path / LARGE.name
        shutil.copyfile(LARGE, report_path)
        first = bundle.write_bundle(report_path, force=True).read_bytes()
        second = bundle.write_bundle(report_path, force=True).read_bytes()
        assert first == second


class TestPlatformIndependence:
    def _rehome(self, tmp_path: pathlib.Path, name: str, prefix: str, sep: str) -> pathlib.Path:
        """Rewrite the fixture's relative paths into an absolute form.

        Rewrites every place a path appears -- target.source_path,
        location.file, AND the title suffix -- because that is exactly the set an
        incomplete normaliser gets wrong.
        """
        data = json.loads(SMALL.read_text(encoding="utf-8"))
        old_root = data["target"]["source_path"].rstrip("/")

        def absolutise(value: str) -> str:
            return (prefix + value).replace("/", sep)

        data["target"]["source_path"] = absolutise(old_root) + sep
        for entry in data["suppressed_findings"]:
            finding = entry["finding"]
            old_file = finding["location"]["file"]
            new_file = absolutise(old_file.replace("\\", "/"))
            # The title ends with the raw location.file (scan.rs:237).
            assert finding["title"].endswith(old_file)
            finding["title"] = finding["title"][: -len(old_file)] + new_file
            finding["location"]["file"] = new_file

        p = tmp_path / name
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return p

    def test_a_windows_written_and_a_linux_written_report_produce_the_same_root(self, tmp_path):
        """The property path normalisation exists for.

        Fails on any implementation that normalises only the PathBuf-typed
        fields, because `title` carries the path too.
        """
        windows = self._rehome(
            tmp_path, "ares-report-win.json", "D:/Github repo/ARES/4R3S/", "\\"
        )
        linux = self._rehome(
            tmp_path, "ares-report-nix.json", "/home/runner/work/4R3S/4R3S/", "/"
        )

        win_doc = bundle.build_bundle(load_report(windows))
        nix_doc = bundle.build_bundle(load_report(linux))

        assert win_doc["tree"]["merkle_root"] == nix_doc["tree"]["merkle_root"]
        # The raw bytes genuinely differ, so this is not a trivially-equal pair.
        assert win_doc["source"]["report_sha256"] != nix_doc["source"]["report_sha256"]

    def test_the_absolute_forms_match_the_original_relative_form(self, tmp_path):
        """Re-homing the target must not change the claim either."""
        original = bundle.build_bundle(load_report(SMALL))["tree"]["merkle_root"]
        windows = self._rehome(tmp_path, "ares-report-w.json", "D:/x/y/", "\\")
        assert bundle.build_bundle(load_report(windows))["tree"]["merkle_root"] == original

    def test_no_machine_path_reaches_a_published_leaf_field(self, tmp_path):
        windows = self._rehome(tmp_path, "ares-report-w.json", "D:/Github repo/ARES/", "\\")
        doc = bundle.build_bundle(load_report(windows))
        for leaf in doc["leaves"]:
            for name, value in leaf["fields"].items():
                if isinstance(value, str):
                    canonical.assert_no_machine_path(name, value)

    def test_an_nfd_and_an_nfc_filename_produce_the_same_root(self, tmp_path):
        """macOS writes decomposed filenames; Windows and Linux composed."""
        roots = set()
        for label, filename in (("nfd", "caf\u0065\u0301.rs"), ("nfc", "caf\u00e9.rs")):
            data = json.loads(SMALL.read_text(encoding="utf-8"))
            root_dir = data["target"]["source_path"]
            for entry in data["suppressed_findings"]:
                finding = entry["finding"]
                old = finding["location"]["file"]
                new = f"{root_dir}{filename}"
                finding["title"] = finding["title"][: -len(old)] + new
                finding["location"]["file"] = new
            p = tmp_path / f"ares-report-{label}.json"
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")
            roots.add(bundle.build_bundle(load_report(p))["tree"]["merkle_root"])
        assert len(roots) == 1


class TestInterpreterIndependence:
    def test_leaf_preimage_bytes_match_a_pinned_hex_literal(self):
        """Interpreter-independent by construction, and that is the point.

        CI pins Python 3.12 while development runs 3.14, and
        docs/SVC-RISK-1-ASSUMPTIONS.md:98-108 records that a local run and a CI
        run are not interchangeable on this repo. Neither environment can
        exercise the other, so a pinned byte string is what makes the two
        comparable at all: if 3.12 and 3.14 ever framed a leaf differently, this
        literal is what would catch it.
        """
        rep = load_report(SMALL)
        entry = rep.data["suppressed_findings"][0]
        fields = canonical.project_finding(
            entry["finding"],
            kind="suppressed",
            target_root=rep.data["target"]["source_path"],
            suppression_reason=entry["reason"],
            suppressed_by=entry["suppressed_by"],
        )
        preimage = canonical.leaf_preimage(fields)
        assert len(preimage) == 581
        assert preimage.hex().startswith(
            # lp("ares.evidence.leaf/1") -- u32be length 20, then the tag
            "00000014" + b"ares.evidence.leaf/1".hex()
        )
        import hashlib

        assert (
            hashlib.sha256(preimage).hexdigest()
            == "9aaf6b839807ff63defb4c0b162a3fab83e695e1ca3f61ac6536e522015be883"
        )

    def test_no_float_is_ever_constructed_from_a_report_number(self):
        """parse_float=str makes the spelling question moot rather than answering it."""
        rep = load_report(SMALL)
        finding = rep.data["suppressed_findings"][0]["finding"]
        assert isinstance(finding["confidence"], str)
        for key in ("line_start", "line_end", "column_start", "column_end"):
            assert finding["location"][key] is None or isinstance(
                finding["location"][key], str
            )
