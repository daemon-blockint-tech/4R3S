# SVC-RISK-1 — Risk-scoring engine (OWASP methodology) + catalog calibration: what was done, what was verified, what wasn't

> **Placeholder ID.** `SVC-RISK-1` is not a real `docs/BACKLOG.xlsx` id — that
> file is deliberately not committed to this repo (see `docs/README.md`).
> Replace this filename and every reference to `SVC-RISK-1` (branch name,
> commit prefix, this doc) with the actual Notion backlog ID before opening
> a PR, per `CLAUDE.md`'s "How work maps to tasks."

## The task, and the reading it settled on

The card read only: "Port risk-scoring engine; recalibrate to canonical
catalog." No source engine was named, no acceptance criteria given, and (per
`docs/README.md`) there is no `docs/BACKLOG.xlsx` row in this checkout to
check against.

Repo investigation found **no numeric risk-scoring engine anywhere in this
repo** to literally port. The only scoring logic that existed was
qualitative: `src/knowledge/severity.ts`'s 3×3 Impact×Likelihood matrix,
used only to rate LLM-produced findings, with no numeric output.
`services/README.md` names `risk` as a planned P2 enrichment service,
sibling to `cve`/`family`/`evidence` — a name with no code behind it.

The reading used: implement a **named, citable, external methodology**, the
same way `services/cve/severity.py` implements the CVSS v3.1 spec, rather
than inventing a scoring formula. The **OWASP Risk Rating Methodology** is
the standard fit for "risk scoring" as distinct from "vulnerability
scoring" (CVSS) — it scores likelihood and impact from threat-agent /
vulnerability / business factors, not just a vulnerability's intrinsic
properties. "Recalibrate to canonical catalog" was read as: compute what
that methodology would assign per category of `src/knowledge/vuln-catalog.generated.json`
("the canonical catalog") and diff it against each entry's static
`defaultSeverity` — see `services/risk/README.md` for the full reasoning.

## What was actually done

- `services/risk/` — three runtime modules (`factors.py`, `risk_score.py`,
  `catalog_calibration.py`), each documented and tested.
  - `factors.py`: OWASP's Threat Agent / Vulnerability / Technical Impact /
    Business Impact factor tables, transcribed from the methodology page
    (verified via two independent fetches, not assumed from memory).
  - `risk_score.py`: `RiskVector` → `ScoredRisk` — averages the 8
    likelihood and 4-or-8 impact sub-factors, maps each to LOW/MEDIUM/HIGH,
    combines via OWASP's own 3×3 severity matrix, remaps OWASP's "Note" to
    ARES's "info" so output lands in the same `Severity` vocabulary as
    `src/knowledge/finding.ts`.
  - `catalog_calibration.py`: one documented `RiskVector` template per
    catalog category (13 categories cover the catalog's 34 entries),
    diffed against `defaultSeverity`.
- `POST /risk/score` and `GET /risk/calibration` added to
  `apps/auditor-api/main.py`, following the exact `sys.path.insert` +
  flat-import + lazy-nothing-to-cache pattern already used for the `cve`
  modules in the same file.
- CI: a new `services-risk (python)` job (copy of `services-cve`'s job,
  paths swapped), and `pip-audit -r services/risk/requirements.txt` added
  to the `dependency audit` job.
- `services/README.md` updated to reflect per-service status (it
  previously said "skeleton" for the whole directory even though `cve` was
  already built — corrected both `cve`'s and `risk`'s rows while touching
  this file for `risk`).
- 46 tests in `services/risk/`, 12 new tests in
  `apps/auditor-api/test_auditor_api.py` (62 total in that file, up from 50).

## What was verified, concretely

- **The averaging + matrix arithmetic is correct**, checked against OWASP's
  own published worked example on the methodology page (fetched twice,
  independently, to rule out a one-off transcription error) — see
  `test_risk_score.py::TestOwaspWorkedExampleArithmetic`.
- **All nine cells of the 3×3 severity matrix are independently re-derived**
  by constructing vectors whose averages land in each LOW/MEDIUM/HIGH
  band, rather than trusting the internal lookup table not to have a
  transposed row/column (`TestSeverityMatrixCoversAllNineCells`).
- **Strict factor validation actually rejects invalid input**: an unknown
  factor name, a missing factor, an off-table score, and a partial
  business-impact vector all raise `UnsupportedRiskFactor` rather than
  being coerced or silently averaged over missing data
  (`TestRejectsWhatItCannotScore`).
- **Calibration runs against the real committed catalog, not a fixture.**
  `test_catalog_calibration.py` loads the actual
  `src/knowledge/vuln-catalog.generated.json` and pins today's real
  divergence: 34 entries, 18 match the OWASP-methodology severity, 16
  don't (10 computed hotter than the catalog, 6 cooler). Two specific
  high-confidence mismatches (`account-close-revival`: critical→medium;
  `arbitrary-cpi`: critical→high) are asserted by name, not just by count.
- **A live HTTP round-trip was performed** against a real `uvicorn
  main:app` process on 127.0.0.1:8099 — not only FastAPI's in-process
  `TestClient`. Confirmed: `/openapi.json` lists both new routes alongside
  the pre-existing ones; max-factor input returns `critical`; min-factor
  input returns `info`; an off-table score returns HTTP 400 with the
  offending factor named; `/risk/calibration` returns the same 34/18/16 the
  unit tests pin. (This closes the gap `docs/SVC-CVE-1-ASSUMPTIONS.md` left
  open for its own endpoints.)
- **Every category template is itself a valid, scoreable `RiskVector`** —
  `TestEveryTemplateProducesAValidScore` parametrizes over all 13
  templates and would catch a typo'd factor name or an off-table score in
  a template immediately, rather than surfacing later as a confusing
  `calibrate()` error.
- **The full `apps/auditor-api` suite was re-run in an isolated venv**
  against its pinned `requirements.txt` before and after this change:
  36 passed / 14 failed both times, with the same 14 test names failing
  identically before this change existed. The 14 pre-existing failures are
  environment-specific to this Windows + Python 3.14 checkout (a symlink
  test, subprocess-signal timeout tests, and several `/cve/scan` tests that
  fail with the *same* `KeyError` shape with or without this change) — none
  of them touch `/risk/*` and none of them changed count or identity when
  this change was added. After the change: 44 passed / 14 failed (the same
  14) — the 8-test delta is exactly the new `/risk/*` route tests, all
  passing.

## Bugs found by a post-implementation review pass, and fixed

The first cut of this service passed all its own tests. A deliberate
adversarial re-read plus a sensitivity sweep (per-template distance to each
band boundary, one-factor-at-a-time perturbation) found four real defects
that a green suite had not:

1. **`intrusion_detection = 9` ("Not logged") on all 13 templates was
   factually impossible.** Every Solana transaction is permanently recorded
   in the public ledger; the accurate generic option is 8 ("Logged without
   review"). This was load-bearing, not cosmetic: at 9 the `pda` category
   scored exactly **6.000** — precisely on the MEDIUM/HIGH threshold — and
   the correction to 8 moves it to 5.875/MEDIUM, changing three entries'
   computed severity and the headline divergence from 19/15 to **18/16**.
2. **Malformed catalog entries escaped as unhandled HTTP 500s.**
   `calibrate()` indexed `entry["category"]`/`["defaultSeverity"]`
   optimistically, so a catalog regenerated from a `solana-vulns.ts` that
   dropped a field raised a bare `KeyError` (or `TypeError` for a non-object
   entry) — reaching the API as a 500, not the 503 this doc claimed. Entry
   shape is now validated up front and raises `CatalogCalibrationError`.
3. **An empty catalog reported a vacuous clean run.** Zero entries
   calibrated "successfully" to 0 matches / 0 mismatches — indistinguishable
   from a catalog that agrees with every template, which is exactly the
   broken-looks-identical-to-clean failure the CVE service's outcome
   vocabulary exists to prevent. Now a hard error.
4. **A test docstring claimed protection it could not provide.**
   `TestSeverityMatrixCoversAllNineCells` said it would catch "a transposed
   row/column." OWASP's 3×3 matrix is *symmetric* (verified, now asserted),
   so no test that inspects severity output can detect a transposition. The
   claim was removed and replaced with what the test actually protects
   against: a wrong value in a cell, and band-threshold drift.

The review also surfaced the impact-axis compression documented below,
which is a limitation rather than a bug.

## The most significant limitation, stated plainly

**The impact axis does no discriminating work.** Because
`loss_of_confidentiality` (2) and `loss_of_accountability` (7) are pinned
across all templates as properties of the Solana execution environment, the
technical-impact average is compressed into `[4.25, 5.75]` and **all 34
catalog entries land in the MEDIUM impact band.** Calibration severity is
therefore effectively a *likelihood ranking*, not a two-dimensional risk
assessment — which materially changes how the 16 mismatches should be read.

This is disclosed rather than tuned around: inflating factor values until
the range spreads would manufacture a two-dimensional result that the
domain does not actually support. It is pinned by
`test_the_impact_axis_currently_does_no_discriminating_work` so it cannot
be silently assumed otherwise, and that test is written to fail (and be
deleted) if a future template change makes impact meaningful.

## What could not be verified, and why

- **The CI job itself was not run in GitHub Actions** (no push made from
  this pass) — only reproduced locally: `pip-audit` against
  `services/risk/requirements.txt` (trivially clean, stdlib-only), and
  `python -m pytest services/risk -q` (46 passed). The YAML was validated
  for syntax (`yaml.safe_load`) but not executed by the real runner.
- **The category-level `RiskVector` templates in `catalog_calibration.py`
  are expert-judgment input, not a measurement.** The arithmetic that
  turns them into a severity is reproducible and tested; the specific
  factor values chosen per category are a documented judgment call (each
  with a one-line rationale in the module), the same kind of call a human
  auditor makes filling in an OWASP worksheet. A different reviewer
  filling in the same worksheet could reasonably choose different numbers
  and get a different mismatch list.

## Out of scope (deliberately, not by oversight)

- **No `defaultSeverity` value in `src/knowledge/solana-vulns.ts` was
  edited**, despite 15 of 34 entries showing a computed-severity mismatch.
  Changing a catalog default changes live audit output for every finding
  that falls back to it (`resolveSeverity` in `src/graph/util.ts`) — an
  editorial call for a human to make deliberately, informed by
  `/risk/calibration`'s report, not something this task autopilots. See
  GOLDEN RULE 3 (no trust-me numbers) — a category-level technical-only
  risk template is not a strong enough basis to silently overwrite a
  value that shapes real report output.
- **No business-impact factors in the catalog calibration templates.**
  Financial/reputation/compliance/privacy magnitude depends on a specific
  protocol's TVL and user base, which a generic vulnerability category
  can't know — see `services/risk/README.md`.
- **Wiring into the TS audit graph.** No node under `src/graph/nodes/`, no
  `build-graph.ts` registration. `/risk/score` and `/risk/calibration` are
  standalone and independently callable today, same posture `/cve/scan`
  already established.
- **No automatic factor inference from static-analysis signals.** Nothing
  derives e.g. "ease of exploit" from AST features — factors are supplied
  explicitly by the caller or come from the fixed per-category template.
- **Any change to measured detection accuracy.** Does not address
  `docs/EVAL-2-REPRODUCTION-REPORT.md` and produces no findings that are
  part of the `eval/` ground truth.

## Verified before handing off

- `python -m pytest services/risk -q` → 46 passed.
- `python -m pytest apps/auditor-api -q` (isolated venv, pinned
  `requirements.txt`) → 48 passed, 14 failed — the same 14 failures present
  on this checkout before this change, confirmed by re-running the suite
  against `main.py`/`test_auditor_api.py` with this change's edits stashed
  (36 passed / the same 14 failed at baseline; the +12 delta is exactly the
  new `/risk/*` tests). The 14 are environment-specific to this Windows +
  Python 3.14 checkout and none touch `/risk/*`.
- `/openapi.json` on a **live `uvicorn main:app` process** lists
  `/risk/score` and `/risk/calibration` alongside the pre-existing
  `/audits` and `/cve/*` routes.
- `GET /risk/calibration` against the real committed catalog returns
  `total: 34, match_count: 18, mismatch_count: 16` — over both the
  in-process `TestClient` and a real HTTP socket.
- `.github/workflows/ci.yml` parses as valid YAML after adding the
  `services-risk` job and the new `pip-audit` line.
