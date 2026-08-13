# services/risk — OWASP-methodology risk scoring + catalog calibration

Scores a risk (likelihood factors + impact factors) using the **OWASP Risk
Rating Methodology**, and separately calibrates
`src/knowledge/vuln-catalog.generated.json`'s static `defaultSeverity`
values against what that methodology would assign per category. Exposed
via `POST /risk/score` and `GET /risk/calibration` in `apps/auditor-api`.

Deterministic by construction: no LLM, no network — plain averaging and
table lookups against the methodology's own published tables. See
"Hermetic by default" in [`SECURITY.md`](../../SECURITY.md).

## Why OWASP, and what "port" meant here

The task card ("Port risk-scoring engine; recalibrate to canonical
catalog") named no source to port from — there is no numeric risk-scoring
engine anywhere in this repo. The reading used: implement a **named,
citable, external methodology** exactly the way `services/cve/severity.py`
implements the CVSS v3.1 spec, rather than inventing a formula. OWASP's
methodology is the standard fit for "risk scoring" as distinct from
"vulnerability scoring" (CVSS) — it scores likelihood and impact from
threat-agent/vulnerability/business factors, not just a vulnerability's
intrinsic properties. Full reasoning: `docs/SVC-RISK-1-ASSUMPTIONS.md`.

## Scope

- **`risk_score.py`** implements only the methodology's arithmetic:
  average 8 likelihood sub-factors, average 4 impact sub-factors (business
  impact if fully supplied, else technical impact), map each average to
  LOW/MEDIUM/HIGH, combine via OWASP's own 3×3 matrix. It does not infer
  factor values from anything — a caller (human analyst, or
  `catalog_calibration.py`'s per-category template) supplies them.
- Factor scores are validated strictly against OWASP's own enumerated
  options per factor (e.g. Motive is one of `{1, 4, 9}`) — the page
  instructs analysts to "select one of the options associated with each
  factor," so an out-of-table value is rejected, not coerced or clamped.
- **`catalog_calibration.py`** applies one documented `RiskVector`
  *template* per catalog category (13 categories cover the catalog's 34
  entries) and diffs the resulting severity against each entry's
  `defaultSeverity`. Category-level, not entry-level: a category's
  threat-agent/vulnerability profile is a real judgment call, and a bug
  class's *reachability* doesn't vary entry-by-entry the way its business
  impact would.

## Modules

| File | Responsibility |
|---|---|
| `factors.py` | OWASP's Threat Agent / Vulnerability / Technical Impact / Business Impact factor tables, copied verbatim from the methodology page. |
| `risk_score.py` | `RiskVector` (caller-supplied factor scores) → `ScoredRisk` (likelihood/impact levels + OWASP severity, remapped to ARES's `info`/`low`/`medium`/`high`/`critical`). |
| `catalog_calibration.py` | Loads `vuln-catalog.generated.json`, applies `CATEGORY_RISK_TEMPLATES`, returns a `CalibrationReport` of matches/mismatches. |

## A known discrepancy in the source material, documented rather than papered over

OWASP's own published worked example on the methodology page uses three
factor values (`Motive=2`, `Size=1`, `Intrusion detection=2`) that are not
among that same page's enumerated options for those factors (`Motive` only
defines `{1, 4, 9}`, etc.) — confirmed via two independent fetches of the
page, not a transcription error on this end. `test_risk_score.py`'s
`TestOwaspWorkedExampleArithmetic` documents this and reproduces the
example's stated *averages* and final severity directly, rather than
silently substituting different numbers to make the example fit and
calling that a reproduction of the source.

## Business impact is intentionally excluded from catalog calibration

`CATEGORY_RISK_TEMPLATES` in `catalog_calibration.py` supplies only
likelihood + technical-impact factors, never business-impact factors.
Financial/reputation/compliance/privacy magnitude depends on a specific
protocol's TVL and user base — a generic vulnerability category can't know
that, and guessing it would be exactly the "trust-me number" this repo's
GOLDEN RULE 3 forbids. This means calibration severity is a **technical**
risk assessment, not a full business risk assessment; see the module
docstring and `docs/SVC-RISK-1-ASSUMPTIONS.md`.

## The impact axis does not discriminate — read the calibration accordingly

**The single most important caveat on this service's output.** Two of
OWASP's four technical-impact factors are pinned across every category
template, because they are properties of the Solana execution environment
rather than of any one bug class:

- `loss_of_confidentiality = 2` — all on-chain account data is already
  world-readable, so a program bug almost never *causes* a confidentiality
  loss.
- `loss_of_accountability = 7` — on-chain actions are permanently
  attributable to a pubkey, but a pubkey is pseudonymous and freshly
  generated per attack.

With two of four factors fixed, the impact average is structurally
compressed into `[4.25, 5.75]` and **every one of the 34 catalog entries
lands in the MEDIUM impact band.** The impact axis therefore does no
discriminating work at all: calibration severity is effectively a
*likelihood ranking*. `test_catalog_calibration.py::test_the_impact_axis_currently_does_no_discriminating_work`
pins this so it can't quietly be assumed otherwise; if a future template
change makes impact meaningful, that test fails and should be deleted.

This is a genuine limitation of applying OWASP's generic impact model to
this domain, disclosed rather than tuned around — the fix is not to inflate
factor values until the range spreads.

## Today's real divergence (a snapshot, not a target)

Running calibration against the committed catalog today: **34 entries, 18
match the OWASP-methodology severity, 16 don't** (10 computed hotter than
the catalog, 6 cooler). `test_catalog_calibration.py` pins these counts so
a future catalog edit that silently drifts fails CI instead of passing
quietly.

The two starkest mismatches — `account-close-revival` (catalog: critical,
computed: medium) and `arbitrary-cpi` (catalog: critical, computed: high)
— are worth a human look: both suggest the category-level template
underweights an entry whose *specific* mechanism (full state wipe;
arbitrary program control) is more severe than its category's general
profile. That is the expected failure mode of category-grain templates,
not evidence the catalog is wrong.

### The `pda` category turns on a single factor choice

`pda` scores likelihood **5.875**, just 0.125 under the MEDIUM/HIGH
threshold of 6.0 — the most boundary-fragile template in the set. Had
`intrusion_detection` been left at 9 ("Not logged") it would score exactly
**6.000** and flip to HIGH, changing three entries' computed severity. It
is 8 ("Logged without review") because *every Solana transaction is
permanently recorded in the public ledger* — 9 is not merely pessimistic
there, it is impossible. Pinned by
`test_pda_sits_close_to_a_band_boundary`.

## What this does not do

- **Does not edit `solana-vulns.ts`'s `defaultSeverity` values.**
  Mismatches are reported via `/risk/calibration` and asserted in tests;
  changing a catalog default changes every audit that falls back to it
  (`resolveSeverity` in `src/graph/util.ts`) — a human editorial call, not
  something this task autopilots. See `docs/SVC-RISK-1-ASSUMPTIONS.md`.
- **No wiring into the TS audit graph.** `/risk/score` and
  `/risk/calibration` are standalone endpoints today, same posture as
  `/cve/scan`.
- **No automatic factor inference.** Nothing derives "ease of exploit"
  from static-analysis signals — factors are supplied explicitly or come
  from the fixed per-category template.
