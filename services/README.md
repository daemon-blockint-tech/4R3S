# services/ — detector & data services (Rust / Python)

Enrichment around the core (P2): `risk` · `cve` · `family` · `evidence`. See `docs/DEVELOPMENT_PLAN.md` §S3.

Status, per service:

| Service | Status |
|---|---|
| `cve` | Built — offline RustSec advisory matching. See `services/cve/README.md`. |
| `risk` | Built — OWASP Risk Rating Methodology scoring + vuln-catalog calibration. See `services/risk/README.md`. |
| `family` | Skeleton. |
| `evidence` | Skeleton. |
