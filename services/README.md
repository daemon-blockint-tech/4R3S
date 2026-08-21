# services/ — detector & data services (Rust / Python)

Enrichment around the core (P2): `risk` · `cve` · `family` · `evidence`. See `docs/DEVELOPMENT_PLAN.md` §S3.

Status, per service:

| Service | Status |
|---|---|
| `cve` | Built — offline RustSec advisory matching. See `services/cve/README.md`. |
| `risk` | Built — OWASP Risk Rating Methodology scoring + vuln-catalog calibration. See `services/risk/README.md`. |
| `family` | Built — winnowing-based clone clustering + fork flag propagation. See `services/family/README.md`. |
| `evidence` | Off-chain half built — Merkle evidence bundling + verifier. The `evidence_registry` Anchor program is **source + host-target spec tests only: never compiled to SBF, never deployed, no cluster anchor exists.** See `services/evidence/README.md`. |
