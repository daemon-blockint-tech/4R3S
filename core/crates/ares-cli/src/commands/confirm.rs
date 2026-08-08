use crate::commands::validate::{run_poc, PocVerdict};
use ares_core::{
    AresConfig, AresError, AresResult, AuditReport, Finding, Severity, ValidationOutcome,
};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Read a scan's report, fork-run each finding's generated PoC, and write
/// confirmed/refuted/inconclusive verdicts + adjusted severity/confidence back
/// onto the findings (POC-2).
///
/// This is a deliberately separate pass from `scan` (GOLDEN RULE #2: the core
/// detection path has no network or randomness). Fork confirmation spawns a
/// `solana-test-validator` and optionally clones live mainnet accounts, so it
/// only ever runs as this explicit, opt-in second step — `scan` itself is
/// untouched. The original `ares-report-<name>.json` is left byte-for-byte
/// intact; this writes a sibling `ares-report-<name>.confirmed.json` so the
/// deterministic artifact and its fork-derived confirmation stay separable.
pub async fn execute(
    scan_output: &Path,
    fork_mainnet: bool,
    fork_slot: Option<u64>,
    config: &AresConfig,
    rpc_url_override: Option<String>,
) -> AresResult<()> {
    info!("ARES Fork Confirmation");
    info!("Scan output: {:?}", scan_output);

    let (report_path, mut report) = load_report(scan_output).await?;
    info!(
        "Loaded report for target: {} ({} findings)",
        report.target.name,
        report.findings.len()
    );

    let project_root = report.target.source_path.clone();

    let mut validator_handle: Option<crate::fork_validator::ForkValidator> = None;
    let local_rpc: Option<String> = if fork_mainnet || config.mainnet_fork_enabled {
        let rpc_url = rpc_url_override
            .or_else(|| config.mainnet_rpc_url.clone())
            .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
        let slot = fork_slot.or(config.mainnet_fork_slot);
        let clone_accounts = config.mainnet_clone_accounts.clone();

        info!(
            "[POC-2] Starting mainnet fork validator | RPC={} | Slot={:?} | Clones={:?}",
            rpc_url, slot, clone_accounts
        );

        let mut builder = crate::fork_validator::ForkValidator::builder(rpc_url)
            .slot(slot)
            .clone_accounts(clone_accounts);

        // Register the real deployed program (now that POC-1 can supply one)
        // so the forked validator's cloned state matches what the PoCs target.
        if let Some(program_id) = report.target.program_id.clone() {
            if let Some(program_so) = find_program_so(&project_root) {
                info!(
                    "Registering program {} ({:?}) with the fork validator",
                    program_id, program_so
                );
                builder = builder.program(program_id, program_so);
            }
        }

        let mut validator = builder.build();
        match validator.start().await {
            Ok(url) => {
                info!("Mainnet fork validator ready at {}", url);
                validator_handle = Some(validator);
                Some(url)
            }
            Err(e) => {
                warn!(
                    "Failed to start fork validator: {}. Continuing without fork.",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    for finding in report.findings.iter_mut() {
        confirm_finding(finding, &project_root, local_rpc.as_deref()).await;
    }

    if let Some(validator) = validator_handle {
        validator.stop().await;
        info!("Fork validator stopped.");
    }

    recompute_severity_counts(&mut report);

    let confirmed_count = count_outcome(&report, ValidationOutcome::Confirmed);
    let refuted_count = count_outcome(&report, ValidationOutcome::Refuted);
    let inconclusive_count = count_outcome(&report, ValidationOutcome::Inconclusive);

    let confirmed_path = confirmed_report_path(&report_path);
    let json = serde_json::to_string_pretty(&report)?;
    tokio::fs::write(&confirmed_path, json).await?;

    info!(
        "Confirmation complete | confirmed={} refuted={} inconclusive={}",
        confirmed_count, refuted_count, inconclusive_count
    );
    info!("Confirmed report written to: {:?}", confirmed_path);

    Ok(())
}

/// Fork-run one finding's PoC (if it has one) and apply the resulting
/// confirmed/refuted/inconclusive verdict, with the accompanying
/// severity/confidence adjustment, directly to the finding.
async fn confirm_finding(finding: &mut Finding, project_root: &Path, local_rpc: Option<&str>) {
    let Some(poc_path) = finding.proof_of_concept.clone() else {
        return;
    };

    if !poc_path.exists() {
        warn!(
            "PoC for finding {} not found on disk ({:?}); marking inconclusive",
            finding.id, poc_path
        );
        finding.validation = Some(ValidationOutcome::Inconclusive);
        return;
    }

    let staged = match stage_poc_for_cargo_test(&poc_path, project_root).await {
        Ok(path) => path,
        Err(e) => {
            warn!(
                "Could not stage PoC for finding {} ({}); marking inconclusive",
                finding.id, e
            );
            finding.validation = Some(ValidationOutcome::Inconclusive);
            return;
        }
    };

    // A PoC the generator could not wire to the target cannot confirm anything.
    // `poc.rs` records that as a leading `// ARES-WIRING:` marker: `unwired` means
    // no IDL instruction matched, so the harness still carries placeholder
    // instruction data (`&[]`) and a `Pubkey::new_unique()` program id — it never
    // invokes the audited program at all. Running it and reading the exit code
    // still yields a verdict, and that verdict was being applied: a finding could
    // be recorded as fork-Confirmed, with confidence forced to 0.95 and its
    // severity upgraded, on the strength of a transaction sent to a random pubkey.
    // The marker was written for exactly this decision and never read.
    let wiring = tokio::fs::read_to_string(&staged.path)
        .await
        .ok()
        .and_then(|src| {
            src.lines()
                .next()
                .and_then(|l| l.strip_prefix("// ARES-WIRING: "))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    if wiring != "wired" {
        warn!(
            "Finding {} INCONCLUSIVE — PoC wiring is `{}`, so the harness does not \
             fully exercise the target program; refusing to read a verdict from it",
            finding.id, wiring
        );
        finding.validation = Some(ValidationOutcome::Inconclusive);
        return;
    }

    match run_poc(&staged.path, project_root, local_rpc).await {
        Ok(PocVerdict::Passed) => {
            info!(
                "Finding {} CONFIRMED (PoC transaction succeeded)",
                finding.id
            );
            apply_confirmed(finding);
        }
        Ok(PocVerdict::Failed) => {
            info!("Finding {} REFUTED (PoC transaction failed)", finding.id);
            apply_refuted(finding);
        }
        Ok(PocVerdict::Inconclusive) => {
            // The harness did not build, or matched no test. Neither outcome is
            // evidence about the finding, so the finding keeps its scan-time
            // severity rather than being upgraded or written off.
            warn!(
                "Finding {} INCONCLUSIVE — the PoC did not run to a verdict",
                finding.id
            );
            finding.validation = Some(ValidationOutcome::Inconclusive);
        }
        Err(e) => {
            warn!(
                "Finding {} inconclusive: PoC could not be run to a verdict ({})",
                finding.id, e
            );
            finding.validation = Some(ValidationOutcome::Inconclusive);
        }
    }
}

/// A PoC harness made visible to `cargo test`, cleaned up when it goes out of
/// scope.
///
/// The copy has to sit inside the audited crate — cargo only builds integration
/// tests it finds under `tests/` — but it must not survive the run. ARES audits
/// somebody else's repository: a harness left in `tests/` references program
/// symbols that repo does not export, so every later `cargo test` there fails to
/// build. That also poisons the rest of our own pass, since a package that does
/// not build emits no `test result:` line and `run_poc` returns `Inconclusive`
/// for every remaining finding. Cleaning up in `Drop` covers the early returns
/// and the panic path, not just the happy one.
struct StagedPoc {
    path: PathBuf,
    /// False for PoCs run from their original location — deleting the user's
    /// own `.ts`/`.sh` file would be destroying input, not cleaning up.
    is_copy: bool,
}

impl Drop for StagedPoc {
    fn drop(&mut self) {
        if self.is_copy {
            if let Err(e) = std::fs::remove_file(&self.path) {
                warn!(
                    "Could not remove staged PoC {:?}: {}. The audited repository \
                     may not build until it is deleted by hand.",
                    self.path, e
                );
            }
        }
    }
}

/// Copy a generated `.rs` PoC harness into the target project's `tests/`
/// directory so `cargo test` compiles and runs it as an integration test.
///
/// `scan` writes generated PoCs to a separate `<output>/poc/` folder for
/// reporting purposes; that folder is outside the target's own Cargo crate,
/// so `cargo test` never sees files sitting there. Non-`.rs` PoCs (`.ts`,
/// `.sh`) are run directly from their original location and returned as-is.
async fn stage_poc_for_cargo_test(poc_path: &Path, project_root: &Path) -> AresResult<StagedPoc> {
    if poc_path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return Ok(StagedPoc {
            path: poc_path.to_path_buf(),
            is_copy: false,
        });
    }

    let tests_dir = project_root.join("tests");
    tokio::fs::create_dir_all(&tests_dir).await?;

    let file_name = poc_path.file_name().ok_or_else(|| {
        AresError::Execution(format!("PoC path has no file name: {:?}", poc_path))
    })?;
    let staged_path = tests_dir.join(file_name);
    tokio::fs::copy(poc_path, &staged_path).await?;
    Ok(StagedPoc {
        path: staged_path,
        is_copy: true,
    })
}

/// Confirmed: the exploit is proven, so confidence gets a high floor and
/// severity is upgraded one tier (capped at Critical) — a confirmed finding is
/// never less serious than the analyzer's initial (possibly speculative) guess.
fn apply_confirmed(finding: &mut Finding) {
    finding.validation = Some(ValidationOutcome::Confirmed);
    finding.confidence = finding.confidence.max(0.95);
    finding.severity = upgrade_severity(finding.severity);
}

/// Refuted: the PoC ran and did not reproduce the finding, so confidence drops
/// sharply and severity is downgraded one tier (floored at Informational).
/// The finding is kept (not moved to `suppressed_findings`) since a failing
/// harness run — unlike an LLM-judged false positive — does not by itself rule
/// out a real issue the generated harness simply didn't exercise correctly.
fn apply_refuted(finding: &mut Finding) {
    finding.validation = Some(ValidationOutcome::Refuted);
    finding.confidence = (finding.confidence * 0.3).min(0.2);
    finding.severity = downgrade_severity(finding.severity);
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Informational => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn severity_from_rank(rank: u8) -> Severity {
    match rank {
        0 => Severity::Informational,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

fn upgrade_severity(s: Severity) -> Severity {
    severity_from_rank((severity_rank(s) + 1).min(4))
}

fn downgrade_severity(s: Severity) -> Severity {
    severity_from_rank(severity_rank(s).saturating_sub(1))
}

/// Recompute the report's severity-count breakdown after confirm/refute may
/// have shifted individual findings' severities. Deliberately does NOT touch
/// `tests_passed`/`tests_failed` — those already carry `scan`'s Trident
/// fuzz-campaign results, and repurposing them for fork-confirmation counts
/// would silently conflate two different signals.
fn recompute_severity_counts(report: &mut AuditReport) {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut informational = 0usize;
    for finding in &report.findings {
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Informational => informational += 1,
        }
    }
    report.summary.critical_count = critical;
    report.summary.high_count = high;
    report.summary.medium_count = medium;
    report.summary.low_count = low;
    report.summary.informational_count = informational;
}

fn count_outcome(report: &AuditReport, outcome: ValidationOutcome) -> usize {
    report
        .findings
        .iter()
        .filter(|f| f.validation == Some(outcome))
        .count()
}

/// Load an `AuditReport` from either a direct JSON file path, or a scan output
/// directory containing an `ares-report-<name>.json` file (mirroring how
/// `commands::report::execute` locates it).
async fn load_report(scan_output: &Path) -> AresResult<(PathBuf, AuditReport)> {
    if scan_output.is_file() {
        let content = tokio::fs::read_to_string(scan_output).await?;
        let report: AuditReport = serde_json::from_str(&content)
            .map_err(|e| AresError::Parse(format!("Failed to parse report: {}", e)))?;
        return Ok((scan_output.to_path_buf(), report));
    }

    // Deterministic pick: newest report = lexicographically greatest filename.
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut entries = tokio::fs::read_dir(scan_output).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("ares-report-") && name_str.ends_with(".json") {
            candidates.push(entry.path());
        }
    }
    candidates.sort();

    if let Some(path) = candidates.pop() {
        let content = tokio::fs::read_to_string(&path).await?;
        let report: AuditReport = serde_json::from_str(&content)
            .map_err(|e| AresError::Parse(format!("Failed to parse report: {}", e)))?;
        return Ok((path, report));
    }

    Err(AresError::NotFound(format!(
        "No ares-report-*.json found in {:?}",
        scan_output
    )))
}

/// Derive the confirmed-report sibling path: `ares-report-<name>.json` ->
/// `ares-report-<name>.confirmed.json`, next to the original.
fn confirmed_report_path(report_path: &Path) -> PathBuf {
    let stem = report_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("ares-report");
    let dir = report_path.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!("{}.confirmed.json", stem))
}

/// Look for a compiled `.so` for the target under its `target/deploy/`
/// directory (the standard Anchor/cargo-build-sbf output location).
fn find_program_so(project_root: &Path) -> Option<PathBuf> {
    let deploy_dir = project_root.join("target/deploy");
    let entries = std::fs::read_dir(&deploy_dir).ok()?;
    // Sort for a deterministic pick when multiple .so files are present.
    let mut so_files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("so"))
        .collect();
    so_files.sort();
    so_files.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::{CodeLocation, ProgramTarget, ReportMetadata, ReportSummary};
    use chrono::Utc;

    fn sample_finding(id: &str, severity: Severity, confidence: f64) -> Finding {
        Finding {
            id: id.to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            severity,
            category: ares_core::VulnerabilityCategory::SignerAuthorization,
            location: CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "r".to_string(),
            references: vec![],
            confidence,
            validation: None,
        }
    }

    fn sample_report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            target: ProgramTarget {
                name: "test-program".to_string(),
                repository_url: None,
                commit_hash: None,
                program_id: None,
                source_path: PathBuf::from("."),
                idl_path: None,
            },
            findings,
            suppressed_findings: vec![],
            metadata: ReportMetadata {
                generated_at: Utc::now(),
                ares_version: "0.1.0".to_string(),
                scan_duration_secs: 1,
                agent_pipeline: vec![],
                tools_used: vec![],
            },
            summary: ReportSummary::default(),
        }
    }

    #[test]
    fn severity_upgrade_and_downgrade_are_inverse_and_capped() {
        assert_eq!(upgrade_severity(Severity::Informational), Severity::Low);
        assert_eq!(upgrade_severity(Severity::Critical), Severity::Critical); // capped
        assert_eq!(downgrade_severity(Severity::Critical), Severity::High);
        assert_eq!(
            downgrade_severity(Severity::Informational),
            Severity::Informational
        ); // floored
    }

    #[test]
    fn apply_confirmed_raises_confidence_and_severity() {
        let mut f = sample_finding("F-1", Severity::Medium, 0.5);
        apply_confirmed(&mut f);
        assert_eq!(f.validation, Some(ValidationOutcome::Confirmed));
        assert_eq!(f.severity, Severity::High);
        assert!(f.confidence >= 0.95);
    }

    #[test]
    fn apply_confirmed_never_lowers_high_confidence() {
        let mut f = sample_finding("F-1", Severity::Low, 0.99);
        apply_confirmed(&mut f);
        assert!(f.confidence >= 0.99);
    }

    #[test]
    fn apply_refuted_lowers_confidence_and_severity() {
        let mut f = sample_finding("F-2", Severity::High, 0.9);
        apply_refuted(&mut f);
        assert_eq!(f.validation, Some(ValidationOutcome::Refuted));
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.confidence <= 0.2);
    }

    #[test]
    fn inconclusive_leaves_finding_otherwise_unchanged() {
        let mut f = sample_finding("F-3", Severity::High, 0.7);
        f.validation = Some(ValidationOutcome::Inconclusive);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, 0.7);
    }

    #[test]
    fn recompute_severity_counts_matches_findings() {
        let mut report = sample_report(vec![
            sample_finding("F-1", Severity::Critical, 0.9),
            sample_finding("F-2", Severity::Critical, 0.9),
            sample_finding("F-3", Severity::Low, 0.5),
        ]);
        recompute_severity_counts(&mut report);
        assert_eq!(report.summary.critical_count, 2);
        assert_eq!(report.summary.low_count, 1);
        assert_eq!(report.summary.high_count, 0);
    }

    #[test]
    fn count_outcome_filters_by_validation_field() {
        let mut a = sample_finding("F-1", Severity::High, 0.9);
        a.validation = Some(ValidationOutcome::Confirmed);
        let mut b = sample_finding("F-2", Severity::Low, 0.1);
        b.validation = Some(ValidationOutcome::Refuted);
        let c = sample_finding("F-3", Severity::Medium, 0.5); // None
        let report = sample_report(vec![a, b, c]);

        assert_eq!(count_outcome(&report, ValidationOutcome::Confirmed), 1);
        assert_eq!(count_outcome(&report, ValidationOutcome::Refuted), 1);
        assert_eq!(count_outcome(&report, ValidationOutcome::Inconclusive), 0);
    }

    #[test]
    fn confirmed_report_path_appends_confirmed_suffix() {
        let path = Path::new("/out/ares-report-myprog.json");
        assert_eq!(
            confirmed_report_path(path),
            PathBuf::from("/out/ares-report-myprog.confirmed.json")
        );
    }

    #[tokio::test]
    async fn stage_poc_for_cargo_test_copies_rs_into_tests_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let poc_dir = dir.path().join("output/poc");
        std::fs::create_dir_all(&poc_dir).unwrap();
        let poc_path = poc_dir.join("f1_test.rs");
        std::fs::write(&poc_path, "// poc content").unwrap();

        let staged = stage_poc_for_cargo_test(&poc_path, dir.path())
            .await
            .unwrap();
        assert_eq!(staged.path, dir.path().join("tests/f1_test.rs"));
        assert!(staged.path.exists());
        assert_eq!(
            std::fs::read_to_string(&staged.path).unwrap(),
            "// poc content"
        );
    }

    #[tokio::test]
    async fn staged_poc_is_removed_from_the_audited_repo_when_dropped() {
        // ARES audits somebody else's checkout. A harness left behind in their
        // `tests/` directory references symbols their crate does not export, so
        // `cargo test` there stops building — we would break a customer's build
        // and walk away. It also poisons our own pass: a package that will not
        // build prints no `test result:`, so every later finding in the same
        // repo degrades to Inconclusive.
        let dir = tempfile::TempDir::new().unwrap();
        let poc_dir = dir.path().join("output/poc");
        std::fs::create_dir_all(&poc_dir).unwrap();
        let poc_path = poc_dir.join("f1_test.rs");
        std::fs::write(&poc_path, "// poc content").unwrap();

        let staged_path = {
            let staged = stage_poc_for_cargo_test(&poc_path, dir.path())
                .await
                .unwrap();
            assert!(staged.path.exists());
            staged.path.clone()
        };

        assert!(
            !staged_path.exists(),
            "staged PoC survived the run and will break the audited repo's build"
        );
        // The generator's own copy is input, not our artifact.
        assert!(poc_path.exists());
    }

    #[tokio::test]
    async fn dropping_a_non_copied_poc_does_not_delete_the_users_file() {
        // `.ts`/`.sh` PoCs run from where they already live. Deleting one on
        // drop would destroy input rather than clean up after ourselves.
        let dir = tempfile::TempDir::new().unwrap();
        let poc_path = dir.path().join("exploit.sh");
        std::fs::write(&poc_path, "#!/bin/sh\nexit 0\n").unwrap();

        drop(
            stage_poc_for_cargo_test(&poc_path, dir.path())
                .await
                .unwrap(),
        );
        assert!(poc_path.exists());
    }

    #[tokio::test]
    async fn stage_poc_for_cargo_test_leaves_non_rs_in_place() {
        let dir = tempfile::TempDir::new().unwrap();
        let poc_path = dir.path().join("exploit.sh");
        std::fs::write(&poc_path, "#!/bin/sh\nexit 0\n").unwrap();

        let staged = stage_poc_for_cargo_test(&poc_path, dir.path())
            .await
            .unwrap();
        assert_eq!(staged.path, poc_path);
    }

    #[tokio::test]
    async fn load_report_reads_direct_file_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let report = sample_report(vec![sample_finding("F-1", Severity::High, 0.9)]);
        let path = dir.path().join("ares-report-x.json");
        tokio::fs::write(&path, serde_json::to_string(&report).unwrap())
            .await
            .unwrap();

        let (loaded_path, loaded) = load_report(&path).await.unwrap();
        assert_eq!(loaded_path, path);
        assert_eq!(loaded.target.name, "test-program");
    }

    #[tokio::test]
    async fn load_report_finds_report_in_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let report = sample_report(vec![]);
        let path = dir.path().join("ares-report-x.json");
        tokio::fs::write(&path, serde_json::to_string(&report).unwrap())
            .await
            .unwrap();

        let (loaded_path, _) = load_report(dir.path()).await.unwrap();
        assert_eq!(loaded_path, path);
    }

    #[tokio::test]
    async fn load_report_errors_when_no_report_present() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = load_report(dir.path()).await;
        assert!(result.is_err());
    }
}
