use ares_core::{
    AresConfig, AresResult, AuditReport, Finding, ProgramTarget, ReportMetadata, ReportSummary,
    Severity, VulnerabilityCategory,
};
use ares_mapper::MapperAgent;
use ares_policy::PolicyEngine;
use ares_trident::{check_trident_installation, TridentTool};
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{info, warn};

/// Execute a full security scan on a Solana program.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    program_path: &Path,
    config: &AresConfig,
    _target: Option<String>,
    full_pipeline: bool,
    fuzz: bool,
    poc: bool,
    max_duration: u64,
    output: &Path,
) -> AresResult<()> {
    let scan_start = Instant::now();
    info!("=========================================");
    info!("ARES V3 Security Scan");
    info!("Target: {:?}", program_path);
    info!(
        "Full Pipeline: {} | Fuzz: {} | PoC: {}",
        full_pipeline, fuzz, poc
    );
    info!("Max Duration: {}s", max_duration);
    info!("=========================================");

    // Phase 1: Policy check — ensure we are scanning allowed targets only
    let policy = PolicyEngine::new(config.policy_file.as_deref())?;
    policy.check_scan_permission(program_path)?;
    info!(
        "Policy check passed: scan authorized for {:?}",
        program_path
    );

    // Verify Trident is available
    let trident_version = check_trident_installation().await?;
    info!("Trident version: {}", trident_version);

    // Phase 1: Initialize program target
    let target_name = program_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let program_idl = find_idl_file(program_path);
    let commit_hash = get_git_commit_hash(program_path).await?;

    let program_target = ProgramTarget {
        name: target_name.clone(),
        repository_url: None,
        commit_hash,
        program_id: None,
        source_path: program_path.to_path_buf(),
        idl_path: program_idl,
    };

    info!("Program target initialized: {}", program_target.name);

    // Phase 1: Mapper Agent — map program structure, accounts, instructions
    info!("[1/5] Mapper Agent: Analyzing program structure...");
    let mut mapper = MapperAgent::new(program_path);
    let program_graph = mapper.analyze().await?;
    info!(
        "Program graph: {} modules, {} instructions, {} accounts",
        program_graph.modules.len(),
        program_graph.instructions.len(),
        program_graph.accounts.len()
    );

    // Phase 1: Static analysis + Hypothesis generation
    info!("[2/5] Hypothesis Generator: Identifying potential vulnerability patterns...");
    let hypotheses = generate_initial_hypotheses(&program_graph);
    info!("Generated {} vulnerability hypotheses", hypotheses.len());

    // Initialize Trident tool
    let trident = TridentTool::new(config.trident_path.as_deref())?;
    let trident = trident.with_working_dir(program_path.to_path_buf());

    // Phase 1: Fuzzing with Trident (if enabled)
    let mut findings: Vec<Finding> = Vec::new();
    let mut tests_passed = 0usize;
    let mut tests_failed = 0usize;

    // Phase 3: Cross-instruction data-flow analysis (after findings vec is initialized)
    info!("[2b/5] Cross-Instruction Analyzer: Checking TOCTOU, re-validation gaps...");
    let cross_findings = ares_mapper::cross_analysis::analyze(&program_graph)?;
    info!(
        "Cross-instruction analysis: {} findings",
        cross_findings.len()
    );

    for cf in cross_findings {
        let category = VulnerabilityCategory::from_str_checked(&cf.category)
            .unwrap_or(VulnerabilityCategory::InvariantViolation);
        let severity = if matches!(category, VulnerabilityCategory::ReentrancyRisk) {
            ares_core::Severity::Critical
        } else {
            ares_core::Severity::High
        };
        findings.push(ares_core::Finding {
            id: format!("ARES-CROSS-{}", findings.len() + 1),
            title: format!("{}: {}", cf.category, cf.affected_account),
            description: cf.description,
            severity,
            category,
            location: ares_core::CodeLocation {
                file: program_target.source_path.clone(),
                function: Some(cf.source_instruction),
                ..Default::default()
            },
            proof_of_concept: None,
            recommendation: "Review account validation across instruction boundaries. Ensure state transitions are re-validated.".to_string(),
            references: vec![],
            confidence: cf.confidence,
        });
    }

    if fuzz {
        info!("[3/5] Fuzzer Orchestrator: Running Trident fuzz campaign...");

        // Check if trident tests exist, otherwise initialize
        let fuzz_tests_dir = program_path.join("trident-tests");
        if !fuzz_tests_dir.exists() {
            info!("No trident-tests found. Initializing fuzz tests...");
            trident.init_fuzz_tests().await?;
        }

        // Run fuzz on available test targets
        let fuzz_targets = discover_fuzz_targets(&fuzz_tests_dir).await?;
        info!("Discovered {} fuzz targets", fuzz_targets.len());

        for target_name in fuzz_targets {
            info!("Fuzzing target: {}", target_name);
            let fuzz_result = trident
                .fuzz_run(&target_name, config.max_fuzz_iterations, max_duration)
                .await?;

            if !fuzz_result.success {
                tests_failed += 1;
                for crash in &fuzz_result.crashes {
                    findings.push(Finding {
                        id: format!("ARES-FUZZ-{}", findings.len() + 1),
                        title: format!("Crash in fuzz target '{}'", target_name),
                        description: crash.clone(),
                        severity: Severity::High,
                        category: VulnerabilityCategory::FuzzingCrash,
                        location: Default::default(),
                        proof_of_concept: None,
                        recommendation: "Investigate crash reproduction and root cause analysis."
                            .to_string(),
                        references: vec![],
                        confidence: 0.85,
                    });
                }
                for violation in &fuzz_result.invariant_violations {
                    findings.push(Finding {
                        id: format!("ARES-INV-{}", findings.len() + 1),
                        title: format!("Invariant violation in target '{}'", target_name),
                        description: violation.clone(),
                        severity: Severity::Critical,
                        category: VulnerabilityCategory::InvariantViolation,
                        location: Default::default(),
                        proof_of_concept: None,
                        recommendation: "Review state transition invariants and access controls."
                            .to_string(),
                        references: vec![],
                        confidence: 0.90,
                    });
                }
            } else {
                tests_passed += 1;
                info!("Fuzz target '{}' passed without crashes", target_name);
            }
        }
    } else {
        info!("Fuzzing disabled. Skipping Trident fuzz campaign.");
    }

    // Phase 2: Executable PoC generation using category-specific BanksClient harnesses
    if poc {
        info!("[4/5] Exploit Constructor: Generating proof-of-concept tests...");
        for finding in findings.iter_mut() {
            let poc_path = output.join("poc").join(format!(
                "{}_test.rs",
                finding.id.to_lowercase().replace("-", "_")
            ));
            let poc_code = crate::poc::PocGenerator::generate(finding, &program_target.name);
            tokio::fs::write(&poc_path, poc_code).await?;
            finding.proof_of_concept = Some(poc_path);
            info!("Generated PoC harness: {:?}", finding.proof_of_concept);
        }
    }

    // Phase 3: Semantic false-positive validation (Old validator)
    info!("[4.5/5] Semantic Validator: Suppressing structurally implausible findings...");
    let pre_validation_count = findings.len();
    let validator = crate::validator::SemanticValidator::new(&program_graph);
    findings = validator.validate(findings);
    let suppressed_count = pre_validation_count - findings.len();
    if suppressed_count > 0 {
        info!(
            "Semantic FP filter suppressed {} findings",
            suppressed_count
        );
    }

    // Phase 4: Deterministic Local Judge
    info!("[4.6/5] Local Judge: Deterministic false-positive suppression...");
    let local_judge = ares_mapper::local_judge::LocalJudge::new(config.judge_extended);
    let (retained_findings, mut suppressed_findings) =
        local_judge.judge(findings, &program_graph.source_patterns);
    findings = retained_findings;

    // Phase 7: LLM-as-Judge validation
    info!("[4.75/5] LLM-as-Judge: Assessing vulnerability plausibility...");
    let llm_judge = crate::llm_judge::LlmJudge::new(&program_graph, config);
    let llm_results = llm_judge.validate(findings).await;
    let llm_suppressed = llm_results.iter().filter(|r| r.suppressed).count();
    if llm_suppressed > 0 {
        info!("LLM-as-Judge suppressed {} findings", llm_suppressed);
    }

    // Convert LLM suppressed findings to SuppressedFinding
    for r in &llm_results {
        if r.suppressed {
            suppressed_findings.push(ares_core::SuppressedFinding {
                finding: r.finding.clone(),
                reason: r.reasoning.clone(),
                suppressed_by: "llm_judge".to_string(),
            });
        }
    }

    findings = crate::llm_judge::extract_findings(llm_results);

    // Phase 1: Triager (basic confidence filtering)
    info!("[5/5] Triager: Filtering findings by confidence threshold...");
    let confidence_threshold = 0.70;
    let initial_count = findings.len();

    let mut final_findings = Vec::new();
    for f in findings {
        if f.confidence >= confidence_threshold {
            final_findings.push(f);
        } else {
            suppressed_findings.push(ares_core::SuppressedFinding {
                finding: f,
                reason: "Confidence below threshold".to_string(),
                suppressed_by: "triager".to_string(),
            });
        }
    }
    findings = final_findings;

    let filtered_count = initial_count - findings.len();
    if filtered_count > 0 {
        info!("Filtered out {} low-confidence findings", filtered_count);
    }

    // Phase 4: Economic exploit scoring
    info!("[5.5/5] Exploit Scorer: Estimating extractable economic impact...");
    let (total_economic_impact, max_single_exploit) =
        crate::scorer::ExploitScorer::score_report(&findings);

    // Generate report with real measurements
    let elapsed_secs = scan_start.elapsed().as_secs();
    let summary = ReportSummary {
        total_findings: findings.len(),
        critical_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count(),
        high_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count(),
        medium_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count(),
        low_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count(),
        informational_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Informational))
            .count(),
        false_positives_suppressed: filtered_count,
        poc_generated: findings
            .iter()
            .filter(|f| f.proof_of_concept.is_some())
            .count(),
        tests_passed,
        tests_failed,
        total_economic_impact_lamports: total_economic_impact,
        max_single_exploit_lamports: max_single_exploit,
    };

    let report = AuditReport {
        target: program_target,
        findings,
        suppressed_findings,
        metadata: ReportMetadata {
            generated_at: Utc::now(),
            ares_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_duration_secs: elapsed_secs,
            agent_pipeline: vec![
                "Mapper".to_string(),
                "HypothesisGenerator".to_string(),
                "FuzzerOrchestrator".to_string(),
                "Triager".to_string(),
            ],
            tools_used: vec![
                format!("trident-{}", trident_version),
                "cargo-audit".to_string(),
                "rust-analyzer".to_string(),
            ],
        },
        summary,
    };

    // Write report
    tokio::fs::create_dir_all(output).await?;
    let report_path = output.join(format!("ares-report-{}.json", report.target.name));
    let report_json = serde_json::to_string_pretty(&report)?;
    tokio::fs::write(&report_path, report_json).await?;
    info!("Report written to: {:?}", report_path);

    // Print summary
    info!("=========================================");
    info!("SCAN COMPLETE");
    info!("  Critical:     {}", report.summary.critical_count);
    info!("  High:         {}", report.summary.high_count);
    info!("  Medium:       {}", report.summary.medium_count);
    info!("  Low:          {}", report.summary.low_count);
    info!("  Info:         {}", report.summary.informational_count);
    info!("  PoC Generated: {}", report.summary.poc_generated);
    info!(
        "  Suppressed:   {}",
        report.summary.false_positives_suppressed
    );
    info!("=========================================");

    if report.summary.critical_count > 0 {
        warn!("CRITICAL findings detected! Immediate review recommended.");
    }

    Ok(())
}

/// Find Anchor IDL file in the project.
fn find_idl_file(program_path: &Path) -> Option<PathBuf> {
    let idl_paths = vec![
        program_path.join("target/idl"),
        program_path.join("idl"),
        program_path.join("target/deploy"),
    ];

    for dir in idl_paths {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Get current git commit hash (if in a git repo).
async fn get_git_commit_hash(path: &Path) -> AresResult<Option<String>> {
    let output = tokio::process::Command::new("git")
        .args(["-C", &path.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .await?;

    if output.status.success() {
        let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(Some(hash))
    } else {
        Ok(None)
    }
}

/// Discover fuzz test targets from trident-tests directory.
async fn discover_fuzz_targets(fuzz_tests_dir: &Path) -> AresResult<Vec<String>> {
    let mut targets = Vec::new();

    if !fuzz_tests_dir.exists() {
        return Ok(targets);
    }

    let fuzz_tests = fuzz_tests_dir.join("fuzz_tests");
    if fuzz_tests.exists() {
        let mut entries = tokio::fs::read_dir(&fuzz_tests).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    targets.push(stem.to_string());
                }
            }
        }
    }

    Ok(targets)
}

/// Generate initial vulnerability hypotheses (Phase 1 stub).
fn generate_initial_hypotheses(program_graph: &ares_mapper::ProgramGraph) -> Vec<String> {
    let mut hypotheses = Vec::new();

    // Check for common Solana patterns
    for instruction in &program_graph.instructions {
        if instruction.has_signer_check.is_none() {
            hypotheses.push(format!(
                "Missing signer authorization in instruction '{}'",
                instruction.name
            ));
        }
        if instruction.has_owner_check.is_none() {
            hypotheses.push(format!(
                "Missing ownership check in instruction '{}'",
                instruction.name
            ));
        }
        if instruction.uses_cpi && !instruction.has_cpi_program_id_check {
            hypotheses.push(format!(
                "Arbitrary CPI risk in instruction '{}'",
                instruction.name
            ));
        }
        if instruction.has_arithmetic {
            hypotheses.push(format!(
                "Potential arithmetic overflow in instruction '{}'",
                instruction.name
            ));
        }
    }

    for account in &program_graph.accounts {
        if account.is_initialized_check.is_none() {
            hypotheses.push(format!(
                "Missing initialization check for account '{}'",
                account.name
            ));
        }
        if account.has_close_constraint.is_none() {
            hypotheses.push(format!(
                "Missing close constraint for account '{}' — revival attack risk",
                account.name
            ));
        }
    }

    hypotheses
}

// PoC generation delegated to crate::poc::PocGenerator (Phase 2)
