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
    ast_scan: bool,
    max_duration: u64,
    output: &Path,
) -> AresResult<()> {
    let scan_start = Instant::now();
    info!("=========================================");
    info!("ARES V3 Security Scan");
    info!("Target: {:?}", program_path);
    info!(
        "Full Pipeline: {} | Fuzz: {} | PoC: {} | AST Scan: {}",
        full_pipeline, fuzz, poc, ast_scan
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

    // Refuse a target we cannot read, rather than reporting it clean.
    //
    // `MapperAgent::analyze` recognises only `<target>/programs/` or
    // `<target>/src/` as a source root, and when neither exists it `warn!`s and
    // returns an empty graph. A `warn!` is not part of the contract a caller
    // consumes, so the scan then ran to completion and wrote a fully-formed
    // report: exit 0, `findings: []`, a summary of all zeros, and a
    // `target.name` taken from the last path segment. Scanning a path that does
    // not exist at all produced the same thing — a clean bill of health for a
    // program nobody read.
    //
    // Exit code, report existence and report shape were identical between
    // "scanned and found nothing" and "scanned nothing". For an auditor those
    // are the two claims that must never be confusable, so the check is here, at
    // the boundary, and it is an error rather than a warning.
    if !program_path.exists() {
        return Err(ares_core::AresError::NotFound(format!(
            "Program path does not exist: {}",
            program_path.display()
        )));
    }
    if !program_path.join("programs").is_dir() && !program_path.join("src").is_dir() {
        return Err(ares_core::AresError::NotFound(format!(
            "No source to scan at {}: expected a `programs/` or `src/` directory. \
             ARES reads Solana program source, so a target without one cannot be \
             audited — reporting it as clean would be a false all-clear.",
            program_path.display()
        )));
    }

    // Only when it will actually be used. This ran unconditionally, so
    // `--fuzz false` aborted with "trident-cli not found" before any analysis —
    // the flag skipped the fuzzing WORK but not the fuzzing PREREQUISITE.
    //
    // That made a static-only scan impossible anywhere without a fuzzer
    // installed: CI, a container, and the eval reproduction documented in
    // eval/predictions/README.md, which is `--fuzz false` over 159 targets.
    let trident_version = if fuzz {
        let v = check_trident_installation().await?;
        info!("Trident version: {}", v);
        Some(v)
    } else {
        None
    };

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

    // ORC2-F7: hypotheses become findings here. Before this, the vec built above
    // was logged and dropped, so `findings` was filled only by cross-analysis and
    // the two fuzz paths `--fuzz false` skips — which is why EVAL-2 measured F1
    // 0.0000 with zero predictions across 159 targets.
    //
    // They enter as ordinary findings, not privileged ones: the semantic
    // validator, local judge, LLM judge and triager all run downstream and can
    // reject them. That is the point — a hypothesis that is wrong should be
    // *suppressed* and counted, not silently discarded before anything can see it.
    for h in hypotheses {
        let severity = match h.category {
            VulnerabilityCategory::SignerAuthorization | VulnerabilityCategory::ArbitraryCpi => {
                ares_core::Severity::Critical
            }
            VulnerabilityCategory::OwnershipCheck | VulnerabilityCategory::RevivalAttack => {
                ares_core::Severity::High
            }
            _ => ares_core::Severity::Medium,
        };
        findings.push(ares_core::Finding {
            id: format!("ARES-HYP-{}", findings.len() + 1),
            title: h.title,
            description: h.description,
            severity,
            category: h.category,
            location: ares_core::CodeLocation {
                file: program_target.source_path.clone(),
                function: Some(h.subject),
                ..Default::default()
            },
            proof_of_concept: None,
            recommendation: h.recommendation,
            references: vec![],
            confidence: h.confidence,
            validation: None,
        });
    }

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
            validation: None,
        });
    }

    // ENG-4: ares-mapper's AST scanner (Anchor/Solitaire constraint checks,
    // taint-tracked sinks) — opt-in via --ast-scan, default false. Unlike the
    // hypothesis pipeline (EVAL-3 measured F1 0.3007), this detection path has
    // never been measured against a real corpus at scale. Wired in fully
    // rather than kept as a separate tool, per direction to integrate it
    // "all in one" with the rest of the pipeline — but starting opt-in until
    // there's real precision/recall evidence to justify flipping the default,
    // the same rollout discipline every other detector here already followed.
    if ast_scan {
        info!("[2c/5] AST Scanner: Anchor/Solitaire constraint checks, taint-tracked sinks...");
        let ast_scanner_result = ares_mapper::ast_scanner::scan_directory_ast(program_path);
        info!(
            "AST scanner: {} findings",
            ast_scanner_result.findings.len()
        );
        for af in ast_scanner_result.findings {
            let core_category_str =
                ares_mapper::ast_scanner::ast_category_to_core_category_str(&af.category);
            let category = VulnerabilityCategory::from_str_checked(core_category_str)
                .unwrap_or(VulnerabilityCategory::InvariantViolation);
            // Only three severities exist in ares-mapper's own output today
            // (checked directly against every literal in ast_scanner.rs and
            // taint_engine.rs) — anything else falls through to Medium rather
            // than panicking on a string this function doesn't recognize.
            let severity = match af.severity.as_str() {
                "Critical" => ares_core::Severity::Critical,
                "High" => ares_core::Severity::High,
                _ => ares_core::Severity::Medium,
            };
            findings.push(ares_core::Finding {
                id: format!("ARES-AST-{}", findings.len() + 1),
                title: format!("{}: {}", af.category, af.file.display()),
                description: af.description,
                severity,
                category,
                location: ares_core::CodeLocation {
                    file: af.file,
                    // 0 is ast_scanner's own "no specific line tracked"
                    // sentinel (used throughout its struct-level findings,
                    // which describe a whole Accounts struct, not one
                    // expression) — reporting it literally would read as a
                    // real, if odd, line number rather than "unknown".
                    line_start: if af.line == 0 {
                        None
                    } else {
                        Some(af.line as u32)
                    },
                    ..Default::default()
                },
                proof_of_concept: None,
                recommendation:
                    "Review the flagged Anchor/Solitaire account constraint or taint-tracked sink."
                        .to_string(),
                references: vec![],
                confidence: af.confidence,
                validation: None,
            });
        }
    }

    if fuzz {
        info!("[3/5] Fuzzer Orchestrator: Running Trident fuzz campaign...");

        // Constructed here rather than above, for the same reason the version
        // check moved: `TridentTool::new` resolves `trident` on PATH and errors
        // if it is absent, and the binding is read nowhere outside this block.
        let trident = TridentTool::new(config.trident_path.as_deref())?
            .with_working_dir(program_path.to_path_buf());

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
                        validation: None,
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
                        validation: None,
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
        // Create the output/poc directory up front — PoC writes below would
        // otherwise fail with ENOENT on a fresh output dir (the report-level
        // create_dir_all only runs at the end of the scan).
        tokio::fs::create_dir_all(output.join("poc")).await?;
        // Parse the target IDL once so each PoC can embed real instruction data
        // (Anchor discriminator + args) instead of the placeholder `&[]` (POC-1).
        let target_idl = program_target
            .idl_path
            .as_deref()
            .and_then(crate::idl::load_idl);
        if target_idl.is_none() {
            info!("No parseable IDL for target; PoCs will use placeholder instruction data.");
        }
        // The PoC directory has to exist before the first write. `create_dir_all`
        // for `output` runs further down, when the report is written — after this
        // loop — and it never creates the `poc/` child at all. That was
        // unreachable while ORC2-F7 kept `findings` empty: with nothing to
        // generate a PoC for, the loop never ran and the missing directory never
        // surfaced. Wiring hypotheses into findings makes it the first thing a
        // scan hits, as `Error: IO error: No such file or directory (os error 2)`.
        let poc_dir = output.join("poc");
        tokio::fs::create_dir_all(&poc_dir).await?;

        for finding in findings.iter_mut() {
            let poc_path = poc_dir.join(format!(
                "{}_test.rs",
                finding.id.to_lowercase().replace("-", "_")
            ));
            let instruction = target_idl.as_ref().and_then(|idl| {
                crate::idl::select_instruction(idl, finding.location.function.as_deref())
            });
            let poc_code = crate::poc::PocGenerator::generate(
                finding,
                &program_target.name,
                instruction,
                program_target.program_id.as_deref(),
            );
            tokio::fs::write(&poc_path, poc_code).await?;
            finding.proof_of_concept = Some(poc_path);
            info!("Generated PoC harness: {:?}", finding.proof_of_concept);
        }
    }

    // Phase 3: Semantic false-positive validation (Old validator)
    info!("[4.5/5] Semantic Validator: Suppressing structurally implausible findings...");
    let validator = crate::validator::SemanticValidator::new(&program_graph);
    let (retained, semantic_suppressed) = validator.validate(findings);
    findings = retained;
    if !semantic_suppressed.is_empty() {
        info!(
            "Semantic FP filter suppressed {} findings",
            semantic_suppressed.len()
        );
    }

    // Phase 4: Deterministic Local Judge
    info!("[4.6/5] Local Judge: Deterministic false-positive suppression...");
    let local_judge = ares_mapper::local_judge::LocalJudge::new(config.judge_extended);
    let (retained_findings, mut suppressed_findings) =
        local_judge.judge(findings, &program_graph.source_patterns);
    findings = retained_findings;
    // Carry the semantic validator's suppressions into the same list the judges
    // use, so `suppressed_findings` and the summary's
    // `false_positives_suppressed` describe every filter in the pipeline rather
    // than the last two.
    suppressed_findings.extend(semantic_suppressed);

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

    // Every filter's removals, not just the triager's. `false_positives_suppressed`
    // was set from `filtered_count` — the confidence cut alone — so a scan that
    // suppressed findings in the semantic validator or either judge still reported
    // zero. The field names the FP filters; it should count them.
    let suppressed_total = suppressed_findings.len();

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
        false_positives_suppressed: suppressed_total,
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
            confirmed_at: None,
            ares_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_duration_secs: elapsed_secs,
            // Provenance, and it has to be literally true: the fuzzer is listed
            // only when it ran. This vec was unconditional while the comment
            // below already claimed "only tools actually executed", so every
            // `--fuzz false` report named a stage that never executed and a
            // tool that was never invoked.
            agent_pipeline: {
                let mut p = vec!["Mapper".to_string(), "HypothesisGenerator".to_string()];
                if fuzz {
                    p.push("FuzzerOrchestrator".to_string());
                }
                p.push("Triager".to_string());
                p
            },
            // Provenance: only tools actually executed during this scan.
            tools_used: trident_version
                .map(|v| vec![format!("trident-{}", v)])
                .unwrap_or_default(),
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
/// Deterministic: directory entries are sorted, and an IDL named after the
/// program (`<program>.json`) is preferred over an arbitrary first match.
fn find_idl_file(program_path: &Path) -> Option<PathBuf> {
    let idl_paths = vec![
        program_path.join("target/idl"),
        program_path.join("idl"),
        program_path.join("target/deploy"),
    ];

    let program_name = program_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    for dir in idl_paths {
        let mut json_files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
                .collect(),
            Err(_) => continue,
        };
        json_files.sort();

        if let Some(ref name) = program_name {
            let preferred = dir.join(format!("{}.json", name));
            if json_files.contains(&preferred) {
                return Some(preferred);
            }
        }

        if let Some(first) = json_files.into_iter().next() {
            return Some(first);
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

    // Sort so fuzz targets run in a deterministic order (finding IDs are
    // assigned in execution order).
    targets.sort();

    Ok(targets)
}

/// A hypothesis the program graph supports, already shaped as a finding.
///
/// This returned `Vec<String>` of prose until ORC2-F7. `scan` generated it,
/// logged the count, and dropped it: findings reaching the report came only from
/// `cross_analysis` and the two fuzz paths that `--fuzz false` skips. EVAL-2
/// measured the result — **F1 0.0000 across 159 targets, 170 false negatives,
/// zero predictions** — and the scan logs showed the mechanism directly:
/// `Generated 1 vulnerability hypotheses` followed by `Suppressed: 0`. Zero in
/// both places means the hypotheses were never findings to suppress.
///
/// Prose could not become a `Finding` without a category, so the fix is to
/// produce the category here rather than to parse it back out of a sentence.
struct Hypothesis {
    category: VulnerabilityCategory,
    /// The instruction or account this is about, for the finding's location.
    subject: String,
    title: String,
    description: String,
    recommendation: String,
    /// Deliberately per-category. These are graph-shaped heuristics, not proofs,
    /// and `scan`'s triager drops anything below 0.70 — so a number chosen to
    /// clear that bar rather than to describe the evidence would be tuning the
    /// gate, not measuring the code.
    confidence: f64,
}

fn generate_initial_hypotheses(program_graph: &ares_mapper::ProgramGraph) -> Vec<Hypothesis> {
    let mut hypotheses = Vec::new();

    for instruction in &program_graph.instructions {
        // `Some(false)`, not `is_none()`. `has_signer_check` is
        // `body.map(|b| b.contains("is_signer") || ...)`, so:
        //   None        -> the body could not be extracted; we do not know
        //   Some(false) -> the body WAS read and holds no signer check  <-- the bug
        //   Some(true)  -> a check is present
        // Testing `is_none()` fired only on the case where nothing is known and
        // never on the vulnerability itself, which is why EVAL-2 measured
        // recall 0.0000 for this class across every target that parsed. Claiming
        // a finding from an unreadable body would also be the exact inversion of
        // "better that an agent knows it is blind".
        // Gated to native entry points. `has_signer_check` is read from the BODY,
        // and in Anchor the signer constraint is not in the body — it is
        // `Signer<'info>` in the accounts struct. Firing on an Anchor handler
        // produced 74 predictions against a corpus with ZERO missing-signer
        // ground-truth rows: every one a false positive, and the largest single
        // drag on measured precision. The detector is kept rather than deleted
        // because it is correct for native programs; this corpus contains none.
        //
        // Also requires the body to actually reach into an account. A dispatcher
        // that matches a discriminant and delegates — the canonical native
        // `process_instruction` — never touches one, so reading ITS body for a
        // signer idiom proves nothing; the check belongs in the callee. Once the
        // rustfmt signature fix made these handlers visible, dispatchers were the
        // bulk of this rule's false positives.
        if instruction.has_signer_check == Some(false)
            && instruction.is_native_entry_point
            && !instruction.is_anchor_handler
            && instruction.touches_account_fields
        {
            hypotheses.push(Hypothesis {
                category: VulnerabilityCategory::SignerAuthorization,
                subject: instruction.name.clone(),
                title: format!("Missing signer authorization in '{}'", instruction.name),
                description: format!(
                    "The mapper found no signer check in instruction '{}'. An instruction that \
                     mutates state without asserting the authority signed can be invoked by anyone.",
                    instruction.name
                ),
                recommendation: "Assert the authority is a signer — `Signer<'info>` in Anchor, or \
                                 an explicit `is_signer` check on the raw AccountInfo."
                    .to_string(),
                confidence: 0.72,
            });
        }
        // Same inversion as the signer check above.
        // Conjoined with an actual raw-data read: a missing owner check is only
        // exploitable where the handler decodes an account's bytes.
        // And with the function having been handed an account at all. Every
        // `pub fn` in the crate lands in `graph.instructions` — there is no
        // entry-point filter — so this fired on plain byte-decoding helpers:
        // `pub fn unpack_amount(input: &[u8])` matches
        // `touches_raw_account_data` via `try_from_slice` and has no reason to
        // contain the substring `owner`, and was reported as High at 0.72.
        // The gate is "was handed an account", NOT "is an entry point": a
        // helper taking `bank: &AccountInfo` is neither native entry point nor
        // Anchor handler, yet that is precisely the Cashio root cause and the
        // shape of most function-level corpus rows.
        // An Anchor typed wrapper IS the owner check: `Account<'info, T>`
        // verifies `owner == declared program` on deserialization, so a body
        // with no explicit assertion is the correct shape, not a missing one.
        // Measured: this is the whole of the one false positive that recognising
        // those wrappers as account parameters re-admitted.
        if instruction.has_owner_check == Some(false)
            && instruction.touches_raw_account_data
            && instruction.takes_account_params
            && !instruction.uses_owner_checked_wrapper
        {
            hypotheses.push(Hypothesis {
                category: VulnerabilityCategory::OwnershipCheck,
                subject: instruction.name.clone(),
                title: format!("Missing ownership check in '{}'", instruction.name),
                description: format!(
                    "The mapper found no owner check in instruction '{}'. Without one, an account \
                     owned by a different program can be substituted for the expected one.",
                    instruction.name
                ),
                recommendation: "Constrain the account's owner — a typed `Account<'info, T>` in \
                                 Anchor, or an explicit `owner == program_id` comparison."
                    .to_string(),
                confidence: 0.72,
            });
        }
        if instruction.uses_cpi && !instruction.has_cpi_program_id_check {
            hypotheses.push(Hypothesis {
                category: VulnerabilityCategory::ArbitraryCpi,
                subject: instruction.name.clone(),
                title: format!("Unvalidated CPI target in '{}'", instruction.name),
                description: format!(
                    "Instruction '{}' performs a CPI without validating the target program id, so \
                     the caller chooses which program runs.",
                    instruction.name
                ),
                recommendation: "Compare the target program id against the expected one, or take \
                                 it as a typed `Program<'info, T>` account."
                    .to_string(),
                // Two independent conditions must hold (a CPI exists AND no id
                // check was found), so this is better evidenced than the
                // single-signal hypotheses above.
                confidence: 0.78,
            });
        }
        if instruction.has_unchecked_arithmetic {
            hypotheses.push(Hypothesis {
                category: VulnerabilityCategory::ArithmeticOverflow,
                subject: instruction.name.clone(),
                title: format!("Unchecked arithmetic in '{}'", instruction.name),
                description: format!(
                    "Instruction '{}' mutates with `+=`/`-=`/`*=`/`/=` and shows no `checked_*`, \
                     `saturating_*`, or `wrapping_*` guard anywhere in its body.",
                    instruction.name
                ),
                recommendation: "Use `checked_*` and handle the `None`, or `saturating_*` where \
                                 clamping is the intended behaviour."
                    .to_string(),
                // Gated on `has_unchecked_arithmetic`, not `has_arithmetic`: the
                // latter is set by `.checked_add(` itself, so this hypothesis used
                // to fire on correctly-guarded code.
                confidence: 0.70,
            });
        }
    }

    // Type cosplay: an account struct that cannot identify its own type.
    //
    // Anchor's `#[account]` prepends an 8-byte discriminator and checks it on
    // deserialize; programs that predate or avoid it put the tag in a field
    // (Metaplex uses `key: Key`). With neither, the bytes of any same-sized
    // account decode cleanly as this type, which is the vulnerability.
    //
    // This class had ZERO predictions across the eval corpus before now — not
    // because the rule was wrong but because nothing could see the structs:
    // `graph.accounts` holds only `#[derive(Accounts)]` context structs, and a
    // data struct carries no attribute at all.
    //
    // Measured on the committed corpus before writing this: 27 true positives,
    // 0 false positives, 4 false negatives — precision 1.0000, recall 0.8710.
    // Read that precision with the corpus in mind: its snippets are mostly
    // struct-only, so a whole program (which also holds instruction-argument
    // structs, and those are NOT account data) is not represented. The honest
    // statement is that the false-positive rate on whole programs is unmeasured,
    // not that it is zero.
    //
    // What that unmeasured rate turned out to be: `collect_data_structs`
    // collects EVERY struct, and an Anchor accounts context carries
    // `#[derive(Accounts)]` — not `#[account]` — with its per-field
    // `#[account(..)]` attributes BELOW the declaration, where the backward
    // attribute walk never reaches. So a clean three-instruction vault emitted
    // one hypothesis per context struct plus one per event, none of which
    // anything downstream removes — `SemanticValidator::check` has no
    // TypeCosplay arm. The gates below are what the description's own "If it is
    // used as account data" hedge was standing in for: the rule never checked
    // its own premise.
    for ds in &program_graph.data_structs {
        if ds.has_anchor_account_attr || ds.has_discriminator_field {
            continue;
        }
        // A fieldless struct holds no account data to confuse.
        if ds.field_count == 0 {
            continue;
        }
        // An Anchor accounts context is a parameter list, not stored bytes, so
        // it can never be type cosplay. Skipped by name — with the decode-site
        // set as the escape hatch, which is what makes the name skip safe:
        // names are unique per module, not per crate, so `contexts::Config` and
        // `state::Config` collide, and a bare name skip would suppress the real
        // account struct along with the context. Requiring that nothing decodes
        // the name from account bytes resolves exactly that case.
        //
        // Measured on the 170-row corpus: this takes type-cosplay from
        // 29 TP / 12 FP (P 0.7073) to 29 TP / 3 FP (P 0.9062) — every false
        // positive it removes is a context struct, and no true positive moves.
        if program_graph.accounts.iter().any(|a| a.name == ds.name)
            && !program_graph.account_data_types.contains(&ds.name)
        {
            continue;
        }
        // An `#[event]` payload goes to the transaction log, never to an
        // account, so it can never be substituted for one. Its own gate because
        // client code in the same crate decodes events with `try_from_slice` —
        // so the decode-site signal below would vouch for it.
        if ds.is_anchor_event {
            continue;
        }

        // Whether anything in the program actually decodes these bytes out of
        // an account. NOT a gate: the eval corpus is function- and struct-level
        // snippets, and a struct-only snippet has no use site anywhere, so
        // requiring one removed 27 of 29 true positives and took overall F1 from
        // 0.5673 to 0.3868. It decides the WORDING instead, which is the part
        // that has to be earned: REMEMBER persists a non-speculative finding as
        // prior fact for later audits, so the difference between "is stored in
        // an account" and "if it is stored in an account" is the difference
        // between a fact and a fabrication.
        let decoded_from_account = program_graph.account_data_types.contains(&ds.name);
        let premise = if decoded_from_account {
            format!("Struct '{}' is deserialized from account data", ds.name)
        } else {
            format!("If struct '{}' is used as account data", ds.name)
        };

        hypotheses.push(Hypothesis {
            category: VulnerabilityCategory::TypeCosplay,
            subject: ds.name.clone(),
            title: format!("`{}` carries no type discriminator", ds.name),
            description: format!(
                "{}, it has neither Anchor's `#[account]` attribute nor a leading \
                 discriminator field, so nothing distinguishes its bytes from any other \
                 account of the same size. An attacker can substitute a different account \
                 and have it deserialize cleanly.",
                premise
            ),
            recommendation: "Mark the struct `#[account]` so Anchor writes and checks an \
                             8-byte discriminator, or add a leading type field (`key: Key`) \
                             and assert it before trusting the rest."
                .to_string(),
            // 0.72 for both wordings. A decode site is real corroboration and
            // argues for the 0.78 the CPI rule carries, but splitting the
            // confidence would move findings across the triager's 0.70 cut-off
            // on reasoning rather than on measurement — tuning the gate instead
            // of describing the evidence (GOLDEN RULE 3).
            confidence: 0.72,
        });
    }

    for account in &program_graph.accounts {
        if account.is_initialized_check.is_none() {
            hypotheses.push(Hypothesis {
                category: VulnerabilityCategory::ReInitialization,
                subject: account.name.clone(),
                title: format!("Missing initialization check for '{}'", account.name),
                description: format!(
                    "Account '{}' has no initialization guard, so it can be initialized a second \
                     time and its state reset.",
                    account.name
                ),
                recommendation: "Mark the account `init` (which fails if it already exists), or \
                                 assert an `is_initialized` discriminator before writing."
                    .to_string(),
                confidence: 0.70,
            });
        }
        if account.has_close_constraint.is_none() {
            hypotheses.push(Hypothesis {
                category: VulnerabilityCategory::RevivalAttack,
                subject: account.name.clone(),
                title: format!("Missing close constraint for '{}'", account.name),
                description: format!(
                    "Account '{}' is closed without a constraint that zeroes and reassigns it, so \
                     it can be revived within the same transaction.",
                    account.name
                ),
                recommendation: "Use Anchor's `close = destination`, or zero the data and assign \
                                 the account to the system program manually."
                    .to_string(),
                confidence: 0.70,
            });
        }
    }

    hypotheses
}

// PoC generation delegated to crate::poc::PocGenerator (Phase 2)

#[cfg(test)]
mod hypothesis_tests {
    //! Real source through the real mapper. Each fixture is written to a temp
    //! directory shaped the way `MapperAgent::analyze` expects (`<root>/src/`),
    //! which is also how `eval/stage_ares_core_targets.py` stages a corpus
    //! target — so what fires here is what the scored run produces.
    use super::*;

    async fn hypotheses_for(src: &str) -> Vec<Hypothesis> {
        let dir = tempfile::tempdir().expect("temp dir");
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("lib.rs"), src).unwrap();
        let graph = MapperAgent::new(dir.path())
            .analyze()
            .await
            .expect("mapper analysis");
        generate_initial_hypotheses(&graph)
    }

    fn of(hypotheses: &[Hypothesis], want: VulnerabilityCategory) -> Vec<&str> {
        hypotheses
            .iter()
            .filter(|h| std::mem::discriminant(&h.category) == std::mem::discriminant(&want))
            .map(|h| h.subject.as_str())
            .collect()
    }

    /// A three-instruction Anchor vault with nothing wrong with it. Every
    /// `#[derive(Accounts)]` context and the `#[event]` payload used to yield a
    /// type-cosplay hypothesis apiece, because `collect_data_structs` collects
    /// every struct and a context carries `#[derive(Accounts)]` rather than
    /// `#[account]`. Nothing downstream removed them: `SemanticValidator::check`
    /// has no TypeCosplay arm.
    const CLEAN_ANCHOR_VAULT: &str = r#"
use anchor_lang::prelude::*;

#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.vault.authority = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.total = vault.total.checked_add(amount).unwrap();
        emit!(DepositEvent { amount });
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.total = vault.total.checked_sub(amount).unwrap();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 40)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub total: u64,
}

#[event]
pub struct DepositEvent {
    pub amount: u64,
}
"#;

    #[tokio::test]
    async fn a_clean_anchor_vault_yields_no_type_cosplay() {
        let h = hypotheses_for(CLEAN_ANCHOR_VAULT).await;
        assert_eq!(
            of(&h, VulnerabilityCategory::TypeCosplay),
            Vec::<&str>::new(),
            "an accounts context is a parameter list and an event goes to the \
             log; neither is stored account data"
        );
    }

    /// An `#[event]` payload lives in the transaction log, never in an account,
    /// so it has no account to be substituted for. It needs its own gate rather
    /// than relying on the use-site test: reading an event back out of the log
    /// is done with `try_from_slice`, the very idiom that marks a type as
    /// account data.
    #[tokio::test]
    async fn an_event_decoded_from_the_log_is_not_type_cosplay() {
        let h = hypotheses_for(
            "use anchor_lang::prelude::*;\n\
             \n\
             #[event]\n\
             pub struct DepositEvent {\n\
             \x20   pub amount: u64,\n\
             }\n\
             \n\
             pub fn decode_logged_event(log: &[u8]) -> Result<DepositEvent> {\n\
             \x20   Ok(DepositEvent::try_from_slice(&log[8..])?)\n\
             }\n",
        )
        .await;
        assert_eq!(
            of(&h, VulnerabilityCategory::TypeCosplay),
            Vec::<&str>::new(),
            "decoding an event from the log is not evidence that its bytes \
             live in an account"
        );
    }

    /// The other direction. A struct with no discriminator that IS decoded from
    /// an account's bytes is the real thing, and the gates above must not cost
    /// it — this is the canonical sealevel-attacks type-cosplay shape.
    #[tokio::test]
    async fn an_undiscriminated_type_decoded_from_account_bytes_still_fires() {
        let h = hypotheses_for(
            r#"
use anchor_lang::prelude::*;

#[program]
pub mod type_cosplay {
    use super::*;

    pub fn update_user(ctx: Context<UpdateUser>) -> Result<()> {
        let user = User::try_from_slice(&ctx.accounts.user.data.borrow()).unwrap();
        msg!("GM {}", user.authority);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateUser<'info> {
    user: AccountInfo<'info>,
    authority: Signer<'info>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    authority: Pubkey,
}
"#,
        )
        .await;
        assert_eq!(
            of(&h, VulnerabilityCategory::TypeCosplay),
            vec!["User"],
            "`User` is decoded straight out of an AccountInfo with no \
             discriminator — the context struct beside it is not"
        );
    }

    /// `graph.instructions` holds every `pub fn` in the crate, entry point or
    /// not. A byte-decoding helper matches `touches_raw_account_data` through
    /// `try_from_slice` and has no reason to contain the substring `owner`, so
    /// the ownership rule reported it as High at 0.72 confidence.
    #[tokio::test]
    async fn a_byte_decoding_helper_is_not_missing_an_ownership_check() {
        let h = hypotheses_for(
            "pub fn unpack_amount(input: &[u8]) -> Result<u64, ProgramError> {\n\
             \x20   let amount = u64::try_from_slice(input)?;\n\
             \x20   Ok(amount)\n\
             }\n",
        )
        .await;
        assert_eq!(
            of(&h, VulnerabilityCategory::OwnershipCheck),
            Vec::<&str>::new(),
            "a function handed no account cannot be handed a substituted one"
        );
    }

    /// The native entry point in the shape rustfmt actually emits: 117 columns,
    /// always split. Reading the convention off the `pub fn` line alone made
    /// this program report nothing at all.
    #[tokio::test]
    async fn a_rustfmt_split_native_handler_still_reports_a_missing_owner_check() {
        let h = hypotheses_for(
            "pub fn process_instruction(\n\
             \x20   program_id: &Pubkey,\n\
             \x20   accounts: &[AccountInfo],\n\
             \x20   instruction_data: &[u8],\n\
             ) -> ProgramResult {\n\
             \x20   let state = State::try_from_slice(&accounts[0].data.borrow())?;\n\
             \x20   Ok(())\n\
             }\n",
        )
        .await;
        assert_eq!(
            of(&h, VulnerabilityCategory::OwnershipCheck),
            vec!["process_instruction"]
        );
    }

    /// The Cashio incident shape (`eval/fixtures/rs/incident-repros`): a helper
    /// handed individual accounts. Neither a native entry point nor an Anchor
    /// handler, but the caller still chooses the account, so gating this rule on
    /// entry-point-ness would drop the corpus's most common vulnerable shape.
    #[tokio::test]
    async fn a_helper_handed_an_account_info_still_reports_a_missing_owner_check() {
        let h = hypotheses_for(
            "pub fn mint_ecash(\n\
             \x20   bank: &AccountInfo,\n\
             \x20   amount: u64,\n\
             ) -> ProgramResult {\n\
             \x20   let bank_data = Bank::try_from_slice(&bank.data.borrow())?;\n\
             \x20   Ok(())\n\
             }\n",
        )
        .await;
        assert_eq!(
            of(&h, VulnerabilityCategory::OwnershipCheck),
            vec!["mint_ecash"]
        );
    }
}
