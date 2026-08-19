use std::fmt;
use std::path::PathBuf;
use thiserror::Error;

/// Global result type for ARES operations.
pub type AresResult<T> = Result<T, AresError>;

/// Global error type for ARES operations.
#[derive(Error, Debug)]
pub enum AresError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Trident integration error: {0}")]
    Trident(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Execution failed: {0}")]
    Execution(String),

    #[error("Benchmark error: {0}")]
    Benchmark(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("External tool missing: {0}")]
    ToolMissing(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Vulnerability category for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnerabilityCategory {
    TypeCosplay,
    OwnershipCheck,
    SignerAuthorization,
    ArbitraryCpi,
    InitializationFrontrunning,
    ReentrancyRisk,
    DuplicateMutableAccounts,
    ArithmeticOverflow,
    CloseAccount,
    AccountReloading,
    ReInitialization,
    RevivalAttack,
    AccountDataMatching,
    PdaPrivileges,
    FuzzingCrash,
    InvariantViolation,
    MissingSigner,
    MissingRevalidation,
    UncheckedCast,
    StateTransitionGap,
    Generic,
}

impl VulnerabilityCategory {
    /// Returns all known categories.
    pub fn all() -> &'static [VulnerabilityCategory] {
        &[
            Self::TypeCosplay,
            Self::OwnershipCheck,
            Self::SignerAuthorization,
            Self::ArbitraryCpi,
            Self::InitializationFrontrunning,
            Self::ReentrancyRisk,
            Self::DuplicateMutableAccounts,
            Self::ArithmeticOverflow,
            Self::CloseAccount,
            Self::AccountReloading,
            Self::ReInitialization,
            Self::RevivalAttack,
            Self::AccountDataMatching,
            Self::PdaPrivileges,
            Self::FuzzingCrash,
            Self::InvariantViolation,
            Self::MissingSigner,
            Self::MissingRevalidation,
            Self::UncheckedCast,
            Self::StateTransitionGap,
            Self::Generic,
        ]
    }

    /// Parse a category from a string, returning `None` if unknown.
    pub fn from_str_checked(s: &str) -> Option<Self> {
        match s {
            "type-cosplay" => Some(Self::TypeCosplay),
            "ownership-check" => Some(Self::OwnershipCheck),
            "signer-authorization" | "missing-signer" => Some(Self::SignerAuthorization),
            "arbitrary-cpi" => Some(Self::ArbitraryCpi),
            "initialization-frontrunning" => Some(Self::InitializationFrontrunning),
            "reentrancy-risk" | "reentrancy" => Some(Self::ReentrancyRisk),
            "duplicate-mutable-accounts" => Some(Self::DuplicateMutableAccounts),
            "arithmetic-overflow" => Some(Self::ArithmeticOverflow),
            "close-account" => Some(Self::CloseAccount),
            "account-reloading" | "revival-attack" | "re-initialization" => {
                Some(Self::AccountReloading)
            }
            "account-data-matching" => Some(Self::AccountDataMatching),
            "pda-privileges" => Some(Self::PdaPrivileges),
            "fuzzing-crash" | "fuzzing" => Some(Self::FuzzingCrash),
            "invariant-violation" | "invariant" => Some(Self::InvariantViolation),
            "missing-revalidation" => Some(Self::MissingRevalidation),
            "unchecked-cast" => Some(Self::UncheckedCast),
            "state-transition-gap" => Some(Self::StateTransitionGap),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }
}

impl fmt::Display for VulnerabilityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TypeCosplay => "type-cosplay",
            Self::OwnershipCheck => "ownership-check",
            Self::SignerAuthorization => "signer-authorization",
            Self::ArbitraryCpi => "arbitrary-cpi",
            Self::InitializationFrontrunning => "initialization-frontrunning",
            Self::ReentrancyRisk => "reentrancy-risk",
            Self::DuplicateMutableAccounts => "duplicate-mutable-accounts",
            Self::ArithmeticOverflow => "arithmetic-overflow",
            Self::CloseAccount => "close-account",
            Self::AccountReloading => "account-reloading",
            Self::ReInitialization => "re-initialization",
            Self::RevivalAttack => "revival-attack",
            Self::AccountDataMatching => "account-data-matching",
            Self::PdaPrivileges => "pda-privileges",
            Self::FuzzingCrash => "fuzzing-crash",
            Self::InvariantViolation => "invariant-violation",
            Self::MissingSigner => "missing-signer",
            Self::MissingRevalidation => "missing-revalidation",
            Self::UncheckedCast => "unchecked-cast",
            Self::StateTransitionGap => "state-transition-gap",
            Self::Generic => "generic",
        };
        write!(f, "{}", s)
    }
}

/// Severity level of a vulnerability finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Informational => write!(f, "Informational"),
        }
    }
}

/// Represents a single vulnerability finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: VulnerabilityCategory,
    pub location: CodeLocation,
    pub proof_of_concept: Option<PathBuf>,
    pub recommendation: String,
    pub references: Vec<String>,
    pub confidence: f64, // 0.0 - 1.0
    /// Fork-confirmation outcome from `ares confirm` (POC-2). `None` until a
    /// confirmation pass has run against this finding's `proof_of_concept`.
    /// `#[serde(default)]` so reports written before this field existed still
    /// deserialize.
    #[serde(default)]
    pub validation: Option<ValidationOutcome>,
}

/// Outcome of fork-validating a finding's generated PoC (POC-2): did executing
/// the PoC harness against a sandboxed fork prove the finding, refute it, or
/// fail to reach a trustworthy conclusion?
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationOutcome {
    /// The PoC harness ran and the transaction succeeded: the exploit works.
    Confirmed,
    /// The PoC harness ran and the transaction failed: the finding did not reproduce.
    Refuted,
    /// The PoC could not be run to a trustworthy conclusion (no IDL match at
    /// generation time, or a build/execution error unrelated to the finding).
    Inconclusive,
}

impl fmt::Display for ValidationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Confirmed => "confirmed",
            Self::Refuted => "refuted",
            Self::Inconclusive => "inconclusive",
        };
        write!(f, "{}", s)
    }
}

/// Represents a suppressed finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressedFinding {
    pub finding: Finding,
    pub reason: String,
    // Four write sites, not two: "semantic_validator" (validator.rs),
    // "llm_judge" and "triager" (commands/scan.rs), "local_judge"
    // (ares-mapper/src/local_judge.rs). This is a bare String, not an enum, so
    // this comment is the only place the full vocabulary is written down --
    // keep it in sync with the write sites if a new suppressor is added.
    pub suppressed_by: String,
}

/// Code location reference.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CodeLocation {
    pub file: PathBuf,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
    pub column_start: Option<u32>,
    pub column_end: Option<u32>,
    pub function: Option<String>,
    pub commit: Option<String>,
}

/// A complete audit report for a Solana program.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditReport {
    pub target: ProgramTarget,
    pub findings: Vec<Finding>,
    pub suppressed_findings: Vec<SuppressedFinding>,
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
}

/// Target program specification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProgramTarget {
    pub name: String,
    pub repository_url: Option<String>,
    pub commit_hash: Option<String>,
    pub program_id: Option<String>,
    pub source_path: PathBuf,
    pub idl_path: Option<PathBuf>,
}

/// Metadata for an audit report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportMetadata {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// When `ares confirm` last fork-ran this report's PoCs, if it ever has.
    /// `generated_at` above is set once, at `scan` time, and `confirm` does not
    /// touch it -- so before this field existed, a `.confirmed.json` carried
    /// only the original scan's timestamp and nothing recorded when the
    /// confirmation pass itself ran. `#[serde(default)]` so a report written
    /// before this field existed still deserializes, the same convention
    /// `Finding.validation` already uses.
    #[serde(default)]
    pub confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub ares_version: String,
    pub scan_duration_secs: u64,
    pub agent_pipeline: Vec<String>,
    pub tools_used: Vec<String>,
}

/// Summary statistics for an audit report.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub informational_count: usize,
    pub false_positives_suppressed: usize,
    pub poc_generated: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    /// Phase 4: Estimated total economic impact (lamports) across all findings.
    pub total_economic_impact_lamports: u64,
    /// Phase 4: Maximum extractable value from a single finding (lamports).
    pub max_single_exploit_lamports: u64,
}

/// Benchmark result for a single protocol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkResult {
    pub protocol_name: String,
    pub source: String,
    pub total_critical_high: usize,
    pub detected_critical_high: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    /// Renamed to known_audit_recall for honesty. Was `detection_rate`.
    /// This is TP / Expected — how many *known audit findings* we recalled.
    /// It is NOT "all vulnerabilities in the codebase".
    #[serde(rename = "detection_rate")]
    pub known_audit_recall: f64,
    pub fp_rate: f64,
    pub poc_success_rate: f64,
    pub execution_time_secs: u64,
    /// Phase 4: Estimated maximum extractable economic value (lamports).
    pub economic_score_lamports: u64,
    /// Phase 6: Precision = TP / (TP + FP). Real-world: often 40-70%.
    pub precision: f64,
    /// Phase 6: Recall = TP / (TP + FN) — same as known_audit_recall.
    pub recall: f64,
    /// Phase 6: F1 Score = 2 * (precision * recall) / (precision + recall).
    pub f1_score: f64,
    /// Phase 9: Which categories were actually detected by the analyzer.
    pub detected_categories: Vec<String>,
    /// Phase 10: Total unique categories flagged by the analyzer (TP + FP).
    /// Represents findings that require human triage.
    pub total_findings: usize,
}

/// LLM provider selection for ARES-as-Judge.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    Openai,
    Anthropic,
    Ollama,
    #[default]
    Disabled,
}

/// Configuration for ARES CLI.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AresConfig {
    pub trident_path: Option<PathBuf>,
    pub solana_cli_path: Option<PathBuf>,
    pub anchor_cli_path: Option<PathBuf>,
    pub output_dir: PathBuf,
    pub sandbox_image: String,
    pub max_fuzz_iterations: u64,
    pub max_scan_duration_secs: u64,
    pub llm_model: String,
    pub llm_provider: LlmProvider,
    pub llm_api_key: Option<String>,
    pub llm_base_url: Option<String>,
    pub llm_judge_enabled: bool,
    /// Extended deterministic heuristics for the Local Judge
    pub judge_extended: bool,
    /// Max LLM tokens per API call (budget throttle).
    pub llm_max_tokens_per_call: u32,
    /// Max findings sent to LLM per scan (prioritizes high-confidence).
    pub llm_max_findings_per_scan: usize,
    pub policy_file: Option<PathBuf>,
    pub benchmark_dataset_path: Option<PathBuf>,
    /// Enable mainnet fork simulation in PoC validation.
    pub mainnet_fork_enabled: bool,
    /// Specific slot to fork from (None = latest).
    pub mainnet_fork_slot: Option<u64>,
    /// RPC URL to fork mainnet state from (default: https://api.mainnet-beta.solana.com).
    pub mainnet_rpc_url: Option<String>,
    /// Accounts to `--clone` into the local validator (program IDs, token accounts, PDAs).
    pub mainnet_clone_accounts: Vec<String>,
}

impl Default for AresConfig {
    fn default() -> Self {
        Self {
            trident_path: None,
            solana_cli_path: None,
            anchor_cli_path: None,
            output_dir: PathBuf::from("./ares-output"),
            sandbox_image: "ares-v3/sandbox:latest".to_string(),
            max_fuzz_iterations: 100_000,
            max_scan_duration_secs: 3600,
            llm_model: "claude-3-5-sonnet".to_string(),
            llm_provider: LlmProvider::Disabled,
            llm_api_key: None,
            llm_base_url: None,
            llm_judge_enabled: false,
            judge_extended: false,
            llm_max_tokens_per_call: 2048,
            llm_max_findings_per_scan: 20,
            policy_file: Some(PathBuf::from("ares-policy.toml")),
            benchmark_dataset_path: Some(PathBuf::from("./dataset")),
            mainnet_fork_enabled: false,
            mainnet_fork_slot: None,
            mainnet_rpc_url: Some("https://api.mainnet-beta.solana.com".to_string()),
            mainnet_clone_accounts: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Informational.to_string(), "Informational");
    }

    #[test]
    fn test_severity_serde_roundtrip() {
        let sev = Severity::Critical;
        let json = serde_json::to_string(&sev).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }

    #[test]
    fn test_vulnerability_category_all_contains_all() {
        let all = VulnerabilityCategory::all();
        assert!(all.contains(&VulnerabilityCategory::TypeCosplay));
        assert!(all.contains(&VulnerabilityCategory::OwnershipCheck));
        assert!(all.contains(&VulnerabilityCategory::Generic));
        assert!(all.contains(&VulnerabilityCategory::StateTransitionGap));
        assert_eq!(all.len(), 21);
    }

    #[test]
    fn test_vulnerability_category_roundtrip() {
        // Only test categories that roundtrip uniquely (not aliased via from_str_checked)
        let unique_cats = [
            VulnerabilityCategory::TypeCosplay,
            VulnerabilityCategory::OwnershipCheck,
            VulnerabilityCategory::SignerAuthorization,
            VulnerabilityCategory::ArbitraryCpi,
            VulnerabilityCategory::InitializationFrontrunning,
            VulnerabilityCategory::ReentrancyRisk,
            VulnerabilityCategory::DuplicateMutableAccounts,
            VulnerabilityCategory::ArithmeticOverflow,
            VulnerabilityCategory::CloseAccount,
            VulnerabilityCategory::AccountReloading,
            VulnerabilityCategory::AccountDataMatching,
            VulnerabilityCategory::PdaPrivileges,
            VulnerabilityCategory::FuzzingCrash,
            VulnerabilityCategory::InvariantViolation,
            VulnerabilityCategory::MissingRevalidation,
            VulnerabilityCategory::UncheckedCast,
            VulnerabilityCategory::StateTransitionGap,
            VulnerabilityCategory::Generic,
        ];
        for cat in &unique_cats {
            let display = cat.to_string();
            let parsed = VulnerabilityCategory::from_str_checked(&display);
            assert_eq!(
                parsed,
                Some(cat.clone()),
                "Failed to roundtrip: {}",
                display
            );
        }
    }

    #[test]
    fn test_vulnerability_category_display() {
        assert_eq!(
            VulnerabilityCategory::TypeCosplay.to_string(),
            "type-cosplay"
        );
        assert_eq!(
            VulnerabilityCategory::SignerAuthorization.to_string(),
            "signer-authorization"
        );
        assert_eq!(
            VulnerabilityCategory::ArbitraryCpi.to_string(),
            "arbitrary-cpi"
        );
        assert_eq!(VulnerabilityCategory::Generic.to_string(), "generic");
    }

    #[test]
    fn test_vulnerability_category_serde() {
        let cat = VulnerabilityCategory::ReentrancyRisk;
        let json = serde_json::to_string(&cat).unwrap();
        assert_eq!(json, "\"reentrancy-risk\"");
        let back: VulnerabilityCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }

    #[test]
    fn test_vulnerability_category_from_str_aliases() {
        assert_eq!(
            VulnerabilityCategory::from_str_checked("reentrancy-risk"),
            Some(VulnerabilityCategory::ReentrancyRisk)
        );
        assert_eq!(
            VulnerabilityCategory::from_str_checked("reentrancy"),
            Some(VulnerabilityCategory::ReentrancyRisk)
        );
        assert_eq!(
            VulnerabilityCategory::from_str_checked("unknown-category"),
            None
        );
    }

    #[test]
    fn test_state_transition_gap_display_and_roundtrip() {
        assert_eq!(
            VulnerabilityCategory::StateTransitionGap.to_string(),
            "state-transition-gap"
        );
        assert_eq!(
            VulnerabilityCategory::from_str_checked("state-transition-gap"),
            Some(VulnerabilityCategory::StateTransitionGap)
        );
    }

    #[test]
    fn test_vulnerability_category_matches_ts_catalog() {
        // ENG-2: every VulnerabilityCategory variant (except the documented
        // "generic" fallback) must resolve, via the hand-maintained
        // reconciliation mapping, to a real VULN_CATALOG entry. This can't be
        // a literal Display-string-equals-catalog-id check: several variants
        // (e.g. OwnershipCheck -> missing-owner-check) are intentional
        // semantic collapses onto a differently-named catalog entry, not
        // exact matches -- the mapping file is the source of truth for how
        // those resolve, not this test. Both JSON files are checked-in
        // snapshots (the catalog one regenerated via
        // `npm run export:vuln-catalog`); solana-vulns.test.ts's freshness
        // test keeps the catalog snapshot from silently drifting.
        let mapping_json = include_str!("../../../../eval/mappings/ares-core-categories.json");
        let mapping: serde_json::Value = serde_json::from_str(mapping_json).unwrap();
        let categories = mapping["categories"].as_object().unwrap();

        let catalog_json = include_str!("../../../../src/knowledge/vuln-catalog.generated.json");
        let catalog: serde_json::Value = serde_json::from_str(catalog_json).unwrap();
        let catalog_ids: std::collections::HashSet<&str> = catalog
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect();

        for cat in VulnerabilityCategory::all() {
            let s = cat.to_string();
            let entry = categories.get(s.as_str()).unwrap_or_else(|| {
                panic!(
                    "VulnerabilityCategory::{:?} (\"{}\") has no entry in \
                     eval/mappings/ares-core-categories.json",
                    cat, s
                )
            });
            match entry["vuln_catalog_id"].as_str() {
                Some(catalog_id) => assert!(
                    catalog_ids.contains(catalog_id),
                    "VulnerabilityCategory::{:?} (\"{}\") maps to catalog id \
                     \"{}\" per ares-core-categories.json, but that id does not \
                     exist in vuln-catalog.generated.json",
                    cat,
                    s,
                    catalog_id
                ),
                None => assert_eq!(
                    s, "generic",
                    "VulnerabilityCategory::{:?} (\"{}\") has a null vuln_catalog_id \
                     in ares-core-categories.json but is not the documented \
                     \"generic\" exception",
                    cat, s
                ),
            }
        }
    }

    #[test]
    fn test_finding_default_values() {
        let finding = Finding {
            id: "F-001".to_string(),
            title: "Test".to_string(),
            description: "Desc".to_string(),
            severity: Severity::High,
            category: VulnerabilityCategory::OwnershipCheck,
            location: CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "Fix".to_string(),
            references: vec![],
            confidence: 0.8,
            validation: None,
        };
        assert_eq!(finding.id, "F-001");
        assert_eq!(finding.category, VulnerabilityCategory::OwnershipCheck);
        assert_eq!(finding.confidence, 0.8);
    }

    #[test]
    fn test_code_location_default() {
        let loc = CodeLocation::default();
        assert!(loc.file.as_os_str().is_empty());
        assert!(loc.line_start.is_none());
        assert!(loc.line_end.is_none());
    }

    #[test]
    fn test_ares_error_display() {
        let err = AresError::Config("missing field".to_string());
        assert_eq!(err.to_string(), "Config error: missing field");

        let err = AresError::Parse("invalid json".to_string());
        assert_eq!(err.to_string(), "Parse error: invalid json");

        let err = AresError::Execution("timeout".to_string());
        assert_eq!(err.to_string(), "Execution failed: timeout");
    }

    #[test]
    fn test_benchmark_result_defaults() {
        let result = BenchmarkResult {
            protocol_name: "test".to_string(),
            source: "stub".to_string(),
            total_critical_high: 5,
            detected_critical_high: 4,
            false_positives: 1,
            false_negatives: 1,
            known_audit_recall: 0.8,
            fp_rate: 0.2,
            poc_success_rate: 0.0,
            execution_time_secs: 10,
            economic_score_lamports: 1_000_000,
            precision: 0.8,
            recall: 0.8,
            f1_score: 0.8,
            detected_categories: vec!["type-cosplay".to_string()],
            total_findings: 5,
        };
        assert_eq!(result.protocol_name, "test");
        assert_eq!(result.detected_categories.len(), 1);
    }

    #[test]
    fn test_llm_provider_default_is_disabled() {
        let provider = LlmProvider::default();
        assert_eq!(provider, LlmProvider::Disabled);
    }

    #[test]
    fn test_config_default() {
        let config = AresConfig::default();
        assert_eq!(config.llm_provider, LlmProvider::Disabled);
        assert!(!config.llm_judge_enabled);
        assert_eq!(config.llm_model, "claude-3-5-sonnet");
    }

    #[test]
    fn test_report_summary_default() {
        let summary = ReportSummary::default();
        assert_eq!(summary.total_findings, 0);
        assert_eq!(summary.total_economic_impact_lamports, 0);
    }

    #[test]
    fn test_serde_json_finding() {
        let finding = Finding {
            id: "F-001".to_string(),
            title: "Test".to_string(),
            description: "Desc".to_string(),
            severity: Severity::Critical,
            category: VulnerabilityCategory::ArbitraryCpi,
            location: CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "Fix".to_string(),
            references: vec!["ref1".to_string()],
            confidence: 0.95,
            validation: Some(ValidationOutcome::Confirmed),
        };
        let json = serde_json::to_string_pretty(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding.id, back.id);
        assert_eq!(finding.category, back.category);
        assert_eq!(finding.severity, back.severity);
        assert_eq!(finding.references, back.references);
        assert_eq!(finding.validation, back.validation);
    }

    #[test]
    fn test_finding_validation_defaults_to_none_when_absent_from_json() {
        // Backward compatibility: reports written before this field existed
        // (no "validation" key at all) must still deserialize.
        let json = r#"{
            "id": "F-002",
            "title": "t",
            "description": "d",
            "severity": "High",
            "category": "generic",
            "location": { "file": "", "line_start": null, "line_end": null,
                "column_start": null, "column_end": null, "function": null, "commit": null },
            "proof_of_concept": null,
            "recommendation": "r",
            "references": [],
            "confidence": 0.5
        }"#;
        let finding: Finding = serde_json::from_str(json).unwrap();
        assert_eq!(finding.validation, None);
    }

    #[test]
    fn test_validation_outcome_display_and_serde() {
        assert_eq!(ValidationOutcome::Confirmed.to_string(), "confirmed");
        assert_eq!(ValidationOutcome::Refuted.to_string(), "refuted");
        assert_eq!(ValidationOutcome::Inconclusive.to_string(), "inconclusive");

        let json = serde_json::to_string(&ValidationOutcome::Refuted).unwrap();
        assert_eq!(json, "\"refuted\"");
        let back: ValidationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ValidationOutcome::Refuted);
    }
}
