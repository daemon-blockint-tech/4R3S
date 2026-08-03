use ares_core::{Finding, Severity, VulnerabilityCategory};
use tracing::info;

/// Economic exploit scorer (SCONE-bench inspired).
///
/// Translates vulnerability categories into estimated extractable value
/// measured in lamports (1 SOL = 1_000_000_000 lamports).
///
/// This is a heuristic model; real extraction depends on program state,
/// but the scoring allows ARES to prioritize findings by economic impact
/// and to compare against Trident Arena (which has no economic metric).
///
/// Scoring rules:
/// - Critical / reentrancy / arbitrary CPI with writable accounts: full account drain (up to 1_000_000_000)
/// - High / missing signer / owner: partial drain or unauthorized transfer (up to 500_000_000)
/// - Medium / initialization / revival: griefing or state corruption (up to 100_000_000)
/// - Low / informational: minimal direct value (up to 10_000_000)
/// - Fuzz crash / invariant violation: potential for full drain if exploitable (up to 1_000_000_000)
pub struct ExploitScorer;

impl ExploitScorer {
    /// Score a single finding and return estimated max extractable lamports.
    pub fn score_finding(finding: &Finding) -> u64 {
        let base = match finding.severity {
            Severity::Critical => 1_000_000_000u64,
            Severity::High => 500_000_000u64,
            Severity::Medium => 100_000_000u64,
            Severity::Low => 10_000_000u64,
            Severity::Informational => 1_000_000u64,
        };

        let multiplier = match &finding.category {
            VulnerabilityCategory::ReentrancyRisk
            | VulnerabilityCategory::ArbitraryCpi
            | VulnerabilityCategory::InvariantViolation => 10,
            VulnerabilityCategory::SignerAuthorization | VulnerabilityCategory::OwnershipCheck => 5,
            VulnerabilityCategory::InitializationFrontrunning
            | VulnerabilityCategory::AccountReloading => 3,
            VulnerabilityCategory::FuzzingCrash => 8,
            VulnerabilityCategory::MissingRevalidation => 4,
            _ => 1,
        };

        // Confidence dampens the score: low-confidence findings are less likely
        // to be reliably exploitable in practice.
        let confidence_dampener = (finding.confidence * 10.0).clamp(1.0, 10.0) as u64;

        let raw = base.saturating_mul(multiplier);
        let dampened = raw.saturating_mul(confidence_dampener) / 10;

        // Cap at 10 SOL to avoid absurd outliers
        dampened.min(10_000_000_000)
    }

    /// Score an entire report and return total + max.
    pub fn score_report(findings: &[Finding]) -> (u64, u64) {
        let mut total = 0u64;
        let mut max_single = 0u64;

        for finding in findings {
            let score = Self::score_finding(finding);
            total = total.saturating_add(score);
            max_single = max_single.max(score);
        }

        info!(
            "Economic scoring complete | total={} lamports ({:.4} SOL) | max_single={} lamports ({:.4} SOL)",
            total,
            total as f64 / 1_000_000_000.0,
            max_single,
            max_single as f64 / 1_000_000_000.0
        );

        (total, max_single)
    }
}
