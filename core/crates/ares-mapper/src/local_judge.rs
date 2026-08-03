use crate::source_patterns::SourcePatterns;
use ares_core::{Finding, SuppressedFinding, VulnerabilityCategory};
use tracing::info;

/// Phase 4 Deterministic Local Judge
/// Suppresses systematic false positives using AST metadata (SourcePatterns).
/// Fully deterministic: no LLM, no network, identical output for identical AST.
pub struct LocalJudge {
    extended_heuristics: bool,
}

impl LocalJudge {
    pub fn new(extended_heuristics: bool) -> Self {
        Self {
            extended_heuristics,
        }
    }

    /// Evaluates a list of findings against the source patterns.
    /// Returns (retained_findings, suppressed_findings).
    pub fn judge(
        &self,
        findings: Vec<Finding>,
        patterns: &SourcePatterns,
    ) -> (Vec<Finding>, Vec<SuppressedFinding>) {
        let mut retained = Vec::new();
        let mut suppressed = Vec::new();

        for finding in findings {
            let cat = &finding.category;

            let mut should_suppress = false;
            let mut reason = String::new();

            // Rule 1: Type Cosplay
            if matches!(
                cat,
                VulnerabilityCategory::TypeCosplay | VulnerabilityCategory::OwnershipCheck
            ) && patterns.is_anchor_heavy
                && patterns.unchecked_fields == 0
            {
                should_suppress = true;
                reason = "Anchor-heavy protocol with fully typed accounts automatically validates discriminator/ownership.".to_string();
            }

            // Rule 2: Signer Authorization
            if matches!(cat, VulnerabilityCategory::SignerAuthorization)
                && patterns.is_anchor_heavy
                && !patterns.has_raw_handler
            {
                should_suppress = true;
                reason = "Anchor-heavy protocol with no raw AccountInfo handlers uses Anchor's Signer<'info> for validation.".to_string();
            }

            // Rule 3: Arbitrary CPI
            if matches!(cat, VulnerabilityCategory::ArbitraryCpi) {
                if patterns.cpi_all_validated {
                    should_suppress = true;
                    reason = "All CPI calls are preceded by explicit program_id validation in the same basic block.".to_string();
                } else if patterns.has_typed_program && !patterns.has_raw_unvalidated_cpi {
                    should_suppress = true;
                    reason = "CPI is done via Anchor CpiContext (typed program ID) and no raw unvalidated invoke() exists.".to_string();
                }
            }

            // Rule 4: Reentrancy Risk
            if matches!(cat, VulnerabilityCategory::ReentrancyRisk) {
                let overlap: Vec<_> = patterns
                    .write_accounts
                    .intersection(&patterns.cpi_accounts)
                    .collect();
                if overlap.is_empty() {
                    should_suppress = true;
                    reason = "No account is both written to and passed to a CPI call within the same instruction.".to_string();
                }
            }

            // Extended v29 Heuristics (if enabled)
            if self.extended_heuristics {
                // Large DEXes (Drift, Mango) often have complex nested structs where simple taint misses the bounds checks
                if patterns.is_large_dex && matches!(cat, VulnerabilityCategory::UncheckedCast) {
                    // Be more forgiving on unchecked-cast if we know it's a huge DEX with custom math wrappers
                    // (Drift/Mango use massive custom I80F48 / fixed point math that looks like unchecked casts to simple AST)
                    if finding.description.contains("as u64") {
                        should_suppress = true;
                        reason = "Extended v29 heuristic: large DEX uses custom fixed-point math wrappers.".to_string();
                    }
                }

                if matches!(cat, VulnerabilityCategory::DuplicateMutableAccounts)
                    && patterns.is_anchor_heavy
                {
                    should_suppress = true;
                    reason = "Extended v29 heuristic: Anchor naturally prevents duplicate mutable accounts via constraints.".to_string();
                }
            }

            if should_suppress {
                suppressed.push(SuppressedFinding {
                    finding,
                    reason,
                    suppressed_by: "local_judge".to_string(),
                });
            } else {
                retained.push(finding);
            }
        }

        info!(
            "Local Judge: Suppressed {} false positives deterministically",
            suppressed.len()
        );
        (retained, suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::{CodeLocation, Finding, Severity, VulnerabilityCategory};

    fn dummy_finding(category: VulnerabilityCategory) -> Finding {
        Finding {
            id: "1".to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            category,
            location: CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "Fix".to_string(),
            references: vec![],
            confidence: 0.8,
        }
    }

    #[test]
    fn test_suppress_type_cosplay() {
        let judge = LocalJudge::new(false);
        let findings = vec![dummy_finding(VulnerabilityCategory::TypeCosplay)];
        let patterns = SourcePatterns {
            is_anchor_heavy: true,
            ..Default::default()
        };

        let (retained, suppressed) = judge.judge(findings, &patterns);
        assert_eq!(retained.len(), 0);
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].suppressed_by, "local_judge");
    }

    #[test]
    fn test_retain_type_cosplay() {
        let judge = LocalJudge::new(false);
        let findings = vec![dummy_finding(VulnerabilityCategory::TypeCosplay)];
        let patterns = SourcePatterns {
            is_anchor_heavy: true,
            unchecked_fields: 1,
            ..Default::default()
        };

        let (retained, suppressed) = judge.judge(findings, &patterns);
        assert_eq!(retained.len(), 1);
        assert_eq!(suppressed.len(), 0);
    }
}
