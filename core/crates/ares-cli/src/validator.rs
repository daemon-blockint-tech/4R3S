use ares_core::{Finding, Severity, VulnerabilityCategory};
use ares_mapper::{AccountEffect, InstructionNode, ProgramGraph};
use tracing::{info, warn};

/// Semantic false-positive filter for ARES findings.
///
/// Many static-analysis heuristics produce false positives when looked at in isolation.
/// This validator uses the ProgramGraph to suppress findings that are structurally
/// implausible, reducing FP rates toward the <15% target.
///
/// Rules implemented:
/// 1. Missing-signer on read-only / non-privileged accounts → LOW or suppressed.
/// 2. Missing-owner on PDAs (implicit owner = program) → suppressed.
/// 3. Arithmetic finding on checked-math operations → suppressed.
/// 4. Cross-instruction re-validation where the account is never actually mutated → suppressed.
pub struct SemanticValidator<'a> {
    graph: &'a ProgramGraph,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub finding: Finding,
    pub suppressed: bool,
    pub reason: Option<String>,
}

impl<'a> SemanticValidator<'a> {
    pub fn new(graph: &'a ProgramGraph) -> Self {
        Self { graph }
    }

    /// Run the full validation pipeline over a list of findings.
    pub fn validate(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let mut validated = Vec::new();
        let mut suppressed_count = 0usize;

        let total = findings.len();
        for finding in findings {
            match self.check(&finding) {
                ValidationResult {
                    finding: mut f,
                    suppressed: false,
                    reason: Some(reason),
                } => {
                    // Downgraded but kept
                    warn!("Finding {} downgraded: {}", f.id, reason);
                    // Lower confidence slightly
                    f.confidence *= 0.9;
                    validated.push(f);
                }
                ValidationResult {
                    finding: _,
                    suppressed: true,
                    reason: Some(reason),
                } => {
                    suppressed_count += 1;
                    info!("Finding suppressed (FP filter): {}", reason);
                }
                ValidationResult {
                    finding: f,
                    suppressed: false,
                    reason: None,
                } => {
                    validated.push(f);
                }
                ValidationResult {
                    finding: f,
                    suppressed: true,
                    reason: None,
                } => {
                    // Should not happen in practice (suppressed always has a reason), but handle gracefully
                    suppressed_count += 1;
                    info!("Finding {} suppressed without stated reason", f.id);
                }
            }
        }

        if suppressed_count > 0 {
            info!(
                "Semantic FP filter: {} of {} findings suppressed",
                suppressed_count, total
            );
        }

        validated
    }

    /// Evaluate a single finding against the graph.
    fn check(&self, finding: &Finding) -> ValidationResult {
        match &finding.category {
            VulnerabilityCategory::SignerAuthorization => self.check_signer(finding),
            VulnerabilityCategory::OwnershipCheck => self.check_owner(finding),
            VulnerabilityCategory::ArbitraryCpi => self.check_cpi(finding),
            VulnerabilityCategory::InitializationFrontrunning
            | VulnerabilityCategory::ReInitialization => self.check_init(finding),
            VulnerabilityCategory::FuzzingCrash | VulnerabilityCategory::InvariantViolation => {
                self.check_fuzz(finding)
            }
            VulnerabilityCategory::MissingRevalidation => self.check_revalidation(finding),
            _ => ValidationResult {
                finding: finding.clone(),
                suppressed: false,
                reason: None,
            },
        }
    }

    /// Rule 1: If the instruction does not perform any privileged operation
    /// (no writes, no CPI, no state changes), a missing signer check is likely benign.
    fn check_signer(&self, finding: &Finding) -> ValidationResult {
        let instr_name = finding.location.function.as_deref().unwrap_or("unknown");

        if let Some(instr) = self.find_instruction(instr_name) {
            let has_effects = !instr.effects.is_empty();
            let does_writes = instr.effects.iter().any(|(_, e)| {
                matches!(
                    e,
                    AccountEffect::Write | AccountEffect::Create | AccountEffect::Close
                )
            });
            let does_cpi = instr.uses_cpi;

            if !does_writes && !does_cpi && has_effects {
                return ValidationResult {
                    finding: finding.clone(),
                    suppressed: true,
                    reason: Some(format!(
                        "Instruction '{}' has no writes/CPI - missing signer is likely benign.",
                        instr.name
                    )),
                };
            }
        }

        ValidationResult {
            finding: finding.clone(),
            suppressed: false,
            reason: None,
        }
    }

    /// Rule 2: If the account is a PDA (has seeds) or is owned by the program
    /// implicitly, a missing owner check is often a false positive.
    fn check_owner(&self, finding: &Finding) -> ValidationResult {
        // Suppress only when the finding's OWN account has PDA seeds — the
        // presence of an unrelated seeded account elsewhere in the graph says
        // nothing about this finding. The account name is recovered from the
        // title ("<category>: <account>") or from the quoted name in the
        // description (same heuristic as check_revalidation).
        let account_name = finding
            .title
            .split(": ")
            .nth(1)
            .map(|s| s.to_string())
            .or_else(|| {
                finding
                    .description
                    .split('\'')
                    .nth(1)
                    .map(|s| s.to_string())
            });

        if let Some(name) = account_name {
            if let Some(account) = self.graph.accounts.iter().find(|a| a.name == name) {
                if account.seeds.is_some() {
                    return ValidationResult {
                        finding: finding.clone(),
                        suppressed: true,
                        reason: Some(format!(
                            "Account '{}' has PDA seeds - implicit program ownership; owner check FP suppressed.",
                            name
                        )),
                    };
                }
            }
        }

        ValidationResult {
            finding: finding.clone(),
            suppressed: false,
            reason: None,
        }
    }

    /// Rule 3: Arbitrary CPI is only a real concern if the CPI passes
    /// a writable account to an unchecked program.
    fn check_cpi(&self, finding: &Finding) -> ValidationResult {
        let instr_name = finding.location.function.as_deref().unwrap_or("unknown");

        if let Some(instr) = self.find_instruction(instr_name) {
            let passes_writable = instr
                .effects
                .iter()
                .any(|(_, e)| matches!(e, AccountEffect::CpiPass | AccountEffect::Write));

            if !passes_writable {
                return ValidationResult {
                    finding: finding.clone(),
                    suppressed: true,
                    reason: Some(format!(
                        "Instruction '{}' does not pass writable accounts to CPI - arbitrary CPI risk is minimal.",
                        instr.name
                    )),
                };
            }
        }

        ValidationResult {
            finding: finding.clone(),
            suppressed: false,
            reason: None,
        }
    }

    /// Rule 4: Initialization findings are only relevant if the account
    /// is actually created in the program and is mutable.
    fn check_init(&self, finding: &Finding) -> ValidationResult {
        let account_name = finding.location.function.as_deref().unwrap_or("unknown");

        if let Some(account) = self.graph.accounts.iter().find(|a| a.name == account_name) {
            if !account.is_mutable {
                return ValidationResult {
                    finding: finding.clone(),
                    suppressed: true,
                    reason: Some(format!(
                        "Account '{}' is immutable - initialization frontrunning not applicable.",
                        account.name
                    )),
                };
            }
        }

        ValidationResult {
            finding: finding.clone(),
            suppressed: false,
            reason: None,
        }
    }

    /// Rule 5: Fuzz crashes / invariant violations are always kept (they
    /// represent real runtime behavior), but downgrade confidence if no
    /// corresponding static-analysis finding exists.
    fn check_fuzz(&self, finding: &Finding) -> ValidationResult {
        // Fuzz findings are never fully suppressed because they are runtime evidence.
        // However, if confidence is very low, downgrade severity.
        if finding.confidence < 0.5 {
            let mut f = finding.clone();
            f.severity = Severity::Low;
            return ValidationResult {
                finding: f,
                suppressed: false,
                reason: Some("Low-confidence fuzz finding downgraded to Low.".to_string()),
            };
        }

        ValidationResult {
            finding: finding.clone(),
            suppressed: false,
            reason: None,
        }
    }

    /// Rule 6: Missing re-validation is only relevant if the account
    /// is actually written in one instruction and read in another.
    fn check_revalidation(&self, finding: &Finding) -> ValidationResult {
        let account = &finding.description; // heuristic: use description to extract account name
        let account_name = account.split('\'').nth(1).unwrap_or("unknown");

        let written = self.graph.instructions.iter().any(|i| {
            i.effects.iter().any(|(a, e)| {
                a == account_name
                    && matches!(
                        e,
                        AccountEffect::Write | AccountEffect::Create | AccountEffect::Close
                    )
            })
        });

        if !written {
            return ValidationResult {
                finding: finding.clone(),
                suppressed: true,
                reason: Some(format!(
                    "Account [{}] is never written - missing re-validation is not a concern.",
                    account_name
                )),
            };
        }

        ValidationResult {
            finding: finding.clone(),
            suppressed: false,
            reason: None,
        }
    }

    fn find_instruction(&self, name: &str) -> Option<&InstructionNode> {
        self.graph.instructions.iter().find(|i| i.name == name)
    }
}
