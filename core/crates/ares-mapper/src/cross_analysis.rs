use ares_core::AresResult;
use std::collections::{BTreeMap, BTreeSet};
use tracing::info;

use crate::{AccountEffect, ProgramGraph};

/// Cross-instruction data-flow analyzer.
/// Detects vulnerabilities that only appear when looking at the interaction
/// between multiple instructions (TOCTOU, missing re-validation, re-entrancy).
// BTreeMap iteration is sorted by account name, keeping finding order and
// descriptions deterministic.
#[derive(Debug, Clone, Default)]
pub struct CrossInstructionAnalyzer {
    /// For each account name, which instructions write to it.
    pub writes: BTreeMap<String, Vec<String>>,
    /// For each account name, which instructions read from it.
    pub reads: BTreeMap<String, Vec<String>>,
    /// For each account name, which instructions create (init) it.
    pub creates: BTreeMap<String, Vec<String>>,
    /// For each account name, which instructions close it.
    pub closes: BTreeMap<String, Vec<String>>,
}

/// A vulnerability that only manifests across instruction boundaries.
#[derive(Debug, Clone)]
pub struct CrossInstructionFinding {
    pub category: String,
    pub description: String,
    pub affected_account: String,
    pub source_instruction: String,
    pub sink_instruction: String,
    pub confidence: f64,
}

impl CrossInstructionAnalyzer {
    /// Build the read/write/create/close maps from a ProgramGraph.
    pub fn from_graph(graph: &ProgramGraph) -> AresResult<Self> {
        let mut analyzer = Self::default();

        for instr in &graph.instructions {
            for (account, effect) in &instr.effects {
                match effect {
                    AccountEffect::Read => {
                        analyzer
                            .reads
                            .entry(account.clone())
                            .or_default()
                            .push(instr.name.clone());
                    }
                    AccountEffect::Write => {
                        analyzer
                            .writes
                            .entry(account.clone())
                            .or_default()
                            .push(instr.name.clone());
                    }
                    AccountEffect::Create => {
                        analyzer
                            .creates
                            .entry(account.clone())
                            .or_default()
                            .push(instr.name.clone());
                        // A creation also counts as a write
                        analyzer
                            .writes
                            .entry(account.clone())
                            .or_default()
                            .push(instr.name.clone());
                    }
                    AccountEffect::Close => {
                        analyzer
                            .closes
                            .entry(account.clone())
                            .or_default()
                            .push(instr.name.clone());
                        // A close is also a write
                        analyzer
                            .writes
                            .entry(account.clone())
                            .or_default()
                            .push(instr.name.clone());
                    }
                    AccountEffect::CpiPass => {
                        // CPI pass does not directly change local read/write maps;
                        // it is used in re-entrancy risk analysis separately.
                    }
                }
            }
        }

        info!(
            "CrossInstructionAnalyzer built | {} read accounts | {} write accounts | {} create | {} close",
            analyzer.reads.len(),
            analyzer.writes.len(),
            analyzer.creates.len(),
            analyzer.closes.len()
        );

        Ok(analyzer)
    }

    /// Detect missing re-validation of an account between instructions.
    /// If instruction A writes to account X, and instruction B later uses X
    /// without re-checking signer / ownership / state, that's a TOCTOU risk.
    pub fn find_missing_revalidation(&self, graph: &ProgramGraph) -> Vec<CrossInstructionFinding> {
        let mut findings = Vec::new();

        for (account, writers) in &self.writes {
            // Find which instructions read this account after it could have been written
            if let Some(readers) = self.reads.get(account) {
                for writer in writers {
                    for reader in readers {
                        if writer == reader {
                            continue; // same instruction is fine (local check)
                        }

                        // Check if the reader re-validates the account
                        let reader_instr = graph.instructions.iter().find(|i| i.name == *reader);
                        let revalidates = reader_instr.is_some_and(|i| {
                            // If the reader has a signer or owner check, we consider it re-validated
                            i.has_signer_check.unwrap_or(false)
                                || i.has_owner_check.unwrap_or(false)
                        });

                        if !revalidates {
                            findings.push(CrossInstructionFinding {
                                category: "missing-revalidation".to_string(),
                                description: format!(
                                    "Account '{}' is written by '{}' but read by '{}' without re-validation of signer/owner.",
                                    account, writer, reader
                                ),
                                affected_account: account.clone(),
                                source_instruction: writer.clone(),
                                sink_instruction: reader.clone(),
                                confidence: 0.75,
                            });
                        }
                    }
                }
            }
        }

        if !findings.is_empty() {
            info!(
                "Cross-instruction analysis: {} missing re-validation findings",
                findings.len()
            );
        }

        findings
    }

    /// Detect re-entrancy risks via CPI.
    /// If an instruction performs a CPI to an external program, and that program
    /// could invoke back into the current program on a shared writable account,
    /// flag it.
    pub fn find_reentrancy_risk(&self, graph: &ProgramGraph) -> Vec<CrossInstructionFinding> {
        let mut findings = Vec::new();

        for instr in &graph.instructions {
            if !instr.uses_cpi {
                continue;
            }

            // Collect all accounts this instruction writes to AND passes to CPI
            // (BTreeSet so the intersection below is sorted/deterministic).
            let written_accounts: BTreeSet<String> = instr
                .effects
                .iter()
                .filter(|(_, e)| {
                    matches!(
                        e,
                        AccountEffect::Write | AccountEffect::Create | AccountEffect::Close
                    )
                })
                .map(|(name, _)| name.clone())
                .collect();

            let cpi_accounts: BTreeSet<String> = instr
                .effects
                .iter()
                .filter(|(_, e)| matches!(e, AccountEffect::CpiPass))
                .map(|(name, _)| name.clone())
                .collect();

            let intersection: Vec<String> = written_accounts
                .intersection(&cpi_accounts)
                .cloned()
                .collect();

            if !intersection.is_empty() {
                findings.push(CrossInstructionFinding {
                    category: "reentrancy-risk".to_string(),
                    description: format!(
                        "Instruction '{}' passes writable accounts ({:?}) to CPI without re-entrancy guards.",
                        instr.name, intersection
                    ),
                    affected_account: intersection.join(", "),
                    source_instruction: instr.name.clone(),
                    sink_instruction: "external_cpi".to_string(),
                    confidence: 0.70,
                });
            }
        }

        findings
    }

    /// Detect state transition gaps.
    /// If an account is created in instruction A but never properly initialized
    /// (no init check in subsequent instructions that write to it), flag it.
    pub fn find_state_transition_gaps(&self, graph: &ProgramGraph) -> Vec<CrossInstructionFinding> {
        let mut findings = Vec::new();

        for (account, creators) in &self.creates {
            // After creation, every subsequent writer should have an init check
            if let Some(writers) = self.writes.get(account) {
                for writer in writers {
                    if creators.contains(writer) {
                        continue; // the creator itself is expected to init
                    }

                    let writer_instr = graph.instructions.iter().find(|i| i.name == *writer);
                    let has_init_check = writer_instr
                        .and_then(|_i| {
                            // Look for any account in the graph matching this writer that has init check
                            graph.accounts.iter().find(|a| a.name == *account)
                        })
                        .is_some_and(|a| a.is_initialized_check.unwrap_or(false));

                    if !has_init_check {
                        findings.push(CrossInstructionFinding {
                            category: "state-transition-gap".to_string(),
                            description: format!(
                                "Account '{}' is created by '{}' but written by '{}' without initialization re-check.",
                                account, creators.join(", "), writer
                            ),
                            affected_account: account.clone(),
                            source_instruction: creators[0].clone(),
                            sink_instruction: writer.clone(),
                            confidence: 0.65,
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Analyze the full ProgramGraph for cross-instruction vulnerabilities.
/// Returns all findings from every analyzer module.
pub fn analyze(graph: &ProgramGraph) -> AresResult<Vec<CrossInstructionFinding>> {
    let analyzer = CrossInstructionAnalyzer::from_graph(graph)?;

    let mut all = Vec::new();
    all.extend(analyzer.find_missing_revalidation(graph));
    all.extend(analyzer.find_reentrancy_risk(graph));
    all.extend(analyzer.find_state_transition_gaps(graph));

    if !all.is_empty() {
        info!(
            "Cross-instruction analysis complete: {} findings",
            all.len()
        );
    } else {
        info!(
            "Cross-instruction analysis complete: no cross-instruction vulnerabilities detected."
        );
    }

    Ok(all)
}
