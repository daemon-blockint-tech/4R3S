use std::collections::HashSet;

/// Extracted boolean metadata from Phase 2 AST scanning.
/// Used by the Phase 4 Local Judge for deterministic false-positive suppression.
#[derive(Debug, Clone, Default)]
pub struct SourcePatterns {
    /// True if anchor_field_count > 5 && typed_anchor_fields > count/2
    pub is_anchor_heavy: bool,
    /// Number of UncheckedAccount or AccountInfo fields
    pub unchecked_fields: usize,
    /// True if there's any function handler with a raw AccountInfo parameter
    pub has_raw_handler: bool,
    /// True if ALL `invoke` or `invoke_signed` calls are preceded by a program_id check
    pub cpi_all_validated: bool,
    /// True if there's a CpiContext::new_with_signer (Anchor CPI) usage
    pub has_typed_program: bool,
    /// True if there is a raw invoke() call without preceding validation
    pub has_raw_unvalidated_cpi: bool,
    /// Set of accounts that are written to
    pub write_accounts: HashSet<String>,
    /// Set of accounts that are passed to CPI
    pub cpi_accounts: HashSet<String>,
    /// Extended v29 heuristic: true if the program has > 1000 instructions/functions
    /// (proxy for a very large DEX like Mango or Drift)
    pub is_large_dex: bool,
    /// Extended v29 heuristic: true if the program mixes raw Rust and Anchor heavily,
    /// meaning we shouldn't suppress as aggressively as pure Anchor
    pub is_mixed_architecture: bool,
}
