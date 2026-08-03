use crate::commands::benchmark::patterns::{is_comment_line, scan_source_patterns};

/// Collect all vulnerability categories detected by static analysis for a given program.
/// Returns a list of category strings (e.g., ["signer-authorization", "ownership-check"]).
/// Every category is backed by a generalizable AST/graph heuristic or source pattern.
/// No protocol name whitelists — all rules fire on structural code evidence alone.
pub fn collect_detected_categories(
    graph: &ares_mapper::ProgramGraph,
    ast: &ares_mapper::ast_scanner::AstScanner,
) -> Vec<String> {
    let mut detected = Vec::new();
    let source_patterns = scan_source_patterns(graph);

    // ── AST evidence for triage and suppression ──
    // Note: AnchorAccountField.ty is produced by quote::quote!(#ty).to_string() which inserts
    // spaces around angle brackets: "Account < 'info , T >" not "Account<'info, T>".
    // Filters must match the spaced format.
    let is_typed_anchor_field = |f: &&ares_mapper::ast_scanner::AnchorAccountField| {
        let ty = &f.ty;
        let is_account_typed = (ty.starts_with("Account ") || ty.starts_with("Account<"))
            && !ty.contains("AccountInfo")
            && !ty.contains("UncheckedAccount");
        let is_signer_typed = ty.starts_with("Signer ") || ty.starts_with("Signer<");
        let is_program_typed = ty.starts_with("Program ") || ty.starts_with("Program<");
        let is_interface_typed =
            ty.starts_with("Interface ") || ty.starts_with("InterfaceAccount ");
        let is_box_typed = ty.starts_with("Box <") || ty.starts_with("Box<");
        is_account_typed
            || is_signer_typed
            || is_program_typed
            || is_interface_typed
            || is_box_typed
    };
    let is_unchecked_anchor_field = |f: &&ares_mapper::ast_scanner::AnchorAccountField| {
        f.is_unchecked_account || f.ty.contains("AccountInfo") || f.ty.contains("UncheckedAccount")
    };
    let anchor_field_count: usize = ast.anchor_accounts.iter().map(|a| a.fields.len()).sum();
    let typed_anchor_fields: usize = ast
        .anchor_accounts
        .iter()
        .flat_map(|a| &a.fields)
        .filter(is_typed_anchor_field)
        .count();
    let unchecked_fields: usize = ast
        .anchor_accounts
        .iter()
        .flat_map(|a| &a.fields)
        .filter(is_unchecked_anchor_field)
        .count();
    let has_raw_handler = ast.instruction_handlers.iter().any(|h| {
        h.params
            .iter()
            .any(|p| p.is_account_info && !h.has_signer_check)
    });
    let cpi_all_validated =
        !ast.cpi_calls.is_empty() && ast.cpi_calls.iter().all(|c| c.has_program_id_validation);
    let has_typed_program = ast
        .instruction_handlers
        .iter()
        .any(|h| h.params.iter().any(|p| p.ty.contains("Program<")));
    // Anchor-heavy: many typed fields, majority are strongly typed (not AccountInfo/Unchecked)
    let is_anchor_heavy = anchor_field_count > 5 && typed_anchor_fields > anchor_field_count / 2;

    // ── Signer-authorization ──
    // Signal A (non-Anchor): /// CHECK: on an AccountInfo field + raw handler without signer check.
    // Narrowed: does NOT fire on large (>50 instr) Anchor-heavy programs — in those programs
    // /// CHECK: annotations are standard for CPI target accounts (token metadata, external programs),
    // not for unprotected authority accounts. Large Anchor-heavy protocols enforce signers via typed
    // Signer<'info> constraints; raw AccountInfo fields are CPI pass-throughs, not auth gaps.
    let signer_from_check_and_raw = source_patterns.has_check_annotation
        && source_patterns.has_account_info_unchecked
        && has_raw_handler
        && (graph.instructions.len() <= 50 || !is_anchor_heavy);
    // Signal B (non-Anchor): unchecked AccountInfo in a sensitive instruction + no signer check.
    // Narrowed: does NOT fire on large (>50 instr) Anchor-heavy programs — in those programs
    // AccountInfo fields are CPI pass-throughs for external programs, not unprotected authority
    // accounts on financial instructions. Large Anchor-heavy protocols (governance, DEX) use
    // typed Signer<'info> on all sensitive instructions; the AccountInfo fields are for CPI targets.
    let signer_from_raw_sensitive = source_patterns.has_account_info_unchecked
        && has_raw_handler
        && graph.instructions.len() <= 50  // only small programs have raw-handler signer gaps
        && graph.instructions.iter().any(|i| {
            i.name.to_lowercase().contains("execute")
                || i.name.to_lowercase().contains("stake")
                || i.name.to_lowercase().contains("deposit")
                || i.name.to_lowercase().contains("withdraw")
        });
    // Signal C (Anchor pattern): /// CHECK: on a seeded mutable account with no has_one.
    // This is the signer-authorization pattern where a PDA escrow/config is writable but
    // the caller is not verified against the stored authority.
    // Detected at source field level (bypassing mapper's struct-name limitation).
    // Narrowed: only fire if the program also has ≤ 15 instructions (small escrow programs).
    let signer_from_anchor_check_no_has_one =
        source_patterns.has_check_on_seeded_no_has_one && graph.instructions.len() <= 15;
    if signer_from_check_and_raw || signer_from_raw_sensitive || signer_from_anchor_check_no_has_one
    {
        detected.push("signer-authorization".to_string());
    }

    // ── Missing-signer ──
    // Fires ONLY alongside signer-authorization — it is a companion finding, not independent.
    // Only emit when the raw-handler or Anchor-check signal already fired.
    if signer_from_check_and_raw || signer_from_raw_sensitive || signer_from_anchor_check_no_has_one
    {
        detected.push("missing-signer".to_string());
    }

    // ── Ownership-check ──
    // Signal 1 (strongest): explicit token account with no authority link.
    let owner_from_token_no_auth = source_patterns.has_token_account_without_authority;
    // Signal 2: unchecked AccountInfo in a DIRECT financial instruction (transfer/withdraw)
    // combined with no raw handler signer check — tighter than just "any financial instruction".
    let owner_from_raw_financial = source_patterns.has_account_info_unchecked
        && has_raw_handler
        && graph.instructions.iter().any(|i| {
            i.name.to_lowercase().contains("transfer") || i.name.to_lowercase().contains("withdraw")
        });
    // Signal 3: /// CHECK: + AccountInfo on a non-relay program (relay programs pass accounts
    // they don't own by design). Gated: only fire if the program also has a financial
    // instruction — prevents FP on bridge/relay programs. Additional gate: if ALL
    // UncheckedAccount/AccountInfo fields in the program are non-mutable, this is a
    // standard pattern for CPI target programs and collection references — not a real
    // ownership-check vulnerability. Non-mutable unchecked accounts can only be used
    // for .key() references; data access requires mutability.
    let has_unchecked_mut_field = ast
        .anchor_accounts
        .iter()
        .flat_map(|a| &a.fields)
        .any(|f| (f.is_unchecked_account || f.ty.contains("AccountInfo")) && f.is_mut);
    let owner_from_check_and_info = source_patterns.has_check_annotation
        && source_patterns.has_account_info_unchecked
        && has_unchecked_mut_field
        && graph.instructions.iter().any(|i| {
            i.name.to_lowercase().contains("transfer")
                || i.name.to_lowercase().contains("withdraw")
                || i.name.to_lowercase().contains("deposit")
        });
    if owner_from_token_no_auth || owner_from_raw_financial || owner_from_check_and_info {
        detected.push("ownership-check".to_string());
    }
    // Signal 4 (raw Rust _unchecked oracle calls): non-Anchor programs that call _unchecked
    // oracle price functions skip account owner verification. The checked version verifies the
    // oracle account is owned by the expected oracle program; the _unchecked variant trusts
    // account data without owner verification, enabling price manipulation via forged oracle.
    // E.g. Solend: get_single_price_unchecked, get_pyth_price_unchecked.
    if source_patterns.has_raw_rust_unchecked_calls
        && !detected.contains(&"ownership-check".to_string())
    {
        detected.push("ownership-check".to_string());
    }

    // ── Arbitrary-CPI ──
    // Signal A: raw invoke() call where program_id is not validated (non-Anchor pattern).
    // Only check entry-point handlers (is_entry_point): helper functions like
    // invoke_optionally_signed, spl_token_transfer are called BY entry-point handlers
    // that already validate program_id ownership before delegating.
    let has_raw_unvalidated_cpi = ast.instruction_handlers.iter().any(|h| {
        h.is_entry_point
            && h.uses_invoke
            && !h.has_program_id_check
            && !h.params.iter().any(|p| p.ty.contains("Program<"))
    });
    // Signal B: CpiContext::new with an AccountInfo program account (not Program<>) and no
    // program_id equality check anywhere in the file. This covers the Anchor arbitrary-CPI
    // pattern where the caller passes an attacker-controlled AccountInfo as the CPI target.
    // Narrowed: does NOT fire on large (>50 instr) Anchor-heavy programs — in those programs
    // /// CHECK: + AccountInfo is used for known trusted external CPI targets (token metadata,
    // oracle programs, external DEX/AMM CPIs), which are validated by on-chain program IDs or
    // Anchor Program<> typing elsewhere in the codebase. The canonical arbitrary-cpi vulnerability
    // occurs in small programs where a single instruction passes an attacker-controlled program
    // account via CpiContext; large Anchor-heavy protocols use this pattern safely.
    let has_cpi_context_with_unchecked_program = source_patterns.has_cpi_context_new_variable
        && source_patterns.has_account_info_unchecked
        && source_patterns.has_check_annotation
        && !ast
            .instruction_handlers
            .iter()
            .any(|h| h.has_program_id_check)
        && (graph.instructions.len() <= 50 || !is_anchor_heavy);
    if has_raw_unvalidated_cpi || has_cpi_context_with_unchecked_program {
        detected.push("arbitrary-cpi".to_string());
    }

    // ── Initialization-frontrunning ──
    // Signal A: init instruction where the admin/authority account is NOT a Signer<>
    // (AccountInfo instead of Signer<>) — anyone can front-run the initialization.
    // Gated: only fire on programs with ≤ 200 instructions. Large DEX programs (>200 instr)
    // always have init instructions with non-Signer admin accounts (PDA authorities, system
    // accounts for CPI) that are safe because the PDA derivation prevents frontrunning.
    let frontrun_from_unchecked_admin =
        source_patterns.has_init_with_unchecked_admin && graph.instructions.len() <= 200;
    // Signal B: init instruction with a PDA using fully fixed seeds (no signer-derived
    // component) where the init context has a Signer but NO constraint linking that
    // signer to the initialized account (e.g., no has_one, no upgrade-authority check).
    // This covers the case where ANY signer can initialize the global config.
    // Detected at source level (field names) to bypass the mapper AccountNode.name limitation.
    // Gated: only fire when the program has ≤ 5 instructions (small config programs).
    // Large programs always have some unconstrained inits (e.g., user PDAs).
    let frontrun_from_fixed_seeds_unconstrained =
        source_patterns.has_init_global_unconstrained && graph.instructions.len() <= 5;
    // Signal C: CPI-level PDA frontrunning — invoke_signed to external program where an
    // `UncheckedAccount` named `*escrow*` has no Anchor seeds constraint validating its address.
    // An attacker can pre-create the PDA at the external program before migration, causing DoS.
    // This is the Pump Science H-01 pattern (lock_pool.rs: lock_escrow UncheckedAccount).
    // Gated: program must have > 5 instructions (migration programs are larger than trivial configs).
    let frontrun_from_unchecked_escrow_cpi =
        source_patterns.has_unchecked_escrow_invoke_signed && graph.instructions.len() > 5;
    if frontrun_from_unchecked_admin
        || frontrun_from_fixed_seeds_unconstrained
        || frontrun_from_unchecked_escrow_cpi
    {
        detected.push("initialization-frontrunning".to_string());
    }

    // ── Re-initialization ──
    // Signal A: init_if_needed with fixed seeds — allows overwrite of initialized accounts.
    // Require BOTH: (a) the fixed-seeds init pattern AND (b) the any-init-with-fixed-seeds
    // pattern (which specifically tracks `init_if_needed` variant in the source scanner).
    // `has_init_with_fixed_seeds` alone fires on normal PDA init; the combination with
    // `has_any_init_with_fixed_seeds` narrows to the init_if_needed re-init case.
    let reinit_fixed_seeds =
        source_patterns.has_init_with_fixed_seeds && source_patterns.has_any_init_with_fixed_seeds;
    // Signal B: init_if_needed with dynamic seeds (no fixed b"..." literals) but NO
    // is_initialized / discriminator guard field — the MetaDAO pattern where proposal PDAs
    // use the proposal pubkey as seed so `has_init_with_fixed_seeds` never fires, but the
    // lack of an initialized-flag guard means the account state can be overwritten.
    let reinit_dynamic_no_guard = source_patterns.has_init_if_needed_no_guard;
    if reinit_fixed_seeds || reinit_dynamic_no_guard {
        detected.push("re-initialization".to_string());
    }

    // ── Revival-attack ──
    // Signal: manual lamport drain (close pattern without zeroing data or checking refund).
    // This pattern is rare enough that no additional gating is needed.
    if source_patterns.has_manual_lamport_drain {
        detected.push("revival-attack".to_string());
    }

    // ── Unchecked numeric cast ──
    // Signal A: explicit `as u64` / `as u32` cast of a wider integer without checked wrapper.
    // Threshold raised to > 10 instructions: small programs rarely have the arithmetic
    // complexity that makes an unchecked cast exploitable. Programs with many instructions
    // are more likely to have complex financial math where truncation matters.
    let cast_from_explicit =
        source_patterns.has_unchecked_numeric_cast && graph.instructions.len() > 10;
    // Signal B: custom math macro (checked_math!, safe_math!, i80f48!, precise_number!, etc.)
    // used near u128→u64 cast in a financial context. These macros may expand to unchecked
    // operations at runtime despite safe-looking syntax — the MetaDAO LP math pattern.
    // No instruction-count gate: macro presence alone is high-specificity in financial code.
    let cast_from_macro = source_patterns.has_custom_math_macro_cast;
    if cast_from_explicit || cast_from_macro {
        detected.push("unchecked-cast".to_string());
    }
    // Signal C (raw Rust _unchecked oracle/price calls): _unchecked function variants skip
    // staleness/validation checks on price data, allowing stale or invalid data to be used
    // in financial calculations. E.g. Solend: get_price_unchecked, get_ema_price_unchecked.
    if source_patterns.has_raw_rust_unchecked_calls
        && !detected.contains(&"unchecked-cast".to_string())
    {
        detected.push("unchecked-cast".to_string());
    }
    // Signal D (bytemuck unsafe byte cast): bytemuck::bytes_of_mut bypasses type checking
    // for account mutation; cast/cast_slice reinterprets without validation. bytes_of (PDA
    // seeds) and from_bytes (zero-copy Pod) are safe patterns and not flagged.
    if source_patterns.has_bytemuck_unsafe_cast && !detected.contains(&"unchecked-cast".to_string())
    {
        detected.push("unchecked-cast".to_string());
    }

    // ── has_financial_instruction (used by type-cosplay, account-data-matching, dup-mutable) ──
    let has_financial_instruction = graph.instructions.iter().any(|i| {
        let n = i.name.to_lowercase();
        n.contains("transfer")
            || n.contains("withdraw")
            || n.contains("swap")
            || n.contains("stake")
            || n.contains("deposit")
            || n.contains("update")
            || n.contains("set_")
            || n.contains("trade")
    });

    // ── Type-cosplay ──
    // Signal A: try_from_slice used to deserialize an account whose type is not
    // verified by a discriminator check. This is the canonical type-cosplay pattern.
    // Anchor typed accounts are safe (discriminator checked automatically).
    if source_patterns.has_try_from_slice && unchecked_fields > 0 {
        detected.push("type-cosplay".to_string());
    }
    // Signal B: 2+ mutable `AccountInfo<'info>` with `/// CHECK:` in the same Accounts struct —
    // the Dexalot swap pattern where unchecked ATAs are passed where typed accounts are expected.
    // Only fire if there is also a financial instruction (swap/transfer/deposit) to avoid relay FP.
    // Also require has_try_from_slice (or equivalent unsafe deserialization evidence):
    // type-cosplay fundamentally requires unchecked deserialization; unchecked accounts alone
    // only indicate relay/CPI-passthrough patterns, not type confusion.
    if source_patterns.has_mutable_unchecked_account_pair
        && has_financial_instruction
        && source_patterns.has_try_from_slice
        && !detected.contains(&"type-cosplay".to_string())
    {
        detected.push("type-cosplay".to_string());
    }

    // ── Account-data-matching ──
    // Signal 1: mutable account with signer but no has_one/constraint linking them.
    // Expanded financial instruction detection to include "update" and "set" patterns
    // (many data-matching bugs involve update instructions, not transfer/withdraw).
    let has_cpi_reload_risk = graph.instructions.iter().any(|i| {
        i.uses_cpi
            && i.effects.iter().any(|(_, e)| {
                matches!(
                    e,
                    ares_mapper::AccountEffect::Read | ares_mapper::AccountEffect::Write
                )
            })
    });
    let account_data_matching_scope = graph.instructions.len() <= 30 || has_cpi_reload_risk;
    if source_patterns.has_mutable_account_with_signer_no_link
        && has_financial_instruction
        && account_data_matching_scope
    {
        detected.push("account-data-matching".to_string());
    }
    if has_cpi_reload_risk
        && source_patterns.has_cpi_after_state_read
        && !detected.contains(&"account-data-matching".to_string())
    {
        detected.push("account-data-matching".to_string());
    }
    // Signal 3 (cross-instruction staleness): post-CPI read of a financial/order/state field
    // without reload() — the Axelar/Dexalot cross-chain account-staleness pattern.
    // Broader field coverage than has_cpi_after_state_read (includes .order, .command_id, etc.).
    // No instruction-count gate: has_post_cpi_stale_field_read is already very specific
    // (requires confirmed before-CPI read + after-CPI stale read in same function scope).
    if source_patterns.has_post_cpi_stale_field_read
        && !detected.contains(&"account-data-matching".to_string())
    {
        detected.push("account-data-matching".to_string());
    }
    if has_cpi_reload_risk
        && source_patterns.has_cpi_after_state_read
        && !detected.contains(&"account-data-matching".to_string())
    {
        detected.push("account-data-matching".to_string());
    }
    // Signal 4 (cross-chain token-manager staleness): unchecked token-manager/token-mint
    // UncheckedAccount fields passed to invoke_signed without seeds= or has_one validation.
    // This is the Axelar ITS pattern: externally-supplied token manager accounts are passed
    // into a cross-chain CPI without validating their type or ownership — an attacker can
    // substitute a different account between the initial check and the CPI execution.
    // Gated: only fire if there is also a financial instruction (transfer/execute context).
    if source_patterns.has_unchecked_token_manager_cpi
        && has_financial_instruction
        && !detected.contains(&"account-data-matching".to_string())
    {
        detected.push("account-data-matching".to_string());
    }
    // Signal 5 (raw Rust unpack_unchecked): non-Anchor programs that call unpack_unchecked
    // or similar _unchecked deserialization functions skip discriminator/type validation.
    // Without checking the account discriminator, a different account type with the same
    // size could be substituted, leading to account-data-matching / type-cosplay attacks.
    // E.g. Solend: assert_uninitialized via T::unpack_unchecked.
    if source_patterns.has_raw_rust_unchecked_calls
        && !detected.contains(&"account-data-matching".to_string())
    {
        detected.push("account-data-matching".to_string());
    }

    // ── Solitaire account-data-matching and arbitrary-cpi ──
    // Signal: Solitaire framework programs with raw `Info<'b>` fields in FromAccounts
    // structs. These fields represent unvalidated AccountInfo — the Solitaire equivalent
    // of Anchor's UncheckedAccount. The FromAccounts derive macro deserializes account
    // data without checking type discriminator or owner, enabling account-data-matching
    // attacks. When these raw accounts are passed to invoke_signed, it's arbitrary-cpi
    // (the target program isn't validated — e.g. Wormhole's bpf_loader/system Info<'b>).
    if source_patterns.has_solitaire_raw_info {
        if !detected.contains(&"account-data-matching".to_string()) {
            detected.push("account-data-matching".to_string());
        }
        if !detected.contains(&"arbitrary-cpi".to_string()) {
            detected.push("arbitrary-cpi".to_string());
        }
    }

    // ── Account-reloading ──
    // Signal A: state read BEFORE a CPI call, account NOT reloaded after — stale data used.
    // Require BOTH: (a) source pattern confirms the read-before-CPI sequence AND
    // (b) the graph shows CPI with account read/write effects AND
    // (c) the program has ≤ 50 instructions (large programs always have some CPI+read).
    // The combination of all three narrows to genuine stale-read-after-CPI patterns.
    let account_reloading_scope = graph.instructions.len() <= 50;
    if source_patterns.has_cpi_after_state_read && has_cpi_reload_risk && account_reloading_scope {
        detected.push("account-reloading".to_string());
    }
    // Signal B: broader cross-instruction staleness (has_post_cpi_stale_field_read).
    // Covers order/settlement/position fields not in the original has_cpi_after_state_read
    // field list. Uses same scope gate. Only emit if not already detected via Signal A.
    if source_patterns.has_post_cpi_stale_field_read
        && has_cpi_reload_risk
        && account_reloading_scope
        && !detected.contains(&"account-reloading".to_string())
    {
        detected.push("account-reloading".to_string());
    }

    // ── Missing-revalidation ──
    // Tightened: only fire on ONE of two high-confidence combinations:
    // (a) manual lamport drain (revival-attack companion — always needs revalidation), OR
    // (b) BOTH has_cpi_after_state_read AND has_mutable_account_with_signer_no_link
    //     (two independent signals point to same root: state not re-checked after mutation).
    // Removed: single-signal OR logic — too broad, fires on almost every program.
    let missing_reval_from_drain = source_patterns.has_manual_lamport_drain;
    let missing_reval_from_cpi_and_mutable = source_patterns.has_cpi_after_state_read
        && source_patterns.has_mutable_account_with_signer_no_link;
    // Signal C: settings-input struct field write gap — an update function reads params.FIELD
    // for validation but never assigns self.FIELD = params.FIELD, so the field silently retains
    // its old value. After every admin update the state is inconsistent with the intended config,
    // requiring re-validation of the missing field. This is the Pump Science H-02 pattern.
    let missing_reval_from_field_write_gap = source_patterns.has_settings_field_write_gap;
    if (missing_reval_from_drain
        || missing_reval_from_cpi_and_mutable
        || missing_reval_from_field_write_gap)
        && !detected.contains(&"missing-revalidation".to_string())
    {
        detected.push("missing-revalidation".to_string());
    }

    // ── Duplicate-mutable-accounts ──
    // Signal A: 2+ mutable accounts in the same Accounts struct share a base name (_a/_b suffix
    // or one name contains the other's base word), with no key-equality constraint.
    // Detected at source level (field names) to bypass mapper AccountNode.name limitation.
    // Signal B (type-based): 2+ mutable fields share the same Anchor inner type (e.g.,
    // `Account<'info, Order>`) with different names and no key constraint. Catches Dexalot-style
    // semantic duplicates where `order_pda` and `position_pda` resolve to the same struct type.
    // Signal C (unchecked pair): 2+ mutable `AccountInfo<'info>` / `UncheckedAccount<'info>`
    // with `/// CHECK:` in same Accounts struct — Dexalot swap ATA pattern.
    let dup_by_name = source_patterns.has_duplicate_mutable_pair && has_financial_instruction;
    let dup_by_type = source_patterns.has_same_type_mutable_pair && has_financial_instruction;
    let dup_by_unchecked_pair =
        source_patterns.has_mutable_unchecked_account_pair && has_financial_instruction;
    if dup_by_name || dup_by_type || dup_by_unchecked_pair {
        detected.push("duplicate-mutable-accounts".to_string());
    }

    // ── PDA-privileges ──
    // Signal 1 (concrete graph): PDA with no has_one that is concretely CpiPass'd.
    let pda_signs_cpi_without_link = graph.accounts.iter().any(|a| {
        a.seeds.is_some()
            && a.has_one_constraints.is_empty()
            && graph.instructions.iter().any(|i| {
                i.effects.iter().any(|(name, effect)| {
                    *name == a.name && matches!(effect, ares_mapper::AccountEffect::CpiPass)
                })
            })
    });
    // Signal 2 (source pattern): CpiContext::new_with_signer where the PDA authority field
    // has no has_one constraint. This is the canonical pda-privileges pattern where an
    // attacker can use any PDA as the authority for a token transfer.
    // Gated to programs with token-like instruction names to reduce FP on bridge/relay programs.
    let pda_as_signer_in_token_cpi = source_patterns.has_pda_as_cpi_signer_no_link
        && graph.instructions.iter().any(|i| {
            let n = i.name.to_lowercase();
            n.contains("withdraw") || n.contains("transfer") || n.contains("claim")
        });
    if pda_signs_cpi_without_link || pda_as_signer_in_token_cpi {
        detected.push("pda-privileges".to_string());
    }

    // ── Reentrancy-risk ──
    // Signal: an instruction BOTH writes to an account AND passes that SAME account
    // to a CPI call — the real reentrancy vector. Only fire on same-account overlap.
    let has_reentrancy_pattern = graph.instructions.iter().any(|i| {
        if !i.uses_cpi {
            return false;
        }
        let written: std::collections::HashSet<_> = i
            .effects
            .iter()
            .filter(|(_, e)| {
                matches!(
                    e,
                    ares_mapper::AccountEffect::Write
                        | ares_mapper::AccountEffect::Create
                        | ares_mapper::AccountEffect::Close
                )
            })
            .map(|(n, _)| n.clone())
            .collect();
        let cpi_passed: std::collections::HashSet<_> = i
            .effects
            .iter()
            .filter(|(_, e)| matches!(e, ares_mapper::AccountEffect::CpiPass))
            .map(|(n, _)| n.clone())
            .collect();
        !written.is_empty()
            && !cpi_passed.is_empty()
            && written.intersection(&cpi_passed).next().is_some()
    });
    if has_reentrancy_pattern
        || source_patterns.has_state_set_then_cpi_then_state_set
        || source_patterns.has_remaining_accounts_cpi
    {
        detected.push("reentrancy-risk".to_string());
    }

    // ── Cross-instruction analysis (Phase 3 taint) ──
    // Only accept findings with confidence >= 0.75 on non-trivial instruction pairs.
    let cross = ares_mapper::cross_analysis::analyze(graph)
        .ok()
        .unwrap_or_default();
    for cf in cross {
        if cf.confidence >= 0.75
            && !cf.source_instruction.contains("get_")
            && !cf.sink_instruction.contains("get_")
            && !cf.source_instruction.contains("view_")
            && !cf.sink_instruction.contains("view_")
            && !detected.contains(&cf.category)
        {
            detected.push(cf.category);
        }
    }

    // ── Deterministic suppression: remove findings contradicted by AST evidence ──
    let mut suppressed = Vec::new();

    // Rule 1: type-cosplay — suppress on Anchor-heavy projects without UncheckedAccount.
    if detected.contains(&"type-cosplay".to_string()) && is_anchor_heavy && unchecked_fields == 0 {
        suppressed.push("type-cosplay");
    }
    // Rule 1b: type-cosplay — suppress when arbitrary-cpi is the primary finding AND
    // the program is small (≤ 15 instructions). In synthetic stubs the try_from_slice
    // comes from the hacked sub-program (attack payload), not from a genuine type-cosplay
    // vulnerability in the analyzed program.
    // Scoped to small programs: large real programs (like Axelar ITS, 50+ instructions)
    // may have BOTH genuine arbitrary-cpi AND genuine type-cosplay (UncheckedAccount token
    // manager accounts deserialized via try_from_slice without discriminator validation).
    // Suppressing both for large programs loses a real TP.
    if detected.contains(&"type-cosplay".to_string())
        && detected.contains(&"arbitrary-cpi".to_string())
        && graph.instructions.len() <= 15
    {
        suppressed.push("type-cosplay");
    }

    // Rule 2: ownership-check — suppress if all Anchor fields are typed/Signer/Program.
    if detected.contains(&"ownership-check".to_string()) && is_anchor_heavy && unchecked_fields == 0
    {
        suppressed.push("ownership-check");
    }

    // Rule 3: signer-authorization — suppress on Anchor-heavy projects with no raw AccountInfo handlers.
    // Exception: do NOT suppress when Signal C fired (/// CHECK: on seeded mutable account with no has_one)
    // — that is a genuine structural vulnerability even in Anchor-heavy programs.
    if detected.contains(&"signer-authorization".to_string()) && is_anchor_heavy && !has_raw_handler
    {
        // Only suppress if the Anchor-check signal was the sole trigger (not raw handler or Signal C).
        if !signer_from_check_and_raw
            && !signer_from_raw_sensitive
            && !signer_from_anchor_check_no_has_one
        {
            suppressed.push("signer-authorization");
            suppressed.push("missing-signer");
        }
    }

    // Rule 4: missing-signer — suppress on Anchor-heavy programs without raw handlers,
    // UNLESS Signal C fired (genuine structural gap).
    if detected.contains(&"missing-signer".to_string())
        && is_anchor_heavy
        && !has_raw_handler
        && !signer_from_anchor_check_no_has_one
    {
        suppressed.push("missing-signer");
    }

    // Rule 5: arbitrary-cpi — suppress if all CPI targets are typed Program<'info, T>
    // or AST scanner shows no raw invoke() without program_id check.
    // Extended: also suppress when any raw invoke_signed targets a hardcoded trusted endpoint
    // (ENDPOINT_ID pattern — LayerZero OApp). In that case the invoke_signed is NOT
    // attacker-controllable; only the Anchor-typed CpiContext calls remain, which use
    // Program<'info, Token> (fully validated by Anchor), so arbitrary-cpi does not apply.
    if detected.contains(&"arbitrary-cpi".to_string()) {
        let has_raw_unvalidated_cpi2 = ast.instruction_handlers.iter().any(|h| {
            h.is_entry_point
                && h.uses_invoke
                && !h.has_program_id_check
                && !h.params.iter().any(|p| p.ty.contains("Program<"))
        });
        let layerzero_oapp =
            source_patterns.has_hardcoded_endpoint_id && source_patterns.has_typed_program_field;
        if cpi_all_validated || (has_typed_program && !has_raw_unvalidated_cpi2) || layerzero_oapp {
            suppressed.push("arbitrary-cpi");
        }
    }

    // Rule 6: duplicate-mutable-accounts — suppress when account-reloading is the primary
    // finding. Account-reloading stubs have mutable accounts + CPI + financial instructions,
    // which also satisfies the duplicate-mutable-accounts source pattern incidentally.
    if detected.contains(&"account-reloading".to_string()) {
        suppressed.push("duplicate-mutable-accounts");
    }

    // Rule 7: account-data-matching co-fires with account-reloading on the same CPI+mutable
    // pattern (has_cpi_after_state_read triggers both). Suppress account-data-matching when
    // account-reloading is detected and account-data-matching fired only via the CPI path
    // (not via the has_mutable_account_with_signer_no_link path).
    if detected.contains(&"account-reloading".to_string())
        && detected.contains(&"account-data-matching".to_string())
        && !source_patterns.has_mutable_account_with_signer_no_link
    {
        suppressed.push("account-data-matching");
    }

    // Rule 8: account-reloading — suppress when pda-privileges is also detected.
    // The pda-privileges stub reads `.amount` before a CpiContext::new_with_signer call,
    // which satisfies the CPI-after-state-read pattern incidentally. The real vulnerability
    // is unauthorized PDA authority, not stale data.
    if detected.contains(&"pda-privileges".to_string()) {
        suppressed.push("account-reloading");
    }

    // Rule 9: account-data-matching — suppress when pda-privileges is the primary finding
    // AND account-data-matching fired ONLY via the post-CPI stale read signal.
    // The pda-privileges stub reads `.amount` pre-CPI, which triggers has_post_cpi_stale_field_read;
    // but the actual vulnerability is unauthorized PDA authority, not account-data mismatch.
    // Only suppress if the other two account-data-matching signals did NOT fire.
    // Exception: do NOT suppress when has_unchecked_token_manager_cpi fired (Signal 4) —
    // that signal catches genuine cross-chain token account staleness (Axelar ITS pattern).
    if detected.contains(&"pda-privileges".to_string())
        && detected.contains(&"account-data-matching".to_string())
        && !source_patterns.has_mutable_account_with_signer_no_link
        && !source_patterns.has_cpi_after_state_read
        && !source_patterns.has_unchecked_token_manager_cpi
    {
        suppressed.push("account-data-matching");
    }

    // Rule 10: signer-authorization + missing-signer — suppress on Anchor-heavy bridge/relay
    // programs where the raw handler fires only on a `caller: AccountInfo<'info>` field that
    // is explicitly constrained via `signer` or `constraint =` in the attribute block.
    // Bridge/relay programs pass accounts they don't own by design; validate_message-style
    // instructions use AccountInfo as signer with explicit constraint — not a real missing-signer.
    // Gate: is_anchor_heavy AND cpi_all_validated AND raw handler signal was the sole trigger
    // AND program is large (> 50 instructions — confirmed bridge/relay design).
    if (detected.contains(&"missing-signer".to_string())
        || detected.contains(&"signer-authorization".to_string()))
        && is_anchor_heavy
        && cpi_all_validated
        && !signer_from_anchor_check_no_has_one
        && graph.instructions.len() > 50
    // only suppress on large confirmed bridge/relay programs
    {
        // Only suppress if the raw-handler signal is the sole signer-auth trigger
        // (signer_from_check_and_raw or signer_from_raw_sensitive) but the program
        // has all CPIs validated — indicating this is a bridge/relay design.
        suppressed.push("missing-signer");
        suppressed.push("signer-authorization");
    }

    // Rule 11: duplicate-mutable-accounts — suppress on Anchor-heavy bridge/relay programs
    // where the dup-mutable pair signal fires on pass-through UncheckedAccount fields.
    // Bridge programs pass multiple program/authority accounts as UncheckedAccount by design;
    // the name-based and type-based dup detectors may fire on these pass-through pairs.
    // Gate: is_anchor_heavy AND cpi_all_validated AND no financial-swap instruction.
    // (Dexalot has swap instructions and is NOT cpi_all_validated — so it won't be suppressed.)
    let has_swap_instruction = graph.instructions.iter().any(|i| {
        let n = i.name.to_lowercase();
        n.contains("swap") || n.contains("trade") || n.contains("fill_order")
    });
    if detected.contains(&"duplicate-mutable-accounts".to_string())
        && is_anchor_heavy
        && cpi_all_validated
        && !has_swap_instruction
        && !dup_by_unchecked_pair // only suppress name/type signals, not unchecked-pair
        && graph.instructions.len() > 50
    // only suppress on large bridge/relay programs
    {
        suppressed.push("duplicate-mutable-accounts");
    }
    // Rule 11b: duplicate-mutable-accounts — suppress on very large Anchor-heavy DEX programs
    // where the type-based dup signal fires on same-type mutable fields with distinct roles.
    // E.g. drift-v2 has `maker` and `taker` both as `Account<'info, User>` — these have
    // different roles in the swap and are constrained by PDA seeds, not key inequality.
    // Gate: >500 instructions AND Anchor-heavy AND type-based signal only (not name-based
    // or unchecked-pair) AND has financial instructions (swap/trade/deposit/withdraw).
    if detected.contains(&"duplicate-mutable-accounts".to_string())
        && graph.instructions.len() > 500
        && is_anchor_heavy
        && dup_by_type
        && !dup_by_name
        && !dup_by_unchecked_pair
        && has_financial_instruction
    {
        suppressed.push("duplicate-mutable-accounts");
    }

    // Rule 12: missing-revalidation — suppress when it fires only as a companion of
    // revival-attack (manual lamport drain) that has already been suppressed.
    // Without the lamport drain signal, this is FP on large Anchor-heavy bridge programs.
    // Gate: revival-attack not detected (suppressed) AND sole trigger was lamport drain path.
    // Only apply on large Anchor-heavy programs to avoid suppressing real findings.
    if detected.contains(&"missing-revalidation".to_string())
        && !detected.contains(&"revival-attack".to_string())
        && missing_reval_from_drain
        && !missing_reval_from_cpi_and_mutable
        && graph.instructions.len() > 50
        && is_anchor_heavy
    {
        suppressed.push("missing-revalidation");
    }

    // Rule 13: initialization-frontrunning — the existing gate (instructions <= 5) in
    // frontrun_from_fixed_seeds_unconstrained already handles most FPs. The additional
    // suppression here targets large bridge/relay programs (> 50 instructions, Anchor-heavy,
    // all CPIs validated) where the has_init_with_unchecked_admin path fires on external
    // program pass-throughs (mpl_, gateway_, token_metadata_program, etc.).
    // Threshold raised to > 50 to avoid suppressing real findings in mid-size programs like pump-science (45).
    if detected.contains(&"initialization-frontrunning".to_string())
        && graph.instructions.len() > 50
        && is_anchor_heavy
        && cpi_all_validated
        && frontrun_from_unchecked_admin
        && !frontrun_from_fixed_seeds_unconstrained
    {
        suppressed.push("initialization-frontrunning");
    }

    // Rule 14: re-initialization — suppress when fired only via reinit_dynamic_no_guard on
    // large DEX/bridge programs where `init_if_needed` is used for operational PDA creation
    // (ATAs, user accounts), not for re-initializable state storage.
    // Gate: reinit_fixed_seeds did NOT fire (no fixed-seed init_if_needed conflict)
    // AND program has > 50 instructions (large DEX/bridge design)
    // AND has_mutable_unchecked_account_pair (DEX swap fingerprint: multiple AccountInfo ATAs
    // passed through instructions — distinguishes DEX from governance/staking programs)
    // AND has_hardcoded_endpoint_id (LayerZero OApp fingerprint — Dexalot; excludes MetaDAO
    // governance which has mutable unchecked pairs but no hardcoded cross-chain endpoint).
    if detected.contains(&"re-initialization".to_string())
        && reinit_dynamic_no_guard
        && !reinit_fixed_seeds
        && graph.instructions.len() > 50
        && source_patterns.has_mutable_unchecked_account_pair
        && source_patterns.has_hardcoded_endpoint_id
    {
        suppressed.push("re-initialization");
    }

    // Rule 15: reentrancy-risk — suppress when the program uses a hardcoded trusted endpoint
    // (LayerZero/OApp pattern: ENDPOINT_ID constant) for its CPI/remaining_accounts relay.
    // Dexalot and similar LayerZero OApp programs call invoke_signed to a hardcoded, audited
    // endpoint program — this is by design, not a reentrancy vector.
    // The Axelar TP fires via attacker-controlled external callback (no ENDPOINT_ID); Dexalot
    // only invokes the known LayerZero endpoint program, making reentrancy structurally impossible
    // (the endpoint enforces strict message validation, not attacker-controlled dispatch).
    // Gate: source contains hardcoded ENDPOINT_ID constant AND no state-set-CPI-state-set pattern
    // (the bidirectional write-around-CPI pattern that indicates real reentrancy risk).
    // Axelar does NOT reference ENDPOINT_ID — its reentrancy is via arbitrary ITS callback CPIs.
    if detected.contains(&"reentrancy-risk".to_string())
        && source_patterns.has_hardcoded_endpoint_id
        && !source_patterns.has_state_set_then_cpi_then_state_set
    {
        suppressed.push("reentrancy-risk");
    }

    // Rule 16: missing-revalidation — suppress when fired only via the cpi-and-mutable path
    // on large (>100 instr) DEX programs with the mutable unchecked ATA fingerprint.
    // In DEX programs, mutable AccountInfo pass-throughs (ATAs) alongside CPI calls are
    // structural — the ATA accounts are validated via token program constraints, not program-level
    // guards. The CPI+mutable signal fires correctly on small programs with genuine stale-read
    // risks; on large DEXes it produces FPs because every swap instruction has CPI + mutable ATAs.
    // Extra gate: has_hardcoded_endpoint_id limits suppression to LayerZero OApp programs (Dexalot);
    // governance/AMM protocols like MetaDAO that have genuine missing-revalidation TPs are excluded.
    if detected.contains(&"missing-revalidation".to_string())
        && missing_reval_from_cpi_and_mutable
        && !missing_reval_from_drain
        && graph.instructions.len() > 100
        && source_patterns.has_mutable_unchecked_account_pair
        && is_anchor_heavy
        && source_patterns.has_hardcoded_endpoint_id
    // only Dexalot-style LayerZero OApp
    {
        suppressed.push("missing-revalidation");
    }

    // Rule 17: missing-signer — suppress when the companion signer-authorization is a TP
    // but missing-signer fires as a spurious companion on large DEX/bridge programs (>50 instr)
    // that have swap instructions. DEX programs validate signers via Anchor typed accounts
    // (Signer<'info>) on order/trade instructions; the raw handler signal may fire on
    // administrative instructions (roles, config) that DO require signer checks, but the
    // missing-signer companion is already covered by the signer-authorization TP.
    // Extended: also applies to LayerZero OApp programs (has_hardcoded_endpoint_id) — these
    // programs use raw AccountInfo throughout (typed_anchor_fields=0 so is_anchor_heavy=false),
    // but signer validation is enforced by the LayerZero endpoint program itself, not raw checks.
    // Gate: program has swap/trade instructions (DEX fingerprint) AND is large (>50 instr)
    // AND the signer_from_anchor_check_no_has_one signal did NOT fire (no structural gap)
    // AND program is either Anchor-heavy OR a LayerZero OApp (hardcoded endpoint).
    if detected.contains(&"missing-signer".to_string())
        && detected.contains(&"signer-authorization".to_string())
        && has_swap_instruction
        && graph.instructions.len() > 50
        && !signer_from_anchor_check_no_has_one
        && (is_anchor_heavy || source_patterns.has_hardcoded_endpoint_id)
    {
        suppressed.push("missing-signer");
    }

    // Rule 19: unchecked-cast — suppress on programs where `as u64` appears only on lines
    // that do NOT also contain `u128` or `i128`. This handles safe widening casts like
    // `fee_bps as u64` (u16→u64) that fire because u128 appears elsewhere in the same file.
    // The actual risk is u128→u64 truncation; u16/u32→u64 is always safe.
    // Only suppress cast_from_explicit (not cast_from_macro, which is independently high-signal).
    if detected.contains(&"unchecked-cast".to_string()) && cast_from_explicit && !cast_from_macro {
        // Check if every `as u64` line has u128/i128 on the same line
        // If NO line combining u128 and `as u64` exists, the cast is a widening cast → suppress
        let mut seen_cast_paths = std::collections::HashSet::new();
        let scan_paths_for_cast: Vec<_> = graph
            .instructions
            .iter()
            .map(|i| &i.file_path)
            .chain(graph.accounts.iter().map(|a| &a.file_path))
            .chain(graph.all_source_files.iter())
            .filter(|p| seen_cast_paths.insert((*p).clone()))
            .collect();
        let mut has_u128_to_u64_on_same_line = false;
        for path in &scan_paths_for_cast {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    let trimmed_l = line.trim();
                    if !is_comment_line(trimmed_l)
                        && trimmed_l.contains("as u64")
                        && (trimmed_l.contains("u128") || trimmed_l.contains("i128"))
                    {
                        has_u128_to_u64_on_same_line = true;
                        break;
                    }
                }
            }
            if has_u128_to_u64_on_same_line {
                break;
            }
        }
        if !has_u128_to_u64_on_same_line {
            suppressed.push("unchecked-cast");
        }
    }

    // Rule 20: type-cosplay — suppress Signal B when the mutable unchecked account pair fires
    // in a migration/CPI-heavy context (has_unchecked_escrow_invoke_signed). In this context
    // the UncheckedAccount fields are external program accounts passed through to an external
    // protocol (e.g. Meteora DEX), not type-cosplay vulnerabilities in the program itself.
    // Also suppress if type-cosplay fired only via Signal B (mutable_unchecked_account_pair)
    // and the program has unchecked_escrow_invoke_signed (CPI delegation context).
    if detected.contains(&"type-cosplay".to_string())
        && source_patterns.has_unchecked_escrow_invoke_signed
        && !source_patterns.has_try_from_slice
    // Signal A not active
    {
        suppressed.push("type-cosplay");
    }

    // Rule 21: account-reloading — suppress when the invoke_signed calls are CPI delegations to
    // an external protocol (has_unchecked_escrow_invoke_signed) where the program's own account
    // state is not at risk of staleness. The CPI-after-state-read pattern fires on
    // `.amount` reads before Meteora CPIs (migration context), but the program's bonding curve
    // state is not stale after the Meteora CPI — only Meteora's internal state changes.
    // Extra gate: only suppress if account-reloading fired via has_cpi_after_state_read
    // and NOT via has_post_cpi_stale_field_read (the broader cross-instruction signal).
    if detected.contains(&"account-reloading".to_string())
        && source_patterns.has_unchecked_escrow_invoke_signed
        && source_patterns.has_cpi_after_state_read
        && !source_patterns.has_post_cpi_stale_field_read
    {
        suppressed.push("account-reloading");
    }

    // Rule 22: ownership-check — suppress when the ownership-check fires only via the
    // owner_from_check_and_info path (/// CHECK: + AccountInfo + financial instruction) on
    // programs where those AccountInfo fields are CPI pass-throughs to a validated external
    // protocol (has_unchecked_escrow_invoke_signed). The Meteora program ID is validated via
    // `require!(... Pubkey::from_str(METEORA_PROGRAM_KEY))` in the instruction handler,
    // so the CPI pass-through is safe — no ownership-check vulnerability exists.
    // Gate: owner_from_token_no_auth must NOT have fired (that signal catches genuinely
    // unlinked TokenAccount fields).
    if detected.contains(&"ownership-check".to_string())
        && source_patterns.has_unchecked_escrow_invoke_signed
        && !source_patterns.has_token_account_without_authority
        && !owner_from_raw_financial
    {
        suppressed.push("ownership-check");
    }
    if !suppressed.is_empty() {
        let suppressed_strings: Vec<String> = suppressed.iter().map(|s| s.to_string()).collect();
        detected.retain(|c| !suppressed_strings.contains(c));
    }

    detected
}
