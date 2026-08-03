#![allow(clippy::needless_range_loop, unused_variables, unused_assignments)]

/// Scanned source-code patterns for a single protocol. Built once per protocol.
#[derive(Debug, Default, Clone)]
pub struct SourcePatterns {
    pub has_account_info_unchecked: bool,
    pub has_check_annotation: bool,
    pub has_try_from_slice: bool,
    pub has_manual_lamport_drain: bool,
    pub has_init_with_unchecked_admin: bool,
    pub has_init_with_fixed_seeds: bool,
    pub has_cpi_context_new_variable: bool,
    pub has_cpi_after_state_read: bool,
    pub has_state_set_then_cpi_then_state_set: bool,
    pub has_pda_without_constraint: bool,
    pub has_invoke_helper_call: bool,
    pub has_mutable_account_with_signer_no_link: bool,
    pub has_token_account_without_authority: bool,
    pub has_any_init_with_fixed_seeds: bool,
    pub has_unchecked_numeric_cast: bool,
    /// init context has fixed seeds AND no has_one linking signer to a config/global/state PDA.
    /// Detected at source level (field names), bypassing the mapper's struct-name limitation.
    pub has_init_global_unconstrained: bool,
    /// Two or more mutable accounts in the same Accounts struct share a base name (_a/_b suffix
    /// or one name contains the other's base word), with no key-equality constraint between them.
    pub has_duplicate_mutable_pair: bool,
    /// Source contains `CpiContext::new_with_signer` — PDA is used as a CPI authority.
    pub has_cpi_new_with_signer: bool,
    /// A PDA account (seeds present) is used as CPI authority (new_with_signer) without
    /// a has_one constraint linking it to the signer. Detected at struct field level.
    pub has_pda_as_cpi_signer_no_link: bool,
    /// A `/// CHECK:`-annotated field in an Accounts struct has `seeds =` AND no `has_one`,
    /// indicating the field's ownership is not verified despite being constrained by PDA seeds.
    /// Detected at field level (bypassing the mapper's struct-name limitation).
    pub has_check_on_seeded_no_has_one: bool,
    /// Two or more mutable fields in the same Accounts struct share the *same Anchor inner type*
    /// (e.g., `Account<'info, Order>`) with no key-inequality constraint between them.
    /// This catches semantic duplicates regardless of field name — e.g., `order_pda` and
    /// `position_pda` that both resolve to `Account<'info, Order>`.
    pub has_same_type_mutable_pair: bool,
    /// `init_if_needed` is used in an Accounts struct where the initialized account
    /// has NO `is_initialized` guard field and IS NOT protected by a user-key seed.
    /// This catches dynamic-seed re-initialization (MetaDAO futarchy proposals).
    pub has_init_if_needed_no_guard: bool,
    /// Source contains a custom math macro invocation (e.g., `checked_math!`, `safe_math!`,
    /// `math!`, `precise_number!`) near a `u128` value in a financial context.
    /// These macros may expand to unchecked operations at runtime despite safe-looking syntax.
    pub has_custom_math_macro_cast: bool,
    /// A CPI call is followed by a read of a field on an account that was passed into the CPI
    /// AND the account is NOT reloaded before the read — cross-instruction staleness pattern.
    /// Broader than `has_cpi_after_state_read`: also covers `.order`, `.qty`, `.filled_amount`.
    pub has_post_cpi_stale_field_read: bool,
    /// Two or more mutable `AccountInfo<'info>` or `UncheckedAccount<'info>` fields in the same
    /// Accounts struct are annotated with `/// CHECK:` — both fields are fully unchecked.
    /// This is the Dexalot swap pattern: `taker_src_asset_ata`, `spl_vault_src_asset_ata`, etc.
    /// Signals both `duplicate-mutable-accounts` (unchecked pair) and `type-cosplay` (unchecked
    /// account passed where typed account expected).
    pub has_mutable_unchecked_account_pair: bool,
    /// A CPI `invoke` or `invoke_signed` call is made with `remaining_accounts` passed as account
    /// infos — the cross-chain callback reentrancy pattern.  An attacker-controlled external program
    /// receives `remaining_accounts` and can call back into this program before state is committed.
    /// This is the Axelar ITS interchain-transfer reentrancy vector (Ackee audit finding).
    pub has_remaining_accounts_cpi: bool,
    /// The source code references a hardcoded endpoint program ID string constant
    /// (e.g. `ENDPOINT_ID`, `Pubkey::from_str(ENDPOINT_ID)`).  This indicates a LayerZero OApp
    /// or similar trusted-endpoint program where invoke_signed calls go to a known, audited
    /// endpoint rather than an attacker-controlled program.  Used to suppress reentrancy-risk
    /// FPs on programs that use remaining_accounts relay for trusted cross-chain message delivery.
    pub has_hardcoded_endpoint_id: bool,
    /// One or more Accounts struct fields use the strongly-typed `Program<'info, T>` type,
    /// indicating that the CPI target program is validated by Anchor's type system.
    /// Programs that only use `Program<'info, Token>`, `Program<'info, System>`, etc. as their
    /// CPI targets cannot be subject to arbitrary-CPI (the type check rejects wrong programs).
    pub has_typed_program_field: bool,
    /// `invoke_signed` is called to an external program AND the Accounts struct contains an
    /// `UncheckedAccount` or `AccountInfo` field named `*escrow*` with NO `seeds =` constraint
    /// in its attribute block. This is the Pump Science H-01 CPI-level PDA frontrunning pattern:
    /// the `lock_escrow` PDA address is passed unchecked to Meteora's `create_lock_escrow`,
    /// so an attacker can pre-create the escrow PDA at Meteora before the protocol calls this,
    /// causing a DoS by locking funds into an attacker-controlled escrow.
    pub has_unchecked_escrow_invoke_signed: bool,
    /// A function accepting a settings-input struct reads `params.FIELD` for validation
    /// but omits `self.FIELD = params.FIELD` for at least one field in the update body.
    /// This is the Pump Science H-02 missing-field-write pattern: `update_settings()` reads
    /// `params.migration_token_allocation` in `validate_settings` but never assigns it back,
    /// so the field silently stays at its old value after every admin update.
    pub has_settings_field_write_gap: bool,
    /// An Accounts struct has multiple `UncheckedAccount`/`AccountInfo` fields with names
    /// indicating token-manager or token-mint roles (e.g. `token_manager_pda`, `token_mint`,
    /// `token_manager_ata`) WITHOUT `seeds =` or `has_one` constraints, AND the instruction
    /// handler calls `invoke_signed` passing these accounts. This is the Axelar ITS pattern:
    /// token account data (type, ownership) is not re-validated after the CPI that mutates
    /// the cross-chain token transfer — the account could have been substituted by an attacker.
    /// Signals `account-data-matching` (state not re-checked after CPI mutation).
    pub has_unchecked_token_manager_cpi: bool,
    /// Raw Rust program (non-Anchor) using `next_account_info` pattern with calls to
    /// `_unchecked` function variants (e.g. `get_price_unchecked`, `unpack_unchecked`).
    /// The `_unchecked` naming convention signals that the checked variant performs
    /// security validation (owner verification, staleness check, discriminator check)
    /// that the unchecked version skips. Found in Solend, Wormhole (Solitaire), etc.
    pub has_raw_rust_unchecked_calls: bool,
    /// Raw Rust program uses `bytemuck::bytes_of` or similar unsafe byte-level casting
    /// for account serialization. This bypasses type checking and can lead to type
    /// confusion if account data layout changes. Signals `unchecked-cast`.
    pub has_bytemuck_unsafe_cast: bool,
    /// Solitaire framework program with `Info<'b>` fields in `FromAccounts` structs.
    /// These represent raw AccountInfo accounts without type validation (the Solitaire
    /// equivalent of Anchor's UncheckedAccount). Signals `account-data-matching` (data
    /// read without type check) and `arbitrary-cpi` (invoke_signed with unvalidated targets).
    pub has_solitaire_raw_info: bool,
}

/// Returns true if a line is a single-line comment (/// or // or /* block).
pub fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with("* ")
        || trimmed == "*/"
}

/// Extracts code-only content by removing comment lines.
pub fn code_only(content: &str) -> String {
    content
        .lines()
        .filter(|l| !is_comment_line(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Scan all unique source files referenced by the graph for vulnerability patterns.
/// Uses precise pattern matching to minimize false positives on single-vulnerability programs.
pub fn scan_source_patterns(graph: &ares_mapper::ProgramGraph) -> SourcePatterns {
    let mut patterns = SourcePatterns::default();
    let mut seen_paths = std::collections::HashSet::new();

    let paths: Vec<_> = graph
        .instructions
        .iter()
        .map(|i| &i.file_path)
        .chain(graph.accounts.iter().map(|a| &a.file_path))
        .chain(graph.all_source_files.iter())
        .filter(|p| seen_paths.insert(*p))
        .cloned()
        .collect();

    for path in paths {
        let path_str = path.to_string_lossy().to_string();
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<_> = content.lines().collect();
        let code = code_only(&content);

        // ── AccountInfo<'info> or UncheckedAccount used where typed account should be ──
        let mut in_accounts_struct = false;
        for line in lines.iter() {
            if line.contains("#[derive(Accounts") || line.contains("#[derive(Accounts<") {
                in_accounts_struct = true;
            }
            if in_accounts_struct
                && (line.trim().starts_with("pub ") || line.trim().starts_with("#[account("))
                && (line.contains("AccountInfo<") || line.contains("UncheckedAccount"))
            {
                patterns.has_account_info_unchecked = true;
            }
            if in_accounts_struct && line.trim().starts_with("}") {
                in_accounts_struct = false;
            }
        }

        // ── /// CHECK: annotation on an account that should be validated ──
        for (i, line) in lines.iter().enumerate() {
            if line.contains("/// CHECK:") || line.contains("// CHECK:") {
                // Look ahead up to 6 non-empty lines, skipping attribute macros
                // and interior attribute lines (mut, seeds, bump) until we hit the
                // actual field declaration (starts with `pub `).
                let mut field_line: Option<&str> = None;
                for l in lines.iter().skip(i + 1).take(6) {
                    let trimmed = l.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.starts_with("#[") {
                        continue;
                    }
                    if !trimmed.starts_with("pub ") {
                        continue;
                    }
                    field_line = Some(l);
                    break;
                }
                if let Some(fl) = field_line {
                    let fl_lower = fl.to_lowercase();
                    if fl_lower.contains("authority")
                        || fl_lower.contains("signer")
                        || fl_lower.contains("vault")
                        || fl_lower.contains("admin")
                        || fl_lower.contains("program")
                        || fl_lower.contains("escrow")
                        || fl_lower.contains("token_account")
                        || fl_lower.contains("token")
                        || fl_lower.contains("pool")
                        || fl_lower.contains("order")
                        || fl_lower.contains("metadata")
                        || fl_lower.contains("position")
                        || fl_lower.contains("portfolio")
                        || fl_lower.contains("handler")
                        || fl_lower.contains("oracle")
                    {
                        patterns.has_check_annotation = true;
                    }
                }
            }
        }

        // ── try_from_slice without explicit discriminator / owner check ──
        // Only flag in program source files, not test/benchmark/client utility files.
        // Exclude lines where try_from_slice is called on Pubkey or primitive numeric types
        // (u128, u64, etc.) — these parse fixed-format on-chain data, not account type substitution.
        // The canonical type-cosplay pattern is SomeAccountType::try_from_slice(&data) without
        // a discriminator check — Anchor's Account<T> validates the discriminator automatically.
        let is_test_or_util_file = path_str.contains("/tests/")
            || path_str.contains("\\tests\\")
            || path_str.contains("/client/")
            || path_str.contains("\\client\\")
            || path_str.contains("/bench/")
            || path_str.contains("\\bench\\")
            || path_str.contains("/benchmark/")
            || path_str.contains("\\benchmark\\");
        if !is_test_or_util_file
            && code.contains("try_from_slice")
            && !code.contains("discriminator")
            && !code.contains("Account::try_from")
            && !code.contains("AccountLoad")
        {
            let safe_prefixes = [
                "Pubkey::try_from_slice",
                "u128::try_from_slice",
                "u64::try_from_slice",
                "i128::try_from_slice",
                "i64::try_from_slice",
                "BigNum::try_from_slice",
            ];
            let has_unsafe_try_from = lines.iter().any(|l| {
                l.contains("try_from_slice")
                    && !safe_prefixes.iter().any(|p| l.contains(p))
                    && !l.trim().starts_with("//")
                    && !l.contains("Account::try_from")
            });
            if has_unsafe_try_from {
                patterns.has_try_from_slice = true;
            }
        }

        // ── Unchecked numeric downcast (u128→u64, etc.) ──
        // Require u128 or i128 to also be present: `i64 as u64` (e.g. timestamp casts)
        // is safe and not a financial truncation vulnerability.
        // Exclude files where every `as u64` / `as u32` cast line shows evidence of
        // safe wrapping: checked/saturating arithmetic, try_into, or a custom function
        // call (the function performs the safety check internally).
        if (code.contains("u128") || code.contains("i128")) && code.contains("as u64") {
            let downcast_lines: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("as u64") || l.contains("as u32") || l.contains("as u16"))
                .map(|l| l.trim())
                .collect();
            let all_safe_downcast = !downcast_lines.is_empty()
                && downcast_lines.iter().all(|l| {
                    l.contains("checked_")
                        || l.contains("saturating_")
                        || l.contains("try_into()")
                        || (l.contains("(") && l.contains(").unwrap()"))
                        || (l.contains("(") && l.contains(")?"))
                });
            if !all_safe_downcast {
                patterns.has_unchecked_numeric_cast = true;
            }
        }

        // ── Manual close without Anchor close constraint ──
        // `has_raw_lamport_drain`: raw borrow_mut() lamport manipulation (low-level close pattern).
        // `has_anchor_lamport_drain`: `sub_lamports(` is an actual drain; `get_lamports()` alone
        //   is a rent-exemption READ, not a drain — exclude it to avoid FP on programs that
        //   check rent after a transfer (e.g. Axelar gas-service collect_fees).
        //   `add_lamports(` alone = receiving, not draining. Only fire on sub_lamports.
        let has_raw_lamport_drain = code.contains("lamports()") && code.contains("borrow_mut()");
        let has_anchor_lamport_drain = code.contains("sub_lamports(");
        let has_lamport_drain = has_raw_lamport_drain || has_anchor_lamport_drain;
        let has_close_constraint = code.contains("close=") || code.contains("close =");
        let has_discriminator_zero =
            code.contains("fill(0)") || code.contains("try_borrow_mut_data");
        if has_lamport_drain && !has_close_constraint && !has_discriminator_zero {
            patterns.has_manual_lamport_drain = true;
        }

        // ── init_if_needed with fixed / literal seeds (re-initializable) ──
        if code.contains("init_if_needed") {
            for line in lines.iter() {
                let trimmed = line.trim();
                if trimmed.starts_with("seeds = [") || trimmed.starts_with("seeds=[") {
                    let seeds_part = if let Some(start) = line.find('[') {
                        if let Some(end) = line[start..].find(']') {
                            &line[start..start + end + 1]
                        } else {
                            ""
                        }
                    } else {
                        ""
                    };
                    if seeds_part.contains("b\"")
                        && !seeds_part.contains(".key()")
                        && !seeds_part.contains("as_ref()")
                    {
                        patterns.has_init_with_fixed_seeds = true;
                    }
                }
            }
        }

        // ── Any init (init or init_if_needed) with fixed seeds (front-runnable) ──
        if code.contains("init,") || code.contains("init_if_needed") {
            for line in lines.iter() {
                let trimmed = line.trim();
                if trimmed.starts_with("seeds = [") || trimmed.starts_with("seeds=[") {
                    let seeds_part = if let Some(start) = line.find('[') {
                        if let Some(end) = line[start..].find(']') {
                            &line[start..start + end + 1]
                        } else {
                            ""
                        }
                    } else {
                        ""
                    };
                    if seeds_part.contains("b\"")
                        && !seeds_part.contains(".key()")
                        && !seeds_part.contains("as_ref()")
                    {
                        patterns.has_any_init_with_fixed_seeds = true;
                    }
                }
            }
        }

        // ── CpiContext::new with a user-controlled program variable ──
        if code.contains("CpiContext::new(") {
            let cpi_lines: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("CpiContext::new("))
                .collect();
            for l in cpi_lines {
                let l_lower = l.to_lowercase();
                if (l_lower.contains("cpi_program")
                    || l_lower.contains("plugin_program")
                    || l_lower.contains("program.clone()")
                    || l_lower.contains("handler"))
                    && !l_lower.contains("token_program")
                    && !l_lower.contains("system_program")
                    && !l_lower.contains("associated_token")
                {
                    patterns.has_cpi_context_new_variable = true;
                }
            }
        }

        // ── Account state read -> CPI -> same state read again (stale data) ──
        if code.contains("invoke(")
            || code.contains("invoke_signed(")
            || code.contains("CpiContext")
        {
            for (i, line) in lines.iter().enumerate() {
                if line.contains("invoke(")
                    || line.contains("invoke_signed(")
                    || line.contains("CpiContext")
                {
                    let before = &lines[..i].join("\n");
                    // Scope `after` to the current function / item so that a
                    // `reload()` in a *different* function doesn't poison the check.
                    let mut after_end = lines.len();
                    for j in (i + 1)..lines.len() {
                        let t = lines[j].trim_start();
                        if t.starts_with("pub fn ")
                            || t.starts_with("fn ")
                            || t.starts_with("#[derive(")
                            || t.starts_with("pub struct ")
                            || t.starts_with("#[account")
                            || t.starts_with("#[error_code")
                        {
                            after_end = j;
                            break;
                        }
                    }
                    let after = &lines[i..after_end].join("\n");
                    let fields = [
                        ".load()",
                        ".data",
                        ".amount",
                        ".price",
                        ".nonce",
                        ".total_staked",
                        ".input",
                        ".state",
                        ".balance",
                        ".rewards",
                        ".metadata",
                        ".approved",
                        ".vault",
                        ".qty",
                        ".filled",
                    ];
                    let has_before = fields.iter().any(|f| before.contains(f));
                    let has_after = fields.iter().any(|f| after.contains(f));
                    if has_before
                        && has_after
                        && !after.contains("AccountReload")
                        && !after.contains("reload()")
                    {
                        patterns.has_cpi_after_state_read = true;
                    }
                }
            }
        }

        // ── State set -> CPI -> state set again on same account (reentrancy-like) ──
        // Requires a dot-prefix on the field name (e.g. `.state =`, `.data =`) to ensure
        // we are matching account field mutations, NOT local variable assignments like
        // `cpi_data = ...` or `quote_return_data = ...` (Dexalot FP source).
        let content_lower = content.to_lowercase();
        if (content_lower.contains(".approved = ")
            || content_lower.contains(".state = ")
            || content_lower.contains(".data = "))
            && (code.contains("invoke(") || code.contains("invoke_signed("))
        {
            for field in [".approved", ".state", ".data", ".nonce", ".total_staked"] {
                let writes: Vec<_> = lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.to_lowercase().contains(&format!("{} =", field)))
                    .collect();
                if writes.len() >= 2 {
                    let first_idx = writes.first().map_or(0, |(i, _)| *i);
                    let last_idx = writes.last().map_or(0, |(i, _)| *i);
                    let middle = &lines[first_idx..last_idx].join("\n");
                    if middle.contains("invoke(") || middle.contains("invoke_signed(") {
                        patterns.has_state_set_then_cpi_then_state_set = true;
                    }
                }
            }
        }

        // ── Indirect CPI via helper function calls (reentrancy-like) ──
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let is_helper_call = (trimmed.contains("invoke_")
                || trimmed.contains("callback")
                || trimmed.contains("external_")
                || trimmed.contains("handler")
                || trimmed.contains("oracle")
                || trimmed.contains("aggregator")
                || trimmed.contains("yield_"))
                && (trimmed.contains("(&ctx.accounts.")
                    || trimmed.contains("(&")
                    || trimmed.contains("ctx.accounts."));
            if is_helper_call {
                let window_start = i.saturating_sub(15);
                let window_end = (i + 15).min(lines.len());
                let before = &lines[window_start..i].join("\n").to_lowercase();
                let after = &lines[i..window_end].join("\n").to_lowercase();
                let sets_before = before.contains(".approved =")
                    || before.contains(".state =")
                    || before.contains(".data =")
                    || before.contains(".nonce =")
                    || before.contains(".total_staked =");
                let sets_after = after.contains(".approved =")
                    || after.contains(".state =")
                    || after.contains(".data =")
                    || after.contains(".nonce =")
                    || after.contains(".total_staked =");
                if sets_before && sets_after {
                    patterns.has_invoke_helper_call = true;
                }
            }
        }

        // Pre-extract all #[derive(Accounts)] struct bodies for precise struct-level scanning
        let mut struct_bodies: Vec<String> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("#[derive(Accounts") || line.contains("#[derive(Accounts<") {
                let rest = lines[i..].join("\n");
                if let Some(body_start) = rest.find('{') {
                    if let Some(body_end) = rest[body_start..].find('}') {
                        let body = &rest[body_start..body_start + body_end + 1];
                        struct_bodies.push(body.to_string());
                    }
                }
            }
        }

        // ── PDA without has_one constraint ──
        for body in &struct_bodies {
            let body_code = code_only(body);
            let has_pda_comment =
                body.contains("/// PDA") || body.contains("// PDA") || body.contains("PDA without");
            let lower = body.to_lowercase();
            let has_pda_field =
                lower.contains("pub ") && (lower.contains("_pda") || lower.contains("pda_"));
            let has_named_pda = body.to_lowercase().contains("callback_pda")
                || body.to_lowercase().contains("pool_authority_pda");
            if (has_pda_comment || has_pda_field || has_named_pda)
                && !body_code.contains("has_one")
                && !body_code.contains("constraint =")
            {
                patterns.has_pda_without_constraint = true;
            }
        }

        // ── init_if_needed with fixed / literal seeds (re-initializable) ──
        for body in &struct_bodies {
            let body_code = code_only(body);
            if !body_code.contains("init_if_needed") {
                continue;
            }
            for line in body_code.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("seeds = [") || trimmed.starts_with("seeds=[") {
                    let seeds_part = if let Some(start) = line.find('[') {
                        if let Some(end) = line[start..].find(']') {
                            &line[start..start + end + 1]
                        } else {
                            ""
                        }
                    } else {
                        ""
                    };
                    if seeds_part.contains("b\"")
                        && !seeds_part.contains(".key()")
                        && !seeds_part.contains("as_ref()")
                    {
                        patterns.has_init_with_fixed_seeds = true;
                    }
                }
            }
        }

        // ── Any init (init or init_if_needed) with fixed seeds (front-runnable) ──
        for body in &struct_bodies {
            let body_code = code_only(body);
            if !body_code.contains("init,") && !body_code.contains("init_if_needed") {
                continue;
            }
            for line in body_code.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("seeds = [") || trimmed.starts_with("seeds=[") {
                    let seeds_part = if let Some(start) = line.find('[') {
                        if let Some(end) = line[start..].find(']') {
                            &line[start..start + end + 1]
                        } else {
                            ""
                        }
                    } else {
                        ""
                    };
                    if seeds_part.contains("b\"")
                        && !seeds_part.contains(".key()")
                        && !seeds_part.contains("as_ref()")
                    {
                        patterns.has_any_init_with_fixed_seeds = true;
                    }
                }
            }
        }

        // ── init with unchecked admin (AccountInfo / UncheckedAccount on authority-like field) ──
        for body in &struct_bodies {
            let body_code = code_only(body);
            if !body_code.contains("init,") && !body_code.contains("init_if_needed") {
                continue;
            }
            let body_lines: Vec<&str> = body_code.lines().collect();
            for (idx, line) in body_lines.iter().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("pub ")
                    && (trimmed.contains("AccountInfo<'info>")
                        || trimmed.contains("UncheckedAccount<'info>"))
                {
                    let lower = trimmed.to_lowercase();
                    // Exclude known safe patterns: external programs passed as unchecked references
                    // (mpl_, spl_, token_, system_, associated_, bpf_, event_, gas_, gateway_,
                    //  metadata_program, sysvar_) — these are relay/bridge design patterns.
                    let is_external_program = lower.contains("mpl_")
                        || lower.contains("system_program")
                        || lower.contains("token_program")
                        || lower.contains("associated_token_program")
                        || lower.contains("bpf_loader")
                        || lower.contains("event_authority")
                        || lower.contains("gas_service")
                        || lower.contains("gateway_program")
                        || lower.contains("gateway_event")
                        || lower.contains("metadata_program")
                        || lower.contains("sysvar")
                        || lower.contains("its_program")
                        || lower.contains("axelar")
                        // Transfer destination accounts are NOT admin/config — they are the
                        // recipient of a cross-chain or token transfer.  Field names starting
                        // with "destination" (e.g. destination_token_authority) are safe to
                        // exclude.  Likewise "new_owner" / "new_authority" are transfer targets.
                        || lower.contains("destination")
                        || lower.starts_with("pub new_");
                    if is_external_program {
                        continue;
                    }
                    // Exclude authority-like fields that are PDA-derived: if the account attribute
                    // block immediately preceding this field (up to 8 lines back) contains
                    // `seeds = [` then the field is PDA-constrained and cannot be front-run.
                    // This correctly handles the Dexalot pattern:
                    //   `pub admin: AccountInfo<'info>` with `seeds = [ADMIN_SEED, payer.key().as_ref()]`
                    let has_seeds_constraint = {
                        let lookback = idx.saturating_sub(8);
                        body_lines[lookback..idx].iter().any(|l| {
                            let lt = l.trim();
                            lt.starts_with("seeds = [") || lt.starts_with("seeds=[")
                        })
                    };
                    if has_seeds_constraint {
                        continue;
                    }
                    if lower.contains("authority")
                        || lower.contains("admin")
                        || lower.contains("owner")
                        || lower.contains("escrow")
                        || lower.contains("config")
                        || lower.contains("handler")
                        || lower.contains("plugin")
                        // "program" only when not an external program reference
                        || (lower.contains("program") && !lower.contains("program_id") && !lower.contains("_program"))
                    {
                        patterns.has_init_with_unchecked_admin = true;
                    }
                }
            }
        }

        // ── CpiContext::new_with_signer presence ──
        if code.contains("CpiContext::new_with_signer(") {
            patterns.has_cpi_new_with_signer = true;
        }

        // ── PDA used as CPI signer with no has_one constraint ──
        // Scan for CpiContext::new_with_signer where the PDA authority field has no has_one.
        // This is the canonical pda-privileges pattern.
        if code.contains("CpiContext::new_with_signer(") {
            for body in &struct_bodies {
                let body_code = code_only(body);
                // Must have seeds (is a PDA)
                let has_seeds = body_code.contains("seeds = [") || body_code.contains("seeds=[");
                // No has_one linking the PDA authority to the signer
                let no_has_one = !body_code.contains("has_one");
                // Has a Signer in the same Accounts struct (so the vuln is caller-controlled)
                let has_signer = body_code.contains("Signer<'info>");
                // The PDA must NOT be a user-specific PDA (contains user's key in seeds)
                // User-specific PDAs with seeds = [b"...", user.key().as_ref()] are not vulnerable.
                // But pda-privileges stub uses metadata_account.creator (not signer.key()) — still FP risk.
                // Just require: seeds present, no has_one, has Signer (so someone else controls it).
                if has_seeds && no_has_one && has_signer {
                    patterns.has_pda_as_cpi_signer_no_link = true;
                }
            }
        }

        // ── CHECK annotation on a seeded mutable account with no has_one (signer-authorization) ──
        // This is Signal C for signer-authorization, detected at field level.
        // The mapper stores struct names, not field names; we scan source directly.
        for body in &struct_bodies {
            let _body_code = code_only(body);
            let body_lines_raw: Vec<_> = body.lines().collect();
            // Find /// CHECK: lines and look at the following account attribute
            for (idx, line) in body_lines_raw.iter().enumerate() {
                if !line.contains("/// CHECK:") && !line.contains("// CHECK:") {
                    continue;
                }
                // Look ahead: find the associated #[account(...)] block and pub field line
                let window_end = (idx + 12).min(body_lines_raw.len());
                let window = &body_lines_raw[idx..window_end].join("\n");
                let window_code = code_only(window);
                // Has seeds (is a PDA-constrained field)
                let has_seeds = window.contains("seeds = [") || window.contains("seeds=[");
                // No has_one in this field's constraint block
                let no_has_one = !window_code.contains("has_one");
                // Field is mutable
                let is_mutable =
                    window.contains("mut,") || window.contains("mut]") || window.contains("mut)");
                if has_seeds && no_has_one && is_mutable {
                    patterns.has_check_on_seeded_no_has_one = true;
                }
            }
        }

        // ── init with global/config PDA using fixed seeds AND no has_one linking signer ──
        // This is Signal B for initialization-frontrunning, detected at field level (not struct level).
        // The mapper stores struct names in AccountNode.name, not field names; we scan source directly.
        for body in &struct_bodies {
            let body_code = code_only(body);
            if !body_code.contains("init,") && !body_code.contains("init_if_needed") {
                continue;
            }
            // Does this init body have fixed seeds pointing to a config/global/state PDA?
            let has_global_seeds = body_code.lines().any(|l| {
                let t = l.trim();
                (t.starts_with("seeds = [") || t.starts_with("seeds=[")) && {
                    let seeds_part = if let Some(s) = l.find('[') {
                        if let Some(e) = l[s..].find(']') {
                            &l[s..s + e + 1]
                        } else {
                            ""
                        }
                    } else {
                        ""
                    };
                    seeds_part.contains("b\"")
                        && !seeds_part.contains(".key()")
                        && !seeds_part.contains("as_ref()")
                }
            });
            // Is there a field named with config/global/state/registry?
            let has_global_field = body_code.lines().any(|l| {
                let l_lower = l.to_lowercase();
                l_lower.trim().starts_with("pub ")
                    && (l_lower.contains("config")
                        || l_lower.contains("global")
                        || l_lower.contains("registry")
                        || l_lower.contains("state"))
            });
            // Is there a Signer present?
            let has_signer_field = body_code.contains("Signer<'info>");
            // Is there no has_one constraint linking signer to the config account?
            let has_link = body_code.contains("has_one") || body_code.contains("constraint =");
            if has_global_seeds && has_global_field && has_signer_field && !has_link {
                patterns.has_init_global_unconstrained = true;
            }
        }

        // ── init_if_needed with NO is_initialized guard and NOT user-key seeds ──
        // Catches MetaDAO-style re-initialization: dynamic seeds (proposal pubkey) but
        // no discriminator/is_initialized guard prevents account overwrite.
        for body in &struct_bodies {
            let body_code = code_only(body);
            if !body_code.contains("init_if_needed") {
                continue;
            }
            // No is_initialized field or check in the struct body
            let no_guard = !body_code.to_lowercase().contains("is_initialized")
                && !body_code.contains("discriminator")
                && !body_code.contains("initialized: bool");
            // Has a mutable financial field (so the account actually holds value)
            let has_financial_field = body_code.lines().any(|l| {
                let ll = l.to_lowercase();
                ll.trim().starts_with("pub ")
                    && (ll.contains("amount")
                        || ll.contains("balance")
                        || ll.contains("lamports")
                        || ll.contains("price")
                        || ll.contains("value")
                        || ll.contains("proposal")
                        || ll.contains("vote")
                        || ll.contains("stake"))
            });
            if no_guard && has_financial_field {
                patterns.has_init_if_needed_no_guard = true;
            }
        }

        // ── Custom math macro near u128 in financial context ──
        // Detects `checked_math!(...)`, `safe_math!(...)`, `math!(...)`, `precise_number!(...)`
        // etc. that wrap potentially unsafe numeric operations. These macros may expand to
        // unchecked casts even though the call site looks safe syntactically.
        {
            let financial_math_macros = [
                "checked_math!",
                "safe_math!",
                "math_error!",
                "fixed_math!",
                "precise_number!",
                "decimal_math!",
                "i80f48!",
                "fp32!",
            ];
            let has_macro = financial_math_macros.iter().any(|m| code.contains(m));
            // Also check for any `!(` pattern near u128/i128 in arithmetic context
            let has_u128_macro_context = code.contains("u128")
                && (code.contains("as u64") || code.contains("as i64") || code.contains("as u32"))
                && lines.iter().any(|l| {
                    let ll = l.trim();
                    (ll.contains("u128") || ll.contains("i128"))
                        && ll.contains("!(")
                        && (ll.contains("price")
                            || ll.contains("amount")
                            || ll.contains("value")
                            || ll.contains("liquidity")
                            || ll.contains("reserve")
                            || ll.contains("lp"))
                });
            if has_macro || has_u128_macro_context {
                patterns.has_custom_math_macro_cast = true;
            }
        }

        // ── Post-CPI stale field read (cross-instruction staleness) ──
        // Broader than has_cpi_after_state_read: covers order/settlement/position fields
        // that are not in the original field list. Targets Dexalot/Axelar patterns.
        if code.contains("invoke(")
            || code.contains("invoke_signed(")
            || code.contains("CpiContext")
        {
            let stale_fields = [
                ".load()",
                ".data",
                ".amount",
                ".price",
                ".nonce",
                ".total_staked",
                ".input",
                ".state",
                ".balance",
                ".rewards",
                ".metadata",
                ".approved",
                ".vault",
                ".qty",
                ".filled",
                ".order",
                ".filled_amount",
                ".qty_left",
                ".position",
                ".command_id",
                ".sequence",
                ".msg_hash",
                ".payload",
                ".status",
                ".total",
                ".reserve",
                ".base_amount",
                ".quote_amount",
            ];
            for (i, line) in lines.iter().enumerate() {
                let is_cpi_line = line.contains("invoke(")
                    || line.contains("invoke_signed(")
                    || (line.contains("CpiContext") && !line.contains("//"));
                if !is_cpi_line {
                    continue;
                }
                // Scope to current function
                let mut fn_end = lines.len();
                for j in (i + 1)..lines.len() {
                    let t = lines[j].trim_start();
                    if t.starts_with("pub fn ")
                        || t.starts_with("fn ")
                        || t.starts_with("#[derive(")
                        || t.starts_with("pub struct ")
                    {
                        fn_end = j;
                        break;
                    }
                }
                let after = &lines[i..fn_end].join("\n");
                let has_stale_after = stale_fields.iter().any(|f| after.contains(f));
                // The account field is also accessed before the CPI (confirming it was live data)
                let before = &lines[..i].join("\n");
                let has_read_before = stale_fields.iter().any(|f| before.contains(f));
                if has_stale_after
                    && has_read_before
                    && !after.contains("reload()")
                    && !after.contains("AccountReload")
                    && !after.contains(".reload(")
                {
                    patterns.has_post_cpi_stale_field_read = true;
                }
            }
        }

        // ── Remaining-accounts CPI (cross-chain callback reentrancy) ──
        // Detects the pattern where `invoke` or `invoke_signed` is called with
        // `remaining_accounts` passed as the account list — an attacker-controlled
        // external program receives remaining_accounts and can call back into this
        // program before state is committed.  This is the Axelar ITS interchain-transfer
        // callback reentrancy vector (Ackee audit finding).
        // Gate: requires:
        //   (a) invoke or invoke_signed in the file
        //   (b) remaining_accounts passed into an account_infos vector
        //   (c) AccountMeta / account_meta construction (caller builds ix metadata from
        //       remaining_accounts payload — the cross-chain relay pattern)
        // This distinguishes cross-chain relay programs (Axelar, Wormhole) from programs
        // that merely iterate remaining_accounts for optional accounts (Drift, Mango).
        if (code.contains("invoke(") || code.contains("invoke_signed("))
            && code.contains("remaining_accounts")
            && (code.contains("account_infos.extend") || code.contains("ix_accounts.extend"))
            && (code.contains("AccountMeta") || code.contains("account_meta"))
        {
            patterns.has_remaining_accounts_cpi = true;
        }

        // ── Hardcoded endpoint program ID ──
        // Detects programs that call invoke/invoke_signed to a hardcoded trusted endpoint
        // (LayerZero OApp pattern: `ENDPOINT_ID` constant, or `Pubkey::from_str(ENDPOINT_ID)`).
        // These programs use remaining_accounts relay for trusted cross-chain message delivery,
        // NOT for attacker-controlled callbacks.  Used to suppress reentrancy-risk FPs.
        if code.contains("ENDPOINT_ID")
            || code.contains("from_str(ENDPOINT_ID")
            || (code.contains("from_str(") && code.contains("ENDPOINT"))
        {
            patterns.has_hardcoded_endpoint_id = true;
        }

        // ── Typed Program<'info, T> field in Accounts struct ──
        // Detects Anchor Accounts structs that use `Program<'info, T>` fields for their CPI
        // target programs (Token, System, AssociatedToken, etc.).  When present, all CPI targets
        // from CpiContext::new(cpi_program, ...) are validated by Anchor's type system —
        // the arbitrary-cpi pattern does not apply to these programs.
        if code.contains("Program<'info,") {
            patterns.has_typed_program_field = true;
        }

        // ── Unchecked escrow passed to invoke_signed (CPI-level PDA frontrunning) ──
        // Detects the Pump Science H-01 pattern: `invoke_signed` is present AND the Accounts
        // struct has an `UncheckedAccount` or `AccountInfo` field whose name contains "escrow"
        // AND that field has NO `seeds =` constraint in its attribute block (so Anchor does not
        // validate its address). An attacker can pre-create the escrow PDA at the external
        // program (Meteora) before the protocol calls this instruction, causing DoS.
        if code.contains("invoke_signed(") {
            for body in &struct_bodies {
                let body_lines_raw: Vec<&str> = body.lines().collect();
                for (idx, line) in body_lines_raw.iter().enumerate() {
                    let trimmed = line.trim();
                    if !trimmed.starts_with("pub ") {
                        continue;
                    }
                    let lower = trimmed.to_lowercase();
                    if !lower.contains("escrow") {
                        continue;
                    }
                    let is_unchecked =
                        trimmed.contains("UncheckedAccount") || trimmed.contains("AccountInfo<");
                    if !is_unchecked {
                        continue;
                    }
                    let lookback_start = idx.saturating_sub(10);
                    let attr_block = body_lines_raw[lookback_start..idx].join("\n");
                    let has_seeds =
                        attr_block.contains("seeds = [") || attr_block.contains("seeds=[");
                    if !has_seeds {
                        patterns.has_unchecked_escrow_invoke_signed = true;
                    }
                }
            }
        }

        // ── Settings-input struct field write gap (missing-revalidation via omitted assignment) ──
        // Detects the Pump Science H-02 pattern: a function (update_* / set_*) accepts a
        // settings-input struct parameter, reads multiple `params.FIELD` values via self-assignments
        // (`self.X = params.X`), but at least one field defined in the input struct is never
        // assigned back — meaning that field silently retains its old value after every update.
        // Algorithm:
        //   1. Find struct definitions (AnchorSerialize / AnchorDeserialize / plain) with pub fields.
        //   2. For each such struct (the "input struct"), extract its field names.
        //   3. Find function bodies that: (a) accept a parameter of that struct type, AND
        //      (b) contain at least 3 `self.X = params.X` assignments (confirming it is an
        //      update function, not a validation-only function).
        //   4. For each field in the input struct, check if `self.FIELD` appears in the fn body.
        //   5. If any field is missing from the self-assignments → flag the gap.
        {
            // Collect all struct definitions and their pub fields
            let mut input_structs: Vec<(String, Vec<String>)> = Vec::new(); // (struct_name, fields)
            let mut in_struct = false;
            let mut brace_depth = 0usize;
            let mut current_struct_name = String::new();
            let mut current_fields: Vec<String> = Vec::new();
            for line in lines.iter() {
                let trimmed = line.trim();
                if !in_struct {
                    // Look for struct definitions that derive serialization (input structs)
                    // e.g. `pub struct GlobalSettingsInput {`
                    if (trimmed.starts_with("pub struct ") || trimmed.starts_with("struct "))
                        && trimmed.contains('{')
                    {
                        let name_part = trimmed
                            .trim_start_matches("pub ")
                            .trim_start_matches("struct ")
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if name_part.to_lowercase().contains("input")
                            || name_part.to_lowercase().contains("params")
                            || name_part.to_lowercase().contains("settings")
                            || name_part.to_lowercase().contains("config")
                        {
                            in_struct = true;
                            brace_depth = trimmed
                                .chars()
                                .filter(|&c| c == '{')
                                .count()
                                .saturating_sub(trimmed.chars().filter(|&c| c == '}').count());
                            current_struct_name = name_part;
                            current_fields.clear();
                        }
                    }
                } else {
                    brace_depth += trimmed.chars().filter(|&c| c == '{').count();
                    brace_depth =
                        brace_depth.saturating_sub(trimmed.chars().filter(|&c| c == '}').count());
                    if brace_depth == 0 {
                        in_struct = false;
                        if !current_fields.is_empty() {
                            input_structs
                                .push((current_struct_name.clone(), current_fields.clone()));
                        }
                    } else if trimmed.starts_with("pub ") {
                        // Extract field name: `pub migration_token_allocation: u64,`
                        let field_name = trimmed
                            .trim_start_matches("pub ")
                            .split(':')
                            .next()
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default();
                        if !field_name.is_empty()
                            && field_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                        {
                            current_fields.push(field_name);
                        }
                    }
                }
            }

            // Now scan function bodies for update patterns
            if !input_structs.is_empty() {
                let mut fn_start: Option<usize> = None;
                let mut fn_brace_depth = 0usize;
                let mut fn_body_lines: Vec<&str> = Vec::new();
                let mut fn_name = String::new();

                for (idx, line) in lines.iter().enumerate() {
                    let trimmed = line.trim();
                    if fn_start.is_none() {
                        // Detect update/set function signatures
                        let is_update_fn = (trimmed.starts_with("pub fn ")
                            || trimmed.starts_with("fn "))
                            && (trimmed.contains("update_")
                                || trimmed.contains("set_")
                                || trimmed.contains("_settings")
                                || trimmed.contains("_params"));
                        if is_update_fn {
                            fn_name = trimmed.to_string();
                            fn_start = Some(idx);
                            fn_brace_depth = trimmed
                                .chars()
                                .filter(|&c| c == '{')
                                .count()
                                .saturating_sub(trimmed.chars().filter(|&c| c == '}').count());
                            fn_body_lines.clear();
                            fn_body_lines.push(line);
                        }
                    } else {
                        fn_brace_depth += trimmed.chars().filter(|&c| c == '{').count();
                        fn_brace_depth = fn_brace_depth
                            .saturating_sub(trimmed.chars().filter(|&c| c == '}').count());
                        fn_body_lines.push(line);
                        if fn_brace_depth == 0 {
                            // End of function — analyze body
                            let fn_body = fn_body_lines.join("\n");
                            // Count self.X = params.X assignments
                            let assign_count = fn_body_lines
                                .iter()
                                .filter(|l| {
                                    let t = l.trim();
                                    t.starts_with("self.") && t.contains("= params.")
                                })
                                .count();
                            // Only check update functions with ≥ 3 assignments
                            if assign_count >= 3 {
                                for (_, fields) in &input_structs {
                                    // The update function assigns at least 3 fields.
                                    // Check if any field from the input struct is MISSING
                                    // from the self-assignments (self.FIELD = ...) in the
                                    // update fn body, suggesting an accidental omission.
                                    // Extra gate: the field must appear elsewhere in the file
                                    // (e.g., referenced in a validate function), confirming
                                    // it is a real input field, not an optional override.
                                    let mut gap_count = 0usize;
                                    for field in fields.iter() {
                                        let self_write = format!("self.{} =", field);
                                        // Field is missing from update assignments
                                        if !fn_body.contains(&self_write) {
                                            // Confirm the field is actually used elsewhere in the file
                                            // (e.g., in a validate_* function or requirement check)
                                            let field_ref = format!("params.{}", field);
                                            let appears_elsewhere = code.contains(&field_ref)
                                                && !fn_body.contains(&field_ref);
                                            if appears_elsewhere {
                                                gap_count += 1;
                                            }
                                        }
                                    }
                                    // Only flag if exactly 1 field is missing (specific oversight)
                                    // and input struct has >= 5 fields (real settings struct)
                                    if (1..=2).contains(&gap_count) && fields.len() >= 5 {
                                        patterns.has_settings_field_write_gap = true;
                                    }
                                }
                            }
                            fn_start = None;
                            fn_body_lines.clear();
                        }
                    }
                }
            }
        }

        // ── Unchecked token-manager accounts passed to invoke_signed (Axelar ITS pattern) ──
        // Detects Accounts structs containing multiple UncheckedAccount/AccountInfo fields
        // named with token-manager or token-mint semantics (token_manager_pda, token_mint,
        // token_manager_ata, etc.) that have NO seeds= or has_one constraint, combined with
        // invoke_signed calls in the same file. This is the account-data-matching vulnerability:
        // the program passes externally-supplied token manager accounts into a CPI without
        // verifying their type or ownership — an attacker can substitute a different account.
        if code.contains("invoke_signed(") {
            for body in &struct_bodies {
                let body_lines_raw: Vec<&str> = body.lines().collect();
                // Collect (line_idx, field_name) for each token-manager UncheckedAccount field
                let mut token_mgr_fields: Vec<(usize, String)> = Vec::new();
                for (idx, line) in body_lines_raw.iter().enumerate() {
                    let trimmed = line.trim();
                    if !trimmed.starts_with("pub ") {
                        continue;
                    }
                    let lower = trimmed.to_lowercase();
                    let is_unchecked =
                        trimmed.contains("UncheckedAccount") || trimmed.contains("AccountInfo<");
                    if !is_unchecked {
                        continue;
                    }
                    let is_token_manager_role = lower.contains("token_manager")
                        || lower.contains("token_mint")
                        || (lower.contains("token") && lower.contains("ata"))
                        || lower.contains("token_program");
                    if is_token_manager_role {
                        let field_name = trimmed
                            .strip_prefix("pub ")
                            .and_then(|s| s.split(':').next())
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default();
                        token_mgr_fields.push((idx, field_name));
                    }
                }
                // Need ≥ 2 token-manager UncheckedAccount fields.
                // Check per-field: each field must NOT have its own seeds= or has_one constraint.
                // We scan backward from the field line to find its #[account(...)] attribute block.
                if token_mgr_fields.len() >= 2 {
                    let mut unconstrained_count = 0usize;
                    for (field_idx, _field_name) in &token_mgr_fields {
                        let mut field_has_constraint = false;
                        // Scan backward up to 6 lines looking for #[account(...)] attribute
                        for back in (1..=6).rev() {
                            if *field_idx < back {
                                continue;
                            }
                            let attr_line = body_lines_raw[field_idx - back].trim();
                            if attr_line.starts_with("#[account(") {
                                let lower = attr_line.to_lowercase();
                                if lower.contains("seeds") || lower.contains("has_one") {
                                    field_has_constraint = true;
                                }
                                break;
                            }
                            // Stop scanning if we hit another pub field or closing brace
                            if attr_line.starts_with("pub ") || attr_line.starts_with("}") {
                                break;
                            }
                        }
                        if !field_has_constraint {
                            unconstrained_count += 1;
                        }
                    }
                    if unconstrained_count >= 2 {
                        patterns.has_unchecked_token_manager_cpi = true;
                    }
                }
            }
        }

        // ── Type-based duplicate mutable accounts ──
        // Detects two mutable fields in the same Accounts struct with the same Anchor inner type
        // (e.g., two `Account<'info, Order>` fields both marked mut). This catches semantic
        // duplicates regardless of field name — fixing the Dexalot gap where `order_pda` and
        // `position_pda` share the same type but differ in name.
        for body in &struct_bodies {
            let body_code = code_only(body);
            let body_lines: Vec<_> = body_code.lines().collect();
            // Collect (field_name, anchor_inner_type) for each mutable field
            let mut mut_typed_fields: Vec<(String, String)> = Vec::new();
            for (idx, line) in body_lines.iter().enumerate() {
                let is_mut =
                    line.contains("mut,") || line.contains("mut]") || line.contains("mut)");
                if !is_mut {
                    continue;
                }
                for j in (idx + 1)..(idx + 8).min(body_lines.len()) {
                    let fl = body_lines[j].trim();
                    if !fl.starts_with("pub ") {
                        continue;
                    }
                    // Extract field name
                    let field_name = fl
                        .strip_prefix("pub ")
                        .and_then(|s| s.split(':').next())
                        .map(|s| s.trim().to_lowercase())
                        .unwrap_or_default();
                    // Extract inner type of Account<'info, T> → T
                    let inner_type = if let Some(start) = fl.find("Account<'info,") {
                        let rest = &fl[start + "Account<'info,".len()..];
                        rest.split('>')
                            .next()
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default()
                    } else if let Some(start) = fl.find("AccountLoader<'info,") {
                        let rest = &fl[start + "AccountLoader<'info,".len()..];
                        rest.split('>')
                            .next()
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    if !field_name.is_empty() && !inner_type.is_empty() {
                        mut_typed_fields.push((field_name, inner_type));
                    }
                    break;
                }
            }
            // Check for same inner type appearing twice — no key constraint between them
            let no_key_constraint =
                !body_code.contains("key() !=") && !body_code.contains("key() ==");
            if no_key_constraint && mut_typed_fields.len() >= 2 {
                'type_dup: for i in 0..mut_typed_fields.len() {
                    for j in (i + 1)..mut_typed_fields.len() {
                        let (ref name_a, ref ty_a) = mut_typed_fields[i];
                        let (ref name_b, ref ty_b) = mut_typed_fields[j];
                        // Same non-trivial inner type, different field names
                        if ty_a == ty_b && name_a != name_b && ty_a.len() > 2 {
                            patterns.has_same_type_mutable_pair = true;
                            break 'type_dup;
                        }
                    }
                }
            }
        }
        // Operates on struct bodies directly (field names), bypassing mapper AccountNode.name limitation.
        for body in &struct_bodies {
            let body_code = code_only(body);
            // Collect mutable field names
            let body_lines: Vec<_> = body_code.lines().collect();
            let mut mut_fields: Vec<String> = Vec::new();
            for (idx, line) in body_lines.iter().enumerate() {
                let is_mut =
                    line.contains("mut,") || line.contains("mut]") || line.contains("mut)");
                if is_mut {
                    // Look ahead for the pub field declaration
                    for j in (idx + 1)..(idx + 8).min(body_lines.len()) {
                        let fl = body_lines[j].trim();
                        if fl.starts_with("pub ") {
                            // Extract field name: "pub vault_a: Account<...>"
                            if let Some(name_part) = fl.strip_prefix("pub ") {
                                let field_name = name_part
                                    .split(':')
                                    .next()
                                    .unwrap_or("")
                                    .trim()
                                    .to_lowercase();
                                if !field_name.is_empty() {
                                    mut_fields.push(field_name);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            // Does the struct have no key-equality constraint between the pair?
            let no_key_constraint =
                !body_code.contains("key() !=") && !body_code.contains("key() ==");
            // Check for _a/_b pairs or shared base word
            if mut_fields.len() >= 2 {
                'dup_outer: for i in 0..mut_fields.len() {
                    for j in (i + 1)..mut_fields.len() {
                        let a = &mut_fields[i];
                        let b = &mut_fields[j];
                        // Pattern 1: explicit _a / _b / _from / _to suffix — only fire when
                        // both names have the same base after stripping the pairing suffix.
                        let a_stripped = a
                            .strip_suffix("_a")
                            .or_else(|| a.strip_suffix("_b"))
                            .or_else(|| a.strip_suffix("_from"))
                            .or_else(|| a.strip_suffix("_to"))
                            .unwrap_or(a.as_str());
                        let b_stripped = b
                            .strip_suffix("_a")
                            .or_else(|| b.strip_suffix("_b"))
                            .or_else(|| b.strip_suffix("_from"))
                            .or_else(|| b.strip_suffix("_to"))
                            .unwrap_or(b.as_str());
                        if a_stripped == b_stripped && !a_stripped.is_empty() && (a != b)
                        // only if they actually differ (suffixes were stripped)
                            && no_key_constraint
                        {
                            patterns.has_duplicate_mutable_pair = true;
                            break 'dup_outer;
                        }
                        // Pattern 2: same type name (exact match after stripping numeric/underscore suffix)
                        // e.g., "user_account_1" and "user_account_2" share base "user_account"
                        // NOTE: substring containment (e.g., "vault" in "vault_authority") is intentionally
                        // excluded to avoid FP on structs where one field governs another.
                        let a_base = a.trim_end_matches(|c: char| c == '_' || c.is_numeric());
                        let b_base = b.trim_end_matches(|c: char| c == '_' || c.is_numeric());
                        if !a_base.is_empty() && !b_base.is_empty()
                            && a_base == b_base  // exact base match only, not substring
                            && a != b
                            && no_key_constraint
                        {
                            patterns.has_duplicate_mutable_pair = true;
                            break 'dup_outer;
                        }
                    }
                }
            }
        }

        // ── Mutable unchecked AccountInfo pairs (Dexalot-style swap pattern) ──
        // Detects 2+ mutable `AccountInfo<'info>` or `UncheckedAccount<'info>` fields in the same
        // Accounts struct that are annotated with `/// CHECK:`. This indicates both fields are
        // fully unchecked — the canonical type-cosplay AND duplicate-mutable-accounts pattern for
        // bridge/DEX programs that pass unchecked token accounts (ATAs) without typed constraints.
        for body in &struct_bodies {
            let body_lines_raw: Vec<_> = body.lines().collect();
            let mut mutable_unchecked_count = 0usize;
            let mut i = 0;
            while i < body_lines_raw.len() {
                let line = body_lines_raw[i];
                // Look for `/// CHECK:` or `// CHECK:` annotation
                if line.contains("/// CHECK:") || line.contains("// CHECK:") {
                    // Scan ahead for the #[account(mut...)] attribute and pub field line
                    let window_end = (i + 8).min(body_lines_raw.len());
                    let window = &body_lines_raw[i..window_end];
                    let has_mut_attr = window.iter().any(|l| {
                        let t = l.trim();
                        t.starts_with("#[account(")
                            && (t.contains("mut,") || t.contains("mut)") || t.contains("mut]"))
                    });
                    let is_unchecked_type = window.iter().any(|l| {
                        let t = l.trim();
                        t.starts_with("pub ")
                            && (t.contains("AccountInfo<'info>")
                                || t.contains("UncheckedAccount<'info>"))
                    });
                    if has_mut_attr && is_unchecked_type {
                        mutable_unchecked_count += 1;
                    }
                }
                i += 1;
            }
            if mutable_unchecked_count >= 2 {
                patterns.has_mutable_unchecked_account_pair = true;
            }
        }

        // ── Mutable account with signer but no has_one / constraint / associated_token / seeds ──
        // Also detects TokenAccount without authority constraint ──
        for body in &struct_bodies {
            let body_code = code_only(body);
            let has_signer = body_code.contains("Signer<'info>");
            let body_lines: Vec<_> = body_code.lines().collect();

            // Find mutable non-signer fields that are NOT TokenAccount / Mint / ATA.
            // We look ahead from the `mut` attribute line to the `pub` field line
            // and verify the field itself is not a Signer and not a token type.
            let mut has_unlinked_non_token_mut = false;
            for (idx, line) in body_lines.iter().enumerate() {
                let is_mut =
                    line.contains("mut,") || line.contains("mut]") || line.contains("mut)");
                let is_signer_attr = line.contains("Signer<'info>");
                if is_mut && !is_signer_attr {
                    for j in (idx + 1)..(idx + 8).min(body_lines.len()) {
                        let fl = body_lines[j].trim();
                        if fl.starts_with("pub ") {
                            let is_field_signer = fl.contains("Signer<'info>");
                            let is_token_type = fl.contains("TokenAccount")
                                || fl.contains("Account<'info, Mint>")
                                || fl.contains("AssociatedTokenAccount");
                            if !is_field_signer && !is_token_type {
                                let is_raw_unchecked = fl.contains("AccountInfo<'info>")
                                    || fl.contains("UncheckedAccount");
                                if !is_raw_unchecked {
                                    has_unlinked_non_token_mut = true;
                                }
                            }
                            break;
                        }
                    }
                }
            }

            let has_link = body_code.contains("has_one")
                || body_code.contains("constraint =")
                || body_code.contains("associated_token")
                || body_code.contains("token::authority")
                || body_code.contains("seeds = [")
                || body_code.contains("seeds=[");
            if has_signer && has_unlinked_non_token_mut && !has_link {
                patterns.has_mutable_account_with_signer_no_link = true;
            }
            let has_token_account =
                body_code.contains("TokenAccount") || body_code.contains("Account<'info, Mint>");
            if has_signer && has_token_account && !has_link {
                patterns.has_token_account_without_authority = true;
            }
        }

        // ── Raw Rust _unchecked function calls (non-Anchor programs) ──
        // In raw Rust programs (no #[derive(Accounts)]), the _unchecked naming convention
        // signals that the checked variant performs security validation this version skips.
        // E.g. Solend: get_single_price_unchecked, unpack_unchecked, get_price_unchecked
        if !is_test_or_util_file && code.contains("next_account_info") {
            let unchecked_call_lines: Vec<_> = lines
                .iter()
                .filter(|l| {
                    let t = l.trim();
                    t.contains("_unchecked(") || t.contains("_unchecked_mut(")
                })
                .filter(|l| !l.trim().starts_with("//"))
                .collect();
            if !unchecked_call_lines.is_empty() {
                patterns.has_raw_rust_unchecked_calls = true;
            }
        }

        // ── bytemuck unsafe byte casts ──
        // bytes_of_mut: direct mutation bypassing type safety (real unchecked-cast signal).
        // cast/cast_slice: type reinterpretation without validation.
        // bytes_of alone is standard PDA seed serialization — NOT a signal.
        // from_bytes/from_bytes_mut are standard zero-copy Pod deserialization — NOT a signal.
        // Exclude test/util files: bytes_of_mut in test helpers is not production risk.
        if !is_test_or_util_file
            && (code.contains("bytemuck::bytes_of_mut")
                || code.contains("bytemuck::cast")
                || code.contains("bytemuck::cast_slice"))
        {
            patterns.has_bytemuck_unsafe_cast = true;
        }

        // ── Solitaire framework raw Info<'b> fields ──
        // Solitaire programs use `Info<'b>` for raw AccountInfo (no type validation).
        // The `FromAccounts` derive macro deserializes these without checking account
        // type or owner — equivalent to Anchor's UncheckedAccount.
        // Detect: struct fields of type `Info<'b>` or `Mut<Info<'b>>` (without Signer
        // or Sysvar wrapper) inside `#[derive(FromAccounts)]` structs.
        if code.contains("FromAccounts") && code.contains("Info<'") {
            // Check for raw Info<'b> fields (not wrapped in Signer/Sysvar/Derive)
            let mut in_from_accounts = false;
            for line in lines.iter() {
                if line.contains("FromAccounts") {
                    in_from_accounts = true;
                }
                if in_from_accounts && line.trim().starts_with("pub ") {
                    let lt = line.trim();
                    // Check for raw Info<'b> or Mut<Info<'b>> without Signer/Sysvar/Derive
                    if (lt.contains("Info<'") || lt.contains("Info <'"))
                        && !lt.contains("Signer<")
                        && !lt.contains("Sysvar<")
                        && !lt.contains("Derive<")
                        && !lt.contains("Data<'")
                        && !lt.contains("MaybeMut<")
                    {
                        patterns.has_solitaire_raw_info = true;
                    }
                }
                if in_from_accounts && line.trim().starts_with("}") && !line.contains("{") {
                    in_from_accounts = false;
                }
            }
        }
    }

    patterns
}
