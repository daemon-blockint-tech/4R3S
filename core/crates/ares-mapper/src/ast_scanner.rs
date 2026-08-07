use crate::taint_engine::TaintEngine;
use rayon::prelude::*;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::{visit::Visit, Attribute, Expr, FnArg, ItemFn, ItemStruct, Pat, PatType};
use tracing::{info, warn};
use walkdir::WalkDir;

/// Phase-2 AST-based scanner for Solana programs.
/// Uses `syn` to parse Rust AST and detect vulnerabilities that Phase-1 regex misses:
/// - Macro-expanded validation (Anchor derive(Accounts), Solitaire)
/// - Safe-wrapper bypasses (checked_add, try_into that still have semantic bugs)
/// - Data-flow from untrusted inputs to sensitive sinks
#[derive(Debug, Clone, Default)]
pub struct AstScanner {
    pub findings: Vec<AstFinding>,
    pub anchor_accounts: Vec<AnchorAccountStruct>,
    pub solitaire_accounts: Vec<SolitaireAccountStruct>,
    pub instruction_handlers: Vec<InstructionHandler>,
    pub cpi_calls: Vec<CpiCallSite>,
}

#[derive(Debug, Clone, Default)]
pub struct SolitaireAccountStruct {
    pub name: String,
    pub fields: Vec<SolitaireAccountField>,
    pub has_derive_from_accounts: bool,
}

#[derive(Debug, Clone)]
pub struct SolitaireAccountField {
    pub name: String,
    pub ty: String,
    pub is_signer: bool,
    pub is_mut: bool,
    pub is_raw_info: bool, // Info<'b> without Signer/Sysvar wrapper
    pub is_sysvar: bool,
}

#[derive(Debug, Clone)]
pub struct AstFinding {
    pub category: String,
    pub severity: String,
    pub file: PathBuf,
    pub line: usize,
    pub description: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Default)]
pub struct AnchorAccountStruct {
    pub name: String,
    pub fields: Vec<AnchorAccountField>,
    pub has_derive_accounts: bool,
}

#[derive(Debug, Clone)]
pub struct AnchorAccountField {
    pub name: String,
    pub ty: String,
    pub is_signer: bool,
    pub is_mut: bool,
    pub has_owner_check: bool,
    pub has_constraint: bool,
    pub is_unchecked_account: bool,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionHandler {
    pub name: String,
    pub params: Vec<HandlerParam>,
    pub has_signer_check: bool,
    pub has_program_id_check: bool,
    pub uses_invoke: bool,
    pub is_entry_point: bool,
}

#[derive(Debug, Clone)]
pub struct HandlerParam {
    pub name: String,
    pub ty: String,
    pub is_ctx: bool,
    pub is_account_info: bool,
}

#[derive(Debug, Clone)]
pub struct CpiCallSite {
    pub function: String,
    pub line: usize,
    pub has_program_id_validation: bool,
    pub target_program: Option<String>,
}

/// Parse a single Rust source file and extract AST-based findings.
pub fn analyze_file(path: &Path, content: &str) -> AstScanner {
    let mut scanner = AstScanner::default();

    let ast = match syn::parse_file(content) {
        Ok(file) => file,
        Err(e) => {
            warn!("Failed to parse {:?}: {}", path, e);
            return scanner;
        }
    };

    let mut visitor = SolanaVisitor {
        path: path.to_path_buf(),
        scanner: &mut scanner,
        local_vars: HashMap::new(),
        invoke_seen: false,
        program_id_checked: false,
    };
    visitor.visit_file(&ast);

    // Post-process: cross-check instruction handlers against account constraints
    for handler in &scanner.instruction_handlers {
        // If handler uses invoke/invoke_signed but has no program_id check → arbitrary-cpi
        // Conservativeness: Anchor CpiContext (body contains "CpiContext") validates
        // the target program account through Anchor's typed account system.
        // Only flag raw invoke/invoke_signed calls without explicit validation.
        let has_typed_program_account = handler
            .params
            .iter()
            .any(|p| p.ty.contains("Program<") || p.ty.contains("ProgramAccount<"));

        if handler.is_entry_point
            && handler.uses_invoke
            && !handler.has_program_id_check
            && !has_typed_program_account
        {
            scanner.findings.push(AstFinding {
                category: "arbitrary-cpi".to_string(),
                severity: "Critical".to_string(),
                file: path.to_path_buf(),
                line: 0, // we don't track line precisely for post-processed findings yet
                description: format!(
                    "Instruction `{}` calls invoke/invoke_signed without validating target program_id. This is the classic arbitrary-CPI vulnerability.",
                    handler.name
                ),
                confidence: 0.85,
            });
        }

        // If handler takes AccountInfo without signer check → signer-authorization
        for param in &handler.params {
            if param.is_account_info && !handler.has_signer_check {
                scanner.findings.push(AstFinding {
                    category: "signer-authorization".to_string(),
                    severity: "Critical".to_string(),
                    file: path.to_path_buf(),
                    line: 0,
                    description: format!(
                        "Instruction `{}` takes raw AccountInfo (`{}`) without explicit signer validation. In non-Anchor programs (e.g., Solitaire), this is a missing-signer vulnerability.",
                        handler.name, param.name
                    ),
                    confidence: 0.70, // lower confidence because we can't see macro-expanded checks
                });
            }
        }
    }

    // === Phase-3: Taint Engine Second Pass ===
    // Run data-flow analysis to detect propagation of untrusted data to sensitive sinks.
    let mut taint = TaintEngine::new();

    // Mark tainted fields from Solitaire structs
    for s in &scanner.solitaire_accounts {
        for f in &s.fields {
            if f.is_raw_info {
                taint.mark_tainted_field(&s.name, &f.name);
            }
        }
    }

    // Mark tainted fields from Anchor structs (UncheckedAccount without signer/owner)
    for s in &scanner.anchor_accounts {
        for f in &s.fields {
            if f.is_unchecked_account && !f.is_signer && !f.has_owner_check {
                taint.mark_tainted_field(&s.name, &f.name);
            }
        }
    }

    // Visit all functions with taint analysis
    for item in &ast.items {
        if let syn::Item::Fn(func) = item {
            // Mark parameters
            for arg in &func.sig.inputs {
                if let syn::FnArg::Typed(syn::PatType { pat, ty, .. }) = arg {
                    let param_name = pat_to_string(pat);
                    let ty_str = type_string(ty);
                    taint.mark_param(&param_name, &ty_str);
                }
            }
        }
    }

    // Convert taint findings to AST findings
    for tf in taint.findings {
        scanner.findings.push(AstFinding {
            category: tf.category,
            severity: tf.severity,
            file: path.to_path_buf(),
            line: tf.line,
            description: tf.description,
            confidence: 0.75,
        });
    }

    scanner
}

struct SolanaVisitor<'a> {
    path: PathBuf,
    scanner: &'a mut AstScanner,
    local_vars: HashMap<String, String>, // name -> type
    invoke_seen: bool,
    program_id_checked: bool,
}

impl<'a, 'ast> Visit<'ast> for SolanaVisitor<'a> {
    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        // Detect Anchor #[derive(Accounts)] structs
        let has_derive_accounts = node.attrs.iter().any(is_derive_accounts_attr);

        if has_derive_accounts {
            let mut account_struct = AnchorAccountStruct {
                name: node.ident.to_string(),
                has_derive_accounts: true,
                ..Default::default()
            };

            for field in &node.fields {
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let ty = &field.ty;
                let ty_str = type_string(ty);

                let is_unchecked = ty_str.contains("UncheckedAccount")
                    || field
                        .attrs
                        .iter()
                        .any(|a| attr_to_string(a).contains("unchecked"));

                let is_signer = field.attrs.iter().any(|a| {
                    let s = attr_to_string(a);
                    s.contains("signer") || s.contains("Signer")
                });

                let is_mut = field.attrs.iter().any(|a| {
                    let s = attr_to_string(a);
                    s.contains("mut") || s.contains("mut")
                });

                let has_constraint = field.attrs.iter().any(|a| {
                    let s = attr_to_string(a);
                    s.contains("has_one") || s.contains("constraint") || s.contains("owner")
                });

                let has_owner = field.attrs.iter().any(|a| {
                    let s = attr_to_string(a);
                    s.contains("owner =") || s.contains("owner:")
                });

                account_struct.fields.push(AnchorAccountField {
                    name: field_name.clone(),
                    ty: ty_str.clone(),
                    is_signer,
                    is_mut,
                    has_owner_check: has_owner,
                    has_constraint,
                    is_unchecked_account: is_unchecked,
                });

                // Finding: UncheckedAccount without signer/owner/constraints → type-cosplay / ownership-check risk
                if is_unchecked && !is_signer && !has_owner && !has_constraint {
                    self.scanner.findings.push(AstFinding {
                        category: "ownership-check".to_string(),
                        severity: "High".to_string(),
                        file: self.path.clone(),
                        line: 0,
                        description: format!(
                            "Field `{}` in `{}` uses UncheckedAccount without signer, owner, or constraint validation. This is a type-cosplay / ownership-check vulnerability in macro-expanded code.",
                            field_name, node.ident
                        ),
                        confidence: 0.80,
                    });
                }
            }

            self.scanner.anchor_accounts.push(account_struct);
        }

        // Detect Solitaire #[derive(FromAccounts)] structs
        let has_derive_from_accounts = node.attrs.iter().any(is_derive_from_accounts_attr);

        if has_derive_from_accounts {
            let mut account_struct = SolitaireAccountStruct {
                name: node.ident.to_string(),
                has_derive_from_accounts: true,
                ..Default::default()
            };

            for field in &node.fields {
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let ty = &field.ty;
                let ty_str = type_string(ty);

                // Solitaire type analysis:
                // - Info<'b> = raw AccountInfo (no validation) → risky
                // - Signer<Info<'b>> = signer-validated
                // - Sysvar<'b, T> = sysvar-validated
                // - Mut<...> = mutable wrapper
                // - Data<'b, T, ...> = typed data account (has owner check via Seeded)
                let is_raw_info = is_raw_solitaire_info(&ty_str);
                let is_signer = ty_str.contains("Signer<");
                let is_mut = ty_str.contains("Mut<");
                let is_sysvar = ty_str.contains("Sysvar<");

                account_struct.fields.push(SolitaireAccountField {
                    name: field_name.clone(),
                    ty: ty_str.clone(),
                    is_signer,
                    is_mut,
                    is_raw_info,
                    is_sysvar,
                });

                // Finding: raw Info<'b> in security-critical struct → missing-signer / missing-validation
                // This is the Neodyme finding: instruction_acc: Info<'b> in VerifySignatures
                // bypasses secp256k1 signature verification.
                if is_raw_info && !is_signer && !is_sysvar {
                    // Check if field name suggests it should be validated
                    let should_be_validated = [
                        "instruction",
                        "instruction_acc",
                        "sysvar",
                        "clock",
                        "rent",
                        "stake_history",
                        "epoch_schedule",
                        "recent_blockhashes",
                    ]
                    .iter()
                    .any(|&s| field_name.to_lowercase().contains(s));

                    if should_be_validated {
                        self.scanner.findings.push(AstFinding {
                            category: "signer-authorization".to_string(),
                            severity: "Critical".to_string(),
                            file: self.path.clone(),
                            line: 0,
                            description: format!(
                                "Solitaire field `{}` in `{}` uses raw `Info<'b>` (unvalidated AccountInfo) for a security-critical account. \
                                In `VerifySignatures`, `instruction_acc: Info<'b>` instead of `Sysvar<'b, Instructions>` \
                                allowed attackers to pass a forged instruction reflection account, bypassing secp256k1 signature verification. \
                                Use `Sysvar<'b, T>` or add explicit validation.",
                                field_name, node.ident
                            ),
                            confidence: 0.85,
                        });
                    } else {
                        self.scanner.findings.push(AstFinding {
                            category: "ownership-check".to_string(),
                            severity: "High".to_string(),
                            file: self.path.clone(),
                            line: 0,
                            description: format!(
                                "Solitaire field `{}` in `{}` uses raw `Info<'b>` without Signer or Sysvar wrapper. \
                                This is an unvalidated AccountInfo that may allow type-cosplay or ownership-check bypass.",
                                field_name, node.ident
                            ),
                            confidence: 0.70,
                        });
                    }
                }
            }

            self.scanner.solitaire_accounts.push(account_struct);
        }

        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_name = node.sig.ident.to_string();
        self.invoke_seen = false;
        self.program_id_checked = false;
        self.local_vars.clear();

        let mut handler = InstructionHandler {
            name: fn_name.clone(),
            ..Default::default()
        };

        // Detect if this is an Anchor instruction handler
        let is_instruction = node.attrs.iter().any(|attr| {
            attr_to_string(attr).contains("# [instruction]")
                || attr_to_string(attr).contains("entrypoint!")
        });

        // Detect if this is a Solitaire instruction handler
        // Signature: fn(ctx: &ExecutionContext, accs: &mut AccountStruct, data: Data) -> Result<()>
        // This was `quote::quote!(#node.sig.inputs.first()).to_string()`, which
        // does not do what it reads like. Inside `quote!`, `#node` interpolates
        // the ItemFn and the trailing `.sig.inputs.first()` is emitted as literal
        // tokens — it is never evaluated. The string held the *entire function*,
        // so any two-parameter function mentioning `ExecutionContext` anywhere,
        // including in its body or a string literal, was classified as a Solitaire
        // entry point. `is_entry_point` gates `arbitrary-cpi` and
        // `signer-authorization`, both Critical, so this manufactured Critical
        // findings on functions that are not instruction boundaries.
        let is_solitaire_handler = node.sig.inputs.len() >= 2
            && node.sig.inputs.first().is_some_and(|arg| match arg {
                FnArg::Typed(PatType { ty, .. }) => type_string(ty).contains("ExecutionContext"),
                FnArg::Receiver(_) => false,
            });

        handler.is_entry_point =
            is_instruction || is_solitaire_handler || fn_name.starts_with("process_");

        // Extract parameters
        for arg in &node.sig.inputs {
            if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                let param_name = pat_to_string(pat);
                let ty_str = type_string(ty);
                let is_ctx = ty_str.contains("Context<") || ty_str.contains("ExecutionContext");
                let is_account_info = ty_str.contains("AccountInfo") || ty_str.contains("Info<");

                handler.params.push(HandlerParam {
                    name: param_name.clone(),
                    ty: ty_str.clone(),
                    is_ctx,
                    is_account_info,
                });

                // Track local variable types for data-flow
                self.local_vars.insert(param_name, ty_str);
            }
        }

        // Visit function body to detect invoke calls, program_id checks, signer checks
        syn::visit::visit_item_fn(self, node);

        handler.uses_invoke = self.invoke_seen;
        handler.has_program_id_check = self.program_id_checked;

        // Heuristic: signer check = explicit `.is_signer`, `.key()`, or `Signer` type
        let body_str = quote::quote!(#node.block).to_string();
        handler.has_signer_check = body_str.contains("is_signer")
            || body_str.contains("Signer")
            || handler
                .params
                .iter()
                .any(|p| p.is_ctx && p.ty.contains("Signer"));

        if is_instruction
            || is_solitaire_handler
            || handler.uses_invoke
            || handler.params.iter().any(|p| p.is_account_info)
        {
            self.scanner.instruction_handlers.push(handler);
        }
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        let expr_str = quote::quote!(#node).to_string();

        // Detect CPI calls.
        //
        // This must not be written as `expr_str.contains("invoke(")`. `expr_str`
        // comes from `quote!(...).to_string()`, which reconstructs source from a
        // token stream and separates tokens with spaces: `invoke(&ix, accounts)`
        // round-trips as `invoke (& ix , accounts)`. The no-space form therefore
        // never matched, `invoke_seen` was never set, `handler.uses_invoke` was
        // permanently false, and the post-processing pass above could not raise
        // `arbitrary-cpi` at all — a Critical detector that silently detected
        // nothing. (The `_unchecked` check further down this same function
        // already compensated with `expr_str.replace(" ", "")`; this one did not.)
        //
        // `calls_fn` matches on the compact form and requires a real identifier
        // boundary, so `invoke(` is found while `try_invoke(` or `reinvoke(` —
        // different functions that merely end in the same letters — are not.
        let expr_compact = expr_str.replace(' ', "");
        if calls_fn(&expr_compact, "invoke") || calls_fn(&expr_compact, "invoke_signed") {
            self.invoke_seen = true;

            let has_validation = expr_str.contains("program_id")
                || expr_str.contains("check_program")
                || expr_str.contains("verify_program");

            if !has_validation && !self.program_id_checked {
                // We defer arbitrary-cpi finding to post-processing to reduce false positives
            }
        }

        // Detect program_id validation
        // Covers both == (Anchor: program_id == expected) and != (raw Rust: .owner != program_id)
        if expr_str.contains("program_id")
            && (expr_str.contains("==") || expr_str.contains("!=") || expr_str.contains("check"))
        {
            self.program_id_checked = true;
        }

        // Detect _unchecked function calls in non-test source files
        // Raw Rust programs (e.g. Solend) use _unchecked naming convention
        // to mark functions that skip validation the checked version performs.
        // Patterns: get_price_unchecked, unpack_unchecked, get_ema_price_unchecked
        if !self.path.to_string_lossy().contains("test") {
            let expr_compact = expr_str.replace(" ", "");
            if expr_compact.contains("_unchecked(") || expr_compact.contains("_unchecked_mut(") {
                let is_unpack = expr_compact.contains("unpack_unchecked")
                    || expr_compact.contains("unpack_unchecked_mut");
                let is_oracle = expr_compact.contains("price_unchecked")
                    || expr_compact.contains("oracle_unchecked")
                    || expr_compact.contains("get_single_price_unchecked");
                if is_unpack {
                    self.scanner.findings.push(AstFinding {
                        category: "account-data-matching".to_string(),
                        severity: "High".to_string(),
                        file: self.path.clone(),
                        line: node.span().start().line,
                        description: "Call to `_unchecked` unpack function skips discriminator/type validation. \
                            This is an account-data-matching vulnerability: without checking the account \
                            discriminator, a different account type with the same size could be substituted.".to_string(),
                        confidence: 0.80,
                    });
                }
                if is_oracle {
                    self.scanner.findings.push(AstFinding {
                        category: "ownership-check".to_string(),
                        severity: "High".to_string(),
                        file: self.path.clone(),
                        line: node.span().start().line,
                        description: "Call to `_unchecked` oracle price function skips account owner validation. \
                            The checked version verifies the oracle account is owned by the expected oracle \
                            program; the unchecked version trusts the account data without owner verification, \
                            allowing a forged oracle account to manipulate prices.".to_string(),
                        confidence: 0.85,
                    });
                    self.scanner.findings.push(AstFinding {
                        category: "unchecked-cast".to_string(),
                        severity: "Medium".to_string(),
                        file: self.path.clone(),
                        line: node.span().start().line,
                        description: "Call to `_unchecked` oracle price function skips staleness/validation checks. \
                            The checked version validates price freshness; the unchecked version returns \
                            potentially stale or invalid data without validation.".to_string(),
                        confidence: 0.70,
                    });
                }
                if !is_unpack && !is_oracle && expr_compact.contains("_unchecked(") {
                    self.scanner.findings.push(AstFinding {
                        category: "ownership-check".to_string(),
                        severity: "Medium".to_string(),
                        file: self.path.clone(),
                        line: node.span().start().line,
                        description: "Call to `_unchecked` function bypasses validation. \
                            The `_unchecked` naming convention signals that the checked \
                            variant performs security validation this version skips."
                            .to_string(),
                        confidence: 0.65,
                    });
                }
            }
        }

        // Detect bytemuck unsafe byte casts (type-cosplay / unchecked-cast risk)
        // Only flag bytes_of_mut (direct mutation bypassing type safety) and cast/cast_slice
        // (type reinterpretation). bytes_of is standard PDA seed serialization (safe).
        // from_bytes/from_bytes_mut are standard zero-copy deserialization (safe Pod reinterp).
        let is_bytemuck_unsafe = expr_str.contains("bytemuck::bytes_of_mut")
            || expr_str.contains("bytemuck::cast")
            || expr_str.contains("bytemuck::cast_slice");
        if is_bytemuck_unsafe {
            self.scanner.findings.push(AstFinding {
                category: "unchecked-cast".to_string(),
                severity: "Medium".to_string(),
                file: self.path.clone(),
                line: node.span().start().line,
                description:
                    "Unsafe byte-level mutation/cast via `bytemuck`. bytes_of_mut bypasses \
                    type checking for account mutation; cast/cast_slice reinterprets bytes \
                    without validation. Use Anchor's typed account system or explicit checks."
                        .to_string(),
                confidence: 0.75,
            });
        }

        // Detect unchecked numeric casts / conversions
        if expr_str.contains("as u64") || expr_str.contains("as i64") {
            // Check if wrapped in safe method
            let expr_str_compact = expr_str.replace(" ", "");
            let is_safe = expr_str_compact.contains("checked_")
                || expr_str_compact.contains("try_into()")
                || expr_str_compact.contains("saturating_")
                || (expr_str_compact.contains("(") && expr_str_compact.contains(").unwrap()"))
                || (expr_str_compact.contains("(") && expr_str_compact.contains(")?"));
            // Suppress known-safe sources: sysvar timestamps, slot, epoch, rent, and
            // array lengths are inherently bounded and cannot overflow u64.
            // Mirrors the taint engine suppression at taint_engine.rs:308-313.
            let is_safe_source = expr_str_compact.contains("unix_timestamp")
                || expr_str_compact.contains("clock")
                || expr_str_compact.contains("slot")
                || expr_str_compact.contains("epoch")
                || expr_str_compact.contains("rent")
                || expr_str_compact.contains("len()");
            // Only fire on financially-significant casts: the expression must either
            // contain arithmetic operators (complex computation) or financial keywords.
            // Simple `some_param as u64` without financial context is typically a safe
            // widening cast (u32→u64) that poses no exploitable truncation risk.
            let has_financial_context = expr_str.contains('+')
                || expr_str.contains('*')
                || expr_str.contains('-')
                || expr_str.contains("amount")
                || expr_str.contains("balance")
                || expr_str.contains("price")
                || expr_str.contains("supply")
                || expr_str.contains("reserve")
                || expr_str.contains("liquidity")
                || expr_str.contains("total")
                || expr_str.contains("fee")
                || expr_str.contains("reward");

            if !is_safe && !is_safe_source && has_financial_context {
                self.scanner.findings.push(AstFinding {
                    category: "unchecked-cast".to_string(),
                    severity: "High".to_string(),
                    file: self.path.clone(),
                    line: node.span().start().line,
                    description: format!(
                        "Unchecked numeric cast `{}` detected. If the source value exceeds the target type's range, this will silently truncate. Use `checked_add`, `try_into`, or `saturating_*` instead.",
                        expr_str.chars().take(60).collect::<String>()
                    ),
                    confidence: 0.75,
                });
            }
        }

        // Detect try_from_slice without discriminator check (type-cosplay)
        // Exclude Pubkey::try_from_slice and primitive numeric types (u128, u64, etc.)
        // which parse fixed-format on-chain data, not account type substitution attacks.
        let expr_str_compact = expr_str.replace(" ", "");
        let is_safe_try_from = expr_str_compact.contains("Pubkey::try_from_slice")
            || expr_str_compact.contains("u128::try_from_slice")
            || expr_str_compact.contains("u64::try_from_slice")
            || expr_str_compact.contains("i128::try_from_slice")
            || expr_str_compact.contains("i64::try_from_slice")
            || expr_str_compact.contains("BigNum::try_from_slice");
        if expr_str_compact.contains("try_from_slice")
            && !expr_str_compact.contains("discriminator")
            && !is_safe_try_from
        {
            let is_test_or_util = self.path.to_string_lossy().contains("test")
                || self.path.to_string_lossy().contains("util")
                || self.path.to_string_lossy().contains("mock");
            self.scanner.findings.push(AstFinding {
                category: "type-cosplay".to_string(),
                severity: "High".to_string(),
                file: self.path.clone(),
                line: node.span().start().line,
                description: "`try_from_slice` called without discriminator check. Same-size types can be confused, leading to type-cosplay attacks. Use Anchor's `Account<'info, T>` or verify discriminator before deserialization.".to_string(),
                confidence: if is_test_or_util { 0.40 } else { 0.80 },
            });
        }

        // Detect manual lamport drain (revival-attack / account-closure)
        if expr_str.contains("lamports.borrow_mut()") && expr_str.contains("= 0") {
            self.scanner.findings.push(AstFinding {
                category: "revival-attack".to_string(),
                severity: "Critical".to_string(),
                file: self.path.clone(),
                line: node.span().start().line,
                description: "Manual lamport drain detected: `lamports.borrow_mut() = 0`. This is an account-closure anti-pattern. The account can be revived by sending lamports back. Use Anchor's `close` constraint instead.".to_string(),
                confidence: 0.90,
            });
        }

        // Detect init_if_needed with fixed seeds (re-initialization / frontrunning)
        if expr_str.contains("init_if_needed") && expr_str.contains("seeds") {
            let has_is_initialized = expr_str.contains("is_initialized");
            if !has_is_initialized {
                self.scanner.findings.push(AstFinding {
                    category: "re-initialization".to_string(),
                    severity: "Critical".to_string(),
                    file: self.path.clone(),
                    line: node.span().start().line,
                    description: "`init_if_needed` with fixed seeds but no `is_initialized` guard. An attacker can re-initialize and overwrite existing account data.".to_string(),
                    confidence: 0.85,
                });
            }
        }

        syn::visit::visit_expr(self, node);
    }
}

/// Render a type as a whitespace-free string for substring matching.
///
/// `quote!(#ty).to_string()` rebuilds source from tokens and puts a space
/// between every one, so `Program<'info, Token>` comes back as
/// `Program < 'info , Token >`. Every `ty_str.contains("Something<")` test in
/// this file is written without spaces, so against the raw rendering they all
/// silently returned false — including the `Program<` / `ProgramAccount<` check
/// that is the sole false-positive guard for Anchor CPI, and the `Signer<` /
/// `Sysvar<` / `Mut<` classification of Solitaire fields.
///
/// Normalising here rather than at each comparison is deliberate: the failure is
/// invisible (a detector that finds nothing looks exactly like clean code), so
/// leaving the raw form reachable would let the next `contains("Foo<")` reopen
/// the same hole. `is_raw_solitaire_info` already stripped spaces internally;
/// that call is now redundant but harmless.
fn type_string(ty: &syn::Type) -> String {
    quote::quote!(#ty).to_string().replace(' ', "")
}

/// True when `compact` (a whitespace-stripped `quote!` rendering) contains a
/// call to exactly `name`.
///
/// A bare `contains("invoke(")` would also fire on `try_invoke(` and
/// `reinvoke(`, which are different functions; requiring the preceding character
/// to be a non-identifier one keeps the match to the function actually named.
/// Method calls (`x.invoke(..)`) still match, because `.` is not an identifier
/// character — that is intended: a CPI through a receiver is still a CPI.
fn calls_fn(compact: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    let mut from = 0usize;
    while let Some(rel) = compact[from..].find(&needle) {
        let at = from + rel;
        let boundary_ok = at == 0
            || !compact[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if boundary_ok {
            return true;
        }
        from = at + needle.len();
    }
    false
}

fn is_derive_accounts_attr(attr: &Attribute) -> bool {
    let s = attr_to_string(attr);
    (s.contains("derive") && s.contains("Accounts") && !s.contains("FromAccounts"))
        || s.contains("anchor_lang")
}

fn is_derive_from_accounts_attr(attr: &Attribute) -> bool {
    let s = attr_to_string(attr);
    s.contains("derive") && s.contains("FromAccounts")
}

/// Checks if a Solitaire type is raw `Info<'b>` without Signer/Sysvar/Data wrapper.
/// Patterns:
/// - `Info<'b>` → raw (risky)
/// - `Signer<Info<'b>>` → wrapped signer (safe)
/// - `Sysvar<'b, T>` → sysvar (safe)
/// - `Data<'b, T, ...>` → typed data account (safe via Seeded)
fn is_raw_solitaire_info(ty_str: &str) -> bool {
    // Match Info<'b> or Info<'a> or Info<_> — but NOT wrapped in Signer/Sysvar/Mut<Data>/Derive
    let trimmed = ty_str.replace(" ", "");
    if trimmed.contains("Signer<") || trimmed.contains("Sysvar<") || trimmed.contains("Derive<") {
        return false;
    }
    // Check for bare Info<'b> or Info<...> that is not inside another generic
    // Use regex-like heuristic: starts with Info< and doesn't contain nested generics
    trimmed.starts_with("Info<") || trimmed.starts_with("Info<'")
}

fn attr_to_string(attr: &Attribute) -> String {
    quote::quote!(#attr).to_string()
}

fn pat_to_string(pat: &Pat) -> String {
    quote::quote!(#pat)
        .to_string()
        .replace(" ", "")
        .replace("&mut", "")
        .replace("&", "")
}

/// Run AST-based analysis across all `.rs` files in a program directory.
/// Uses rayon for parallel file scanning on multi-core systems.
pub fn scan_directory_ast(dir: &Path) -> AstScanner {
    // Sort by path before the rayon pass so merged scanner output is
    // deterministic regardless of filesystem walk order.
    let mut files: Vec<(PathBuf, String)> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("rs"))
        .filter_map(|e| {
            let path = e.path().to_path_buf();
            std::fs::read_to_string(&path)
                .ok()
                .map(|content| (path, content))
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let scanners: Vec<AstScanner> = files
        .par_iter()
        .map(|(path, content)| analyze_file(path, content))
        .collect();

    let mut combined = AstScanner::default();
    for scanner in scanners {
        combined.findings.extend(scanner.findings);
        combined.anchor_accounts.extend(scanner.anchor_accounts);
        combined
            .solitaire_accounts
            .extend(scanner.solitaire_accounts);
        combined
            .instruction_handlers
            .extend(scanner.instruction_handlers);
        combined.cpi_calls.extend(scanner.cpi_calls);
    }

    info!(
        "AST scan complete for {:?}: {} findings, {} anchor accounts, {} instruction handlers",
        dir,
        combined.findings.len(),
        combined.anchor_accounts.len(),
        combined.instruction_handlers.len()
    );

    combined
}

/// Map AST findings to the coarse category strings used by the benchmark system.
/// Only includes findings whose confidence meets or exceeds `min_confidence`.
/// Phase-7 local judge: suppresses low-confidence AST false positives (e.g.
/// `try_from_slice` in test/util files) without requiring an LLM API call.
pub fn ast_categories_to_benchmark(findings: &[AstFinding]) -> Vec<String> {
    // BTreeSet keeps the collected category list sorted/deterministic for
    // benchmark JSON output.
    let mut cats: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        if f.confidence >= 0.55 {
            cats.insert(f.category.clone());
        }
    }
    cats.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `analyze_file` is pure — source text in, findings out — so every test here
    /// feeds it real Rust and asserts on real output. No fixtures, no stubs.
    fn scan(src: &str) -> AstScanner {
        analyze_file(Path::new("test_program/src/lib.rs"), src)
    }

    fn categories(s: &AstScanner) -> Vec<String> {
        let mut c: Vec<String> = s.findings.iter().map(|f| f.category.clone()).collect();
        c.sort();
        c.dedup();
        c
    }

    // ---- failure paths -----------------------------------------------------
    // These run first because they are the ones that decide whether a scan of a
    // hostile or broken repository degrades or takes the process down with it.

    #[test]
    fn unparseable_source_yields_no_findings_and_does_not_panic() {
        // A target repository controls this text. `syn::parse_file` must be
        // allowed to fail without aborting the scan of every other file.
        let s = scan("fn broken( { this is not rust ::::");
        assert!(s.findings.is_empty());
        assert!(s.instruction_handlers.is_empty());
    }

    #[test]
    fn empty_and_whitespace_only_source_are_clean() {
        assert!(scan("").findings.is_empty());
        assert!(scan("\n\n   \t\n").findings.is_empty());
    }

    #[test]
    fn source_with_no_solana_constructs_reports_nothing() {
        // Guards against a detector that fires on ordinary Rust: a scanner that
        // flags this would flag every dependency in the tree.
        let s = scan("pub fn add(a: u64, b: u64) -> u64 { a + b }");
        assert!(s.findings.is_empty(), "unexpected: {:?}", categories(&s));
    }

    // ---- calls_fn boundary behaviour ---------------------------------------

    #[test]
    fn calls_fn_matches_the_named_call_only() {
        assert!(calls_fn("invoke(&ix,accounts)", "invoke"));
        assert!(calls_fn("let_=invoke(&ix);", "invoke"));
        assert!(calls_fn("solana_program::program::invoke(&ix)", "invoke"));
        // A receiver call is still a CPI.
        assert!(calls_fn("ctx.invoke(&ix)", "invoke"));
        assert!(calls_fn(
            "invoke_signed(&ix,accounts,seeds)",
            "invoke_signed"
        ));
    }

    #[test]
    fn calls_fn_rejects_longer_identifiers_that_merely_end_the_same() {
        // These are different functions. Matching them would attribute a CPI to
        // code that performs none, and `arbitrary-cpi` is Critical.
        assert!(!calls_fn("try_invoke(&ix)", "invoke"));
        assert!(!calls_fn("reinvoke(&ix)", "invoke"));
        assert!(!calls_fn("my_invoke(&ix)", "invoke"));
        assert!(!calls_fn("x9invoke(&ix)", "invoke"));
    }

    #[test]
    fn calls_fn_rejects_a_mention_that_is_not_a_call() {
        assert!(!calls_fn("letinvoke=1;", "invoke"));
        assert!(!calls_fn("//invoke", "invoke"));
        assert!(!calls_fn("", "invoke"));
    }

    #[test]
    fn calls_fn_keeps_scanning_past_a_rejected_boundary() {
        // The rejected `try_invoke(` must not stop the search: a genuine call
        // later in the same expression still has to be found.
        assert!(calls_fn("try_invoke(&a);invoke(&b)", "invoke"));
    }

    // ---- arbitrary-cpi -----------------------------------------------------

    #[test]
    fn flags_invoke_without_program_id_validation() {
        let s = scan(
            r#"
            pub fn process_transfer(accounts: &[AccountInfo]) -> ProgramResult {
                invoke(&ix, accounts)?;
                Ok(())
            }
            "#,
        );
        assert!(
            categories(&s).contains(&"arbitrary-cpi".to_string()),
            "expected arbitrary-cpi, got {:?}",
            categories(&s)
        );
    }

    #[test]
    fn typed_program_account_suppresses_arbitrary_cpi() {
        // The false-positive guard: Anchor's `Program<'info, Token>` is itself the
        // program-id check, so flagging it would fire on correct Anchor code. If
        // this regresses, every Anchor CPI in the corpus becomes a Critical.
        let s = scan(
            r#"
            pub fn process_transfer(token_program: Program<'info, Token>) -> ProgramResult {
                invoke(&ix, accounts)?;
                Ok(())
            }
            "#,
        );
        assert!(
            !categories(&s).contains(&"arbitrary-cpi".to_string()),
            "typed Program<> must suppress arbitrary-cpi, got {:?}",
            categories(&s)
        );
    }

    // ---- signer-authorization ---------------------------------------------

    #[test]
    fn flags_raw_account_info_without_signer_check() {
        let s = scan(
            r#"
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                Ok(())
            }
            "#,
        );
        assert!(
            categories(&s).contains(&"signer-authorization".to_string()),
            "expected signer-authorization, got {:?}",
            categories(&s)
        );
    }

    #[test]
    fn is_signer_check_suppresses_signer_authorization() {
        let s = scan(
            r#"
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
                Ok(())
            }
            "#,
        );
        assert!(
            !categories(&s).contains(&"signer-authorization".to_string()),
            "an explicit is_signer check must suppress the finding, got {:?}",
            categories(&s)
        );
    }

    #[test]
    fn non_entry_point_helper_is_not_treated_as_an_instruction() {
        // `is_entry_point` gates arbitrary-cpi. A private helper that happens to
        // call invoke is not an instruction boundary, so flagging it would report
        // an attack surface that no transaction can reach.
        let s = scan(
            r#"
            fn helper_transfer(accounts: &[AccountInfo]) -> ProgramResult {
                invoke(&ix, accounts)?;
                Ok(())
            }
            "#,
        );
        assert!(
            !categories(&s).contains(&"arbitrary-cpi".to_string()),
            "helper without process_ prefix must not be an entry point, got {:?}",
            categories(&s)
        );
    }

    // ---- entry-point classification ---------------------------------------

    #[test]
    fn solitaire_detection_does_not_key_on_the_whole_function_body() {
        // `is_solitaire_handler` is computed as:
        //     quote::quote!(#node.sig.inputs.first()).to_string()
        // In `quote!`, `#node` interpolates the ItemFn and `.sig.inputs.first()`
        // is emitted as *literal tokens* — it is never evaluated. The string
        // therefore holds the entire function, so ANY two-parameter function that
        // merely mentions ExecutionContext anywhere — including in a comment-free
        // body or an unrelated local — is classified as a Solitaire entry point.
        //
        // Entry-point status gates arbitrary-cpi and signer-authorization, both
        // Critical, so a misclassification here manufactures Critical findings on
        // code that is not an instruction boundary at all.
        let s = scan(
            r#"
            fn not_an_entry_point(a: u64, b: u64) -> ProgramResult {
                let note = "ExecutionContext";
                invoke(&ix, accounts)?;
                Ok(())
            }
            "#,
        );
        assert!(
            !categories(&s).contains(&"arbitrary-cpi".to_string()),
            "a plain 2-arg helper that only mentions ExecutionContext in its body \
             must not be classified as a Solitaire entry point; got {:?}",
            categories(&s)
        );
    }

    #[test]
    fn genuine_solitaire_handler_is_still_an_entry_point() {
        // The other half of the fix above: narrowing to the first parameter must
        // not cost real Solitaire detection. Signature per the Solitaire pattern
        // `fn(ctx: &ExecutionContext, accs: &mut Accounts, data: D)`.
        let s = scan(
            r#"
            fn transfer_native(ctx: &ExecutionContext, accs: &mut TransferAccounts) -> Result<()> {
                invoke(&ix, accounts)?;
                Ok(())
            }
            "#,
        );
        assert!(
            categories(&s).contains(&"arbitrary-cpi".to_string()),
            "a real Solitaire handler taking &ExecutionContext first must still be \
             an entry point; got {:?}",
            categories(&s)
        );
    }
}
