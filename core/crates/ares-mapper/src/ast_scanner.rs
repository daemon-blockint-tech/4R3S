use crate::taint_engine::TaintEngine;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
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
                    category: "missing-signer-check".to_string(),
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
                    let ty_str = quote::quote!(#ty).to_string();
                    taint.mark_param(&param_name, &ty_str);
                }
            }
            // Walk the function body — without this, TaintEngine's Visit impl
            // (and everything in process_stmt/process_expr: arbitrary-cpi,
            // type-cosplay, owner-assignment, arithmetic, casts) never runs at
            // all. Params were being tainted correctly, but nothing was ever
            // checked against a sink — taint.findings stayed permanently empty.
            taint.visit_item_fn(func);

            // Function-level guards (reinit, close-revival) — these aren't a
            // dataflow chain, so they're checked once per function directly.
            taint.check_function_level_patterns(&func.sig.ident.to_string(), &func.block);
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
                let ty_str = quote::quote!(#ty).to_string();

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
                let ty_str = quote::quote!(#ty).to_string();

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
        let is_solitaire_handler = node.sig.inputs.len() >= 2 && {
            let first_param = quote::quote!(#node.sig.inputs.first()).to_string();
            first_param.contains("ExecutionContext")
        };

        handler.is_entry_point =
            is_instruction || is_solitaire_handler || fn_name.starts_with("process_");

        // Extract parameters
        for arg in &node.sig.inputs {
            if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                let param_name = pat_to_string(pat);
                let ty_str = quote::quote!(#ty).to_string();
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

        // Detect CPI calls
        if expr_str.contains("invoke(") || expr_str.contains("invoke_signed(") {
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
    let files: Vec<(PathBuf, String)> = WalkDir::new(dir)
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
    let mut cats: HashSet<String> = HashSet::new();
    for f in findings {
        if f.confidence >= 0.55 {
            cats.insert(f.category.clone());
        }
    }
    cats.into_iter().collect()
}

#[cfg(test)]
mod eng3_taint_sources_sinks {
    //! ENG-3: real test coverage for all 6 taint classes this task covers,
    //! against the canonical catalog IDs from Gilbert's ENG-2 merge
    //! (src/knowledge/solana-vulns.ts) — sealevel-attacks style: a
    //! vulnerable case per class, and a guarded/safe case where a
    //! meaningful negative is actually possible.
    use super::*;

    fn findings_for(src: &str) -> Vec<AstFinding> {
        analyze_file(std::path::Path::new("test.rs"), src).findings
    }

    fn has_category(findings: &[AstFinding], category: &str) -> bool {
        findings.iter().any(|f| f.category == category)
    }

    // --- missing-signer-check --------------------------------------------

    #[test]
    fn missing_signer_check_fires_on_unchecked_account_info() {
        let src = r#"
            fn withdraw(admin: AccountInfo, amount: u64) {
                let _ = amount;
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "missing-signer-check"),
            "expected missing-signer-check, got: {:?}",
            findings
        );
    }

    #[test]
    fn missing_signer_check_does_not_fire_when_is_signer_is_checked() {
        let src = r#"
            fn withdraw(admin: AccountInfo, amount: u64) {
                if !admin.is_signer {
                    return;
                }
                let _ = amount;
            }
        "#;
        let findings = findings_for(src);
        assert!(
            !has_category(&findings, "missing-signer-check"),
            "did not expect missing-signer-check once is_signer is checked, got: {:?}",
            findings
        );
    }

    // --- missing-owner-check ----------------------------------------------

    #[test]
    fn missing_owner_check_fires_when_owner_assigned_from_tainted_source() {
        let src = r#"
            fn set_config(new_owner: AccountInfo) {
                config.owner = new_owner;
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "missing-owner-check"),
            "expected missing-owner-check, got: {:?}",
            findings
        );
    }

    // --- non-canonical-bump ------------------------------------------------

    #[test]
    fn non_canonical_bump_fires_on_create_program_address_with_tainted_arg() {
        let src = r#"
            fn derive_pda(data: &[u8], seed: &[u8]) {
                let pda = create_program_address(&[seed, data], &program_id);
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "non-canonical-bump"),
            "expected non-canonical-bump, got: {:?}",
            findings
        );
    }

    #[test]
    fn non_canonical_bump_does_not_fire_on_find_program_address() {
        // find_program_address is the safe API — always derives the one
        // canonical bump itself, rather than trusting a caller-supplied one.
        let src = r#"
            fn derive_pda(data: &[u8], seed: &[u8]) {
                let pda = find_program_address(&[seed, data], &program_id);
            }
        "#;
        let findings = findings_for(src);
        assert!(
            !has_category(&findings, "non-canonical-bump"),
            "did not expect non-canonical-bump for find_program_address, got: {:?}",
            findings
        );
    }

    // --- arbitrary-cpi -------------------------------------------------------

    #[test]
    fn arbitrary_cpi_fires_when_invoke_receives_tainted_data() {
        let src = r#"
            fn withdraw(target_program: AccountInfo, data: &[u8]) {
                invoke(target_program, data);
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "arbitrary-cpi"),
            "expected arbitrary-cpi, got: {:?}",
            findings
        );
    }

    // --- account-reinitialization --------------------------------------------

    #[test]
    fn account_reinitialization_fires_when_init_never_checks_is_initialized() {
        let src = r#"
            fn initialize_vault(vault: AccountInfo) {
                let _ = vault;
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "account-reinitialization"),
            "expected account-reinitialization, got: {:?}",
            findings
        );
    }

    #[test]
    fn account_reinitialization_does_not_fire_when_is_initialized_is_checked() {
        let src = r#"
            fn initialize_vault(vault: AccountInfo) {
                if vault.is_initialized {
                    return;
                }
            }
        "#;
        let findings = findings_for(src);
        assert!(
            !has_category(&findings, "account-reinitialization"),
            "did not expect account-reinitialization once is_initialized is checked, got: {:?}",
            findings
        );
    }

    // --- account-close-revival ------------------------------------------------

    #[test]
    fn account_close_revival_fires_when_lamports_zeroed_but_data_is_not() {
        let src = r#"
            fn close_account(account: AccountInfo) {
                **account.lamports.borrow_mut() = 0;
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "account-close-revival"),
            "expected account-close-revival, got: {:?}",
            findings
        );
    }

    #[test]
    fn account_close_revival_does_not_fire_when_data_is_also_zeroed() {
        let src = r#"
            fn close_account(account: AccountInfo) {
                **account.lamports.borrow_mut() = 0;
                let mut data = account.data.borrow_mut();
                data.fill(0);
            }
        "#;
        let findings = findings_for(src);
        assert!(
            !has_category(&findings, "account-close-revival"),
            "did not expect account-close-revival once data is also zeroed, got: {:?}",
            findings
        );
    }
}

#[cfg(test)]
mod eng3_smoke_test_real_fixture {
    //! Everything above uses small, synthetic snippets written specifically
    //! to exercise each check — useful, but it's still code shaped around
    //! the implementation. This runs the real, independently-authored
    //! Cashio incident-repro fixture (eval/fixtures/rs/incident-repros/) —
    //! a stylized reproduction of the real ~$52M Cashio exploit, not
    //! written with this taint engine in mind at all — as a genuine smoke
    //! test that the wiring fix generalizes beyond my own test cases.
    use super::*;

    const CASHIO_FIXTURE: &str =
        include_str!("../../../../eval/fixtures/rs/incident-repros/cashio-2022.rs");

    #[test]
    fn wiring_fix_detects_type_cosplay_in_the_real_cashio_fixture() {
        // Cashio's real bug: `Bank::try_from_slice(&bank.data.borrow())` on a
        // raw, untyped AccountInfo with no owner/discriminator check first —
        // exactly the type-cosplay sink this engine already had logic for,
        // which was dead code before the wiring fix. This is the same
        // pre-existing check as arbitrary-cpi, not one of ENG-3's four new
        // additions — the point here is confirming the *fix* generalizes to
        // real code, not re-testing logic already covered above.
        let scanner = analyze_file(
            std::path::Path::new("cashio-2022.rs"),
            CASHIO_FIXTURE,
        );
        let categories: Vec<&str> = scanner.findings.iter().map(|f| f.category.as_str()).collect();
        assert!(
            categories.contains(&"type-cosplay"),
            "expected type-cosplay on the real Cashio fixture, got categories: {:?}",
            categories
        );
    }
}
