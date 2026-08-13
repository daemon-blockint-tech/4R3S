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
    pub has_one: bool,
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
                    let ty_str = type_string(ty);
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

            let mut all_attrs_text = String::new();
            let mut authority_like_fields: Vec<String> = Vec::new();

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

                let has_one = field
                    .attrs
                    .iter()
                    .any(|a| attr_to_string(a).contains("has_one"));

                let has_owner = field.attrs.iter().any(|a| {
                    let s = attr_to_string(a);
                    s.contains("owner =") || s.contains("owner:")
                });

                // has_one = authority lives on the account being validated (e.g.
                // the vault field), not on the authority field itself — Anchor
                // checks `vault.authority == authority.key()`. So whether *this*
                // field is properly guarded is a whole-struct question: does any
                // field's attribute text reference it by name via has_one? Collect
                // the raw text and the authority-like names now; check after the
                // loop once every field has been seen.
                for attr in &field.attrs {
                    all_attrs_text.push_str(&attr_to_string(attr));
                    all_attrs_text.push(' ');
                }
                if !field_name.is_empty()
                    && (field_name == "authority"
                        || field_name == "admin"
                        || field_name.ends_with("_authority")
                        || field_name.ends_with("_admin"))
                {
                    authority_like_fields.push(field_name.clone());
                }

                account_struct.fields.push(AnchorAccountField {
                    name: field_name.clone(),
                    ty: ty_str.clone(),
                    is_signer,
                    is_mut,
                    has_owner_check: has_owner,
                    has_constraint,
                    has_one,
                    is_unchecked_account: is_unchecked,
                });

                // Finding: UncheckedAccount without signer/owner/constraints — this is
                // precisely what anchor-constraint-gap's own catalog description names
                // ("using UncheckedAccount without #[account(address = ...)]"), not a
                // generic ownership-check catch-all.
                if is_unchecked && !is_signer && !has_owner && !has_constraint {
                    self.scanner.findings.push(AstFinding {
                        category: "anchor-constraint-gap".to_string(),
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

            // Struct-level: an authority-like field (by Anchor's own conventional
            // naming — the catalog's detection hint names exactly this pattern:
            // "Check for missing has_one on authority fields") that no field's
            // has_one constraint ever references by name. A mutable account can
            // then be acted on without Anchor ever confirming it actually belongs
            // to this particular authority.
            for authority_field in &authority_like_fields {
                let referenced = all_attrs_text.contains("has_one")
                    && all_attrs_text.contains(authority_field.as_str());
                if !referenced {
                    self.scanner.findings.push(AstFinding {
                        category: "anchor-constraint-gap".to_string(),
                        severity: "Medium".to_string(),
                        file: self.path.clone(),
                        line: 0,
                        description: format!(
                            "`{}` has an authority-like field `{}`, but no field's `has_one` constraint \
                            references it. Without `has_one = {}` on the account it authorizes, Anchor \
                            never confirms this signer actually owns/matches the account being acted on.",
                            node.ident, authority_field, authority_field
                        ),
                        confidence: 0.55,
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
                            // ENG-3 renamed this category to the canonical
                            // catalog id (src/knowledge/solana-vulns.ts) at the
                            // handler-param site but missed this Solitaire-field
                            // site, so it emitted a category no catalog entry
                            // matches -- the finding degrades to `other`
                            // downstream despite being Critical.
                            category: "missing-signer-check".to_string(),
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
                            category: "missing-owner-check".to_string(),
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
        //
        // This was `quote::quote!(#node.block).to_string()` — the same defect as
        // `#node.sig.inputs.first()` above. Only `#node` interpolates; `.block`
        // is emitted as the literal tokens `. block` and never evaluated, so the
        // string held the *whole* `ItemFn`, attributes first. syn lowers `///`
        // into `#[doc = "..."]`, so a doc comment reading "caller must be a
        // Signer" set `has_signer_check` and silenced the Critical
        // `missing-signer-check` finding at the top of this file. Deleting the
        // doc comment made the identical code report Critical again.
        let body_str = code_string(&node.block);
        handler.has_signer_check = body_str.contains("is_signer")
            || body_str.contains("Signer")
            // Any parameter typed `Signer` is the check — not only a `Context`.
            //
            // `code_string(&node.block)` renders the BODY, so a `Signer<'info>`
            // in the SIGNATURE is not in `body_str` at all, and the `p.is_ctx &&`
            // conjunct then made this arm unreachable for exactly the shape it
            // exists to recognise: `is_ctx` is set only for `Context<..>` /
            // `ExecutionContext`, never for a bare `&Signer<'info>` argument.
            //
            // The result was a Critical false positive on correct Anchor code:
            // `process_withdraw(authority: &Signer<'info>, ..)` reported
            // `missing-signer-check`, where the parameter type IS the assertion.
            // Trading a false negative (prose suppressing a finding) for a false
            // positive on guarded code is the trade this repo has twice retired
            // rules for.
            || handler.params.iter().any(|p| p.ty.contains("Signer"));

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
                        category: "missing-owner-check".to_string(),
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
                        category: "unsafe-type-cast".to_string(),
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
                        category: "missing-owner-check".to_string(),
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
                category: "unsafe-type-cast".to_string(),
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
                    category: "unsafe-type-cast".to_string(),
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
                category: "account-close-revival".to_string(),
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
                    category: "account-reinitialization".to_string(),
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

/// Render arbitrary code as a whitespace-free string with every literal removed.
///
/// Kept separate from `type_string` because it drops literals as well: prose must
/// not be able to decide a security verdict. Both carriers of English inside a
/// token stream are literals — `#[doc = "..."]`, which is what syn lowers `///`
/// into, and `msg!("caller must be Signer")` — and the heuristics that consume
/// this string match on bare substrings, so a sentence *describing* a check would
/// suppress the finding for its absence. Nothing is lost: every signal those
/// heuristics look for (`is_signer`, `Signer`) is an identifier, never a literal.
/// `type_string` does not strip literals because array types (`[u8; 32]`) carry
/// meaningful ones.
fn code_string<T: quote::ToTokens>(node: &T) -> String {
    strip_literals(quote::quote!(#node))
        .to_string()
        .replace(' ', "")
}

/// Drop every literal token, descending into delimiter groups.
fn strip_literals(tokens: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    use proc_macro2::{Group, TokenTree};
    tokens
        .into_iter()
        .filter_map(|tt| match tt {
            TokenTree::Literal(_) => None,
            TokenTree::Group(g) => Some(TokenTree::Group(Group::new(
                g.delimiter(),
                strip_literals(g.stream()),
            ))),
            other => Some(other),
        })
        .collect()
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
    // Mut<...> only marks writability — it is not a validation wrapper the way
    // Signer<>/Sysvar<> are, so `Mut<Info<'b>>` is still exactly as unvalidated
    // as bare `Info<'b>`, and arguably worse: a mutable, unvalidated account can
    // be written to, not just read. Strip one leading Mut<...> layer before the
    // prefix check, or `starts_with("Info<")` never matches it at all — this
    // account type was completely invisible to this check.
    let inner = trimmed
        .strip_prefix("Mut<")
        .and_then(|s| s.strip_suffix(">"))
        .unwrap_or(trimmed.as_str());
    // Check for bare Info<'b> or Info<...> that is not inside another generic
    // Use regex-like heuristic: starts with Info< and doesn't contain nested generics
    inner.starts_with("Info<") || inner.starts_with("Info<'")
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

/// Translate an `AstFinding`/`TaintFinding` category (aligned to
/// `src/knowledge/solana-vulns.ts`'s catalog IDs, per `ENG-3`/`ENG-4`) into
/// the string `ares_core::VulnerabilityCategory::from_str_checked` already
/// recognizes — so a caller wiring this crate's findings into a real scan
/// (`ares-cli`'s `scan.rs`) gets the correct, specific category, not a
/// silent collapse into `InvariantViolation`.
///
/// Deliberately *not* a new `ares-core` enum variant or a change to
/// `from_str_checked` itself, and deliberately not a dependency on
/// `ares_core` from this crate at all — matching the existing vocabulary
/// rather than extending it.
///
/// **Sourcing, disclosed precisely rather than left to look uniform:**
/// most pairings below are taken directly from
/// `eval/mappings/ares-core-categories.json`, which already documents
/// this exact two-vocabulary split with its own confidence rating per
/// pair. `anchor-constraint-gap` and `non-canonical-bump` have **no
/// entry there at all** — both are categories this crate added after
/// that file was last written, so both are my own coarse-stretch
/// judgment calls, not sourced from anything authoritative. Keep this in
/// sync with that file if either side's vocabulary changes.
///
/// **A real, known limitation worth stating plainly, not leaving
/// implicit:** `from_str_checked` maps `"re-initialization"` and
/// `"revival-attack"` to the *same* `AccountReloading` variant. This
/// crate's `ENG-3` work deliberately keeps `account-reinitialization` and
/// `account-close-revival` as two distinct detection classes — different
/// exploits, different remediation — and that distinction is preserved
/// all the way through this function. It is lost one step later, in
/// `ares-core`'s own enum, which is coarser here than the catalog. Not
/// something this function can fix without either a new `ares-core`
/// variant or a change to `from_str_checked` — both deliberately avoided
/// here in favor of matching what already exists.
pub fn ast_category_to_core_category_str(catalog_category: &str) -> &str {
    match catalog_category {
        // Exact matches, from the mapping file's own table.
        "type-cosplay" => "type-cosplay",
        "arbitrary-cpi" => "arbitrary-cpi",
        "account-data-matching" => "account-data-matching",
        "pda-privileges" => "pda-privileges",
        "reentrancy-risk" => "reentrancy-risk",
        "missing-revalidation" => "missing-revalidation",
        "state-transition-gap" => "state-transition-gap",
        "fuzzing-crash" => "fuzzing-crash",
        // Semantic pairings, also from the mapping file's own table.
        "missing-owner-check" => "ownership-check",
        "missing-signer-check" => "signer-authorization",
        "unsafe-type-cast" => "unchecked-cast",
        "integer-overflow-underflow" => "arithmetic-overflow",
        "account-reinitialization" => "re-initialization",
        "account-close-revival" => "revival-attack",
        // Not in the mapping file at all — my own coarse-stretch, not
        // sourced. anchor-constraint-gap: every finding using it is an
        // account whose relationship/validation was never checked at all
        // (an UncheckedAccount with no signer/owner/constraint, or an
        // authority field no has_one ever references) — the same shape
        // ownership-check already exists to describe.
        "anchor-constraint-gap" => "ownership-check",
        // Not in the mapping file either. non-canonical-bump is
        // create_program_address called with a tainted bump instead of
        // find_program_address's own canonical result — a weak/predictable
        // PDA derivation, the same failure mode pda-privileges' own
        // detection hints describe ("seeds don't include an
        // attacker-unpredictable value").
        "non-canonical-bump" => "pda-privileges",
        // Anything else this crate doesn't currently produce falls
        // through to ares_core's own fallback in from_str_checked.
        other => other,
    }
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
            categories(&s).contains(&"missing-signer-check".to_string()),
            "expected missing-signer-check, got {:?}",
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
            !categories(&s).contains(&"missing-signer-check".to_string()),
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
        // ENG-3 added a second, taint-based arbitrary-cpi detector that flags
        // unvalidated accounts reaching invoke regardless of entry-point status.
        // That is intentional and correct, so assert specifically on the
        // entry-point-gated finding rather than on the category as a whole.
        assert!(
            !s.findings.iter().any(|f| f.category == "arbitrary-cpi"
                && f.description.contains("Instruction `helper_transfer`")),
            "helper without process_ prefix must not be treated as an instruction \
             boundary; got {:?}",
            s.findings
                .iter()
                .map(|f| &f.description)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_doc_comment_mentioning_signer_does_not_suppress_the_finding() {
        // `has_signer_check` was computed from `quote!(#node.block)`, which holds
        // the entire ItemFn including the `#[doc = "..."]` attributes syn lowers
        // `///` into. This source and `flags_raw_account_info_without_signer_check`
        // differ by nothing but a doc comment, so if documentation can change the
        // verdict the two tests disagree — and the direction of the disagreement
        // is a Critical false negative: a real missing-signer bug reported clean.
        let s = scan(
            r#"
            /// Withdraws lamports. Caller must already be a verified Signer.
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                Ok(())
            }
            "#,
        );
        assert!(
            categories(&s).contains(&"missing-signer-check".to_string()),
            "a doc comment is not a signer check; got {:?}",
            categories(&s)
        );
    }

    #[test]
    fn a_string_literal_mentioning_signer_does_not_suppress_the_finding() {
        // Same failure, other carrier: an error message is prose, not a check.
        // `msg!("...Signer...")` next to a missing check is exactly the shape of
        // code this detector exists to catch.
        let s = scan(
            r#"
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                msg!("authority must be a Signer");
                Ok(())
            }
            "#,
        );
        assert!(
            categories(&s).contains(&"missing-signer-check".to_string()),
            "a message string is not a signer check; got {:?}",
            categories(&s)
        );
    }

    #[test]
    fn a_documented_handler_that_really_checks_is_still_suppressed() {
        // The other half: stripping doc text and literals must not cost real
        // suppression, or every documented Solana handler becomes a Critical.
        let s = scan(
            r#"
            /// Withdraws lamports. Caller must already be a verified Signer.
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
                Ok(())
            }
            "#,
        );
        assert!(
            !categories(&s).contains(&"missing-signer-check".to_string()),
            "a real is_signer check must still suppress the finding; got {:?}",
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

    /// The regression that reached main: an Anchor `Signer<'info>` parameter IS
    /// the signer assertion, so flagging it Critical is a false positive on
    /// correct code.
    ///
    /// `code_string(&node.block)` renders the BODY, so a `Signer` appearing in
    /// the SIGNATURE is never in it, and the parameter arm that should have
    /// caught it was gated behind `p.is_ctx` — true only for `Context<..>`,
    /// never for a bare `&Signer<'info>`. The arm was unreachable for exactly
    /// the shape it exists to recognise.
    #[test]
    fn an_anchor_signer_parameter_is_a_signer_check() {
        let s = scan(
            r#"
            pub fn process_withdraw<'info>(
                authority: &Signer<'info>,
                vault: &AccountInfo<'info>,
            ) -> ProgramResult {
                Ok(())
            }
            "#,
        );
        assert!(
            !categories(&s).contains(&"missing-signer-check".to_string()),
            "a Signer<'info> parameter must not read as a missing signer check; got {:?}",
            categories(&s)
        );
    }

    /// The other direction, kept so the fix that introduced the regression is
    /// not undone along with it: prose must NOT satisfy the check. `syn` lowers
    /// `///` into `#[doc = "..."]`, and rendering the whole `ItemFn` let a
    /// comment saying "must be a Signer" silence a Critical finding.
    #[test]
    fn a_doc_comment_mentioning_signer_still_does_not_suppress_the_finding() {
        let s = scan(
            r#"
            /// The caller must be a Signer. This is documentation, not a check.
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                Ok(())
            }
            "#,
        );
        assert!(
            categories(&s).contains(&"missing-signer-check".to_string()),
            "a doc comment must not count as a signer check; got {:?}",
            categories(&s)
        );
    }

    /// And a genuinely unchecked raw handler still fires.
    #[test]
    fn a_raw_account_info_handler_with_no_check_still_fires() {
        let s = scan(
            r#"
            pub fn process_withdraw(authority: AccountInfo) -> ProgramResult {
                Ok(())
            }
            "#,
        );
        assert!(categories(&s).contains(&"missing-signer-check".to_string()));
    }
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
        let scanner = analyze_file(std::path::Path::new("cashio-2022.rs"), CASHIO_FIXTURE);
        let categories: Vec<&str> = scanner
            .findings
            .iter()
            .map(|f| f.category.as_str())
            .collect();
        assert!(
            categories.contains(&"type-cosplay"),
            "expected type-cosplay on the real Cashio fixture, got categories: {:?}",
            categories
        );
    }
}

#[cfg(test)]
mod eng4_catalog_category_fixes {
    //! ENG-4: found by literally doing the task's own to-do — cross-referencing
    //! every detection's category string against the real canonical catalog
    //! (src/knowledge/solana-vulns.ts). 8 findings used category strings that
    //! don't exist in the catalog at all, breaking the link back to it.
    use super::*;

    fn findings_for(src: &str) -> Vec<AstFinding> {
        analyze_file(std::path::Path::new("test.rs"), src).findings
    }

    fn has_category(findings: &[AstFinding], category: &str) -> bool {
        findings.iter().any(|f| f.category == category)
    }

    #[test]
    fn unchecked_account_with_no_validation_is_anchor_constraint_gap_not_generic_ownership_check() {
        // This is precisely what anchor-constraint-gap's own catalog description
        // names — "UncheckedAccount without #[account(address = ...)]" — not a
        // generic ownership-check catch-all that doesn't exist in the catalog.
        let src = r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub target: UncheckedAccount<'info>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "anchor-constraint-gap"),
            "expected anchor-constraint-gap, got: {:?}",
            findings
        );
        assert!(
            !has_category(&findings, "ownership-check"),
            "the old, non-existent category string should never appear again, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_finding_anywhere_still_uses_a_category_string_absent_from_the_real_catalog() {
        // The real, authoritative list from src/knowledge/solana-vulns.ts, kept
        // in sync manually — if this test starts failing because a new,
        // legitimate category was added to the scanner, add it here too rather
        // than assume the mismatch is fine.
        const REAL_CATALOG_IDS: &[&str] = &[
            "missing-signer-check",
            "missing-owner-check",
            "account-data-matching",
            "arbitrary-cpi",
            "non-canonical-bump",
            "pda-seed-collision",
            "account-reinitialization",
            "missing-reload-after-cpi",
            "integer-overflow-underflow",
            "precision-loss",
            "account-close-revival",
            "duplicate-mutable-account",
            "missing-rent-exemption",
            "sysvar-spoofing",
            "anchor-constraint-gap",
            "unchecked-cpi-return",
            "authority-mismanagement",
            "oracle-price-manipulation",
            "insecure-init-order",
            "spl-authority-check",
            "type-cosplay",
            "unsafe-type-cast",
            "missing-slippage-protection",
            "denial-of-service",
            "business-logic-error",
            "upgrade-authority-risk",
            "token-2022-extension-risk",
            "remaining-accounts-validation",
            "instruction-introspection",
            "pda-privileges",
            "reentrancy-risk",
            "missing-revalidation",
            "state-transition-gap",
            "fuzzing-crash",
        ];

        // A broad sweep across every detection path this file has, so a single
        // input exercising many different checks at once catches any category
        // string this test doesn't otherwise touch.
        let src = r#"
            #[derive(Accounts)]
            pub struct Ctx<'info> {
                pub raw: UncheckedAccount<'info>,
            }

            fn process_withdraw(admin: AccountInfo, data: &[u8]) {
                invoke(admin, data);
                let bank_data = Bank::try_from_slice(&data)?;
                let amount = data.len() as u64;
                unpack_unchecked(data);
            }

            fn close_account(account: AccountInfo) {
                **account.lamports.borrow_mut() = 0;
            }

            fn initialize_vault(vault: AccountInfo) {
                let _ = vault;
            }
        "#;
        let findings = findings_for(src);
        for f in &findings {
            assert!(
                REAL_CATALOG_IDS.contains(&f.category.as_str()),
                "category \"{}\" does not exist in the real catalog — found in: {:?}",
                f.category,
                f
            );
        }
    }
}

#[cfg(test)]
mod eng4_anchor_has_one_gap {
    //! ENG-4: the catalog's own anchor-constraint-gap detection hint says
    //! plainly — "Check for missing has_one on authority fields." This is a
    //! genuine gap: has_one lived only as part of a generic has_constraint
    //! catch-all, indistinguishable from an unrelated constraint attribute.
    use super::*;

    fn findings_for(src: &str) -> Vec<AstFinding> {
        analyze_file(std::path::Path::new("test.rs"), src).findings
    }

    fn has_category(findings: &[AstFinding], category: &str) -> bool {
        findings.iter().any(|f| f.category == category)
    }

    #[test]
    fn authority_field_with_no_has_one_anywhere_in_the_struct_is_flagged() {
        let src = r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "anchor-constraint-gap"),
            "expected anchor-constraint-gap for an unreferenced authority field, got: {:?}",
            findings
        );
    }

    #[test]
    fn authority_field_referenced_by_a_real_has_one_is_not_flagged_for_this() {
        let src = r#"
            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                pub authority: Signer<'info>,
                #[account(mut, has_one = authority)]
                pub vault: Account<'info, Vault>,
            }
        "#;
        let findings = findings_for(src);
        // Not a blanket "no anchor-constraint-gap at all" assertion — this
        // struct could still trip other, unrelated checks. Specifically: no
        // finding whose description names this authority field as unreferenced.
        let unreferenced_authority_finding = findings.iter().any(|f| {
            f.category == "anchor-constraint-gap" && f.description.contains("no field's `has_one`")
        });
        assert!(
            !unreferenced_authority_finding,
            "did not expect an unreferenced-authority finding once has_one references it, got: {:?}",
            findings
        );
    }

    #[test]
    fn a_struct_with_no_authority_like_field_at_all_is_not_flagged_for_this() {
        let src = r#"
            #[derive(Accounts)]
            pub struct Ping<'info> {
                #[account(mut)]
                pub counter: Account<'info, Counter>,
            }
        "#;
        let findings = findings_for(src);
        let unreferenced_authority_finding = findings.iter().any(|f| {
            f.category == "anchor-constraint-gap" && f.description.contains("no field's `has_one`")
        });
        assert!(
            !unreferenced_authority_finding,
            "no authority-like field exists here, so this specific check should not fire, got: {:?}",
            findings
        );
    }

    #[test]
    fn a_named_variant_admin_authority_is_also_recognised() {
        let src = r#"
            #[derive(Accounts)]
            pub struct UpdateConfig<'info> {
                pub pool_authority: Signer<'info>,
                #[account(mut)]
                pub config: Account<'info, Config>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "anchor-constraint-gap"),
            "expected the *_authority naming convention to also be recognised, got: {:?}",
            findings
        );
    }
}

#[cfg(test)]
mod eng4_solitaire_mut_info_gap {
    //! ENG-4: `is_raw_solitaire_info` only matched a type string that started
    //! with "Info<" directly — `Mut<Info<'b>>` starts with "Mut<" instead, so a
    //! mutable, completely unvalidated Solitaire account was invisible to this
    //! check entirely. Mut<> only marks writability, not validation, so this is
    //! at least as dangerous as the already-detected immutable case — arguably
    //! more so, since it can be written to, not just read.
    use super::*;

    fn findings_for(src: &str) -> Vec<AstFinding> {
        analyze_file(std::path::Path::new("test.rs"), src).findings
    }

    fn has_category(findings: &[AstFinding], category: &str) -> bool {
        findings.iter().any(|f| f.category == category)
    }

    #[test]
    fn mut_wrapped_raw_info_is_now_detected() {
        let src = r#"
            #[derive(FromAccounts)]
            pub struct VerifySignatures<'b> {
                pub instruction_acc: Mut<Info<'b>>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "missing-signer-check"),
            "expected Mut<Info<'b>> to be detected same as bare Info<'b>, got: {:?}",
            findings
        );
    }

    #[test]
    fn bare_raw_info_still_fires_unaffected_by_the_mut_fix() {
        // Regression check: the already-working, unwrapped case must still work.
        let src = r#"
            #[derive(FromAccounts)]
            pub struct VerifySignatures<'b> {
                pub instruction_acc: Info<'b>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            has_category(&findings, "missing-signer-check"),
            "expected bare Info<'b> to still fire, got: {:?}",
            findings
        );
    }

    #[test]
    fn mut_wrapped_data_account_is_not_misidentified_as_raw_info() {
        // Data<> is Solitaire's typed, owner-checked wrapper (via Seeded) — a
        // real validation wrapper, unlike Mut<> which only marks writability.
        // Mut<Data<...>> must stay correctly excluded, not swept up by the fix.
        let src = r#"
            #[derive(FromAccounts)]
            pub struct UpdateConfig<'b> {
                pub config: Mut<Data<'b, ConfigAccount, { AccountType::Config }>>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            !has_category(&findings, "missing-signer-check")
                && !has_category(&findings, "missing-owner-check"),
            "Mut<Data<...>> is a validated account and must not be flagged as raw info, got: {:?}",
            findings
        );
    }

    #[test]
    fn mut_wrapped_signer_is_not_misidentified_as_raw_info() {
        let src = r#"
            #[derive(FromAccounts)]
            pub struct Withdraw<'b> {
                pub authority: Mut<Signer<Info<'b>>>,
            }
        "#;
        let findings = findings_for(src);
        assert!(
            !has_category(&findings, "missing-signer-check")
                && !has_category(&findings, "missing-owner-check"),
            "Mut<Signer<...>> is already signer-validated and must not be flagged, got: {:?}",
            findings
        );
    }
}

#[cfg(test)]
mod eng4_core_category_translation {
    //! ENG-4: bridges this crate's catalog-aligned category strings to the
    //! separate, older Rust-side vocabulary `ares_core::VulnerabilityCategory`
    //! already recognizes — found while investigating wiring this crate into
    //! the real scan pipeline. Without this, every one of ENG-3/ENG-4's
    //! carefully-fixed categories would silently collapse into
    //! InvariantViolation the moment they reached a real report.
    use super::*;

    /// The real, authoritative set lives in
    /// `core/crates/ares-core/src/lib.rs`'s `from_str_checked` — this crate
    /// doesn't depend on ares-core, so this is a hand-copied mirror of every
    /// string that function recognizes, checked directly against that file
    /// when this test was written. If ares-core's own recognized set changes,
    /// this needs updating too — that's the point of asserting against a
    /// concrete, explicit list rather than nothing at all.
    const CORE_RECOGNIZED_STRINGS: &[&str] = &[
        "type-cosplay",
        "ownership-check",
        "signer-authorization",
        "missing-signer",
        "arbitrary-cpi",
        "initialization-frontrunning",
        "reentrancy-risk",
        "reentrancy",
        "duplicate-mutable-accounts",
        "arithmetic-overflow",
        "close-account",
        "account-reloading",
        "revival-attack",
        "re-initialization",
        "account-data-matching",
        "pda-privileges",
        "fuzzing-crash",
        "fuzzing",
        "invariant-violation",
        "invariant",
        "missing-revalidation",
        "unchecked-cast",
        "state-transition-gap",
        "generic",
    ];

    #[test]
    fn every_catalog_category_this_crate_produces_translates_to_a_string_core_recognizes() {
        // The real, complete set this crate can actually emit — every
        // category string used anywhere in ast_scanner.rs or
        // taint_engine.rs, kept in sync by hand since both files are
        // string-literal-based, not a shared enum.
        let catalog_categories = [
            "arbitrary-cpi",
            "missing-signer-check",
            "anchor-constraint-gap",
            "missing-owner-check",
            "account-data-matching",
            "unsafe-type-cast",
            "type-cosplay",
            "account-close-revival",
            "account-reinitialization",
            "non-canonical-bump",
            "integer-overflow-underflow",
        ];
        for cat in catalog_categories {
            let translated = ast_category_to_core_category_str(cat);
            assert!(
                CORE_RECOGNIZED_STRINGS.contains(&translated),
                "category \"{}\" translated to \"{}\", which ares_core's \
                from_str_checked does not recognize — it would silently \
                collapse to InvariantViolation",
                cat,
                translated
            );
        }
    }

    #[test]
    fn integer_overflow_underflow_maps_to_its_own_distinct_string_not_unchecked_cast() {
        // Real bug caught while writing this: arithmetic and casting are
        // different concepts, and core has a separate, correctly-recognized
        // string for arithmetic specifically — collapsing this into
        // unchecked-cast would have been wrong, not just imprecise.
        assert_eq!(
            ast_category_to_core_category_str("integer-overflow-underflow"),
            "arithmetic-overflow"
        );
    }

    #[test]
    fn an_unknown_category_passes_through_unchanged_rather_than_panicking() {
        // Falls through to core's own from_str_checked fallback
        // (unwrap_or(InvariantViolation)) rather than this function
        // guessing at something it has no mapping for.
        assert_eq!(
            ast_category_to_core_category_str("some-future-category-this-fn-does-not-know-yet"),
            "some-future-category-this-fn-does-not-know-yet"
        );
    }
}

#[cfg(test)]
mod eng4_smoke_test_realistic_fixture {
    //! ENG-4: Checkpoints 1-4 tested only hand-crafted, minimal snippets —
    //! a real gap against the original task's own explicit to-do ("test
    //! against real Anchor programs with known issues"). No existing fixture
    //! in this repo uses Anchor's #[derive(Accounts)] style at all, and a
    //! missing has_one check isn't usually tied to one specific, named,
    //! dollar-amount incident the way Cashio/Wormhole/Mango are — it's a
    //! common vulnerability class. Rather than fabricate a fake incident
    //! attribution, this runs against a realistic, complete Anchor program
    //! (eval/fixtures/rs/pattern-examples/), not a 2-line synthetic snippet.
    use super::*;

    const VAULT_WITHDRAW_FIXTURE: &str = include_str!(
        "../../../../eval/fixtures/rs/pattern-examples/missing-has-one-vault-withdraw.rs"
    );

    #[test]
    fn detects_the_missing_has_one_in_a_realistic_complete_anchor_program() {
        let scanner = analyze_file(
            std::path::Path::new("missing-has-one-vault-withdraw.rs"),
            VAULT_WITHDRAW_FIXTURE,
        );
        let unreferenced_authority_finding = scanner.findings.iter().any(|f| {
            f.category == "anchor-constraint-gap" && f.description.contains("no field's `has_one`")
        });
        assert!(
            unreferenced_authority_finding,
            "expected the has_one gap check to fire on a realistic, complete \
            program, not just the minimal synthetic snippets in \
            eng4_anchor_has_one_gap — got: {:?}",
            scanner.findings
        );
    }
}
