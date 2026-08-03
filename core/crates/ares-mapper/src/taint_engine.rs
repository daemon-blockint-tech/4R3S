use std::collections::{HashMap, HashSet};
use syn::visit::Visit;
use syn::{Block, Expr, ExprMethodCall, ExprPath, ExprReference, Pat, PatIdent, Stmt};

/// Phase-3 Taint Engine: tracks data flow from untrusted sources to sensitive sinks.
///
/// Sources (UNTRUSTED / RED):
/// - AccountInfo / Info<'b> parameters (raw, unvalidated)
/// - Instruction data (raw bytes before deserialization)
/// - CPI caller accounts
///
/// Safe wrappers (sanitize taint -> CLEAN / GREEN):
/// - checked_add, saturating_add
/// - Anchor typed accounts: Account<'info, T> (has discriminator)
/// - Signer<'info>, Sysvar<'b, T>
///
/// Sinks (must receive CLEAN data):
/// - invoke() / invoke_signed() — program_id must be validated/hardcoded
/// - try_from_slice() — must have discriminator check
/// - owner = ... — must not be from untrusted AccountInfo
/// - as u64, arithmetic + * / — must use checked_*/wrapping_* or validated
#[derive(Debug, Clone, Default)]
pub struct TaintEngine {
    /// Variable name -> (tainted, reason)
    pub vars: HashMap<String, TaintState>,
    /// Fields of account structs that are inherently tainted (raw AccountInfo)
    pub tainted_fields: HashMap<String, HashSet<String>>, // struct_name -> {field_names}
    /// Findings: sink reached with tainted data
    pub findings: Vec<TaintFinding>,
    safe_wrappers: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct TaintState {
    pub is_tainted: bool,
    pub source: TaintSource,
    pub path: Vec<String>, // propagation chain: ["param_x", "field_y", "local_z"]
}

#[derive(Debug, Clone)]
pub enum TaintSource {
    RawAccountInfo,     // Info<'b>, AccountInfo (no validation wrapper)
    InstructionData,    // raw instruction bytes
    CpiCaller,          // accounts passed from CPI
    UncheckedField,     // struct field without Signer/Sysvar/Constraint
    Propagated(String), // propagated from another tainted var
    Clean,              // known safe (checked_add, typed account, etc.)
}

#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub category: String,
    pub severity: String,
    pub sink: String,
    pub tainted_var: String,
    pub description: String,
    pub line: usize,
}

impl TaintEngine {
    pub fn new() -> Self {
        let mut safe = HashSet::new();
        safe.insert("checked_add".to_string());
        safe.insert("checked_sub".to_string());
        safe.insert("checked_mul".to_string());
        safe.insert("checked_div".to_string());
        safe.insert("saturating_add".to_string());
        safe.insert("saturating_sub".to_string());
        safe.insert("saturating_mul".to_string());
        safe.insert("wrapping_add".to_string());
        safe.insert("wrapping_sub".to_string());
        safe.insert("try_into".to_string());
        safe.insert("checked_as".to_string());
        Self {
            vars: HashMap::new(),
            tainted_fields: HashMap::new(),
            findings: Vec::new(),
            safe_wrappers: safe,
        }
    }

    /// Mark a parameter as tainted based on its type.
    pub fn mark_param(&mut self, name: &str, ty: &str) {
        let is_raw = ty.contains("AccountInfo")
            || (ty.contains("Info<") && !ty.contains("Signer<") && !ty.contains("Sysvar<"));
        let is_instruction_data = ty.contains("[u8]") || name == "data" || name.ends_with("_data");

        let source = if is_raw {
            TaintSource::RawAccountInfo
        } else if is_instruction_data {
            TaintSource::InstructionData
        } else {
            TaintSource::Clean
        };

        let tainted = matches!(
            source,
            TaintSource::RawAccountInfo | TaintSource::InstructionData
        );

        self.vars.insert(
            name.to_string(),
            TaintState {
                is_tainted: tainted,
                source,
                path: vec![name.to_string()],
            },
        );
    }

    /// Mark struct fields as tainted based on prior AST analysis.
    pub fn mark_tainted_field(&mut self, struct_name: &str, field_name: &str) {
        self.tainted_fields
            .entry(struct_name.to_string())
            .or_default()
            .insert(field_name.to_string());
    }

    /// Check if a variable is tainted.
    pub fn is_tainted(&self, name: &str) -> bool {
        self.vars.get(name).map(|v| v.is_tainted).unwrap_or(false)
    }

    /// Get taint state of an expression.
    fn expr_taint(&self, expr: &Expr) -> TaintState {
        match expr {
            Expr::Path(ExprPath { path, .. }) => {
                let name = path_to_string(path);
                self.vars.get(&name).cloned().unwrap_or_else(|| TaintState {
                    is_tainted: false,
                    source: TaintSource::Clean,
                    path: vec![],
                })
            }
            Expr::Reference(ExprReference { expr: inner, .. }) => self.expr_taint(inner),
            Expr::MethodCall(ExprMethodCall {
                receiver, method, ..
            }) => {
                let recv_taint = self.expr_taint(receiver);
                // Safe wrapper: if method is checked_*, saturating_*, etc., result is CLEAN
                let method_name = method.to_string();
                if self.safe_wrappers.contains(&method_name) || method_name == "try_into" {
                    return TaintState {
                        is_tainted: false,
                        source: TaintSource::Clean,
                        path: recv_taint.path,
                    };
                }
                // Accessing tainted field: e.g., accs.instruction_acc
                if let Expr::Path(ExprPath { path, .. }) = receiver.as_ref() {
                    let base = path_to_string(path);
                    if let Some(fields) = self.tainted_fields.get(&base) {
                        if fields.contains(&method_name) {
                            return TaintState {
                                is_tainted: true,
                                source: TaintSource::Propagated(format!(
                                    "{}.{} (tainted field)",
                                    base, method_name
                                )),
                                path: {
                                    let mut p = recv_taint.path;
                                    p.push(method_name.clone());
                                    p
                                },
                            };
                        }
                    }
                }
                recv_taint
            }
            Expr::Field(field_expr) => {
                // Handle field access: expr.field
                // For now, propagate base taint
                self.expr_taint(&field_expr.base)
            }
            _ => TaintState {
                is_tainted: false,
                source: TaintSource::Clean,
                path: vec![],
            },
        }
    }

    /// Process a statement for taint propagation.
    pub fn process_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    let taint = self.expr_taint(&init.expr);
                    if let Pat::Ident(PatIdent { ident, .. }) = &local.pat {
                        let name = ident.to_string();
                        let mut new_taint = taint.clone();
                        new_taint.path.push(name.clone());
                        self.vars.insert(name, new_taint);
                    }
                }
            }
            Stmt::Expr(expr, _) => {
                self.process_expr(expr);
            }
            _ => {}
        }
    }

    /// Process expression for sink detection.
    pub fn process_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let _func_taint = self.expr_taint(&call.func);
                let func_name = expr_to_string(&call.func);

                // Sink: invoke / invoke_signed
                if func_name.contains("invoke") || func_name.contains("invoke_signed") {
                    // Check arguments for tainted program_id / accounts
                    for arg in &call.args {
                        let arg_taint = self.expr_taint(arg);
                        if arg_taint.is_tainted {
                            self.findings.push(TaintFinding {
                                category: "arbitrary-cpi".to_string(),
                                severity: "Critical".to_string(),
                                sink: func_name.clone(),
                                tainted_var: format!("arg in {}", func_name),
                                description: format!(
                                    "CPI call `{}` receives tainted data from {:?}. \
                                    The target program or account may be attacker-controlled, leading to arbitrary-CPI.",
                                    func_name, arg_taint.source
                                ),
                                line: 0,
                            });
                        }
                    }
                }

                // Sink: try_from_slice without discriminator
                // Exclude Pubkey::try_from_slice and primitive numeric types — these
                // parse fixed-format on-chain data, not account type substitution attacks.
                let func_name_compact = func_name.replace(" ", "");
                let is_safe_try_from = func_name_compact.contains("Pubkey::try_from_slice")
                    || func_name_compact.contains("u128::try_from_slice")
                    || func_name_compact.contains("u64::try_from_slice")
                    || func_name_compact.contains("i128::try_from_slice")
                    || func_name_compact.contains("i64::try_from_slice")
                    || func_name_compact.contains("BigNum::try_from_slice");
                if func_name_compact.contains("try_from_slice") && !is_safe_try_from {
                    if let Some(first_arg) = call.args.first() {
                        let arg_taint = self.expr_taint(first_arg);
                        if arg_taint.is_tainted {
                            self.findings.push(TaintFinding {
                                category: "type-cosplay".to_string(),
                                severity: "High".to_string(),
                                sink: "try_from_slice".to_string(),
                                tainted_var: "data".to_string(),
                                description: format!(
                                    "`try_from_slice` called on tainted data ({:?}). \
                                    Attacker can pass forged account data matching expected size, bypassing type check.",
                                    arg_taint.source
                                ),
                                line: 0,
                            });
                        }
                    }
                }
            }
            Expr::Assign(assign) => {
                let left_str = expr_to_string(&assign.left);
                let right_taint = self.expr_taint(&assign.right);

                // Sink: owner = untrusted
                if left_str.contains("owner") && right_taint.is_tainted {
                    self.findings.push(TaintFinding {
                        category: "ownership-check".to_string(),
                        severity: "Critical".to_string(),
                        sink: "owner assignment".to_string(),
                        tainted_var: left_str.clone(),
                        description: format!(
                            "Account owner set from tainted source ({:?}). \
                            Attacker can reassign ownership to their own program.",
                            right_taint.source
                        ),
                        line: 0,
                    });
                }

                // Propagation
                if let Expr::Path(ExprPath { path, .. }) = assign.left.as_ref() {
                    let name = path_to_string(path);
                    let mut new_taint = right_taint.clone();
                    new_taint.path.push(name.clone());
                    self.vars.insert(name, new_taint);
                }
            }
            Expr::Binary(binary) => {
                // Sink: arithmetic on tainted values without safe wrapper
                let ops = ["Add", "Sub", "Mul", "Div", "Rem", "Shl", "Shr"];
                let op_str = quote::quote!(#binary.op).to_string();
                if ops.iter().any(|o| op_str.contains(o)) {
                    let left_taint = self.expr_taint(&binary.left);
                    let right_taint = self.expr_taint(&binary.right);
                    if left_taint.is_tainted || right_taint.is_tainted {
                        self.findings.push(TaintFinding {
                            category: "unchecked-cast".to_string(),
                            severity: "High".to_string(),
                            sink: format!("arithmetic {}", op_str),
                            tainted_var: format!(
                                "{:?}",
                                if left_taint.is_tainted {
                                    left_taint.source.clone()
                                } else {
                                    right_taint.source.clone()
                                }
                            ),
                            description: format!(
                                "Arithmetic operation `{}` on tainted data ({:?}). \
                                Use checked_add / checked_mul / saturating_* to prevent overflow.",
                                op_str,
                                if left_taint.is_tainted {
                                    &left_taint.source
                                } else {
                                    &right_taint.source
                                }
                            ),
                            line: 0,
                        });
                    }
                }
            }
            Expr::Cast(cast) => {
                // Sink: as u64 / as i64 on tainted values
                let expr_taint = self.expr_taint(&cast.expr);
                let expr_str = expr_to_string(&cast.expr);
                // Suppress false positives: sysvars, timestamps, and known-bounded values
                // are inherently safe to cast.
                let is_safe_source = expr_str.contains("clock")
                    || expr_str.contains("unix_timestamp")
                    || expr_str.contains("rent")
                    || expr_str.contains("epoch")
                    || expr_str.contains("slot")
                    || expr_str.contains("len()")
                    || expr_str.parse::<i64>().is_ok();
                if expr_taint.is_tainted && !is_safe_source {
                    self.findings.push(TaintFinding {
                        category: "unchecked-cast".to_string(),
                        severity: "High".to_string(),
                        sink: "cast".to_string(),
                        tainted_var: expr_str,
                        description: format!(
                            "Unchecked cast on tainted data ({:?}). \
                            If source value exceeds target type range, this wraps/truncates silently.",
                            expr_taint.source
                        ),
                        line: 0,
                    });
                }
            }
            Expr::If(expr_if) => {
                self.process_expr(&expr_if.cond);
                self.process_expr_block(&expr_if.then_branch);
                if let Some((_, else_branch)) = &expr_if.else_branch {
                    self.process_expr(else_branch);
                }
            }
            Expr::Block(expr_block) => {
                self.process_expr_block(&expr_block.block);
            }
            Expr::Match(expr_match) => {
                self.process_expr(&expr_match.expr);
                for arm in &expr_match.arms {
                    self.process_expr(&arm.body);
                }
            }
            Expr::MethodCall(ExprMethodCall {
                receiver, method, ..
            }) => {
                let recv = self.expr_taint(receiver);
                let method_name = method.to_string();
                // Safe wrapper detection: if method is checked_*, result is CLEAN
                if self.safe_wrappers.contains(&method_name) || method_name == "try_into" {
                    // Result is clean — no propagation
                } else {
                    // Normal method call, may propagate
                    if recv.is_tainted {
                        // tainted receiver calling non-safe method
                    }
                }
                // Recurse into receiver
                self.process_expr(receiver);
            }
            _ => {}
        }
    }

    fn process_expr_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.process_stmt(stmt);
        }
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn expr_to_string(expr: &Expr) -> String {
    quote::quote!(#expr).to_string()
}

impl<'a> Visit<'a> for TaintEngine {
    fn visit_expr(&mut self, node: &'a Expr) {
        self.process_expr(node);
        syn::visit::visit_expr(self, node);
    }

    fn visit_stmt(&mut self, node: &'a Stmt) {
        self.process_stmt(node);
        syn::visit::visit_stmt(self, node);
    }
}
