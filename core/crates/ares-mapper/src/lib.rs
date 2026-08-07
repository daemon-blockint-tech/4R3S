use ares_core::AresResult;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

/// Mapper Agent: analyzes Solana program structure, accounts, instructions, and generates a graph.
pub struct MapperAgent {
    program_path: PathBuf,
}

use crate::source_patterns::SourcePatterns;

/// Represents the analyzed structure of a Solana program.
#[derive(Debug, Clone, Default)]
pub struct ProgramGraph {
    pub modules: Vec<ModuleNode>,
    pub instructions: Vec<InstructionNode>,
    pub accounts: Vec<AccountNode>,
    pub cpi_calls: Vec<CpiCall>,
    pub dependencies: Vec<String>,
    pub all_source_files: Vec<PathBuf>,
    pub source_patterns: SourcePatterns,
}

#[derive(Debug, Clone, Default)]
pub struct ModuleNode {
    pub name: String,
    pub file_path: PathBuf,
    pub is_entrypoint: bool,
}

/// Effect an instruction has on a specific account.
///
/// `extract_account_effects` is the only producer, and it emits `Read`, `Write`
/// and `CpiPass` only. **`Create` and `Close` are never constructed**: both come
/// from Anchor `init`/`close` constraints, which live on the accounts struct's
/// fields, while effects are read out of the instruction *body*. Treat any code
/// that branches on them as unreachable until the graph links a `Context<T>`
/// parameter to `T`'s per-field constraints — `find_state_transition_gaps` was
/// deleted (see cross_analysis.rs) because it read as a live detector and could
/// not fire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AccountEffect {
    /// The instruction reads the account (e.g., `ctx.accounts.x.load()`).
    Read,
    /// The instruction writes / mutates the account (e.g., `ctx.accounts.x.data = ...`).
    Write,
    /// The instruction creates / initializes the account (e.g., `init` constraint).
    /// Not produced today — see the type-level note.
    Create,
    /// The instruction closes the account (e.g., `close` constraint).
    /// Not produced today — see the type-level note.
    Close,
    /// The instruction passes this account into a CPI call.
    CpiPass,
}

#[derive(Debug, Clone, Default)]
pub struct InstructionNode {
    pub name: String,
    pub function_name: String,
    pub has_signer_check: Option<bool>,
    pub has_owner_check: Option<bool>,
    pub has_cpi_program_id_check: bool,
    pub uses_cpi: bool,
    /// True when the body performs arithmetic at all — including the *safe*
    /// `checked_*` forms. On its own this is not a vulnerability signal; see
    /// `has_unchecked_arithmetic`.
    pub has_arithmetic: bool,
    /// True when the body mutates with `+=`/`-=`/`*=`/`/=` and shows no
    /// `checked_*` call anywhere.
    ///
    /// `has_arithmetic` cannot answer this: it is set by `.checked_add(` too, so
    /// a handler that carefully guards every operation looks identical to one
    /// that guards none. The only consumer of `has_arithmetic` was the
    /// hypothesis generator, which therefore proposed "potential arithmetic
    /// overflow" for correctly-guarded code — the same failure that retired the
    /// `anchor-constraint-gap` rule (README, Detection accuracy), where 50% of
    /// hits already carried the constraint the rule asked for.
    pub has_unchecked_arithmetic: bool,
    pub file_path: PathBuf,
    pub line_number: Option<u32>,
    /// Data-flow effects this instruction has on specific accounts by name.
    pub effects: Vec<(String, AccountEffect)>,
}

#[derive(Debug, Clone, Default)]
pub struct AccountNode {
    pub name: String,
    pub is_signer: bool,
    pub is_mutable: bool,
    pub is_initialized_check: Option<bool>,
    pub has_close_constraint: Option<bool>,
    pub has_one_constraints: Vec<String>,
    pub seeds: Option<Vec<String>>,
    pub file_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CpiCall {
    pub target_program: String,
    pub instruction: String,
    pub file_path: PathBuf,
    pub line_number: u32,
}

impl MapperAgent {
    pub fn new(program_path: &Path) -> Self {
        Self {
            program_path: program_path.to_path_buf(),
        }
    }

    /// Analyze program structure and build the program graph.
    pub async fn analyze(&mut self) -> AresResult<ProgramGraph> {
        info!("Mapper Agent: Analyzing program at {:?}", self.program_path);

        let mut graph = ProgramGraph::default();

        // Find Rust source files
        let programs_dir = self.program_path.join("programs");
        let src_dir = if programs_dir.exists() {
            programs_dir
        } else {
            self.program_path.join("src")
        };

        if !src_dir.exists() {
            warn!(
                "No programs/ or src/ directory found at {:?}",
                self.program_path
            );
            return Ok(graph);
        }

        // Walk source files
        for entry in WalkDir::new(&src_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("rs"))
        {
            let path = entry.path();
            debug!("Analyzing file: {:?}", path);

            graph.all_source_files.push(path.to_path_buf());

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Detect modules
            if content.contains("#[program]") || content.contains("entrypoint!") {
                graph.modules.push(ModuleNode {
                    name: path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    file_path: path.to_path_buf(),
                    is_entrypoint: content.contains("entrypoint!"),
                });
            }

            // Detect instructions (functions in #[program] modules)
            for (line_no, line) in content.lines().enumerate() {
                let line_num = (line_no + 1) as u32;

                // Look for pub fn declarations that are likely instructions
                if line.trim().starts_with("pub fn ") {
                    let fn_name = line
                        .trim()
                        .strip_prefix("pub fn ")
                        .and_then(|s| s.split('(').next())
                        .unwrap_or("unknown")
                        .trim();

                    let instruction_name = fn_name.to_string();

                    // Analyze the function body for security checks
                    let rest = &content.lines().skip(line_no).collect::<Vec<_>>().join("\n");
                    let body = extract_function_body(rest);

                    let has_signer = body.as_ref().map(|b| {
                        b.contains("is_signer")
                            || b.contains("Signer<")
                            || b.contains("has_one")
                            || b.contains("constraint = signer")
                    });

                    let has_owner = body.as_ref().map(|b| {
                        b.contains("owner")
                            || b.contains("token::authority")
                            || b.contains("constraint = owner")
                    });

                    let has_cpi_check = body.as_ref().is_some_and(|b| {
                        b.contains("program_id")
                            || b.contains("key() !=")
                            || b.contains("expected_program")
                    });

                    let uses_cpi = body.as_ref().is_some_and(|b| {
                        b.contains("invoke(")
                            || b.contains("invoke_signed(")
                            || b.contains("CpiContext")
                    });

                    let has_arithmetic = body.as_ref().is_some_and(|b| {
                        b.contains(".checked_add(")
                            || b.contains(".checked_sub(")
                            || b.contains(".checked_mul(")
                            || b.contains(".checked_div(")
                            || b.contains(" += ")
                            || b.contains(" -= ")
                            || b.contains(" *= ")
                            || b.contains(" /= ")
                    });

                    // Mutating arithmetic with no `checked_*` guard anywhere in the
                    // body. Deliberately conservative at the body level rather than
                    // per-expression: a handler that uses `checked_add` for one
                    // operation and `+=` for another will not be flagged here. That
                    // is the right trade for a *hypothesis* — a missed guard is
                    // recoverable by the later analyzers, whereas flagging guarded
                    // code trains reviewers to ignore the category entirely.
                    let has_unchecked_arithmetic = body.as_ref().is_some_and(|b| {
                        let mutating = b.contains(" += ")
                            || b.contains(" -= ")
                            || b.contains(" *= ")
                            || b.contains(" /= ");
                        let guarded = b.contains(".checked_")
                            || b.contains(".saturating_")
                            || b.contains(".wrapping_")
                            || b.contains(".overflowing_");
                        mutating && !guarded
                    });

                    let effects = extract_account_effects(body.as_deref());

                    graph.instructions.push(InstructionNode {
                        name: instruction_name.clone(),
                        function_name: fn_name.to_string(),
                        has_signer_check: has_signer,
                        has_owner_check: has_owner,
                        has_cpi_program_id_check: has_cpi_check,
                        uses_cpi,
                        has_arithmetic,
                        has_unchecked_arithmetic,
                        file_path: path.to_path_buf(),
                        line_number: Some(line_num),
                        effects,
                    });
                }

                // Detect account structs (#[derive(Accounts)])
                if derives_accounts(line) {
                    // The struct is the next line that is neither blank, nor an
                    // attribute, nor a comment. It used to have to be the next
                    // non-blank line and to start with `pub struct `, which drops
                    // the canonical Anchor PDA form outright — `#[instruction(..)]`
                    // is *mandatory* between the derive and the struct whenever a
                    // `seeds` constraint references an instruction argument, and a
                    // doc comment does the same. The struct was then skipped in
                    // silence: no AccountNode, no warning, and `anchor_field_count`
                    // / `unchecked_fields` under-count, which is what LocalJudge
                    // uses to decide whether to suppress findings.
                    let struct_at = content
                        .lines()
                        .enumerate()
                        .skip(line_no + 1)
                        .find(|(_, l)| {
                            let t = l.trim();
                            !t.is_empty() && !t.starts_with('#') && !t.starts_with("//")
                        });
                    if let Some((sidx, sline)) = struct_at {
                        if let Some(name) = struct_name(sline) {
                            // Find the struct body — from the struct line, not from
                            // the derive: anything skipped above may carry braces.
                            let rest = &content.lines().skip(sidx).collect::<Vec<_>>().join("\n");
                            let struct_body = extract_struct_body(rest);

                            let is_initialized = struct_body.as_ref().map(|b| {
                                b.contains("init")
                                    || b.contains("init_if_needed")
                                    || b.contains("has_one")
                                    || b.contains("constraint =")
                            });

                            let has_close = struct_body
                                .as_ref()
                                .map(|b| b.contains("close=") || b.contains("close ="));

                            // Detect PDA seeds in the account struct
                            let seeds: Option<Vec<String>> = struct_body.as_ref().and_then(|b| {
                                let mut found_seeds = Vec::new();
                                for line in b.lines() {
                                    if line.contains("seeds =") || line.contains("seeds=") {
                                        // Extract seed strings like [b"config"], [user.key().as_ref()]
                                        if let Some(start) = line.find('[') {
                                            if let Some(end) = line[start..].find(']') {
                                                let seeds_str = &line[start..start + end + 1];
                                                found_seeds.push(seeds_str.to_string());
                                            }
                                        }
                                    }
                                }
                                if found_seeds.is_empty() {
                                    None
                                } else {
                                    Some(found_seeds)
                                }
                            });

                            let is_signer = struct_body.as_ref().is_some_and(|b| {
                                b.contains("Signer<") || b.contains("signer: Signer")
                            });

                            let is_mutable = struct_body.as_ref().is_some_and(|b| {
                                b.contains("mut,") || b.contains("mut]") || b.contains("mut)")
                            });

                            graph.accounts.push(AccountNode {
                                name,
                                is_signer,
                                is_mutable,
                                is_initialized_check: is_initialized,
                                has_close_constraint: has_close,
                                has_one_constraints: Vec::new(),
                                seeds,
                                file_path: path.to_path_buf(),
                            });
                        }
                    }
                }

                // Detect CPI calls
                if line.contains("invoke(")
                    || line.contains("invoke_signed(")
                    || line.contains("CpiContext")
                {
                    let target = if line.contains("token::") {
                        "token_program"
                    } else if line.contains("system_program") {
                        "system_program"
                    } else {
                        "unknown_program"
                    };

                    graph.cpi_calls.push(CpiCall {
                        target_program: target.to_string(),
                        instruction: "transfer".to_string(), // simplified
                        file_path: path.to_path_buf(),
                        line_number: line_num,
                    });
                }
            }
        }

        // Check Cargo.toml for dependencies
        let cargo_toml = self.program_path.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                for line in content.lines() {
                    if line.contains("=") && !line.starts_with('[') {
                        if let Some(dep) = line.split('=').next() {
                            graph.dependencies.push(dep.trim().to_string());
                        }
                    }
                }
            }
        }

        // Calculate SourcePatterns
        let mut anchor_field_count = 0;
        let mut typed_anchor_fields = 0;
        let mut unchecked_fields = 0;
        let mut write_accounts = std::collections::HashSet::new();
        let mut cpi_accounts = std::collections::HashSet::new();
        let mut has_raw_handler = false;
        let mut has_typed_program = false;
        let mut has_raw_unvalidated_cpi = false;

        for acc in &graph.accounts {
            // Very simplified heuristic for fields based on AccountNode
            anchor_field_count += 1;
            if acc.is_signer || !acc.has_one_constraints.is_empty() || acc.seeds.is_some() {
                typed_anchor_fields += 1;
            } else if !acc.is_initialized_check.unwrap_or(false) && !acc.is_signer {
                unchecked_fields += 1;
            }
        }

        for instr in &graph.instructions {
            for (acc_name, effect) in &instr.effects {
                match effect {
                    AccountEffect::Write | AccountEffect::Create | AccountEffect::Close => {
                        write_accounts.insert(acc_name.clone());
                    }
                    AccountEffect::CpiPass => {
                        cpi_accounts.insert(acc_name.clone());
                    }
                    _ => {}
                }
            }
            if !instr.has_signer_check.unwrap_or(true) && !instr.has_owner_check.unwrap_or(true) {
                has_raw_handler = true;
            }
            if instr.uses_cpi {
                if !instr.has_cpi_program_id_check {
                    has_raw_unvalidated_cpi = true;
                } else {
                    has_typed_program = true;
                }
            }
        }

        let is_anchor_heavy =
            anchor_field_count > 5 && typed_anchor_fields > (anchor_field_count / 2);
        let cpi_all_validated = graph
            .cpi_calls
            .iter()
            .all(|c| c.target_program != "unknown_program");

        graph.source_patterns = SourcePatterns {
            is_anchor_heavy,
            unchecked_fields,
            has_raw_handler,
            cpi_all_validated,
            has_typed_program,
            has_raw_unvalidated_cpi,
            write_accounts,
            cpi_accounts,
            is_large_dex: graph.instructions.len() > 100, // proxy for >1000 LOC/instr
            is_mixed_architecture: is_anchor_heavy && has_raw_handler,
        };

        info!(
            "Mapper analysis complete: {} modules, {} instructions, {} accounts, {} CPI calls",
            graph.modules.len(),
            graph.instructions.len(),
            graph.accounts.len(),
            graph.cpi_calls.len()
        );

        Ok(graph)
    }
}

/// Extract function body from text starting at function declaration.
fn extract_function_body(text: &str) -> Option<String> {
    let mut depth = 0i32;
    let mut started = false;
    let mut body = String::new();

    for ch in text.chars() {
        if ch == '{' {
            started = true;
            depth += 1;
        }
        if started {
            body.push(ch);
        }
        if ch == '}' {
            depth -= 1;
            if depth == 0 && started {
                break;
            }
        }
    }

    if body.is_empty() {
        None
    } else {
        Some(body)
    }
}

/// Extract struct body from text starting at struct declaration.
fn extract_struct_body(text: &str) -> Option<String> {
    extract_function_body(text)
}

/// True when `line` is a derive attribute listing `Accounts`.
///
/// Compares whole derive entries rather than substrings: `#[derive(Accounts,
/// Clone)]` is ordinary Anchor and must match, while Solitaire's
/// `#[derive(FromAccounts)]` is a different framework's macro and must not. The
/// previous `contains("#[derive(Accounts)")` excluded the multi-derive form,
/// which is why a Clone-deriving Accounts struct was mapped as if absent.
fn derives_accounts(line: &str) -> bool {
    let Some(open) = line.find("#[derive(") else {
        return false;
    };
    let inner = &line[open + "#[derive(".len()..];
    let inner = inner.split(')').next().unwrap_or("");
    inner.split(',').any(|d| d.trim() == "Accounts")
}

/// Struct name from a `struct` declaration line, or `None` if it is not one.
///
/// Cuts at the first character that cannot appear in an identifier, so
/// `pub struct Withdraw<'info> {` yields `Withdraw` for any lifetime name — the
/// previous `trim_end_matches("<'info>")` left `Withdraw<'a>` intact whenever a
/// program used a different one.
fn struct_name(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t
        .strip_prefix("pub struct ")
        .or_else(|| t.strip_prefix("struct "))?;
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Heuristic extraction of per-account effects from an instruction function body.
/// Looks for patterns like `ctx.accounts.x`, `ctx.accounts.x.load_mut()`,
/// `ctx.accounts.x.data = ...`, `invoke(..., &ctx.accounts.x ...)`, etc.
fn extract_account_effects(body: Option<&str>) -> Vec<(String, AccountEffect)> {
    let body = match body {
        Some(b) => b,
        None => return Vec::new(),
    };

    let mut effects = Vec::new();
    let mut seen: std::collections::HashSet<(String, AccountEffect)> =
        std::collections::HashSet::new();

    // Regex-like scan: find `ctx.accounts.<ident>` tokens
    let mut remaining = body;
    while let Some(start) = remaining.find("ctx.accounts.") {
        let after = &remaining[start + "ctx.accounts.".len()..];
        let ident_end = after
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        let account = &after[..ident_end];
        if account.is_empty() {
            remaining = after;
            continue;
        }

        // Determine effect by looking at context after the token
        let context = after[ident_end..].lines().next().unwrap_or("");

        let effect = if context.contains("load_mut()")
            || context.contains(".data =")
            || context.contains(".try_borrow_mut")
            || context.contains(" = ")
            || context.contains(" += ")
            || context.contains(" -= ")
        {
            AccountEffect::Write
        } else if context.contains("invoke(")
            || context.contains("invoke_signed(")
            || context.contains("CpiContext")
        {
            AccountEffect::CpiPass
        } else {
            AccountEffect::Read
        };

        let key = (account.to_string(), effect.clone());
        if seen.insert(key.clone()) {
            effects.push(key);
        }

        remaining = after;
    }

    effects
}

pub mod ast_scanner;
pub mod cross_analysis;
pub mod local_judge;
pub mod source_patterns;
pub mod taint_engine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_graph_default() {
        let graph = ProgramGraph::default();
        assert!(graph.instructions.is_empty());
        assert!(graph.accounts.is_empty());
        assert!(graph.modules.is_empty());
    }

    #[test]
    fn test_module_node_default() {
        let node = ModuleNode::default();
        assert_eq!(node.name, String::new());
        assert!(!node.is_entrypoint);
    }

    #[test]
    fn test_instruction_node_default() {
        let node = InstructionNode::default();
        assert_eq!(node.name, String::new());
        assert!(!node.uses_cpi);
    }

    #[test]
    fn test_account_node_default() {
        let node = AccountNode::default();
        assert_eq!(node.name, String::new());
        assert!(!node.is_mutable);
    }

    #[test]
    fn test_account_effect_clone_and_eq() {
        let a = AccountEffect::Read;
        let b = AccountEffect::Read;
        let c = AccountEffect::Write;
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_extract_account_effects_handles_ctx_accounts() {
        let body = Some(
            r#"
            let foo = &ctx.accounts.foo;
            let bar = &mut ctx.accounts.bar;
            msg!("hello");
            ctx.accounts.baz.load_mut()?;
        "#,
        );
        let effects = extract_account_effects(body);
        assert!(!effects.is_empty(), "Should detect at least one effect");
        // foo is read-only (no mut)
        assert!(effects.contains(&("foo".to_string(), AccountEffect::Read)));
    }

    #[test]
    fn test_extract_account_effects_empty() {
        let effects = extract_account_effects(None);
        assert!(effects.is_empty());
    }

    #[test]
    fn test_extract_account_effects_no_accounts() {
        let effects = extract_account_effects(Some("let x = 1; let y = 2;"));
        assert!(effects.is_empty());
    }

    #[test]
    fn test_extract_account_effects_write() {
        let effects = extract_account_effects(Some("ctx.accounts.config.data = 42;"));
        assert!(effects.contains(&("config".to_string(), AccountEffect::Write)));
    }

    #[test]
    fn test_extract_account_effects_cpi_invoke() {
        let effects = extract_account_effects(Some("ctx.accounts.token_program.invoke(ix)?;"));
        assert!(effects.contains(&("token_program".to_string(), AccountEffect::CpiPass)));
    }

    #[test]
    fn test_extract_account_effects_cpi_signed() {
        let effects =
            extract_account_effects(Some("ctx.accounts.router.invoke_signed(ix, &[seeds])?;"));
        assert!(effects.contains(&("router".to_string(), AccountEffect::CpiPass)));
    }

    #[test]
    fn test_extract_function_body_simple() {
        let text = "fn foo() {\n    let x = 1;\n}";
        let body = extract_function_body(text);
        assert!(
            body.is_some(),
            "Should extract body from multi-line function"
        );
    }

    #[test]
    fn test_extract_function_body_nested() {
        let text = "fn foo() {\n    if true {\n        inner();\n    }\n}";
        let body = extract_function_body(text);
        assert!(body.is_some());
        let b = body.unwrap();
        assert!(b.contains("inner()"));
    }

    #[test]
    fn test_extract_function_body_no_braces() {
        let body = extract_function_body("not a function");
        assert!(body.is_none());
    }

    #[test]
    fn test_extract_account_effects_mut_account() {
        // ctx.accounts.x = conn_text_load_mut → Write
        let effects = extract_account_effects(Some("\nctx.accounts.config.load_mut()?\n"));
        assert!(effects.contains(&("config".to_string(), AccountEffect::Write)));
    }

    #[test]
    fn test_mapper_agent_new() {
        let path = PathBuf::from("/tmp");
        let agent = MapperAgent::new(&path);
        assert_eq!(agent.program_path, path);
    }

    #[test]
    fn test_mapper_new_canonicalizes() {
        let path = PathBuf::from(".");
        let agent = MapperAgent::new(&path);
        // program_path should be a canonical or absolute-like path
        assert!(!agent.program_path.as_os_str().is_empty());
    }

    #[test]
    fn test_source_patterns_default() {
        let sp = SourcePatterns::default();
        assert!(!sp.is_anchor_heavy);
        assert_eq!(sp.unchecked_fields, 0);
        assert!(sp.write_accounts.is_empty());
    }
}

#[cfg(test)]
mod accounts_struct_detection_tests {
    //! `#[derive(Accounts)]` structs were only found when the struct declaration
    //! was the very next non-blank line and the derive list held nothing else.
    //! Both assumptions break on ordinary Anchor code, and the failure is silent:
    //! the struct simply never reaches `graph.accounts`, so every consumer —
    //! `anchor_field_count`, `unchecked_fields`, `is_anchor_heavy`, the hypothesis
    //! generator — reasons about a program it believes has no account structs.
    use super::*;
    use std::fs;

    async fn accounts_for(src: &str) -> Vec<AccountNode> {
        let root = std::env::temp_dir().join(format!(
            "ares-accts-{}-{}",
            std::process::id(),
            // distinct per source so parallel test threads do not share a dir
            src.len() * 31 + src.bytes().map(|b| b as usize).sum::<usize>()
        ));
        let dir = root.join("src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("lib.rs"), src).unwrap();
        let g = MapperAgent::new(&root).analyze().await.unwrap();
        fs::remove_dir_all(&root).ok();
        g.accounts
    }

    /// `#[instruction(..)]` is not optional decoration: Anchor requires it
    /// whenever a `seeds` constraint references an instruction argument, so this
    /// is the canonical PDA struct, not an edge case.
    #[tokio::test]
    async fn instruction_attribute_between_derive_and_struct_is_skipped_over() {
        let accounts = accounts_for(
            "#[derive(Accounts)]\n\
             #[instruction(vault_bump: u8)]\n\
             pub struct Withdraw<'info> {\n\
             \x20   #[account(mut, seeds = [b\"vault\"], bump = vault_bump)]\n\
             \x20   pub vault: Account<'info, Vault>,\n\
             }\n",
        )
        .await;
        assert_eq!(
            accounts.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            vec!["Withdraw"],
            "the seeds-from-argument form must still be mapped"
        );
        assert!(
            accounts[0].seeds.is_some(),
            "seeds must come from the struct body, not from whatever line \
             followed the derive"
        );
    }

    #[tokio::test]
    async fn doc_comment_between_derive_and_struct_is_skipped_over() {
        let accounts = accounts_for(
            "#[derive(Accounts)]\n\
             /// Accounts for the withdraw instruction.\n\
             pub struct Withdraw<'info> {\n\
             \x20   pub vault: Account<'info, Vault>,\n\
             }\n",
        )
        .await;
        assert_eq!(accounts.len(), 1, "got {accounts:?}");
    }

    #[tokio::test]
    async fn multi_derive_lists_still_count_as_accounts_structs() {
        let accounts = accounts_for(
            "#[derive(Accounts, Clone)]\n\
             pub struct Withdraw<'info> {\n\
             \x20   pub vault: Account<'info, Vault>,\n\
             }\n",
        )
        .await;
        assert_eq!(accounts.len(), 1, "got {accounts:?}");
    }

    /// Solitaire's `FromAccounts` is a different framework's macro; treating it
    /// as an Anchor Accounts struct would inflate `anchor_field_count`, which
    /// LocalJudge uses to decide when to *suppress* findings.
    #[tokio::test]
    async fn from_accounts_derive_is_not_an_anchor_accounts_struct() {
        let accounts = accounts_for(
            "#[derive(FromAccounts)]\n\
             pub struct Withdraw<'b> {\n\
             \x20   pub vault: Info<'b>,\n\
             }\n",
        )
        .await;
        assert!(accounts.is_empty(), "got {accounts:?}");
    }

    /// A lifetime other than `'info` used to survive into the name, so the struct
    /// was recorded as `Withdraw<'a>` and never matched by name anywhere.
    #[tokio::test]
    async fn struct_name_excludes_any_lifetime_parameter() {
        let accounts = accounts_for(
            "#[derive(Accounts)]\n\
             pub struct Withdraw<'a> {\n\
             \x20   pub vault: Account<'a, Vault>,\n\
             }\n",
        )
        .await;
        assert_eq!(
            accounts.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            vec!["Withdraw"]
        );
    }
}

#[cfg(test)]
mod unchecked_arithmetic_tests {
    use super::*;
    use std::fs;

    /// Build a one-instruction Anchor-ish program and return its graph.
    async fn graph_for(body: &str) -> ProgramGraph {
        let root =
            std::env::temp_dir().join(format!("ares-arith-{}-{}", std::process::id(), body.len()));
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("lib.rs"),
            format!(
                "#[program]\npub mod p {{\n    use super::*;\n    pub fn withdraw(ctx: Context<W>) -> Result<()> {{\n{body}\n        Ok(())\n    }}\n}}\n"
            ),
        )
        .unwrap();
        let mut m = MapperAgent::new(&root);
        let g = m.analyze().await.unwrap();
        fs::remove_dir_all(&root).ok();
        g
    }

    /// The defect this field exists to fix: `has_arithmetic` is set by
    /// `.checked_add(` itself, so the hypothesis generator proposed "potential
    /// arithmetic overflow" for code that guards every operation. Flagging
    /// already-correct code is what retired `anchor-constraint-gap`.
    #[tokio::test]
    async fn checked_arithmetic_is_not_reported_as_unchecked() {
        let g = graph_for("        vault.total = vault.total.checked_add(amount).unwrap();").await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            !i.has_unchecked_arithmetic,
            "checked_add must not read as unchecked arithmetic"
        );
    }

    #[tokio::test]
    async fn saturating_and_wrapping_also_count_as_guarded() {
        for guard in ["saturating_add", "wrapping_add", "overflowing_add"] {
            let g = graph_for(&format!(
                "        vault.total = vault.total.{guard}(amount);"
            ))
            .await;
            let i = g.instructions.first().expect("one instruction");
            assert!(!i.has_unchecked_arithmetic, "{guard} must count as guarded");
        }
    }

    #[tokio::test]
    async fn bare_compound_assignment_is_unchecked() {
        let g = graph_for("        vault.total += amount;").await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            i.has_unchecked_arithmetic,
            "`+= ` with no guard in the body is the case worth reporting"
        );
    }

    #[tokio::test]
    async fn a_body_with_no_arithmetic_at_all_is_clean() {
        let g = graph_for("        msg!(\"noop\");").await;
        let i = g.instructions.first().expect("one instruction");
        assert!(!i.has_unchecked_arithmetic);
        assert!(!i.has_arithmetic);
    }
}
