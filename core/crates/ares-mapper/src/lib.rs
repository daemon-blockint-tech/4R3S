use ares_core::AresResult;
use std::collections::BTreeSet;
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
    /// Every `struct` in the program, whether or not Anchor manages it.
    ///
    /// `accounts` holds only `#[derive(Accounts)]` context structs. A program's
    /// *data* structs — the ones whose bytes live in an account — carry no such
    /// attribute, so nothing in the graph could see them, and the type-cosplay
    /// class had zero predictions across the whole eval corpus.
    pub data_structs: Vec<DataStructNode>,
    /// Type names the program uses somewhere only *account data* appears.
    ///
    /// `data_structs` cannot distinguish an account's stored type from an
    /// instruction-argument struct, an event payload or a plain helper — the
    /// declaration looks identical. Only the use site can, and type cosplay is
    /// a property of stored bytes, so a struct with no such use site has no
    /// account to be substituted for. Sorted, because everything the graph
    /// feeds must be reproducible byte-for-byte (GOLDEN RULE 2).
    pub account_data_types: BTreeSet<String>,
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
    /// The handler takes `&[AccountInfo]` — a native (non-Anchor) entry point,
    /// where a signer check must be written by hand in the body.
    pub is_native_entry_point: bool,
    /// The handler takes `Context<T>` — Anchor. The signer constraint lives in
    /// the accounts struct (`Signer<'info>`), NOT in the body, so reading the
    /// body for one and finding nothing says nothing at all.
    pub is_anchor_handler: bool,
    /// The signature names an account the caller supplies — `&[AccountInfo]`,
    /// a bare `&AccountInfo` parameter, or `Context<T>`.
    ///
    /// Wider than the two convention flags on purpose. Every `pub fn` in the
    /// crate lands in `instructions`, including byte-decoding helpers like
    /// `unpack_amount(input: &[u8])`, and those match `touches_raw_account_data`
    /// (`try_from_slice`) while having no reason to contain the word `owner` —
    /// so the ownership rule reported them as High. But narrowing to entry
    /// points would throw away the *other* real shape: a helper handed
    /// individual accounts (`bank: &AccountInfo`) is exactly the Cashio root
    /// cause and most of the function-level eval corpus. The honest predicate
    /// is "was it handed an account", not "is it the entry point".
    pub takes_account_params: bool,
    /// The body reads or writes an account's raw bytes or lamports.
    ///
    /// This is what makes a missing owner check *matter*. Without an owner
    /// assertion an account owned by another program can be substituted — but
    /// only code that decodes those bytes is exposed by it.
    pub touches_raw_account_data: bool,
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

/// A plain `struct` and what it carries to distinguish its own type.
///
/// Type cosplay is deserializing one account's bytes as another type. Anchor's
/// `#[account]` prepends an 8-byte discriminator that makes that fail; a bare
/// struct has nothing, so any account of the same size decodes cleanly as it.
#[derive(Debug, Clone, Default)]
pub struct DataStructNode {
    pub name: String,
    /// `#[account]` — Anchor writes and checks an 8-byte type discriminator.
    pub has_anchor_account_attr: bool,
    /// `#[event]` — an Anchor event payload. It is emitted into the transaction
    /// log and never stored in an account, so it has no account to be
    /// substituted for. Tracked separately because client code in the same
    /// crate decodes events with `try_from_slice`, the same idiom that marks a
    /// type as account data.
    pub is_anchor_event: bool,
    /// A leading field that names the type (`key: Key`, `discriminator`, `tag`).
    /// The manual equivalent of Anchor's discriminator; Metaplex uses `key: Key`.
    pub has_discriminator_field: bool,
    pub field_count: usize,
    pub file_path: PathBuf,
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

/// A field whose name says which type the bytes are.
///
/// Anchor's `#[account]` writes an 8-byte discriminator; programs that predate
/// it, or avoid it, put the tag in a field instead — Metaplex uses `key: Key`.
/// Either one makes deserializing the wrong type fail, which is what type
/// cosplay needs to be absent.
fn is_discriminator_field(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "key" | "discriminator" | "account_type" | "tag" | "variant" | "kind" | "state_type"
    )
}

/// Collect every `struct` declaration and whether it can identify its own type.
///
/// Line-based, matching the rest of this walker: the input is one Solana program
/// and the shapes are declaration-level, so a full parse buys nothing here that
/// `ast_scanner` does not already do on the paths that need it.
fn collect_data_structs(content: &str, path: &Path, out: &mut Vec<DataStructNode>) {
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("pub struct ") || trimmed.starts_with("struct ")) {
            continue;
        }
        let name = trimmed
            .trim_start_matches("pub ")
            .trim_start_matches("struct ")
            .trim()
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }

        // Attributes sit above the declaration. Walk back over attribute and
        // comment lines only, so an unrelated earlier struct's attributes are
        // never attributed to this one.
        let mut has_anchor_account_attr = false;
        let mut is_anchor_event = false;
        let mut j = i;
        while j > 0 {
            let above = lines[j - 1].trim();
            if above.starts_with("#[") {
                if above.contains("#[account") {
                    has_anchor_account_attr = true;
                }
                if above.contains("#[event") {
                    is_anchor_event = true;
                }
                j -= 1;
            } else if above.starts_with("//") || above.is_empty() {
                j -= 1;
            } else {
                break;
            }
        }

        // Body up to the closing brace, or the end of the file for a tuple
        // struct / a truncated snippet.
        let mut body = String::new();
        let mut depth = 0usize;
        for l in lines.iter().skip(i) {
            depth += l.matches('{').count();
            body.push_str(l);
            body.push('\n');
            if depth > 0 && l.contains('}') {
                break;
            }
        }

        let mut field_count = 0usize;
        let mut has_discriminator_field = false;
        for field in body.lines().skip(1) {
            let f = field.trim();
            if f.starts_with("//") || f.starts_with("#[") {
                continue;
            }
            if let Some((lhs, _)) = f.split_once(':') {
                let fname = lhs.trim().trim_start_matches("pub ").trim();
                if fname.is_empty() || fname.contains(' ') {
                    continue;
                }
                field_count += 1;
                if is_discriminator_field(fname) {
                    has_discriminator_field = true;
                }
            }
        }

        out.push(DataStructNode {
            name,
            has_anchor_account_attr,
            is_anchor_event,
            has_discriminator_field,
            field_count,
            file_path: path.to_path_buf(),
        });
    }
}

/// The identifier immediately preceding byte offset `end`, if there is one.
fn ident_ending_at(s: &str, end: usize) -> Option<String> {
    let head = &s[..end];
    let start = head
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let name = &head[start..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Type names this file uses somewhere only an account's *data* appears.
///
/// A struct declaration says nothing about whether its bytes are ever stored
/// in an account: an accounts context, an instruction-argument struct, an event
/// payload and a real account type are all just `pub struct X { .. }`. Type
/// cosplay can only happen to stored bytes, so the use site is the evidence.
///
/// Deliberately narrow. An unrecognised spelling costs one missed finding;
/// a loose match (say, every `::<T>` turbofish) puts back the false positives
/// this exists to remove — the rule already fired on every context struct in
/// the program.
/// The byte spellings that mean "these bytes came out of an account".
const ACCOUNT_BYTE_SOURCES: [&str; 6] = [
    ".data.borrow",
    ".try_borrow_data",
    ".try_borrow_mut_data",
    ".data.borrow_mut",
    "account_info",
    ".data",
];

/// Whether `ident` is the whole identifier at the start of `text`, not a prefix
/// of a longer one — so a binding for `buf` is not matched by `buffer`.
fn starts_with_ident(text: &str, ident: &str) -> bool {
    text.strip_prefix(ident)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_'))
}

/// Whether a decode call's argument is account bytes rather than instruction
/// data.
///
/// `T::try_from_slice(..)` is Borsh's entry point for BOTH, and on native Solana
/// the commonest use by far is decoding INSTRUCTION data —
/// `let args = InitArgs::try_from_slice(instruction_data)?;`. Accepting that as
/// proof that `InitArgs` lives in an account made every instruction-argument
/// struct a type-cosplay candidate: the largest false-positive class on native
/// targets, and the one the rule's own finding text asserts as fact
/// ("Struct 'X' is deserialized from account data") rather than hedging. An
/// assertion at 0.72 confidence and non-speculative is exactly the shape
/// REMEMBER persists into durable memory, so the gate has to earn the sentence.
fn decode_reads_account_bytes(content: &str, arg: &str) -> bool {
    if ACCOUNT_BYTE_SOURCES.iter().any(|m| arg.contains(m)) {
        return true;
    }

    // `let buf = acc.data.borrow(); T::try_from_slice(&buf)?` — the bytes reach
    // the decode through a local. Resolve exactly one hop, via the binding line.
    // Deeper chains are given up on rather than guessed at: a missed type costs
    // recall, an invented one costs a false statement of fact.
    let ident: String = arg
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim()
        .trim_start_matches('&')
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        return false;
    }

    content.lines().any(|line| {
        let trimmed = line.trim_start();
        let Some(after_let) = trimmed.strip_prefix("let ") else {
            return false;
        };
        let bound = after_let.strip_prefix("mut ").unwrap_or(after_let);
        starts_with_ident(bound, &ident) && ACCOUNT_BYTE_SOURCES.iter().any(|m| line.contains(m))
    })
}

/// The text of the first argument of the call whose `(` follows `from`.
fn call_argument(content: &str, from: usize) -> &str {
    let Some(open_rel) = content[from..].find('(') else {
        return "";
    };
    let open = from + open_rel;
    let mut depth = 0i32;
    for (i, ch) in content[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &content[open + 1..open + i];
                }
            }
            _ => {}
        }
    }
    ""
}

fn collect_account_data_types(content: &str, out: &mut BTreeSet<String>) {
    // `Vault::try_from_slice(..)`, `state::Vault::unpack(..)` — the manual
    // decode of raw account bytes into a type. `::unpack` covers
    // `unpack_unchecked` / `unpack_from_slice` as a prefix.
    //
    // Gated on the ARGUMENT, not just the call: see `decode_reads_account_bytes`.
    // `::from_account_info` is exempt because its name already states the source.
    for call in [
        "::try_from_slice",
        "::try_deserialize",
        "::deserialize",
        "::unpack",
        "::from_account_info",
    ] {
        for (at, _) in content.match_indices(call) {
            if let Some(name) = ident_ending_at(content, at) {
                if call == "::from_account_info"
                    || decode_reads_account_bytes(content, call_argument(content, at + call.len()))
                {
                    out.insert(name);
                }
            }
        }
    }

    // `Account<'info, Vault>` / `AccountLoader<'info, Pool>` — Anchor's typed
    // wrappers, where the type parameter *is* the account's data. Both spellings
    // are needed: `Account<` does not occur inside `AccountLoader<`. The
    // comma requirement is what excludes `UncheckedAccount<'info>`, which names
    // no type at all, and no wrapper spells `Context<T>` — a context is the
    // parameter list, not the bytes.
    for wrapper in ["Account<", "AccountLoader<"] {
        for (at, _) in content.match_indices(wrapper) {
            let after = &content[at + wrapper.len()..];
            let Some(generics) = after.split('>').next() else {
                continue;
            };
            if !generics.contains(',') {
                continue;
            }
            let last = generics.rsplit(',').next().unwrap_or("");
            let name: String = last
                .trim()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
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

        // Walk source files. WalkDir yields entries in filesystem order, so
        // collect and sort paths first to keep the graph deterministic.
        let mut source_paths: Vec<PathBuf> = WalkDir::new(&src_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("rs"))
            .map(|e| e.path().to_path_buf())
            .collect();
        source_paths.sort();

        for path in &source_paths {
            debug!("Analyzing file: {:?}", path);

            graph.all_source_files.push(path.clone());

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

            // Every `struct` in the file, with what it carries to identify its
            // own type. Collected separately from `accounts` because that list
            // only holds `#[derive(Accounts)]` context structs — a program's
            // *data* structs carry no attribute at all, so nothing in the graph
            // could see them and the type-cosplay class produced zero findings
            // across the whole eval corpus.
            collect_data_structs(&content, path, &mut graph.data_structs);

            // …and which of those names are ever *used* as an account's bytes.
            // Collected over every file, since a struct and its decode site
            // routinely live apart (`state.rs` / `processor.rs`).
            collect_account_data_types(&content, &mut graph.account_data_types);

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

                    // Calling convention, read from the signature rather than the
                    // body. It decides whether an absent signer idiom means
                    // anything: Anchor puts the constraint in the accounts struct,
                    // so an Anchor body with no idiom is the normal, correct shape.
                    //
                    // The WHOLE signature, not the `pub fn` line. The canonical
                    // native handler — `pub fn process_instruction(program_id:
                    // &Pubkey, accounts: &[AccountInfo], instruction_data:
                    // &[u8]) -> ProgramResult` — is 117 columns, so rustfmt
                    // always splits it. Reading one line made the effective gate
                    // "the signature happened to fit on one line": the identical
                    // program, formatted the way it ships, reported
                    // `is_native_entry_point = false` and a genuinely
                    // unauthenticated handler produced no hypothesis at all.
                    //
                    // See `extract_signature` for why the bound is depth-aware
                    // and comment-stripped, and `parameter_list` for why these
                    // predicates read the parameters rather than the whole
                    // declaration.
                    let signature = extract_signature(rest);
                    let params = parameter_list(&signature);
                    let is_native_entry_point = params.contains("&[AccountInfo")
                        || params.contains("& [AccountInfo")
                        || params.contains("accounts: &[");
                    let is_anchor_handler =
                        params.contains("Context<") || params.contains("Context <");
                    // Anchor's typed wrappers name an account as much as a raw
                    // `AccountInfo` does. Without them the gate rejected
                    // `get_config_line(a: &Account<'info, CandyMachine>, ..)`,
                    // which plainly does take an account.
                    //
                    // Measured cost, stated because it is a cost: on the 170-row
                    // corpus this re-admits exactly one row and that row is a
                    // FALSE positive (overall F1 0.5481 -> 0.5461). Kept anyway.
                    // The gate's job is "does this function receive an account",
                    // and for `&Account<'info, T>` the answer is yes; the wrong
                    // label on that row comes from the owner rule's own
                    // heuristic, not from this test. Excluding a whole Anchor
                    // calling convention to buy 0.002 F1 would be fitting the
                    // gate to the corpus rather than to Solana.
                    //
                    // It still rejects `fn lamports(&self)` and
                    // `fn try_borrow_data(&self)` — `AccountInfo`'s own methods
                    // rather than handlers, and the class this gate exists for.
                    let takes_account_params = is_native_entry_point
                        || is_anchor_handler
                        || params.contains("AccountInfo")
                        || [
                            "Account<",
                            "AccountLoader<",
                            "InterfaceAccount<",
                            "SystemAccount<",
                            "UncheckedAccount<",
                            "Signer<",
                        ]
                        .iter()
                        .any(|w| params.contains(w));

                    // The concrete forms a program uses to reach an account's
                    // bytes. `.try_borrow` is a prefix on purpose: `try_borrow_data`,
                    // `try_borrow_mut_data`, `try_borrow_lamports` and the bare
                    // `(*acc.data).try_borrow_mut()` are the same access, and
                    // listing them separately missed the bare form that three
                    // corpus targets use.
                    let touches_raw_account_data = body.as_ref().is_some_and(|b| {
                        [
                            ".data.borrow",
                            ".data).borrow",
                            ".try_borrow",
                            ".lamports.borrow",
                            ".lamports).borrow",
                            "try_from_slice",
                            "::unpack",
                            ".unpack",
                            "deserialize",
                        ]
                        .iter()
                        .any(|needle| b.contains(needle))
                    });

                    let has_signer = body.as_ref().map(|b| {
                        b.contains("is_signer")
                            // solana-program's helper; its absence here made every
                            // program using it read as unchecked.
                            || b.contains("assert_signer")
                            || b.contains("Signer<")
                            || b.contains("has_one")
                            || b.contains("constraint = signer")
                        // NOT `signer(`: it also matches `CpiContext::new_with_signer(`,
                        // a CPI call rather than a signer assertion.
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
                        is_native_entry_point,
                        is_anchor_handler,
                        takes_account_params,
                        touches_raw_account_data,
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

/// The declaration text of the `pub fn` at the start of `text`, up to but not
/// including the body.
///
/// Bounded by the body's `{`, or by the `;` of a bodyless `extern` declaration —
/// otherwise one function's calling convention would be read off the next
/// function's parameters. Both bounds are honoured only at bracket depth 0, and
/// `//` comments are dropped first, because an earlier version scanned for the
/// first `{` or `;` anywhere and claimed in its own comment that "a Rust
/// signature contains neither character". It does:
///
///   - `[u8; 32]` — PDA seeds, discriminators, ed25519 signatures — is an
///     everyday Solana parameter type, and its `;` truncated the signature
///     before the account parameter, blinding every gate below. That was a
///     regression against even the old single-line reader.
///   - `eval/fixtures/rs/incident-repros/cashio-2022.rs` carries prose comments
///     inside its parameter list, and one `;` in such a comment did the same.
fn extract_signature(text: &str) -> String {
    let mut out = String::new();
    let mut depth = 0i32;

    for line in text.lines() {
        // Not a Rust lexer: a `//` inside a string literal would cut early. No
        // signature in the corpus has one, and erring toward a shorter
        // signature only costs recall, never a false positive.
        let code = line.split("//").next().unwrap_or(line);
        for ch in code.chars() {
            match ch {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' | ';' if depth <= 0 => return out,
                _ => {}
            }
            out.push(ch);
        }
        out.push('\n');
    }
    out
}

/// The parameter list of a signature — the first balanced `(...)`, without the
/// enclosing parentheses.
///
/// Predicates about what a function RECEIVES have to read this and not the whole
/// signature, or the return type answers for them:
/// `pub fn describe(id: u64) -> Vec<AccountInfo>` takes no accounts at all but
/// contains "AccountInfo".
fn parameter_list(signature: &str) -> &str {
    let Some(open) = signature.find('(') else {
        return "";
    };
    let mut depth = 0i32;
    for (i, ch) in signature[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &signature[open + 1..open + i];
                }
            }
            _ => {}
        }
    }
    // Unbalanced — a truncated or malformed declaration. Returning the tail
    // rather than "" keeps a split signature readable; the caller only runs
    // `contains` over it.
    &signature[open + 1..]
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

#[cfg(test)]
mod data_struct_tests {
    use super::*;

    fn structs_in(src: &str) -> Vec<DataStructNode> {
        let mut out = Vec::new();
        collect_data_structs(src, Path::new("lib.rs"), &mut out);
        out
    }

    /// The vulnerable shape: no `#[account]`, no type field. Nothing
    /// distinguishes these bytes from any other account of the same size.
    #[test]
    fn a_bare_struct_carries_no_discriminator() {
        let s = structs_in(
            "pub struct PayoutTicket {\n    pub recipient: Pubkey,\n    pub amount_paid: u64,\n}\n",
        );
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "PayoutTicket");
        assert!(!s[0].has_anchor_account_attr);
        assert!(!s[0].has_discriminator_field);
        assert_eq!(s[0].field_count, 2);
    }

    /// Anchor writes and checks an 8-byte discriminator, so this is safe and
    /// must not be flagged — the whole point of the attribute.
    #[test]
    fn an_anchor_account_attribute_is_recognised() {
        let s = structs_in("#[account]\npub struct Vault {\n    pub total: u64,\n}\n");
        assert_eq!(s.len(), 1);
        assert!(s[0].has_anchor_account_attr);
    }

    #[test]
    fn an_anchor_attribute_survives_a_doc_comment_between_it_and_the_struct() {
        // `#[account]` / `/// docs` / `pub struct` is ordinary Anchor style.
        let s =
            structs_in("#[account]\n/// The vault.\npub struct Vault {\n    pub total: u64,\n}\n");
        assert!(
            s[0].has_anchor_account_attr,
            "doc comment must not detach the attribute"
        );
    }

    /// The manual equivalent: Metaplex tags its accounts with a leading `key`.
    #[test]
    fn a_leading_type_field_counts_as_a_discriminator() {
        for field in [
            "key: Key",
            "discriminator: u64",
            "account_type: AccountType",
            "tag: u8",
        ] {
            let s = structs_in(&format!(
                "pub struct S {{\n    pub {field},\n    pub owner: Pubkey,\n}}\n"
            ));
            assert!(s[0].has_discriminator_field, "{field} should count");
        }
    }

    /// The attribute belongs to the struct it precedes, not to a later one.
    /// Getting this wrong marks an undiscriminated struct as safe.
    #[test]
    fn an_earlier_structs_attribute_does_not_attach_to_a_later_one() {
        let s = structs_in(
            "#[account]\npub struct Safe {\n    pub a: u64,\n}\n\npub struct Unsafe {\n    pub b: u64,\n}\n",
        );
        assert_eq!(s.len(), 2);
        assert!(s[0].has_anchor_account_attr);
        assert!(
            !s[1].has_anchor_account_attr,
            "the attribute is not inherited"
        );
    }

    #[test]
    fn field_count_ignores_comments_and_attributes() {
        let s = structs_in(
            "pub struct S {\n    // a note\n    #[serde(skip)]\n    pub a: u64,\n    pub b: Pubkey,\n}\n",
        );
        assert_eq!(s[0].field_count, 2);
    }

    #[test]
    fn a_tuple_struct_and_an_empty_struct_report_no_fields() {
        assert_eq!(
            structs_in("pub struct AmountRange(pub u64, pub u64);\n")[0].field_count,
            0
        );
        assert_eq!(structs_in("pub struct Marker {}\n")[0].field_count, 0);
    }

    #[test]
    fn a_generic_or_lifetime_parameter_is_not_part_of_the_name() {
        let s = structs_in("pub struct Ctx<'info> {\n    pub a: u64,\n}\n");
        assert_eq!(s[0].name, "Ctx");
    }

    /// An `#[event]` payload is emitted into the transaction log; it never
    /// occupies an account, so it cannot be type-cosplayed. It matters because
    /// client-side code in the same crate deserializes events with
    /// `try_from_slice` — the same idiom that marks a type as account data.
    #[test]
    fn an_event_struct_is_flagged_as_an_event() {
        let s = structs_in("#[event]\npub struct DepositEvent {\n    pub amount: u64,\n}\n");
        assert!(s[0].is_anchor_event);
        assert!(!s[0].has_anchor_account_attr);
    }

    #[test]
    fn a_plain_struct_is_not_an_event() {
        let s = structs_in("pub struct Vault {\n    pub total: u64,\n}\n");
        assert!(!s[0].is_anchor_event);
    }
}

#[cfg(test)]
mod tightening_tests {
    use super::*;
    use std::fs;

    async fn graph_for(src: &str, name: &str) -> ProgramGraph {
        let root = std::env::temp_dir().join(format!("ares-tighten-{}-{name}", std::process::id()));
        let s = root.join("src");
        fs::create_dir_all(&s).unwrap();
        fs::write(s.join("lib.rs"), src).unwrap();
        let g = MapperAgent::new(&root).analyze().await.unwrap();
        fs::remove_dir_all(&root).ok();
        g
    }

    /// An Anchor handler keeps its signer constraint in the accounts struct, not
    /// the body. Reading the body and finding nothing says nothing — and firing
    /// on it produced 74 predictions against a corpus with zero ground-truth
    /// rows for the class.
    #[tokio::test]
    async fn an_anchor_handler_is_not_a_native_entry_point() {
        let g = graph_for(
            "pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }",
            "anchor",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(i.is_anchor_handler);
        assert!(!i.is_native_entry_point);
    }

    #[tokio::test]
    async fn a_native_handler_is_an_entry_point() {
        let g = graph_for(
            "pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult { Ok(()) }",
            "native",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(i.is_native_entry_point);
        assert!(!i.is_anchor_handler);
    }

    /// `signer(` also matches `CpiContext::new_with_signer(` — a CPI call, not a
    /// signer assertion. Counting it marked unchecked handlers safe.
    #[tokio::test]
    async fn a_cpi_with_signer_seeds_is_not_a_signer_check() {
        let g = graph_for(
            "pub fn f(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {\n    let c = CpiContext::new_with_signer(a, b, seeds);\n    Ok(())\n}",
            "cpisigner",
        )
        .await;
        assert_eq!(g.instructions[0].has_signer_check, Some(false));
    }

    #[tokio::test]
    async fn assert_signer_counts_as_a_signer_check() {
        let g = graph_for(
            "pub fn f(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {\n    assert_signer(authority)?;\n    Ok(())\n}",
            "assertsigner",
        )
        .await;
        assert_eq!(g.instructions[0].has_signer_check, Some(true));
    }

    /// The bare `(*acc.data).try_borrow_mut()` form, which the per-spelling list
    /// missed — three corpus targets use exactly it.
    #[tokio::test]
    async fn a_bare_try_borrow_counts_as_touching_raw_data() {
        let g = graph_for(
            "pub fn f(accounts: &[AccountInfo]) -> ProgramResult {\n    let d = (*acc.data).try_borrow_mut()?;\n    Ok(())\n}",
            "rawdata",
        )
        .await;
        assert!(g.instructions[0].touches_raw_account_data);
    }

    /// The other direction: a handler that never reads raw bytes has nothing an
    /// owner confusion could expose, so it must not carry the signal.
    #[tokio::test]
    async fn a_handler_that_reads_no_raw_data_does_not_carry_the_signal() {
        let g = graph_for(
            "pub fn f(accounts: &[AccountInfo]) -> ProgramResult {\n    msg!(\"noop\");\n    Ok(())\n}",
            "nodata",
        )
        .await;
        assert!(!g.instructions[0].touches_raw_account_data);
    }
}

#[cfg(test)]
mod signature_tests {
    //! The calling convention decides whether a body-read signal means
    //! anything, and it was read from the `pub fn` line alone. The canonical
    //! native handler signature is 117 columns, so rustfmt always splits it —
    //! which made the effective gate "the signature happened to fit on one
    //! line". The same program, formatted the way it ships, reported
    //! `is_native_entry_point = false` and every rule gated on it went silent.
    use super::*;
    use std::fs;

    async fn graph_for(src: &str, name: &str) -> ProgramGraph {
        let root = std::env::temp_dir().join(format!("ares-sig-{}-{name}", std::process::id()));
        let s = root.join("src");
        fs::create_dir_all(&s).unwrap();
        fs::write(s.join("lib.rs"), src).unwrap();
        let g = MapperAgent::new(&root).analyze().await.unwrap();
        fs::remove_dir_all(&root).ok();
        g
    }

    /// The signature bound used to be `rest.find(['{', ';'])`, whose comment
    /// claimed "a Rust signature contains neither character". `[u8; 32]` — PDA
    /// seeds, discriminators, ed25519 signatures — contains one, and truncating
    /// there cut the signature off before the account parameter. That was a
    /// regression against even the single-line reader it replaced.
    #[tokio::test]
    async fn an_array_parameter_does_not_truncate_the_signature() {
        let g = graph_for(
            "pub fn process(seed: [u8; 32], accounts: &[AccountInfo]) -> ProgramResult {\n\
             \x20   Ok(())\n\
             }\n",
            "array-param-oneline",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            i.is_native_entry_point,
            "`[u8; 32]` before the accounts parameter must not end the signature"
        );
        assert!(i.takes_account_params);
    }

    /// Both defects at once — the shape B2 exists to rescue, carrying the array
    /// parameter that defeated the fix's own bound.
    #[tokio::test]
    async fn a_rustfmt_split_signature_with_an_array_parameter_is_still_an_entry_point() {
        let g = graph_for(
            "pub fn process(\n\
             \x20   seed: [u8; 32],\n\
             \x20   accounts: &[AccountInfo],\n\
             ) -> ProgramResult {\n\
             \x20   Ok(())\n\
             }\n",
            "array-param-split",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(i.is_native_entry_point);
        assert!(i.takes_account_params);
    }

    /// `cashio-2022.rs` carries prose inside its parameter list, and a single
    /// `;` in such a comment truncated the signature exactly as an array type
    /// did.
    #[tokio::test]
    async fn a_semicolon_inside_a_comment_does_not_truncate_the_signature() {
        let g = graph_for(
            "pub fn process(\n\
             \x20   // the caller supplies the bank; we never validate it\n\
             \x20   bank: &AccountInfo,\n\
             ) -> ProgramResult {\n\
             \x20   Ok(())\n\
             }\n",
            "comment-semicolon",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            i.takes_account_params,
            "a `;` inside a comment must not end the signature"
        );
    }

    /// A predicate about what a function RECEIVES must not be answered by its
    /// return type.
    #[tokio::test]
    async fn account_info_in_the_return_type_is_not_an_account_parameter() {
        let g = graph_for(
            "pub fn describe(id: u64) -> Vec<AccountInfo> {\n\
             \x20   Vec::new()\n\
             }\n",
            "return-type-only",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            !i.takes_account_params,
            "this function takes a u64; AccountInfo appears only in its return type"
        );
        assert!(!i.is_native_entry_point);
    }

    /// The `;` bound still has to work for what it was for: a bodyless
    /// declaration must not read the next function's parameters.
    #[tokio::test]
    async fn a_bodyless_declaration_does_not_borrow_the_next_signature() {
        let g = graph_for(
            "pub fn ping(id: u64) -> ProgramResult;\n\
             pub fn handle(accounts: &[AccountInfo]) -> ProgramResult {\n\
             \x20   Ok(())\n\
             }\n",
            "bodyless",
        )
        .await;
        let ping = g
            .instructions
            .iter()
            .find(|i| i.name == "ping")
            .expect("ping");
        assert!(
            !ping.takes_account_params,
            "ping takes a u64; the accounts belong to handle"
        );
    }

    /// Byte-for-byte what `cargo fmt` produces for the canonical native entry
    /// point. If this shape is not recognised, no real native program is.
    #[tokio::test]
    async fn a_rustfmt_split_native_signature_is_still_an_entry_point() {
        let g = graph_for(
            "pub fn process_instruction(\n\
             \x20   program_id: &Pubkey,\n\
             \x20   accounts: &[AccountInfo],\n\
             \x20   instruction_data: &[u8],\n\
             ) -> ProgramResult {\n\
             \x20   Ok(())\n\
             }\n",
            "native-split",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            i.is_native_entry_point,
            "the signature rustfmt actually emits must read as a native entry point"
        );
        assert!(i.takes_account_params);
    }

    /// The same defect on the Anchor side: a split `Context<T>` parameter made
    /// the handler look like neither convention, so the signer rule's
    /// `!is_anchor_handler` guard stopped protecting it.
    #[tokio::test]
    async fn a_rustfmt_split_anchor_signature_is_still_an_anchor_handler() {
        let g = graph_for(
            "pub fn withdraw(\n\
             \x20   ctx: Context<Withdraw>,\n\
             \x20   amount: u64,\n\
             ) -> Result<()> {\n\
             \x20   Ok(())\n\
             }\n",
            "anchor-split",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(i.is_anchor_handler);
        assert!(!i.is_native_entry_point);
        assert!(i.takes_account_params);
    }

    /// The bound that keeps signature accumulation honest. `extern` blocks
    /// declare `pub fn`s with no body, so scanning forward to the next `{`
    /// would read the *following* function's parameters as this one's — and
    /// report an entry point where there is only a syscall declaration.
    #[tokio::test]
    async fn a_bodyless_declaration_does_not_absorb_the_next_signature() {
        let g = graph_for(
            "extern \"C\" {\n\
             \x20   pub fn sol_log_(message: *const u8, len: u64);\n\
             }\n\
             \n\
             pub fn process(accounts: &[AccountInfo]) -> ProgramResult {\n\
             \x20   Ok(())\n\
             }\n",
            "extern-decl",
        )
        .await;
        let decl = g
            .instructions
            .iter()
            .find(|i| i.name == "sol_log_")
            .expect("the declaration is still recorded");
        assert!(
            !decl.is_native_entry_point,
            "a bodyless declaration must stop at its own `;`, not run on into \
             the next function's parameters"
        );
        assert!(!decl.takes_account_params);
    }

    /// A pure byte-decoding helper takes no account at all. This is the signal
    /// the ownership rule needs: `unpack_amount` cannot be handed a substituted
    /// account because it is never handed an account.
    #[tokio::test]
    async fn a_helper_that_takes_no_account_does_not_take_account_params() {
        let g = graph_for(
            "pub fn unpack_amount(input: &[u8]) -> Result<u64, ProgramError> {\n\
             \x20   Ok(u64::try_from_slice(input)?)\n\
             }\n",
            "decode-helper",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(!i.takes_account_params);
        assert!(!i.is_native_entry_point);
        assert!(!i.is_anchor_handler);
    }

    /// A helper handed individual accounts *is* exposed — this is the shape of
    /// the Cashio incident reproduction (`eval/fixtures/rs/incident-repros`),
    /// and of most function-level corpus snippets. It is not an entry point and
    /// not Anchor, so a gate written as `is_native_entry_point ||
    /// is_anchor_handler` would drop exactly the cases the corpus is made of.
    #[tokio::test]
    async fn a_helper_handed_individual_accounts_takes_account_params() {
        let g = graph_for(
            "pub fn mint_ecash(\n\
             \x20   bank: &AccountInfo,\n\
             \x20   amount: u64,\n\
             ) -> ProgramResult {\n\
             \x20   let b = Bank::try_from_slice(&bank.data.borrow())?;\n\
             \x20   Ok(())\n\
             }\n",
            "account-helper",
        )
        .await;
        let i = g.instructions.first().expect("one instruction");
        assert!(
            i.takes_account_params,
            "`bank: &AccountInfo` is an account the caller chooses"
        );
        assert!(
            !i.is_native_entry_point,
            "it is not the program entry point"
        );
    }
}

#[cfg(test)]
mod account_data_type_tests {
    //! Which structs actually hold account bytes. Type cosplay is a property of
    //! *stored* data; a struct's declaration cannot say whether it is stored,
    //! so the use site has to.
    use super::*;
    use std::fs;

    async fn graph_for(src: &str, name: &str) -> ProgramGraph {
        let root = std::env::temp_dir().join(format!("ares-adt-{}-{name}", std::process::id()));
        let s = root.join("src");
        fs::create_dir_all(&s).unwrap();
        fs::write(s.join("lib.rs"), src).unwrap();
        let g = MapperAgent::new(&root).analyze().await.unwrap();
        fs::remove_dir_all(&root).ok();
        g
    }

    /// The largest false-positive class on native targets. Borsh's
    /// `try_from_slice` is the entry point for instruction data AND account
    /// data, and on native Solana the commonest call by far is
    /// `InitArgs::try_from_slice(instruction_data)`. Accepting the call alone as
    /// proof of storage made every instruction-argument struct a type-cosplay
    /// candidate — and the rule states its finding as fact ("Struct 'X' is
    /// deserialized from account data"), non-speculative at 0.72 confidence,
    /// which is the shape REMEMBER writes into durable memory.
    #[tokio::test]
    async fn instruction_data_decoded_with_borsh_is_not_account_data() {
        let g = graph_for(
            "pub fn process(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {\n\
             \x20   let args = InitArgs::try_from_slice(instruction_data)?;\n\
             \x20   Ok(())\n\
             }\n",
            "ix-data-decode",
        )
        .await;
        assert!(
            !g.account_data_types.contains("InitArgs"),
            "instruction arguments are not stored account data: {:?}",
            g.account_data_types
        );
    }

    /// The same struct in the same program IS account data once something
    /// actually reads it out of an account — so the gate is about the argument,
    /// not about the name.
    #[tokio::test]
    async fn the_same_type_counts_once_it_is_read_from_an_account() {
        let g = graph_for(
            "pub fn process(user: &AccountInfo, instruction_data: &[u8]) -> ProgramResult {\n\
             \x20   let args = Config::try_from_slice(instruction_data)?;\n\
             \x20   let cur = Config::try_from_slice(&user.data.borrow())?;\n\
             \x20   Ok(())\n\
             }\n",
            "both-uses",
        )
        .await;
        assert!(
            g.account_data_types.contains("Config"),
            "one account-bytes decode is enough: {:?}",
            g.account_data_types
        );
    }

    /// `let buf = acc.data.borrow(); T::try_from_slice(&buf)` — the bytes reach
    /// the decode through a local. One hop is resolved; dropping it would cost
    /// real recall on native programs.
    #[tokio::test]
    async fn account_bytes_reaching_the_decode_through_a_local_still_count() {
        let g = graph_for(
            "pub fn f(vault: &AccountInfo) -> ProgramResult {\n\
             \x20   let buf = vault.try_borrow_data()?;\n\
             \x20   let v = Vault::try_from_slice(&buf)?;\n\
             \x20   Ok(())\n\
             }\n",
            "indirect-decode",
        )
        .await;
        assert!(
            g.account_data_types.contains("Vault"),
            "{:?}",
            g.account_data_types
        );
    }

    /// The one-hop resolution must key on the whole identifier: a binding for
    /// `buffer` must not satisfy a decode of `buf`.
    #[tokio::test]
    async fn a_similarly_named_binding_does_not_satisfy_the_decode() {
        let g = graph_for(
            "pub fn f(vault: &AccountInfo, instruction_data: &[u8]) -> ProgramResult {\n\
             \x20   let buffer = vault.try_borrow_data()?;\n\
             \x20   let buf = instruction_data;\n\
             \x20   let a = Args::try_from_slice(buf)?;\n\
             \x20   Ok(())\n\
             }\n",
            "ident-boundary",
        )
        .await;
        assert!(
            !g.account_data_types.contains("Args"),
            "`buffer` is not `buf`: {:?}",
            g.account_data_types
        );
    }

    #[tokio::test]
    async fn a_manual_decode_marks_the_type_as_account_data() {
        let g = graph_for(
            "pub fn f(user: &AccountInfo) -> ProgramResult {\n\
             \x20   let u = User::try_from_slice(&user.data.borrow())?;\n\
             \x20   Ok(())\n\
             }\n",
            "manual-decode",
        )
        .await;
        assert!(
            g.account_data_types.contains("User"),
            "{:?}",
            g.account_data_types
        );
    }

    /// A module-qualified path must yield the type, not the module.
    #[tokio::test]
    async fn a_qualified_path_yields_the_type_not_the_module() {
        let g = graph_for(
            "pub fn f(a: &AccountInfo) -> ProgramResult {\n\
             \x20   let v = state::Vault::unpack(&a.data.borrow())?;\n\
             \x20   Ok(())\n\
             }\n",
            "qualified",
        )
        .await;
        assert!(
            g.account_data_types.contains("Vault"),
            "{:?}",
            g.account_data_types
        );
        assert!(!g.account_data_types.contains("state"));
    }

    #[tokio::test]
    async fn an_anchor_typed_wrapper_marks_its_inner_type_as_account_data() {
        let g = graph_for(
            "#[derive(Accounts)]\n\
             pub struct Withdraw<'info> {\n\
             \x20   pub vault: Account<'info, Vault>,\n\
             \x20   pub pool: AccountLoader<'info, Pool>,\n\
             }\n",
            "typed-wrapper",
        )
        .await;
        assert!(
            g.account_data_types.contains("Vault"),
            "{:?}",
            g.account_data_types
        );
        assert!(
            g.account_data_types.contains("Pool"),
            "{:?}",
            g.account_data_types
        );
    }

    /// The context struct itself is a parameter list, never account bytes.
    /// `Context<Withdraw>` and `UncheckedAccount<'info>` must not enrol a type.
    #[tokio::test]
    async fn a_context_or_unchecked_wrapper_enrols_nothing() {
        let g = graph_for(
            "pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {\n\
             \x20   let a: UncheckedAccount<'info> = ctx.accounts.a;\n\
             \x20   Ok(())\n\
             }\n",
            "context-only",
        )
        .await;
        assert!(
            !g.account_data_types.contains("Withdraw"),
            "{:?}",
            g.account_data_types
        );
        assert!(
            g.account_data_types.is_empty(),
            "{:?}",
            g.account_data_types
        );
    }
}
