use crate::idl::IdlInstruction;
use ares_core::{Finding, VulnerabilityCategory};
use chrono::Utc;

/// Generates compilable proof-of-concept harnesses using `solana-program-test`.
/// Each category produces a structurally valid test with attack-specific account setup.
/// The generated files are meant to be placed in the target program's test directory
/// and wired to the actual program entrypoint / .so by the auditor.
pub struct PocGenerator;

impl PocGenerator {
    /// Generate a proof-of-concept harness for a finding.
    ///
    /// When `instruction` (the target's IDL instruction for this finding) and/or
    /// `program_id` are supplied, the placeholder instruction data (`&[]`) and
    /// random program id are replaced with the real Anchor discriminator + args
    /// and the deployed program id (POC-1 wiring). A leading `// ARES-WIRING:`
    /// marker records how complete that wiring is for the downstream fork
    /// validator (POC-2): `wired` (data + program id), `partial` (data only, or
    /// incompletely-encoded args), or `unwired` (no IDL match — placeholder).
    pub fn generate(
        finding: &Finding,
        program_name: &str,
        instruction: Option<&IdlInstruction>,
        program_id: Option<&str>,
    ) -> String {
        let id = &finding.id;

        let harness = match &finding.category {
            VulnerabilityCategory::SignerAuthorization => {
                Self::generate_signer_poc(id, program_name)
            }
            VulnerabilityCategory::OwnershipCheck => Self::generate_owner_poc(id, program_name),
            VulnerabilityCategory::ArbitraryCpi => Self::generate_cpi_poc(id, program_name),
            VulnerabilityCategory::InitializationFrontrunning
            | VulnerabilityCategory::ReInitialization => Self::generate_init_poc(id, program_name),
            VulnerabilityCategory::AccountReloading | VulnerabilityCategory::RevivalAttack => {
                Self::generate_revival_poc(id, program_name)
            }
            VulnerabilityCategory::FuzzingCrash | VulnerabilityCategory::InvariantViolation => {
                Self::generate_invariant_poc(id, program_name, finding)
            }
            _ => Self::generate_generic_poc(id, program_name),
        };

        Self::wire_instruction_data(harness, instruction, program_id)
    }

    /// Replace the placeholder instruction data and program id in a generated
    /// harness with real values, and prepend the `// ARES-WIRING:` marker.
    ///
    /// Every category builder emits the exact placeholder
    /// `Instruction::new_with_bytes(program_id, &[], ...)`, so a single string
    /// replacement wires all of them without touching the attack-specific
    /// account setup that each builder deliberately constructs.
    fn wire_instruction_data(
        harness: String,
        instruction: Option<&IdlInstruction>,
        program_id: Option<&str>,
    ) -> String {
        let (data_expr, data_complete) = match instruction {
            Some(ix) => {
                let (bytes, complete) = crate::idl::instruction_data(ix);
                (crate::idl::byte_slice_literal(&bytes), complete)
            }
            None => ("&[]".to_string(), false),
        };

        let mut wired = harness.replace(
            "Instruction::new_with_bytes(program_id, &[], ",
            &format!("Instruction::new_with_bytes(program_id, {}, ", data_expr),
        );

        if let Some(pid) = program_id {
            wired = wired.replace(
                "Pubkey::new_unique()",
                &format!("\"{}\".parse::<Pubkey>().unwrap()", pid),
            );
        }

        let state = match (instruction.is_some(), data_complete, program_id.is_some()) {
            (true, true, true) => "wired",
            (true, _, _) => "partial",
            (false, _, _) => "unwired",
        };

        format!("// ARES-WIRING: {}\n{}", state, wired)
    }

    fn header(id: &str, program_name: &str, category: &VulnerabilityCategory) -> String {
        format!(
            "// ARES V3 Auto-Generated Proof-of-Concept Test\n// Target: {}\n// Finding ID: {}\n// Category: {}\n// Generated: {}\n// NOTE: This is a compilable harness. Replace placeholder instruction data\n// with actual serialized instruction data from the target program's IDL or source.\n",
            program_name,
            id,
            category,
            Utc::now().to_rfc3339()
        )
    }

    fn imports() -> &'static str {
        "use solana_program_test::*;\nuse solana_sdk::{\n    account::Account,\n    instruction::{AccountMeta, Instruction},\n    pubkey::Pubkey,\n    signature::{Keypair, Signer},\n    system_program,\n    transaction::Transaction,\n};\n"
    }

    /// `pre_start` carries any extra `program_test.add_account(...)` setup the
    /// category needs, spliced in BEFORE `program_test.start()`.
    ///
    /// The split is not stylistic. `ProgramTest::start` takes `self` **by
    /// value**, so an `add_account` call emitted after it is a use-after-move
    /// (E0382) and the harness cannot compile. Because `confirm.rs` stages the
    /// harness into the audited repo's own `tests/` directory, one such template
    /// stopped `cargo test` from building that repo at all — no `test result:`
    /// line, so `run_poc` returned Inconclusive for this finding and every
    /// subsequent one in the same repo.
    fn test_boilerplate(test_name: &str, pre_start: &str, body: &str) -> String {
        format!(
            r#"#[tokio::test]
async fn {}() {{
    // Replace with the actual on-chain program ID or register the compiled .so
    let program_id = Pubkey::new_unique(); // TODO: replace with real program_id
    let mut program_test = ProgramTest::default();
    // TODO: register your program:
    // program_test.add_program("{}", program_id, processor!(your_program::entry));

    // Attacker and victim keypairs
    let attacker = Keypair::new();
    let victim = Keypair::new();

    // Fund accounts
    program_test.add_account(
        attacker.pubkey(),
        Account {{
            lamports: 1_000_000_000,
            ..Account::default()
        }},
    );
    program_test.add_account(
        victim.pubkey(),
        Account {{
            lamports: 1_000_000_000,
            ..Account::default()
        }},
    );
{}
    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    {}
}}
"#,
            test_name,
            program_name_placeholder(),
            pre_start,
            body
        )
    }

    /// The generated harness's **exit code is the verdict**. This emits the block
    /// that makes that true.
    ///
    /// `commands/validate.rs::run_poc` decides `Passed` vs `Failed` from the exit
    /// status of `cargo test` and nothing else, and `commands/confirm.rs` maps
    /// `Passed` to `ValidationOutcome::Confirmed`, forcing confidence to 0.95 and
    /// upgrading severity. Every template used to `println!` on **both** arms and
    /// panic on neither, so `cargo test` exited 0 whether the attack transaction
    /// was accepted or rejected. The verdict was therefore a constant: every PoC
    /// that compiled came back Confirmed.
    ///
    /// The direction of the error made it worse than noise. A *correctly guarded*
    /// program is precisely the one whose check makes `process_transaction` return
    /// `Err` — the arm that printed "check is present" and passed. So the safer the
    /// target, the more confidently it was reported as holding a fork-confirmed
    /// critical exploit.
    ///
    /// Contract, relied on by `run_poc`: exit 0 iff the attack transaction was
    /// accepted. Panic (non-zero) when the program rejected it.
    ///
    /// `tx` names the transaction variable the template built (templates differ:
    /// `transaction`, `tx2`, `tx_reinit`), so the attack transaction this verdict
    /// reports on is always the one the caller actually intends.
    fn verdict_match(tx: &str, guard: &str) -> String {
        format!(
            "let result = banks_client.process_transaction({tx}).await;\n    \
             match result {{\n        \
             Ok(_) => println!(\n            \
             \"ARES-POC: EXPLOIT REPRODUCED — {guard} is missing or bypassable.\"\n        \
             ),\n        \
             // Non-zero exit is the signal for `refuted`. Do not soften this to a\n        \
             // println!: doing so reports every guarded program as exploited.\n        \
             Err(e) => panic!(\n            \
             \"ARES-POC: NOT REPRODUCED — {guard} rejected the attack: {{:?}}\",\n            \
             e\n        \
             ),\n    \
             }}"
        )
    }

    fn generate_signer_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(
            id,
            program_name,
            &VulnerabilityCategory::SignerAuthorization,
        );
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_missing_signer", sanitize_id(id)),
            "",
            &format!(
                "{}{}",
                r#"// Attack: omit the required signer signature in AccountMeta
    let accounts = vec![
        AccountMeta::new(victim.pubkey(), false), // should be true
        AccountMeta::new_readonly(attacker.pubkey(), false),
    ];

    // TODO: Replace &[] with actual serialized instruction data
    let instruction = Instruction::new_with_bytes(program_id, &[], accounts);

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    "#,
                Self::verdict_match("transaction", "the signer check")
            ),
        ));
        s
    }

    fn generate_owner_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::OwnershipCheck);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_wrong_owner", sanitize_id(id)),
            r#"
    // Attack: provide an account owned by system_program instead of the target program
    let fake_account = Keypair::new();
    program_test.add_account(
        fake_account.pubkey(),
        Account {
            lamports: 1_000_000,
            owner: system_program::id(),
            ..Account::default()
        },
    );
"#,
            &format!(
                "{}{}",
                r#"let accounts = vec![
        AccountMeta::new(fake_account.pubkey(), false),
        AccountMeta::new_readonly(attacker.pubkey(), true),
    ];

    let instruction = Instruction::new_with_bytes(program_id, &[], accounts);

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );

    "#,
                Self::verdict_match("transaction", "the account ownership check")
            ),
        ));
        s
    }

    fn generate_cpi_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::ArbitraryCpi);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_arbitrary_cpi", sanitize_id(id)),
            r#"
    // Attack: create a fake program account to impersonate a trusted CPI target
    let fake_program = Keypair::new();
    program_test.add_account(
        fake_program.pubkey(),
        Account {
            lamports: 1_000_000,
            owner: solana_sdk::bpf_loader_upgradeable::id(),
            ..Account::default()
        },
    );
"#,
            &format!(
                "{}{}",
                r#"let accounts = vec![
        AccountMeta::new(victim.pubkey(), false),
        AccountMeta::new_readonly(fake_program.pubkey(), false),
        AccountMeta::new_readonly(attacker.pubkey(), true),
    ];

    let instruction = Instruction::new_with_bytes(program_id, &[], accounts);

    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );

    "#,
                Self::verdict_match("transaction", "the CPI target program-id check")
            ),
        ));
        s
    }

    fn generate_init_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(
            id,
            program_name,
            &VulnerabilityCategory::InitializationFrontrunning,
        );
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_double_init", sanitize_id(id)),
            "",
            &format!(
                "{}{}",
                r#"// Attack: call the initialize instruction twice without checks
    let accounts = vec![
        AccountMeta::new(victim.pubkey(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    let init_instruction = Instruction::new_with_bytes(program_id, &[], accounts.clone());
    let tx1 = Transaction::new_signed_with_payer(
        &[init_instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let res1 = banks_client.process_transaction(tx1).await;
    println!("First init result: {:?}", res1);

    let init_instruction2 = Instruction::new_with_bytes(program_id, &[], accounts.clone());
    let tx2 = Transaction::new_signed_with_payer(
        &[init_instruction2],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    "#,
                Self::verdict_match("tx2", "the re-initialization guard")
            ),
        ));
        s
    }

    fn generate_revival_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::RevivalAttack);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_revival", sanitize_id(id)),
            "",
            &format!(
                "{}{}",
                r#"// Attack: close an account then re-initialize it
    let target_account = Keypair::new();

    // Step 1: Initialize
    let init_accounts = vec![
        AccountMeta::new(target_account.pubkey(), false),
        AccountMeta::new_readonly(attacker.pubkey(), true),
    ];
    let init_ix = Instruction::new_with_bytes(program_id, &[], init_accounts);
    let tx_init = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );
    banks_client.process_transaction(tx_init).await.ok();

    // Step 2: Close (instruction that drains lamports to attacker)
    let close_accounts = vec![
        AccountMeta::new(target_account.pubkey(), false),
        AccountMeta::new(attacker.pubkey(), false),
    ];
    let close_ix = Instruction::new_with_bytes(program_id, &[], close_accounts);
    let tx_close = Transaction::new_signed_with_payer(
        &[close_ix],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );
    banks_client.process_transaction(tx_close).await.ok();

    // Step 3: Re-initialize (revival)
    let reinit_accounts = vec![
        AccountMeta::new(target_account.pubkey(), false),
        AccountMeta::new_readonly(attacker.pubkey(), true),
    ];
    let reinit_ix = Instruction::new_with_bytes(program_id, &[], reinit_accounts);
    let tx_reinit = Transaction::new_signed_with_payer(
        &[reinit_ix],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );

    "#,
                Self::verdict_match("tx_reinit", "the account-close constraint")
            ),
        ));
        s
    }

    fn generate_invariant_poc(id: &str, program_name: &str, finding: &Finding) -> String {
        let mut s = Self::header(id, program_name, &finding.category);
        s.push_str(Self::imports());
        let body = format!(
            r#"// Finding: {}
    // This PoC reproduces the fuzzer-discovered invariant violation.
    // Implement the specific transaction sequence that triggers it.

    let accounts = vec![
        AccountMeta::new(victim.pubkey(), false),
        AccountMeta::new_readonly(attacker.pubkey(), true),
    ];

    let instruction = Instruction::new_with_bytes(program_id, &[], accounts);
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );

    {}"#,
            sanitize_comment(&finding.description).replace('"', "\\\""),
            Self::verdict_match("transaction", "the violated invariant")
        );
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_invariant", sanitize_id(id)),
            "",
            &body,
        ));
        s
    }

    fn generate_generic_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::Generic);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_generic", sanitize_id(id)),
            "",
            &format!(
                "{}{}",
                r#"// Generic PoC harness — implement attack sequence based on finding details.
    let accounts = vec![
        AccountMeta::new(victim.pubkey(), false),
        AccountMeta::new_readonly(attacker.pubkey(), true),
    ];

    let instruction = Instruction::new_with_bytes(program_id, &[], accounts);
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );

    "#,
                Self::verdict_match("transaction", "the program's validation")
            ),
        ));
        s
    }
}

fn sanitize_id(id: &str) -> String {
    id.to_lowercase().replace("-", "_").replace(" ", "_")
}

/// Neutralize control characters (newlines, CR, tabs, etc.) so untrusted
/// fuzzer-derived text cannot break out of the `//` comment it is
/// interpolated into and inject Rust code into the generated PoC.
fn sanitize_comment(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn program_name_placeholder() -> &'static str {
    "target_program"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idl::IdlArg;
    use ares_core::{CodeLocation, Severity};

    fn sample_finding() -> Finding {
        Finding {
            id: "ARES-1".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            severity: Severity::High,
            category: VulnerabilityCategory::SignerAuthorization,
            location: CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "r".to_string(),
            references: vec![],
            confidence: 0.9,
            validation: None,
        }
    }

    fn instruction(name: &str, args: Vec<IdlArg>) -> IdlInstruction {
        IdlInstruction {
            name: name.to_string(),
            accounts: vec![],
            args,
        }
    }

    #[test]
    fn imports_use_single_braces() {
        // Regression: imports() is a plain &str, so it must already contain valid
        // Rust (single braces), not the format!-style `{{` it shipped with.
        let imports = PocGenerator::imports();
        assert!(imports.contains("use solana_sdk::{\n"));
        assert!(!imports.contains("{{"));
    }

    #[test]
    fn unwired_when_no_instruction() {
        let code = PocGenerator::generate(&sample_finding(), "prog", None, None);
        assert!(code.starts_with("// ARES-WIRING: unwired\n"));
        // Placeholder instruction data is left in place.
        assert!(code.contains("Instruction::new_with_bytes(program_id, &[], "));
    }

    #[test]
    fn wires_real_instruction_data() {
        let ix = instruction("log_message", vec![]);
        let code = PocGenerator::generate(&sample_finding(), "prog", Some(&ix), None);
        // The placeholder is gone and real discriminator bytes are embedded.
        assert!(!code.contains("Instruction::new_with_bytes(program_id, &[], "));
        assert!(code.contains("Instruction::new_with_bytes(program_id, &[0x"));
        // Program id still unknown, so this is partial, not fully wired.
        assert!(code.starts_with("// ARES-WIRING: partial\n"));
    }

    #[test]
    fn partial_when_arg_type_unencodable() {
        let ix = instruction(
            "x",
            vec![IdlArg {
                name: "cfg".to_string(),
                ty: serde_json::json!({ "defined": "Config" }),
            }],
        );
        let code = PocGenerator::generate(&sample_finding(), "prog", Some(&ix), Some("prog"));
        // Instruction matched and program id present, but an arg could not be
        // encoded, so the data is incomplete -> partial, never "wired".
        assert!(code.starts_with("// ARES-WIRING: partial\n"));
    }

    #[test]
    fn wires_program_id_when_present() {
        let ix = instruction("log_message", vec![]);
        let code = PocGenerator::generate(
            &sample_finding(),
            "prog",
            Some(&ix),
            Some("So11111111111111111111111111111111111111112"),
        );
        assert!(code.contains(".parse::<Pubkey>().unwrap()"));
        assert!(!code.contains("Pubkey::new_unique()"));
        assert!(code.starts_with("// ARES-WIRING: wired\n"));
    }

    /// Every category, including the ones that fall through to the generic
    /// builder. Iterating the enum is deliberate: the original defect was present
    /// in all seven builders at once, so a test pinning one of them would have
    /// passed while the rest stayed broken.
    fn all_categories() -> Vec<VulnerabilityCategory> {
        use VulnerabilityCategory::*;
        vec![
            SignerAuthorization,
            OwnershipCheck,
            ArbitraryCpi,
            InitializationFrontrunning,
            ReInitialization,
            AccountReloading,
            RevivalAttack,
            FuzzingCrash,
            InvariantViolation,
            TypeCosplay,
            ReentrancyRisk,
            DuplicateMutableAccounts,
            ArithmeticOverflow,
            CloseAccount,
            AccountDataMatching,
            PdaPrivileges,
            MissingSigner,
            MissingRevalidation,
            UncheckedCast,
            Generic,
        ]
    }

    fn harness_for(category: VulnerabilityCategory) -> String {
        let mut f = sample_finding();
        f.category = category;
        PocGenerator::generate(&f, "target_program", None, None)
    }

    #[test]
    fn every_harness_fails_the_test_when_the_attack_is_rejected() {
        // THE VERDICT CONTRACT. `run_poc` reads only the exit code of `cargo
        // test`, and `confirm.rs` maps success to ValidationOutcome::Confirmed
        // with confidence forced to 0.95. A harness that merely prints on the
        // Err arm exits 0 even when the program correctly rejected the attack,
        // so a *well-guarded* program was reported as a fork-confirmed exploit.
        // The panic is what carries the refutation out to the exit code.
        for category in all_categories() {
            let code = harness_for(category.clone());
            assert!(
                code.contains("Err(e) => panic!("),
                "{category:?} harness does not panic when the attack is rejected;                  cargo test would exit 0 and the finding would be marked Confirmed"
            );
        }
    }

    #[test]
    fn no_harness_swallows_the_rejected_arm_with_a_print() {
        // The exact shape of the original bug: both arms printing, neither
        // failing. Guards against a future "friendlier output" refactor quietly
        // restoring a constant-Confirmed verdict.
        for category in all_categories() {
            let code = harness_for(category.clone());
            let err_arm = code
                .split("Err(e) =>")
                .nth(1)
                .unwrap_or_else(|| panic!("{category:?} harness has no Err arm at all"));
            assert!(
                !err_arm.trim_start().starts_with("println!"),
                "{category:?} harness prints on the rejected arm instead of failing"
            );
        }
    }

    #[test]
    fn the_reproduced_arm_succeeds_so_a_real_exploit_still_confirms() {
        // The other direction: the fix must not make every PoC refute. An
        // accepted attack transaction has to leave the test passing.
        for category in all_categories() {
            let code = harness_for(category.clone());
            let ok_arm = code
                .split("Ok(_) =>")
                .nth(1)
                .unwrap_or_else(|| panic!("{category:?} harness has no Ok arm"));
            assert!(
                !ok_arm.trim_start().starts_with("panic!"),
                "{category:?} panics when the exploit DID reproduce, inverting the verdict"
            );
            assert!(
                ok_arm.contains("EXPLOIT REPRODUCED"),
                "{category:?} does not mark the reproduced arm"
            );
        }
    }

    #[test]
    fn every_harness_adds_its_accounts_before_program_test_start() {
        // `ProgramTest::start` takes `self` BY VALUE. An `add_account` call
        // emitted after it is a use-after-move (E0382), so the harness never
        // compiles — and `confirm.rs` stages it into the AUDITED repository's
        // own `tests/` directory, which stops `cargo test` from building that
        // package at all. No `test result:` line is then printed, so `run_poc`
        // returns Inconclusive for this finding AND every later one in the same
        // repo: one bad template zeroes out the whole confirmation pass.
        for category in all_categories() {
            let code = harness_for(category.clone());
            let starts: Vec<usize> = code
                .match_indices("program_test.start()")
                .map(|(i, _)| i)
                .collect();
            assert_eq!(
                starts.len(),
                1,
                "{category:?} harness calls program_test.start() {} times; \
                 `self` can only be consumed once",
                starts.len()
            );
            for (idx, _) in code.match_indices("program_test.add_account(") {
                assert!(
                    idx < starts[0],
                    "{category:?} harness calls program_test.add_account after \
                     program_test.start() consumed `program_test` — E0382, the \
                     harness cannot compile"
                );
            }
        }
    }

    #[test]
    fn every_harness_parses_as_rust() {
        // We cannot `cargo check` the real thing here — that would drag the whole
        // `solana-program-test` runtime into this workspace — so this pins the
        // strongest compile property that is cheap: the emitted file is valid
        // Rust syntax. It generalises `imports_use_single_braces`, which caught
        // one instance of `format!` brace escaping leaking into generated code.
        for category in all_categories() {
            // Parsed whole, `// ARES-WIRING:` marker included — it is a comment,
            // so syn sees exactly what rustc would.
            let code = harness_for(category.clone());
            syn::parse_file(&code).unwrap_or_else(|e| {
                panic!("{category:?} harness is not valid Rust: {e}\n---\n{code}\n---")
            });
        }
    }

    #[test]
    fn ownership_and_cpi_harnesses_still_set_up_their_attack_accounts() {
        // Moving the setup before `start()` must not silently drop it: without
        // the fake account the ownership/CPI attack is not being attempted at
        // all, and a harness that attempts nothing would report `refuted`.
        let owner = harness_for(VulnerabilityCategory::OwnershipCheck);
        assert!(owner.contains("let fake_account = Keypair::new();"));
        assert!(owner.contains("owner: system_program::id(),"));
        assert!(owner.contains("AccountMeta::new(fake_account.pubkey(), false),"));

        let cpi = harness_for(VulnerabilityCategory::ArbitraryCpi);
        assert!(cpi.contains("let fake_program = Keypair::new();"));
        assert!(cpi.contains("owner: solana_sdk::bpf_loader_upgradeable::id(),"));
        assert!(cpi.contains("AccountMeta::new_readonly(fake_program.pubkey(), false),"));
    }

    #[test]
    fn the_verdict_block_reports_on_the_transaction_the_template_built() {
        // The revival and double-init builders name their attack transaction
        // `tx_reinit` / `tx2`. A verdict hard-coded to `transaction` would either
        // not compile or, worse, judge a different transaction than the attack.
        for category in all_categories() {
            let code = harness_for(category.clone());
            let processed: Vec<&str> = code
                .match_indices("banks_client.process_transaction(")
                .map(|(i, _)| {
                    let rest = &code[i + "banks_client.process_transaction(".len()..];
                    &rest[..rest.find(')').unwrap_or(0)]
                })
                .collect();
            let judged = code
                .split("let result = banks_client.process_transaction(")
                .nth(1)
                .map(|r| &r[..r.find(')').unwrap_or(0)])
                .unwrap_or_else(|| panic!("{category:?} never binds a judged result"));
            assert!(
                processed.contains(&judged),
                "{category:?} judges `{judged}` which the template never builds"
            );
        }
    }
}
