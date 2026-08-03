use ares_core::{Finding, VulnerabilityCategory};
use chrono::Utc;

/// Generates compilable proof-of-concept harnesses using `solana-program-test`.
/// Each category produces a structurally valid test with attack-specific account setup.
/// The generated files are meant to be placed in the target program's test directory
/// and wired to the actual program entrypoint / .so by the auditor.
pub struct PocGenerator;

impl PocGenerator {
    pub fn generate(finding: &Finding, program_name: &str) -> String {
        let id = &finding.id;

        match &finding.category {
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
        }
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
        "use solana_program_test::*;\nuse solana_sdk::{{\n    account::Account,\n    instruction::{{AccountMeta, Instruction}},\n    pubkey::Pubkey,\n    signature::{{Keypair, Signer}},\n    system_program,\n    transaction::Transaction,\n}};\n"
    }

    fn test_boilerplate(test_name: &str, body: &str) -> String {
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

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    {}
}}
"#,
            test_name,
            program_name_placeholder(),
            body
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

    let result = banks_client.process_transaction(transaction).await;
    match result {
        Ok(_) => println!("Transaction succeeded — signer check may be MISSING (vulnerability confirmed)."),
        Err(e) => println!("Transaction failed: {:?} — signer check is present.", e),
    }"#,
        ));
        s
    }

    fn generate_owner_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::OwnershipCheck);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_wrong_owner", sanitize_id(id)),
            r#"// Attack: provide an account owned by system_program instead of the target program
    let fake_account = Keypair::new();
    program_test.add_account(
        fake_account.pubkey(),
        Account {
            lamports: 1_000_000,
            owner: system_program::id(),
            ..Account::default()
        },
    );

    let accounts = vec![
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

    let result = banks_client.process_transaction(transaction).await;
    match result {
        Ok(_) => println!("Transaction succeeded — ownership check may be MISSING."),
        Err(e) => println!("Transaction failed: {:?} — ownership check is present.", e),
    }"#,
        ));
        s
    }

    fn generate_cpi_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::ArbitraryCpi);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_arbitrary_cpi", sanitize_id(id)),
            r#"// Attack: create a fake program account to impersonate a trusted CPI target
    let fake_program = Keypair::new();
    program_test.add_account(
        fake_program.pubkey(),
        Account {
            lamports: 1_000_000,
            owner: solana_sdk::bpf_loader_upgradeable::id(),
            ..Account::default()
        },
    );

    let accounts = vec![
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

    let result = banks_client.process_transaction(transaction).await;
    match result {
        Ok(_) => println!("Transaction succeeded — CPI target check may be MISSING."),
        Err(e) => println!("Transaction failed: {:?} — CPI program ID check is present.", e),
    }"#,
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

    let res2 = banks_client.process_transaction(tx2).await;
    match res2 {
        Ok(_) => println!("Second init succeeded — initialization check may be MISSING."),
        Err(e) => println!("Second init failed: {:?} — initialization check is present.", e),
    }"#,
        ));
        s
    }

    fn generate_revival_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::RevivalAttack);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_revival", sanitize_id(id)),
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

    let result = banks_client.process_transaction(tx_reinit).await;
    match result {
        Ok(_) => println!("Revival succeeded — close constraint may be MISSING."),
        Err(e) => println!("Revival failed: {:?} — close constraint is present.", e),
    }"#,
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

    let result = banks_client.process_transaction(transaction).await;
    match result {{
        Ok(_) => println!("Invariant violation PoC executed — inspect program state."),
        Err(e) => println!("Transaction failed: {{:?}} — may require specific preconditions.", e),
    }}"#,
            finding.description.replace('"', "\\\"")
        );
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_invariant", sanitize_id(id)),
            &body,
        ));
        s
    }

    fn generate_generic_poc(id: &str, program_name: &str) -> String {
        let mut s = Self::header(id, program_name, &VulnerabilityCategory::Generic);
        s.push_str(Self::imports());
        s.push_str(&Self::test_boilerplate(
            &format!("test_{}_generic", sanitize_id(id)),
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

    let result = banks_client.process_transaction(transaction).await;
    match result {
        Ok(_) => println!("Transaction succeeded."),
        Err(e) => println!("Transaction failed: {:?}", e),
    }"#,
        ));
        s
    }
}

fn sanitize_id(id: &str) -> String {
    id.to_lowercase().replace("-", "_").replace(" ", "_")
}

fn program_name_placeholder() -> &'static str {
    "target_program"
}
