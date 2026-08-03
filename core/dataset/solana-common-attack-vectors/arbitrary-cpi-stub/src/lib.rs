use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let target_program = next_account_info(accounts_iter)?;
    let source = next_account_info(accounts_iter)?;
    let destination = next_account_info(accounts_iter)?;

    // VULNERABILITY: arbitrary-cpi — invoking user-supplied program without validation
    // Attacker can redirect CPI to a malicious program
    let ix = Instruction {
        program_id: *target_program.key,
        accounts: vec![
            AccountMeta::new(*source.key, true),
            AccountMeta::new(*destination.key, false),
        ],
        data: vec![],
    };

    invoke(&ix, &[source.clone(), destination.clone()])?;

    msg!("CPI executed to {}", target_program.key);
    Ok(())
}
