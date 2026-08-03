use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let external_program = next_account_info(accounts_iter)?;

    // VULNERABILITY: reentrancy-risk — same account in write + CPI pass
    // Write to vault, then pass it to external CPI which could re-enter
    **vault.try_borrow_mut_lamports()? = vault.lamports().checked_sub(100).unwrap_or(0);

    let ix = Instruction {
        program_id: *external_program.key,
        accounts: vec![AccountMeta::new(*vault.key, false)],
        data: vec![],
    };

    invoke_signed(&ix, &[vault.clone()], &[])?;

    msg!("State modified and CPI executed on same account");
    Ok(())
}
