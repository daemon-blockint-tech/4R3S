use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config = next_account_info(accounts_iter)?;

    // VULNERABILITY: initialization-frontrunning — init without payer/system_program constraint
    // Attacker can front-run initialization and set malicious values
    let mut data = config.data.borrow_mut();
    data[0] = 1; // mark as initialized

    msg!("Config initialized");
    Ok(())
}
